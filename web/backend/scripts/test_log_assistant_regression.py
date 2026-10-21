"""
Automates the manual "ask a question, read the answer, check journalctl"
loop this session's whole Log Assistant debugging cycle was built on --
every scenario below is a real incident confirmed live on net-flow, not a
speculative test case (see each scenario's own comment for which bug it
regresses).

Runs SEQUENTIALLY, one request at a time, deliberately -- this host is
CPU-only with OLLAMA_NUM_PARALLEL=1 (see the Log Assistant section of
README.md); firing requests concurrently is confirmed to badly degrade
response times (one earlier stress test saw 400s+ responses and a 502), not
just slow this script down.

This hits the real, deployed HTTP API against real ClickHouse/OpenSearch
data and the real Ollama model -- it is NOT a substitute for the unit-level
tests (mocking semantic_search/the LLM/log_search_service) used while
developing each fix; it's a live smoke test to run after every deploy,
the same role the manual copy-paste testing has played all session.

It can only check what the HTTP response itself reveals -- it has no
ClickHouse access of its own to compute ground truth, so it does NOT
assert specific counts are correct. What it DOES check, generically
(never per-question-phrasing, matching this file's own hard-won lesson
about narrow keyword lists):
  - the request succeeded at all (no HTTP error, no timeout)
  - the answer never attributes a count to an internal schema/field name
    or anomaly-category literal as if it were a real hostname (the
    confirmed "anomaly_reason" / "interface_flapping" leak bugs)
  - the model's own "a number above doesn't match the raw data" grounding
    flag, when present, is surfaced prominently for manual follow-up
    rather than buried in the transcript
  - a vague, contentless non-answer ("...already determined... let me know
    if you need more detail") is flagged for manual follow-up

Usage (from web/backend, with the venv active):
    python scripts/test_log_assistant_regression.py --username admin
(prompts for the password rather than taking it as an argument)

    python scripts/test_log_assistant_regression.py --username admin \
        --base-url http://localhost:8000 --output /tmp/la_regression.json

Exit code is non-zero if any HARD check failed (HTTP error, or an
internal-field-as-hostname leak) -- WARN-level findings (grounding-flag
present, vague non-answer) are printed but don't fail the run, since they
need a human to judge whether they're a real regression or an inherent
LLM-sampling-variance edge case that already has its own safety net.
"""
import argparse
import getpass
import json
import re
import sys
import time
from dataclasses import dataclass, field

import httpx

# Mirrors log_assistant_service.py's own constants for exactly the schema
# field names / anomaly-category literals that were confirmed live to leak
# into conversation history and get mistaken for a hostname (see that
# file's _SCHEMA_FIELD_TOKENS and _VALID_ANOMALY_REASONS). Duplicated here
# rather than imported -- this script is meant to run standalone against a
# deployed HTTP API, potentially from a different checkout/host than the
# backend it's testing, so importing the backend's own module would
# silently test "whatever this script's copy of the code happens to do"
# instead of "whatever the deployed server actually does".
_LEAKED_INTERNAL_TOKENS = (
    "anomaly_reason", "anomaly_reasons", "anomaly_event_count",
    "event_count", "device_count",
    "rare_template", "always_severe", "security_content", "severity_spike",
    "volume_spike", "unusual_template_mix", "unusual_transition", "interface_flapping",
)
_HOSTNAME_LEAK_RE = re.compile(
    r"hostname[^a-zA-Z0-9]{0,20}(" + "|".join(_LEAKED_INTERNAL_TOKENS) + r")\b",
    re.IGNORECASE,
)
_GROUNDING_FLAG_RE = re.compile(r"doesn't match the raw data", re.IGNORECASE)
_VAGUE_NONANSWER_RE = re.compile(
    r"already determined.{0,200}let me know|let me know.{0,200}more detail", re.IGNORECASE | re.DOTALL,
)


@dataclass
class Turn:
    question: str
    # Free-form notes on what this turn is regression-testing -- printed in
    # the summary so a failure/warning is immediately legible without
    # cross-referencing this file.
    note: str = ""


@dataclass
class Scenario:
    name: str
    turns: list[Turn]


@dataclass
class TurnResult:
    scenario: str
    question: str
    note: str
    answer: str | None
    http_error: str | None
    elapsed_s: float
    hard_findings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# Each scenario is a real, confirmed-live incident from this session's
# testing -- see the comment above each one for exactly which fix it
# regresses. New scenarios should follow the same rule: only add one once
# a real failure has actually been seen, not for a hypothetical phrasing.
SCENARIOS: list[Scenario] = [
    Scenario(
        "ranking + named time period on a fixed anomaly category",
        [
            Turn(
                "top n for today with ethernet flapping",
                "anomaly_summary has no time-scoping at all -- the answer must disclose that "
                "'today' was ignored, not silently answer with an all-time cumulative number.",
            ),
        ],
    ),
    Scenario(
        "bare follow-up ranking inheritance",
        [
            Turn("top n for today with ethernet flapping"),
            Turn(
                "what about yesterday",
                "must re-inherit the SAME anomaly reason (interface_flapping), not drift to an "
                "unrelated one or a bare-hostname count.",
            ),
        ],
    ),
    Scenario(
        "bare follow-up count after a ranking turn -- anomaly_reason-as-hostname regression",
        [
            Turn("top n for today with ethernet flapping"),
            Turn(
                "what about last month",
                "CONFIRMED LIVE BUG (fixed): this exact sequence once produced 'scoped to the "
                "hostname `anomaly_reason`, 0 events' -- the schema field name from the previous "
                "turn's own answer text was mistaken for a device. _HOSTNAME_LEAK_RE below is the "
                "automated check for this regressing.",
            ),
        ],
    ),
    Scenario(
        "ranking question must not misroute into count_events's hostname inheritance",
        [
            Turn(
                "top noisiest device today",
                "CONFIRMED LIVE BUG (fixed): this 4-word ranking question was once force-routed "
                "toward count_events via the bare-followup heuristic and answered with an "
                "unrelated inherited hostname's '0 events' instead of a real ranking.",
            ),
        ],
    ),
    Scenario(
        "device/hostname argument alias + zero-tool-call nudge",
        [
            Turn("top device with wireless disconnections"),
            Turn(
                "what about the devices that showed wireless disconnections today",
                "CONFIRMED LIVE BUG (fixed twice): first the model's own 'device=' argument name "
                "was silently dropped (ran unscoped); separately, a zero-tool-call answer invented "
                "per-device numbers with no grounding at all. Watch for the grounding-mismatch "
                "flag below -- its ABSENCE here is not proof of correctness without a human "
                "checking journalctl, since this question shape has no deterministic per-device, "
                "time-scoped tool path yet.",
            ),
        ],
    ),
    Scenario(
        "comparison question must not silently inherit a stale anomaly reason",
        [
            Turn("top n for today with ethernet flapping"),
            Turn(
                "compare yesterday and today",
                "CONFIRMED LIVE BUG (fixed): a comparison question once inherited the previous "
                "turn's anomaly reason via the bare-followup path and answered with the SAME "
                "all-time number for both periods, silently ignoring the comparison.",
            ),
        ],
    ),
    Scenario(
        "relative-time phrase coverage sweep",
        [
            Turn("how many events today"),
            Turn("what about yesterday"),
            Turn("what about this week"),
            Turn("what about last week"),
            Turn("what about this month", "CONFIRMED LIVE GAP (fixed): previously unrecognized entirely."),
            Turn("what about last month", "CONFIRMED LIVE GAP (fixed): previously unrecognized entirely."),
            Turn("what about this hour", "CONFIRMED LIVE GAP (fixed): previously unrecognized entirely."),
            Turn("what about last hour", "CONFIRMED LIVE GAP (fixed): previously unrecognized entirely."),
        ],
    ),
]


def login(client: httpx.Client, base_url: str, username: str, password: str) -> str:
    resp = client.post(f"{base_url}/api/auth/login", data={"username": username, "password": password})
    resp.raise_for_status()
    return resp.json()["access_token"]


def ask(client: httpx.Client, base_url: str, token: str, question: str, history: list[dict]) -> tuple[str | None, str | None, float]:
    """Returns (answer, http_error, elapsed_seconds)."""
    start = time.monotonic()
    try:
        resp = client.post(
            f"{base_url}/api/log-assistant/ask",
            headers={"Authorization": f"Bearer {token}"},
            json={"question": question, "history": history},
        )
        resp.raise_for_status()
        return resp.json()["answer"], None, time.monotonic() - start
    except httpx.HTTPStatusError as exc:
        return None, f"HTTP {exc.response.status_code}: {exc.response.text[:500]}", time.monotonic() - start
    except httpx.HTTPError as exc:
        return None, f"{type(exc).__name__}: {exc}", time.monotonic() - start


def check_answer(answer: str) -> tuple[list[str], list[str]]:
    """Returns (hard_findings, warnings)."""
    hard: list[str] = []
    warn: list[str] = []
    leak = _HOSTNAME_LEAK_RE.search(answer)
    if leak:
        hard.append(f"internal field/category name used as a hostname: matched {leak.group(0)!r}")
    if _GROUNDING_FLAG_RE.search(answer):
        warn.append("model's own grounding-mismatch disclaimer fired -- check journalctl for this turn")
    if _VAGUE_NONANSWER_RE.search(answer):
        warn.append("looks like a vague/contentless non-answer rather than a real restated result")
    return hard, warn


def run(base_url: str, username: str, password: str, delay_s: float, timeout_s: float) -> list[TurnResult]:
    results: list[TurnResult] = []
    with httpx.Client(timeout=timeout_s) as client:
        token = login(client, base_url, username, password)
        for scenario in SCENARIOS:
            history: list[dict] = []
            print(f"\n=== {scenario.name} ===")
            for turn in scenario.turns:
                print(f"  -> {turn.question!r}", end="", flush=True)
                answer, http_error, elapsed = ask(client, base_url, token, turn.question, history)
                result = TurnResult(scenario.name, turn.question, turn.note, answer, http_error, elapsed)
                if http_error:
                    result.hard_findings.append(f"request failed: {http_error}")
                    print(f"  [FAILED in {elapsed:.1f}s] {http_error}")
                else:
                    result.hard_findings, result.warnings = check_answer(answer)
                    status = "FAIL" if result.hard_findings else ("WARN" if result.warnings else "ok")
                    print(f"  [{status} in {elapsed:.1f}s]")
                    print(f"     {answer}")
                    history.append({"question": turn.question, "answer": answer[:4000]})
                for f in result.hard_findings:
                    print(f"     FINDING: {f}")
                for w in result.warnings:
                    print(f"     WARNING: {w}")
                if turn.note:
                    print(f"     (regresses: {turn.note})")
                results.append(result)
                time.sleep(delay_s)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://localhost:8000", help="Backend base URL (default: http://localhost:8000, bypassing nginx)")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", default=None, help="Omit to be prompted (recommended -- avoids shell history)")
    parser.add_argument("--delay", type=float, default=2.0, help="Seconds to wait between requests (default 2 -- this host is CPU-only, sequential-only)")
    parser.add_argument("--timeout", type=float, default=300.0, help="Per-request timeout in seconds (default 300, matching the backend's own proxy_read_timeout)")
    parser.add_argument("--output", default=None, help="Optional path to save the full transcript as JSON")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password: ")
    results = run(args.base_url, args.username, password, args.delay, args.timeout)

    print("\n=== Summary ===")
    hard_total = sum(len(r.hard_findings) for r in results)
    warn_total = sum(len(r.warnings) for r in results)
    print(f"{len(results)} turns run across {len(SCENARIOS)} scenarios -- {hard_total} hard finding(s), {warn_total} warning(s)")
    for r in results:
        if r.hard_findings or r.warnings:
            print(f"  [{r.scenario}] {r.question!r}:")
            for f in r.hard_findings:
                print(f"    FAIL: {f}")
            for w in r.warnings:
                print(f"    WARN: {w}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump([r.__dict__ for r in results], fh, indent=2)
        print(f"\nFull transcript saved to {args.output}")

    sys.exit(1 if hard_total else 0)


if __name__ == "__main__":
    main()
