"""
Log Assistant: semantic search + local-LLM "ask" over log lines already
embedded into OpenSearch by ml/log_assistant_indexer.py. See README's Log
Assistant section for the full architecture.

Two Ollama calls per `ask()`: embed the question with the same embedding
model the indexer used (so the vectors are comparable), then a chat
completion over the retrieved log lines. `semantic_search()` alone only
needs the first, for callers that just want matching log lines without the
extra LLM latency.

NOTE ON TESTING: this file's OpenSearch query shape (k-NN with efficient
filtering, which needs the index's `lucene` engine -- see
opensearch/log_events_index.json) and its Ollama request/response handling
are written against those services' documented APIs, but this project's
dev sandbox couldn't reach opensearch.org or ollama.com to install and
exercise either one live (blocked by the sandbox's own egress proxy, not a
constraint that applies to net-flow itself). Smoke-test both endpoints
after installing OpenSearch/Ollama for real.
"""
import asyncio
import json
import logging
import pathlib
import re
from datetime import datetime, timedelta, timezone

import httpx
from clickhouse_connect.driver.client import Client
from opensearchpy import OpenSearch

from app.core.ch_time import ch_literal
from app.core.config import settings
from app.schemas.log_assistant import AskResponse, ConversationTurn, LogAssistantQuery, LogHit
from app.services import device_service, log_search_service

log = logging.getLogger("log_assistant_service")

# Same design idea sislogIQ's own README documents (a prompts/ folder next
# to the code, editable without a code change) -- kept as a fallback
# in-code default too, so a missing/misconfigured file degrades to a
# working prompt instead of breaking "Ask" entirely.
_DEFAULT_PROMPT_PATH = pathlib.Path(__file__).resolve().parent.parent / "prompts" / "log_assistant_system.txt"
_FALLBACK_SYSTEM_PROMPT = (
    "You are a network log analysis assistant. Answer the question using ONLY the "
    "log excerpts provided below -- do not assume anything about the network that "
    "isn't shown in them. If the excerpts don't contain enough information to "
    "answer, say so plainly instead of guessing."
)


def _load_system_prompt() -> str:
    path = pathlib.Path(settings.log_assistant_system_prompt_file) if settings.log_assistant_system_prompt_file else _DEFAULT_PROMPT_PATH
    try:
        text = path.read_text(encoding="utf-8").strip()
        return text or _FALLBACK_SYSTEM_PROMPT
    except (OSError, UnicodeDecodeError):
        # OSError: missing file, permissions, is-a-directory. UnicodeDecodeError
        # (a ValueError subclass, NOT an OSError): the file exists and is
        # readable but isn't valid UTF-8 (e.g. saved from a Windows editor
        # in some other encoding) -- read_text() raises this separately, and
        # since this runs at import time, letting it propagate would crash
        # the whole FastAPI app on startup, not just degrade "Ask" the way
        # a missing file does.
        log.warning("Log Assistant system prompt file not found/readable at %s, using built-in default", path)
        return _FALLBACK_SYSTEM_PROMPT


# Read once at process start, same as every other setting here -- edit the
# file and restart syslog-ml-web-api to apply, consistent with how every
# other config change in this project (env vars, systemd overrides) works.
_SYSTEM_PROMPT = _load_system_prompt()


async def _embed(question: str) -> list[float]:
    async with httpx.AsyncClient(timeout=settings.ollama_timeout_seconds) as client:
        response = await client.post(
            f"{settings.ollama_url}/api/embed",
            json={
                "model": settings.ollama_embed_model,
                "input": question,
                # Same reasoning as ollama_chat_num_thread -- a one-off
                # embed call doesn't need many threads, and capping it
                # leaves headroom for whatever else (the indexer's own
                # embed calls, an in-flight chat completion) is running.
                "options": {"num_thread": 2},
            },
        )
        response.raise_for_status()
        return response.json()["embeddings"][0]


def _build_query(vector: list[float], query: LogAssistantQuery) -> dict:
    filters = []
    if query.source_ip:
        filters.append({"term": {"source_ip": query.source_ip}})
    if query.vendor:
        filters.append({"term": {"vendor": query.vendor}})
    if query.start or query.end:
        time_range = {}
        if query.start:
            time_range["gte"] = query.start.isoformat()
        if query.end:
            time_range["lte"] = query.end.isoformat()
        filters.append({"range": {"event_time": time_range}})

    knn_clause: dict = {"vector": vector, "k": query.limit}
    if filters:
        # "Efficient filtering": the lucene engine applies these during the
        # ANN graph traversal itself, not as a post-filter on the top-k --
        # without it, a device/time filter on a narrow slice of the index
        # could come back empty even when matching documents exist, simply
        # because none of them happened to be in the unfiltered top-k.
        knn_clause["filter"] = {"bool": {"filter": filters}}
    knn_query: dict = {"knn": {"embedding": knn_clause}}

    # Vector search alone is weak on the things network logs are full of and
    # embeddings represent poorly -- exact IPs, hostnames, error codes,
    # session IDs. "172.22.21.165" or "ACSSERVER" typed into the question
    # should find every log line containing it; a keyword match query
    # guarantees that in a way semantic similarity alone doesn't. Filters
    # are duplicated onto this clause too (not shared with the knn clause
    # above) -- a hybrid query fuses two INDEPENDENT result sets, so a
    # filter applied to only one clause would leave the other one
    # unfiltered in the final fused ranking.
    match_query: dict = {"match": {"message": query.question}}
    if filters:
        match_query = {"bool": {"must": [match_query], "filter": filters}}

    # Fused by this index's default search pipeline (RRF -- see
    # opensearch/setup_index.py's _ensure_hybrid_pipeline), not specified
    # per-query here, so both this and semantic_search() get hybrid
    # ranking without either needing to know the pipeline's name.
    return {"size": query.limit, "query": {"hybrid": {"queries": [match_query, knn_query]}}}


def _hit_to_log_hit(hit: dict) -> LogHit:
    source = hit["_source"]
    return LogHit(
        event_time=source["event_time"],
        source_ip=source["source_ip"],
        hostname=source["hostname"],
        vendor=source["vendor"],
        severity=source["severity"],
        program=source["program"],
        predicted_category=source["predicted_category"],
        message=source["message"],
        is_anomaly=source["is_anomaly"],
        anomaly_reasons=source["anomaly_reasons"],
        score=hit["_score"],
    )


async def semantic_search(os_client: OpenSearch, query: LogAssistantQuery) -> list[LogHit]:
    vector = await _embed(query.question)
    body = _build_query(vector, query)
    result = await asyncio.to_thread(os_client.search, index=settings.opensearch_index, body=body)
    return [_hit_to_log_hit(hit) for hit in result["hits"]["hits"]]


def _raw_data_exists(ch_client, query: LogAssistantQuery) -> int:
    """Cheap existence check against syslog_ml.events using the same
    structural filters as the OpenSearch query (source_ip/vendor/time
    range), ignoring the free-text question entirely -- ClickHouse does
    exact matching, not semantic search, so this only answers "does
    anything matching these filters exist at all", not "is it relevant".
    That's exactly what's needed to disambiguate an empty OpenSearch
    result: if this comes back > 0, the raw data exists but the Log
    Assistant indexer hasn't embedded it yet (see README's "Log
    Assistant" section on its checkpoint) -- confirmed multiple times in
    real use, where "No related log lines were found" looked identical
    for that case and for a genuinely quiet window.

    Only runs when at least one narrow filter is present (source_ip, or a
    bounded start+end range) -- an unfiltered question with zero
    OpenSearch hits never triggers a full, unbounded table scan just to
    explain the empty result.
    """
    if not query.source_ip and not (query.start and query.end):
        return 0

    conditions = []
    params: dict = {}
    if query.source_ip:
        conditions.append("source_ip = %(source_ip)s")
        params["source_ip"] = query.source_ip
    if query.vendor:
        conditions.append("vendor = %(vendor)s")
        params["vendor"] = query.vendor
    # start/end embedded as literals, not bound as query parameters -- see
    # app/core/ch_time.py.
    if query.start:
        conditions.append(f"event_time >= '{ch_literal(query.start)}'")
    if query.end:
        conditions.append(f"event_time <= '{ch_literal(query.end)}'")

    result = ch_client.query(f"SELECT count() FROM syslog_ml.events WHERE {' AND '.join(conditions)}", parameters=params)
    return result.result_rows[0][0]


async def build_coverage_note(ch_client, query: LogAssistantQuery, hits: list[LogHit]) -> str | None:
    if hits:
        return None
    try:
        raw_count = await asyncio.to_thread(_raw_data_exists, ch_client, query)
    except Exception:
        # Best-effort diagnostic only -- a ClickHouse hiccup here must
        # never break the actual search/ask response over a nice-to-have
        # explanation for why it came back empty.
        log.exception("Coverage-note ClickHouse check failed, omitting the note")
        return None
    if raw_count == 0:
        return None
    return (
        f"{raw_count} matching log line(s) exist in ClickHouse for this filter, but haven't been "
        "indexed for semantic search yet -- check Log Search for the raw data, or see README's "
        "\"Log Assistant\" section on the indexer's checkpoint."
    )


# A syslog `message` field has no length guarantee -- most are short, but a
# device is free to log something huge (a stack trace, a base64/hex dump, a
# verbose multi-line payload) in one line, and nothing upstream of this
# truncates it. Feeding that straight into the prompt, times up to
# query.limit (default 10) hits, can make the prompt far bigger than a
# typical one without any warning -- suspected on net-flow as a real
# contributor to "ask" taking far longer than a raw Ollama call with a
# trivial prompt, though not confirmed (correlated with intermittent
# slowness, not reproduced in isolation). Capping defensively either way:
# an LLM summarizing log lines needs enough of each message to identify it,
# not its entire payload verbatim.
_MAX_MESSAGE_CHARS_IN_PROMPT = 500


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[truncated, {len(text)} chars total]"


def _post_chat_sync(url: str, payload: dict, timeout: float) -> dict:
    # Deliberately httpx.Client (sync), not AsyncClient, and run via
    # asyncio.to_thread below -- NOT a style preference. Root-caused on
    # net-flow through direct, repeatable comparison: a raw urllib request
    # and a raw `curl` to this exact endpoint, with this exact payload
    # shape, both completed in seconds; the identical payload sent through
    # httpx.AsyncClient (both against `localhost` and against the literal
    # `127.0.0.1`, ruling out IPv6/dual-stack resolution as the cause)
    # reliably hung until timeout. embed calls elsewhere in this file stay
    # on AsyncClient because they've been reliably fast (sub-second) all
    # session -- this call is the one that waits tens of seconds for a
    # full generated response, which is exactly where the async transport
    # reproduced the hang. Not root-caused deeper than that (a real bug
    # somewhere in httpx/httpcore's async I/O path for a slow-arriving
    # response, on this Python/library version combination, is the leading
    # theory) -- but switching transports is a well-evidenced fix, not a
    # guess: every sync-client test succeeded, every async-client test on
    # this same payload hung.
    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, json=payload)
        response.raise_for_status()
        return response.json()


_NO_HITS_ANSWER = (
    "No related log lines were found in the index for this question/filter -- nothing to "
    "synthesize an answer from, so the local LLM wasn't invoked (it would only produce a "
    "generic non-answer with no real log content to ground it)."
)

# "Ask" used to be pure RAG: embed the question, pull the top-K
# semantically-similar log LINES, stuff them into one prompt, one chat
# call. That architecture structurally cannot answer anything that needs
# counting or comparing across rows -- confirmed in real use on net-flow:
# asked "which device is noisiest this week", it picked three devices out
# of ten retrieved lines whose relevance scores were ~0.015 (indistinguishable
# from noise) and confabulated a plausible-sounding answer with no actual
# count behind it. Replaced with a tool-calling agent: the model gets
# function-calling access to the real aggregate queries this app already
# has (list_devices, search_logs) plus the original semantic_search as one
# tool among others, so "which device is noisiest" now means an actual
# event_count comparison, not a guess from a handful of unrelated lines.
#
# UNTESTED LIVE (same caveat as this file's other Ollama-facing code, see
# the module docstring): tool-calling support for
# OLLAMA_CHAT_MODEL=llama3.2:3b-instruct-q4_K_M via Ollama's /api/chat
# `tools` parameter is written against Ollama's documented API, but this
# sandbox can't reach a live Ollama to exercise it. Smoke-test a real
# question after deploying -- if tool calls never fire (model just answers
# in plain text, ignoring the tools), check Ollama's version supports
# tool-calling for this model.
#
# Confirmed on net-flow: asked to compare one device's event count today
# vs. yesterday, the model called count_events ONCE (a blended ~38-hour
# window matching neither period), then invented a two-way split from that
# single number in its final answer -- despite an explicit instruction not
# to. Prompting alone isn't enough for a 3B model on a genuinely multi-step
# question, so ask() below also enforces this structurally: a
# comparison-phrased question can't get a final answer until at least 2
# real tool calls have happened (see _needs_multiple_data_points), and any
# final answer's count-like numbers are checked against what tools actually
# returned (see _extract_count_claims/_grounded_counts_from_result) --
# an unverifiable number gets a visible caveat instead of being presented
# as fact.
MAX_TOOL_ITERATIONS = 6

_COMPARISON_MARKERS = ("compare", " vs ", " vs. ", "versus", "difference between")


def _needs_multiple_data_points(question: str) -> bool:
    lowered = question.lower()
    return any(marker in lowered for marker in _COMPARISON_MARKERS)


# Confirmed on net-flow as a real regression: "show me warning-severity logs
# ... today" mentions "today" (so single_period matches) but explicitly
# wants the actual log ROWS, not a count -- the model correctly called
# search_logs (exactly what its own tool description says to use it for),
# and the wrong-tool-redirect guard below wrongly refused it anyway, then
# the force-resolve backstop handed back a COUNT instead of the rows asked
# for. A time phrase alone isn't enough to conclude "this wants
# count_events"; this explicit negative signal is checked first.
_LOG_ROWS_MARKERS = ("show me", "show the", "list the", "list all", "display", "which log", "log lines", "the logs", "these logs")


def _wants_log_rows(question: str) -> bool:
    lowered = question.lower()
    return any(marker in lowered for marker in _LOG_ROWS_MARKERS)


def _grounded_counts_from_result(tool_name: str, result: dict) -> set[int]:
    """Exact numeric counts a tool call actually returned, for cross-checking
    against what the model later claims in its final answer -- deliberately
    narrow (only fields we know represent a real count), not a blind walk of
    the whole JSON, since that would also pick up limits/offsets/timestamps
    and produce false "unverified" flags on a correct answer."""
    if tool_name == "count_events":
        count = result.get("count")
        return {count} if isinstance(count, int) else set()
    if tool_name == "list_devices":
        return {
            d["event_count"] for d in result.get("devices_sorted_busiest_first", [])
            if isinstance(d.get("event_count"), int)
        }
    return set()


def _identifiers_from_result(tool_name: str, result: dict) -> set[str]:
    """Hostnames/IPs a tool result mentioned -- these routinely contain
    digit runs of their own (confirmed: 'SF-200-POE-DBN-01' made the claim
    extractor below misread '200' as a claimed count instead of the real
    number, '14', appearing later in the same sentence). Stripping these
    exact strings out of the answer text before counting digits removes
    that false-positive source instead of trying to out-guess it with a
    cleverer regex."""
    ids: set[str] = set()
    if tool_name == "list_devices":
        for d in result.get("devices_sorted_busiest_first", []):
            ids.update(v for v in (d.get("ip"), d.get("hostname")) if isinstance(v, str) and len(v) >= 3)
    elif tool_name == "search_logs":
        for row in result.get("matching_rows", []):
            ids.update(v for v in (row.get("hostname"), row.get("source_ip")) if isinstance(v, str) and len(v) >= 3)
    elif tool_name == "semantic_search":
        for hit in result.get("hits", []):
            ids.update(v for v in (hit.get("hostname"), hit.get("source_ip")) if isinstance(v, str) and len(v) >= 3)
    return ids


# Matches a number next to a count-ish word in either order ("14 events",
# "a total of 122,319") -- deliberately anchored to those words rather than
# any bare digit, so a stray timestamp or port number in the answer text
# doesn't get mistaken for a claimed count. Hostnames/IPs are stripped from
# the text before this runs (see _identifiers_from_result) -- without that,
# this still mismatched a hostname's embedded digits for the real count.
_COUNT_CLAIM_RE = re.compile(
    r"(\d[\d,]*)\s*(?:events?|logs?|log lines?|lines?|entries|occurrences?|times?)\b"
    r"|(?:events?|logs?|log lines?|lines?|entries|count(?:ed)?|total(?:\s+of)?)\D{0,12}?(\d[\d,]*)",
    re.IGNORECASE,
)


def _extract_count_claims(text: str, known_identifiers: set[str]) -> set[int]:
    for identifier in known_identifiers:
        text = re.sub(re.escape(identifier), " ", text, flags=re.IGNORECASE)
    claims = set()
    for first, second in _COUNT_CLAIM_RE.findall(text):
        raw = first or second
        try:
            claims.add(int(raw.replace(",", "")))
        except ValueError:
            continue
    return claims

_AGENT_INSTRUCTIONS = (
    "You have tools that query this network's real, current log data. ALWAYS call a tool to get "
    "real data before answering any question involving a count, a comparison ('noisiest', "
    "'busiest', 'most'), or specific log content -- never guess or estimate from memory, and never "
    "answer from a tool's result until you've actually called it. Use list_devices for 'which "
    "device is noisiest/busiest/most active' questions (it returns devices sorted by event count "
    "already -- the first one is the answer) -- it does NOT accept a hostname/IP filter, so never use "
    "it to ask about ONE already-named device. For 'how many events/logs' for a specific device, "
    "severity, or filter -- including comparing two time periods -- use count_events once PER time "
    "period being asked about (e.g. once for today, once for yesterday); it returns an exact total, "
    "never estimate or reuse a number from a different tool call. Use search_logs only when the "
    "actual log lines themselves are needed (not just a count), for 'show me', 'did X happen', or "
    "exact keyword questions. Use semantic_search only for 'what's going on with/related to <topic>' "
    "questions where you don't have an exact keyword to filter on. A number in your final answer must "
    "come from a tool result for that SAME device/filter/time period -- never attribute one tool "
    "call's result to a different device or period than what it was actually called with. Once every "
    "number the question needs has been retrieved, give a plain, direct final answer in your own "
    "words -- do not call another tool after that, and do not call the same tool twice with the same "
    "arguments.\n\n"
    "Time ranges: below is a list of exact start/end values already computed for you, one per common "
    "phrase -- COPY the pair matching the question's time period character-for-character into a "
    "tool's start/end arguments. Do NOT compute a date yourself by adding/subtracting days -- "
    "confirmed unreliable in testing (e.g. 'this week' was miscomputed as next week, a future date, "
    "because the arithmetic came out backwards). If the question has no time period at all, omit "
    "start/end entirely rather than guessing one."
)

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "list_devices",
            "description": (
                "Lists devices seen in a time window with their total event count, busiest first. "
                "The answer to 'which device is noisiest/busiest/most active' is simply the first "
                "item this returns -- no further comparison needed."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "start": {"type": "string", "description": "ISO 8601 UTC start, e.g. 2026-10-01T00:00:00. Omit for 'last 24 hours'."},
                    "end": {"type": "string", "description": "ISO 8601 UTC end. Omit to mean 'now'."},
                    "limit": {"type": "integer", "description": "Max devices to return. Default 10."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "count_events",
            "description": (
                "Returns the EXACT total count of log events matching the given filters -- use this, "
                "not search_logs, for any 'how many' question or when comparing counts across devices "
                "or time periods. Call it once per time period being compared (e.g. once with today's "
                "start/end, once with yesterday's) -- never reuse one call's count for a different "
                "period."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hostname": {"type": "string"},
                    "source_ip": {"type": "string"},
                    "severity": {"type": "string", "description": "e.g. emerg, alert, crit, err, warning, notice, info, debug"},
                    "program": {"type": "string"},
                    "keyword": {"type": "string", "description": "Substring to match in the log message"},
                    "only_anomalies": {"type": "boolean"},
                    "start": {"type": "string", "description": "ISO 8601 UTC start"},
                    "end": {"type": "string", "description": "ISO 8601 UTC end"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_logs",
            "description": (
                "Searches the raw log events with exact filters (hostname, source IP, severity, "
                "program, a message keyword, whether flagged anomalous) and returns the matching rows "
                "themselves. Use only when the actual log content is needed (e.g. 'show me', 'did X "
                "happen') -- for a count, use count_events instead."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hostname": {"type": "string"},
                    "source_ip": {"type": "string"},
                    "severity": {"type": "string", "description": "e.g. emerg, alert, crit, err, warning, notice, info, debug"},
                    "program": {"type": "string"},
                    "keyword": {"type": "string", "description": "Substring to match in the log message"},
                    "only_anomalies": {"type": "boolean"},
                    "start": {"type": "string", "description": "ISO 8601 UTC start"},
                    "end": {"type": "string", "description": "ISO 8601 UTC end"},
                    "limit": {"type": "integer", "description": "Max rows to return. Default 20."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "semantic_search",
            "description": (
                "Finds log lines similar in MEANING to a short phrase, even without shared words -- "
                "e.g. 'authentication failures' can match a line that says 'login rejected'. Use "
                "only when there's no exact keyword/field to filter on with search_logs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "phrase": {"type": "string", "description": "What to search for, in plain language"},
                    "source_ip": {"type": "string"},
                    "vendor": {"type": "string"},
                    "start": {"type": "string"},
                    "end": {"type": "string"},
                    "limit": {"type": "integer", "description": "Default 10"},
                },
                "required": ["phrase"],
            },
        },
    },
]


def _relative_time_bounds(now: datetime) -> dict[str, tuple[datetime, datetime]]:
    """Real Python arithmetic for the relative-time phrases this app's
    questions actually use, computed once and shared by both the prompt
    hint below (for the model to copy) and _detect_comparison_periods
    (which bypasses the model entirely for a detected today/yesterday/this
    week comparison) -- see both call sites for why neither trusts the
    model to derive these itself."""
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    week_start = now - timedelta(days=7)
    return {
        "today": (today_start, now),
        "yesterday": (yesterday_start, today_start),
        "this week": (week_start, now),
    }


def _relative_time_ranges_hint(now: datetime) -> str:
    """Precomputed start/end literals for common relative-time phrases, for
    the model to copy verbatim instead of computing itself -- confirmed on
    net-flow that giving it only the current date/time and a rule to apply
    ('subtract 7 days') isn't enough: it still got the arithmetic backwards
    (added 7 days, landing on a future date) and separately produced a
    zero-width start==end window for 'today'. Real arithmetic, done once
    here in Python, removes that failure mode entirely."""
    bounds = _relative_time_bounds(now)
    fmt = "%Y-%m-%dT%H:%M:%S"
    today_start, today_end = bounds["today"]
    yesterday_start, yesterday_end = bounds["yesterday"]
    week_start, week_end = bounds["this week"]
    return (
        f"today: start={today_start.strftime(fmt)}, end={today_end.strftime(fmt)}\n"
        f"yesterday: start={yesterday_start.strftime(fmt)}, end={yesterday_end.strftime(fmt)}\n"
        f"this week / past week: start={week_start.strftime(fmt)}, end={week_end.strftime(fmt)}"
    )


# Phrase aliases that map onto the same _relative_time_bounds() key -- "this
# week" and "past week" are used interchangeably in real questions (see the
# original noisiest-device incident, which used "this week").
_PERIOD_PHRASE_ALIASES: list[tuple[str, tuple[str, ...]]] = [
    ("today", ("today",)),
    ("yesterday", ("yesterday",)),
    ("this week", ("this week", "past week", "last week")),
]

_NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
}
# "<N> days ago/before/back" -- confirmed on net-flow as a real gap: only the
# three fixed phrases above were covered, so "three days before" fell through
# to the old generic nudge+grounding path, which produced a redundant
# duplicate tool call and a final answer that silently dropped "today" from
# the comparison entirely (reporting one blended number instead of two).
# Unlike arbitrary date phrasing ("last Monday", "the 1st of October"), which
# can't practically be enumerated, "N days ago" is a small, well-defined
# pattern worth parsing directly rather than hardcoding every example of it.
_N_DAYS_AGO_RE = re.compile(
    r"\b(\d{1,3}|" + "|".join(_NUMBER_WORDS) + r")\s+days?\s+(?:ago|before|back)\b", re.IGNORECASE,
)


def _parse_n_days_ago(question: str, now: datetime) -> tuple[str, datetime, datetime] | None:
    match = _N_DAYS_AGO_RE.search(question.lower())
    if not match:
        return None
    raw = match.group(1)
    n = int(raw) if raw.isdigit() else _NUMBER_WORDS[raw]
    if not 1 <= n <= 365:
        return None
    day_start = (now - timedelta(days=n)).replace(hour=0, minute=0, second=0, microsecond=0)
    return f"{n} day(s) ago", day_start, day_start + timedelta(days=1)


def _detect_comparison_periods(question: str, now: datetime) -> list[tuple[str, datetime, datetime]] | None:
    """If the question names (at least) two of today/yesterday/this week,
    returns their exact boundaries so ask() can fetch both deterministically
    instead of trusting the model's own tool-call arguments and its own
    labeling of which number belongs to which period.

    Confirmed on net-flow this was necessary, not just defensive: asked to
    compare one device's count today vs. yesterday, the model's own first
    tool call used the right start (yesterday's midnight) but the wrong end
    (now, instead of today's midnight) -- silently turning "yesterday" into
    "yesterday+today combined" -- and then its final answer swapped which
    raw number it called "today" vs. "yesterday" on top of that. Both
    numbers were individually real (each came from an actual tool call), so
    the grounding check in ask() didn't catch it; only recomputing the
    periods ourselves and supplying pre-labeled results removes the model's
    chance to make either mistake.

    Returns None (falls back to the generic nudge + grounding-check safety
    net in ask()) when fewer than two known period phrases are mentioned --
    e.g. a device-vs-device comparison with only one implied timeframe, or
    a comparison with no relative-time phrase at all. Also recognizes "N
    days ago/before/back" (see _parse_n_days_ago) as a third kind of period,
    alongside the three fixed phrases -- e.g. "today vs. three days before"."""
    matched = _detect_named_periods(question, now)
    return matched[:2] if len(matched) >= 2 else None


def _detect_named_periods(question: str, now: datetime) -> list[tuple[str, datetime, datetime]]:
    bounds = _relative_time_bounds(now)
    lowered = question.lower()
    matched = [
        (label, *bounds[label])
        for label, phrases in _PERIOD_PHRASE_ALIASES
        if any(phrase in lowered for phrase in phrases)
    ]
    n_days_ago = _parse_n_days_ago(question, now)
    if n_days_ago:
        matched.append(n_days_ago)
    return matched


def _detect_single_period(question: str, now: datetime) -> tuple[str, datetime, datetime] | None:
    """Like _detect_comparison_periods, but for a question naming exactly
    ONE relative-time phrase (today/yesterday/this week/N days ago) rather
    than two to compare -- e.g. a bare follow-up like 'what about
    yesterday?'.

    Confirmed necessary on net-flow: with no deterministic path for a
    single-period question, the model was left to copy the precomputed
    boundary from the prompt itself -- and failed, twice in a row, in two
    different ways ('what about yesterday?' produced a zero-width
    start==end window; the next turn's 'yesterday' produced an INVERTED
    start-after-end window). Both returned count=0, which looked like
    agreement between two independent checks but was actually the same
    structural guarantee twice over: a degenerate window can only ever
    return 0, whether or not the device had any real activity. This closes
    that gap the same way the two-period case was already closed: the
    model is not trusted to reproduce a date boundary via its own token
    generation, however clearly it's spelled out for it."""
    matched = _detect_named_periods(question, now)
    return matched[0] if len(matched) == 1 else None


# How many prior turns to replay into the prompt -- the frontend may send up
# to 10 (see ConversationTurn's schema limit), but each one adds real prompt
# size on top of an already-slow CPU-only generation, so this trims further
# to just enough for a typical "what about X" follow-up to resolve what it's
# asking about.
_MAX_HISTORY_TURNS_IN_PROMPT = 4


def _format_history(history: list[ConversationTurn]) -> str:
    """Prior Q&A turns, bounded and truncated, for ask()'s opening prompt --
    this is what makes a follow-up like 'what about yesterday?' resolvable
    at all, since each turn is otherwise answered from nothing but the
    current question (see ask()'s own history-less behavior before this).

    Deliberately NOT a replay of each turn's full tool-call trace (messages,
    tool results, etc.) -- only the final question/answer text. Replaying
    full traces would both bloat the prompt far more on top of an already
    slow CPU-only generation, and risk the model treating an old tool
    result as still valid for a brand new question when it may no longer
    be (time has passed; "today's count" from 10 minutes ago is already
    stale). The explicit instruction below exists because of that -- a
    model that just restates an old number without re-verifying it
    reintroduces the exact class of bug this project spent this session
    fixing, just one conversation turn removed."""
    if not history:
        return ""
    recent = history[-_MAX_HISTORY_TURNS_IN_PROMPT:]
    lines = [
        "Earlier in this conversation (context only -- time has passed, so re-verify with a fresh "
        "tool call before restating any number from here rather than assuming it's still current). "
        "If the CURRENT question doesn't name a device/host/filter of its own (e.g. 'what about "
        "yesterday?'), it means the SAME one as the most recent turn below -- use that exact "
        "device/filter in your tool call, never switch to an unfiltered or different one just "
        "because the current question didn't repeat it:"
    ]
    for turn in recent:
        lines.append(f"Q: {turn.question}")
        lines.append(f"A: {_truncate(turn.answer, _MAX_MESSAGE_CHARS_IN_PROMPT)}")
    return "\n".join(lines)


# Hostnames/IPs/device ids mentioned in prior turns routinely contain digit
# runs of their own (e.g. 'SF-200-POE-DBN-01') -- confirmed as a real false
# positive: a follow-up's answer that merely REPEATED a device name from
# history (without that name appearing in any tool call/result THIS turn,
# so _identifiers_from_result never saw it) had its embedded "200" misread
# as an ungrounded claimed count. Token shape mirrors _identifiers_from_result's
# intent (hostnames mix letters/digits/hyphens) rather than attempting real
# hostname validation.
_IDENTIFIER_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,}")


def _identifiers_from_history(history: list[ConversationTurn]) -> set[str]:
    out: set[str] = set()
    for turn in history:
        for text in (turn.question, turn.answer):
            for tok in _IDENTIFIER_TOKEN_RE.findall(text):
                if len(tok) >= 4 and any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok):
                    out.add(tok)
    return out


def _parse_tool_datetime(value) -> datetime | None:
    # Tool call arguments arrive as whatever JSON-ish types the model
    # produces -- str is the documented/expected case, but defending
    # against None/missing/malformed here means one bad argument degrades
    # to "treat as unset" instead of a 500 that kills the whole answer.
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _parse_tool_int(value, default: int) -> int:
    """Confirmed on net-flow: the model sent the literal STRING 'null' for
    an omitted limit argument (not an actually-missing key or JSON null,
    either of which the old `int(value or default)` pattern already
    handled via the falsy/None path) -- a non-empty string isn't falsy, so
    it reached a bare int('null') and raised an unhandled ValueError,
    surfaced to the user as an opaque 502. Any value that doesn't parse as
    an int now degrades to the default instead of crashing the request."""
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_tool_bool(value) -> bool:
    """Confirmed live in this app's own logs (not hypothetical): the model
    routinely sends only_anomalies as the STRING 'false' rather than an
    actual JSON boolean. bool('false') is True in Python -- any non-empty
    string is truthy -- so plain bool(value) was silently inverting the
    filter every time this happened, turning 'no anomaly filter' into
    'anomalies only' with no error or warning anywhere. A real bool passes
    through unchanged; a string is matched case-insensitively against the
    common true/false spellings; anything else (None, missing, a stray
    'null') defaults to False exactly as the old `False` default did."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return False


async def _execute_tool(
    name: str, arguments: dict, os_client: OpenSearch, ch_client: Client,
) -> tuple[dict, list[LogHit]]:
    """Returns (JSON-able result for the model, LogHits to surface as this
    response's cited sources -- only semantic_search produces any)."""
    if name == "list_devices":
        result = await asyncio.to_thread(
            device_service.list_devices,
            ch_client,
            start=_parse_tool_datetime(arguments.get("start")),
            end=_parse_tool_datetime(arguments.get("end")),
            limit=min(_parse_tool_int(arguments.get("limit"), 10), 50),
        )
        return {
            "devices_sorted_busiest_first": [
                {"ip": d.ip, "hostname": d.hostname, "vendor": d.vendor, "event_count": d.event_count,
                 "resolution_method": d.resolution_method, "last_seen": d.last_seen.isoformat()}
                for d in result.items
            ],
        }, []

    if name == "count_events":
        count = await asyncio.to_thread(
            log_search_service.count_events,
            ch_client,
            hostname=arguments.get("hostname"),
            source_ip=arguments.get("source_ip"),
            severity=arguments.get("severity"),
            program=arguments.get("program"),
            keyword=arguments.get("keyword"),
            only_anomalies=_parse_tool_bool(arguments.get("only_anomalies")),
            start=_parse_tool_datetime(arguments.get("start")),
            end=_parse_tool_datetime(arguments.get("end")),
        )
        return {"count": count}, []

    if name == "search_logs":
        result = await asyncio.to_thread(
            log_search_service.search_logs,
            ch_client,
            hostname=arguments.get("hostname"),
            source_ip=arguments.get("source_ip"),
            severity=arguments.get("severity"),
            program=arguments.get("program"),
            keyword=arguments.get("keyword"),
            only_anomalies=_parse_tool_bool(arguments.get("only_anomalies")),
            start=_parse_tool_datetime(arguments.get("start")),
            end=_parse_tool_datetime(arguments.get("end")),
            limit=min(_parse_tool_int(arguments.get("limit"), 20), 50),
        )
        return {
            "has_more_beyond_this_page": result.has_more,
            "matching_rows": [
                {"event_time": i.event_time.isoformat(), "hostname": i.hostname, "source_ip": i.source_ip,
                 "severity": i.severity, "program": i.program,
                 "message": _truncate(i.message, _MAX_MESSAGE_CHARS_IN_PROMPT),
                 "is_anomaly": i.is_anomaly, "anomaly_reasons": i.anomaly_reasons}
                for i in result.items
            ],
        }, []

    if name == "semantic_search":
        phrase = arguments.get("phrase") or ""
        sub_query = LogAssistantQuery(
            question=phrase[:1000] or "related logs",
            source_ip=arguments.get("source_ip"),
            vendor=arguments.get("vendor"),
            start=_parse_tool_datetime(arguments.get("start")),
            end=_parse_tool_datetime(arguments.get("end")),
            limit=min(_parse_tool_int(arguments.get("limit"), 10), 50),
        )
        hits = await semantic_search(os_client, sub_query)
        if not hits:
            note = await build_coverage_note(ch_client, sub_query, hits)
            return {"hits": [], "note": note or "No related log lines were found."}, []
        return {
            "hits": [
                {"event_time": h.event_time.isoformat(), "hostname": h.hostname, "source_ip": h.source_ip,
                 "severity": h.severity, "program": h.program,
                 "message": _truncate(h.message, _MAX_MESSAGE_CHARS_IN_PROMPT),
                 "is_anomaly": h.is_anomaly, "anomaly_reasons": h.anomaly_reasons}
                for h in hits
            ],
        }, hits

    return {"error": f"unknown tool '{name}'"}, []


async def ask(os_client: OpenSearch, ch_client, query: LogAssistantQuery) -> AskResponse:
    # Folded into the one user message, not a separate system-role message
    # -- see _post_chat_sync's docstring: a system-role message hung this
    # exact model/Ollama combination for the old single-shot prompt. Not
    # re-verified for a tool-calling request specifically (no live Ollama
    # in this sandbox) -- if agent responses hang where plain "ask" didn't
    # used to, a system-role message is the first thing to rule back in.
    # The model has no system clock -- confirmed on net-flow: asked "this
    # week", it called list_devices with start=2024-10-01 (not even the
    # right year), an arbitrary guess rather than an actual last-7-days
    # window. Happened to still name the right device only because that
    # device has dominated event counts across the whole guessed range --
    # a time-relative question is not safe to trust without this anchor.
    now = datetime.now(timezone.utc)
    history_block = _format_history(query.history)
    opening = (
        f"{_SYSTEM_PROMPT}\n\n{_AGENT_INSTRUCTIONS}\n\nThe current date/time is "
        f"{now.strftime('%Y-%m-%dT%H:%M:%S')} UTC. Precomputed start/end values for common time "
        f"periods (copy the matching pair exactly, do not recompute):\n{_relative_time_ranges_hint(now)}"
        + (f"\n\n{history_block}" if history_block else "")
        + f"\n\n---\n\nQuestion: {query.question}"
    )
    if query.source_ip or query.vendor or query.start or query.end:
        opening += (
            f"\n\n(The user also set these filters as a starting hint -- a tool call that honors "
            f"them, where relevant to the question, is appropriate: source_ip={query.source_ip}, "
            f"vendor={query.vendor}, start={query.start}, end={query.end})"
        )
    messages: list[dict] = [{"role": "user", "content": opening}]
    sources: list[LogHit] = []
    needs_multiple = _needs_multiple_data_points(query.question)
    comparison_periods = _detect_comparison_periods(query.question, now)
    # Mutually exclusive with comparison_periods by construction (2+ matches
    # vs. exactly 1) -- only meaningful when comparison_periods is None.
    single_period = _detect_single_period(query.question, now)
    # Gates the wrong-tool-redirect and force-resolve guards below (NOT the
    # count_events-correction overrides themselves, which stay unconditional
    # -- correcting a count_events call's own date math is always safe
    # regardless of question phrasing). A question wanting actual log rows,
    # not a count, must be allowed to use search_logs/semantic_search even
    # when it also names a time period.
    enforce_count_tool = bool((comparison_periods or single_period) and not _wants_log_rows(query.question))
    periods_resolved = False
    data_tool_calls = 0
    grounded_counts: set[int] = set()
    known_identifiers: set[str] = _identifiers_from_history(query.history)
    nudged = False
    # Updated on every tool call attempt this turn, including a wrong-tool
    # one that got redirected -- a best-effort filter hint for the hard
    # backstop below, when the model gives up calling tools altogether
    # before periods_resolved is ever reached.
    attempted_filter_args: dict = {}

    for _ in range(MAX_TOOL_ITERATIONS):
        body = await asyncio.to_thread(
            _post_chat_sync,
            f"{settings.ollama_url}/api/chat",
            {
                "model": settings.ollama_chat_model,
                "messages": messages,
                "tools": TOOL_DEFINITIONS,
                "stream": False,
                # Bounds worst-case generation time -- see config.py's
                # ollama_num_predict comment for why this matters on
                # CPU-only hardware independent of any other contention.
                "options": {
                    "num_predict": settings.ollama_num_predict,
                    "num_thread": settings.ollama_chat_num_thread,
                },
            },
            settings.ollama_timeout_seconds,
        )
        message = body["message"]
        tool_calls = message.get("tool_calls")
        if not tool_calls:
            answer = message["content"]
            # Confirmed on net-flow: the wrong-tool redirect above works,
            # but only AS FAR AS forcing a retry -- if the model, instead of
            # retrying with count_events, just gives a tool-less final
            # answer anyway, nothing stopped it from stating a NUMBER THAT
            # NO TOOL EVER RETURNED, not even a misattributed real one. That
            # answer's grounded_counts is empty (no tool call succeeded this
            # turn), and the grounding check below has its own condition
            # (`grounded_counts and ...`) short-circuit to False when empty
            # -- so the single worst case, total fabrication with zero real
            # data behind it, is exactly the one case that check couldn't
            # catch. Since comparison_periods/single_period means we
            # already know the exact boundaries needed, there's no reason
            # to keep hoping the model gets there itself: force-resolve
            # right here, using whatever device/filter hint its own
            # (possibly wrong-tool) attempts this turn provided, falling
            # back to conversation history, then hand it the real numbers
            # and require it to just restate them.
            if enforce_count_tool and not periods_resolved:
                periods_resolved = True
                hostname_hint = attempted_filter_args.get("hostname") or next(iter(known_identifiers), None)
                periods_to_resolve = comparison_periods or [single_period]
                labeled_counts = []
                for label, period_start, period_end in periods_to_resolve:
                    count = await asyncio.to_thread(
                        log_search_service.count_events,
                        ch_client,
                        hostname=hostname_hint,
                        source_ip=attempted_filter_args.get("source_ip"),
                        severity=attempted_filter_args.get("severity"),
                        program=attempted_filter_args.get("program"),
                        keyword=attempted_filter_args.get("keyword"),
                        only_anomalies=_parse_tool_bool(attempted_filter_args.get("only_anomalies")),
                        start=period_start,
                        end=period_end,
                    )
                    labeled_counts.append({"period": label, "count": count})
                    grounded_counts.add(count)
                    data_tool_calls += 1
                if hostname_hint:
                    known_identifiers.add(hostname_hint)
                messages.append(message)
                messages.append({
                    "role": "user",
                    "content": (
                        "You answered without calling count_events for this question. Here are the "
                        f"exact, already-verified counts instead: {json.dumps(labeled_counts)}"
                        + (f" (device: {hostname_hint})" if hostname_hint else "")
                        + ". State these exactly as given -- do not call any tool again, and do not "
                        "state a different number."
                    ),
                })
                log.info("Log Assistant FORCE-RESOLVED period(s) after a tool-less answer: %s", labeled_counts)
                continue
            # Confirmed on net-flow: a comparison question got "answered"
            # after a single tool call, with the second data point invented
            # out of nothing. Rather than trust the model's own judgment
            # that it's done, a comparison-phrased question is refused a
            # final answer until it has actually gone back for a second
            # real data point -- once, not in a retry loop, so a model that
            # ignores the nudge still gets an answer rather than hanging.
            if needs_multiple and data_tool_calls < 2 and not nudged:
                nudged = True
                messages.append(message)
                messages.append({
                    "role": "user",
                    "content": (
                        "This question compares multiple things (devices, time periods, etc.), but "
                        "you've only retrieved ONE real data point so far. Call the appropriate tool "
                        "AGAIN for the other item/period before answering -- do not guess, estimate, or "
                        "reuse the first number for the second item."
                    ),
                })
                continue
            claims = _extract_count_claims(answer, known_identifiers)
            if grounded_counts and claims and not claims.issubset(grounded_counts):
                # The model stated a count that doesn't match anything a tool
                # actually returned this turn -- surfaced visibly rather than
                # presented with the same confidence as a verified number,
                # since prompting alone hasn't reliably prevented this (see
                # module comment above MAX_TOOL_ITERATIONS for the incident
                # that prompted this check).
                answer += (
                    "\n\n(Note: at least one number above doesn't match the raw data this answer's "
                    "tool calls actually returned -- double-check it before relying on it.)"
                )
            return AskResponse(answer=answer, sources=sources, model=settings.ollama_chat_model)

        messages.append(message)
        for call in tool_calls:
            fn = call["function"]
            arguments = fn.get("arguments") or {}
            attempted_filter_args.update(
                {k: v for k, v in arguments.items() if k not in ("start", "end", "limit", "phrase") and v}
            )

            if enforce_count_tool and not periods_resolved and fn["name"] != "count_events":
                # Confirmed on net-flow: even with comparison_periods/
                # single_period correctly identifying this as a "count over
                # a known period" question, the model sometimes picks a
                # DIFFERENT tool entirely instead of count_events -- one run
                # called semantic_search with phrase='yesterday' and no
                # device filter, got back 10 unrelated log lines from random
                # other devices, and reported "10 events yesterday" as if
                # that were a real count for the device actually being
                # asked about. Neither override above can catch this since
                # they only intercept count_events calls. Refusing any other
                # tool here forces a retry at count_events specifically,
                # with a concrete device hint pulled from conversation
                # history when one is available.
                hinted = next(iter(_identifiers_from_history(query.history)), None)
                result = {
                    "error": (
                        f"This question asks for an exact count over a specific time period -- call "
                        f"count_events for this, not {fn['name']}."
                        + (f" The device being discussed is {hinted} -- use that as the hostname filter."
                           if hinted else "")
                    ),
                }
                hits = []
                log.info("Log Assistant tool call REDIRECTED (wrong tool for a period-count question): %s(%s)", fn["name"], arguments)
                messages.append({"role": "tool", "content": json.dumps(result)})
                continue

            if fn["name"] == "count_events" and comparison_periods and not periods_resolved:
                # Deterministic override: ignore whatever start/end the model
                # passed and fetch BOTH compared periods ourselves, pre-labeled
                # -- confirmed on net-flow this is necessary, not just
                # defensive (see _detect_comparison_periods' docstring for the
                # exact incident: the model's own call silently blended
                # yesterday+today together, then its final answer swapped
                # which number it called "today" vs. "yesterday" on top of
                # that -- both numbers were individually real, from actual
                # tool calls, so the grounding check alone didn't catch it).
                periods_resolved = True
                filter_args = {k: v for k, v in arguments.items() if k not in ("start", "end")}
                labeled_counts = []
                for label, period_start, period_end in comparison_periods:
                    count = await asyncio.to_thread(
                        log_search_service.count_events,
                        ch_client,
                        hostname=filter_args.get("hostname"),
                        source_ip=filter_args.get("source_ip"),
                        severity=filter_args.get("severity"),
                        program=filter_args.get("program"),
                        keyword=filter_args.get("keyword"),
                        only_anomalies=_parse_tool_bool(filter_args.get("only_anomalies")),
                        start=period_start,
                        end=period_end,
                    )
                    labeled_counts.append({"period": label, "count": count})
                    grounded_counts.add(count)
                    data_tool_calls += 1
                result = {
                    "note": (
                        "These are the exact, already-verified counts for every period being compared. "
                        "State them exactly as labeled -- do not call count_events again for this "
                        "comparison, and do not swap or relabel which number belongs to which period."
                    ),
                    "results": labeled_counts,
                }
                hits: list[LogHit] = []
                known_identifiers |= {
                    v for v in (filter_args.get("hostname"), filter_args.get("source_ip")) if isinstance(v, str) and len(v) >= 3
                }
                log.info("Log Assistant tool call OVERRIDDEN (deterministic period comparison): %s -> %s", arguments, result)
                messages.append({"role": "tool", "content": json.dumps(result)})
                continue

            if fn["name"] == "count_events" and single_period and not periods_resolved:
                # Same idea as the comparison override above, for a question
                # naming only ONE relative-time phrase ("what about
                # yesterday?") rather than two to compare. Confirmed on
                # net-flow this gap was real, not hypothetical: with no
                # deterministic path here, the model's own call for
                # "yesterday" produced a zero-width start==end window one
                # turn, then an inverted start-after-end window the very
                # next turn -- both silently returned count=0 regardless of
                # whether the device had any real activity. See
                # _detect_single_period's docstring for the full incident.
                periods_resolved = True
                label, period_start, period_end = single_period
                filter_args = {k: v for k, v in arguments.items() if k not in ("start", "end")}
                count = await asyncio.to_thread(
                    log_search_service.count_events,
                    ch_client,
                    hostname=filter_args.get("hostname"),
                    source_ip=filter_args.get("source_ip"),
                    severity=filter_args.get("severity"),
                    program=filter_args.get("program"),
                    keyword=filter_args.get("keyword"),
                    only_anomalies=_parse_tool_bool(filter_args.get("only_anomalies")),
                    start=period_start,
                    end=period_end,
                )
                grounded_counts.add(count)
                data_tool_calls += 1
                result = {
                    "note": "This is the exact, already-verified count for the period asked about. State it exactly as given.",
                    "period": label,
                    "count": count,
                }
                hits = []
                known_identifiers |= {
                    v for v in (filter_args.get("hostname"), filter_args.get("source_ip")) if isinstance(v, str) and len(v) >= 3
                }
                log.info("Log Assistant tool call OVERRIDDEN (deterministic single period): %s -> %s", arguments, result)
                messages.append({"role": "tool", "content": json.dumps(result)})
                continue

            if fn["name"] == "count_events" and periods_resolved:
                # Confirmed on net-flow that the "do not call again" note above
                # isn't always enough: the model called count_events a THIRD
                # time anyway (with no hostname filter at all -- a network-wide
                # total over an unrelated window) and then substituted THAT
                # number in place of the correct, already-labeled "today" value
                # in its final answer. Refusing to execute any further
                # count_events call removes this path entirely rather than
                # trying to catch a bad substitution after the fact in the
                # final answer's text.
                result = {
                    "error": (
                        "Already answered -- use the labeled today/yesterday/this-week results already "
                        "given above. Do not call count_events again for this question."
                    ),
                }
                hits = []
                log.info("Log Assistant tool call REFUSED (periods already resolved): %s(%s)", fn["name"], arguments)
                messages.append({"role": "tool", "content": json.dumps(result)})
                continue

            result, hits = await _execute_tool(fn["name"], arguments, os_client, ch_client)
            # Temporary diagnostic: the only way to see what the model actually
            # asked for and what came back, since the old plain access-log line
            # (POST /api/log-assistant/ask 200) hides both -- a 200 here says
            # nothing about whether the tool call itself found real data.
            log.info("Log Assistant tool call: %s(%s) -> %s", fn["name"], arguments, _truncate(json.dumps(result), 1000))
            data_tool_calls += 1
            grounded_counts |= _grounded_counts_from_result(fn["name"], result)
            # From the result (hostnames/IPs the tool found) AND from the call's
            # own arguments -- count_events/search_logs never echo the hostname
            # filter back in their result, only in what was asked for, so the
            # result alone misses the exact case that originally motivated this
            # (a hostname filter argument, not a result field, polluting the
            # digit extraction below).
            known_identifiers |= _identifiers_from_result(fn["name"], result)
            known_identifiers |= {
                v for v in (arguments.get("hostname"), arguments.get("source_ip")) if isinstance(v, str) and len(v) >= 3
            }
            sources.extend(hits)
            messages.append({"role": "tool", "content": json.dumps(result)})

    # Exhausted MAX_TOOL_ITERATIONS without a plain-text final answer --
    # say so rather than silently dropping the question or looping forever
    # (a real risk with a small model: see _AGENT_INSTRUCTIONS' explicit
    # "do not call the same tool twice" for the failure mode this guards).
    return AskResponse(
        answer=(
            "The assistant made several tool calls but didn't settle on a final answer in time -- "
            "try a narrower or more specific question."
        ),
        sources=sources, model=settings.ollama_chat_model,
    )
