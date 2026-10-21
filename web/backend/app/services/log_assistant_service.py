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
from collections import Counter
from datetime import datetime, timedelta, timezone

import httpx
from clickhouse_connect.driver.client import Client
from opensearchpy import OpenSearch
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ch_time import ch_literal
from app.core.config import settings
from app.schemas.log_assistant import AskResponse, ConversationTurn, LogAssistantQuery, LogHit
from app.services import (
    alert_service, anomaly_summary_service, audit_service, device_service, device_silence_service,
    log_search_service, relay_service,
)

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

_COMPARISON_MARKERS = (
    "compare", " vs ", " vs. ", "versus", "difference between",
    # Trend phrasing ("is traffic increasing this week vs last week") --
    # defense-in-depth for the post-tool-call nudge safety net, alongside
    # _PERIOD_PHRASE_ALIASES' own detection of the two actual periods.
    "trend", "trending", "increasing", "decreasing", "increase", "decrease", "growing", "declining",
)


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


# A second, separate regression found right after fixing the first one:
# excluding "show me"-style questions wasn't enough, because the real
# problem is the inverse of what that fix assumed. "what's going on with
# authentication failures this week" mentions "this week" (single_period
# matches) but is a genuinely topical/content question for semantic_search
# -- not a "show me the rows" request either, so _wants_log_rows didn't
# exclude it. The model correctly called semantic_search; the wrong-tool
# redirect refused it anyway; the force-resolve backstop then fell back to
# a LEFTOVER device hostname from conversation history (from an unrelated
# earlier question in the same thread) and force-computed THAT device's
# "this week" event count -- a real number, but with nothing to do with
# "authentication failures" -- and the final answer stated it as if it
# were the answer. A negative exclusion list for "doesn't want a count" was
# never going to cover every way of asking a non-counting question.
# Flipped to requiring a POSITIVE signal instead: explicit counting
# language, a comparison (needs_multiple), or the question being
# genuinely bare (no topical content of its own beyond the time phrase --
# see _is_bare_followup) -- a bare follow-up is presumed to inherit
# whatever intent the conversation already had, since there's nothing else
# in it to go on; a longer, topical question that merely mentions a period
# is not bare and must not be forced toward count_events just because of
# that mention.
_COUNT_INTENT_MARKERS = ("how many", "how much", "count of", "number of", "total of", "total number")


def _wants_count(question: str) -> bool:
    lowered = question.lower()
    return any(marker in lowered for marker in _COUNT_INTENT_MARKERS)


def _is_bare_followup(question: str) -> bool:
    words = re.findall(r"[a-z']+", question.lower())
    return len(words) <= 5


# Confirmed as a real, reproduced bug on net-flow: asked "give me the top
# device with ethernet flapping" and, in a follow-up, "...with wireless
# disconnections", the model ignored the system prompt's explicit
# instruction to use anomaly_summary's `reason` parameter for this exact
# question shape and called list_devices with a hostname carried over from
# conversation history instead -- twice, producing an answer with nothing
# to do with the actual question both times (the second with NO tool call
# at all, just restating the first answer). Prompting alone wasn't enough,
# the same lesson already drawn for count/period questions (see
# enforce_count_tool above) -- so this question shape gets the same
# treatment: detected deterministically and the correct tool forced,
# instead of trusted to the model's own tool choice.
_RANKING_MARKERS = ("most", "top", "which device", "which vendor", "highest", "worst")


def _wants_ranking(question: str) -> bool:
    lowered = question.lower()
    return any(marker in lowered for marker in _RANKING_MARKERS)


def _wants_vendor_grouping(question: str) -> bool:
    return "vendor" in question.lower()


def _detect_anomaly_reason(question: str, history: list["ConversationTurn"] | None = None) -> str | None:
    """Resolves a 'which device/vendor has the most <anomaly type>' question
    to a real anomaly_reason category, or None if this isn't that kind of
    question. Gated on ranking language (top/most/which device/which
    vendor) on top of _resolve_anomaly_reason's own word-overlap/synonym
    matching -- a plain 'which device is busiest' (no anomaly type
    mentioned at all) correctly resolves to nothing here and is left alone
    for list_devices, which is the right tool for that question.

    Also recognizes a bare follow-up that corrects/refines the anomaly type
    of the immediately preceding turn (e.g. "wireless not ethernet" right
    after "...with ethernet flapping") -- confirmed live on net-flow as a
    real gap: such a correction doesn't repeat ranking language itself, so
    without this it fell straight through to the old, unprotected bare-
    followup path (_primary_identifier_from_last_turn), which assumes the
    carried-over entity is a DEVICE and just re-ran list_devices for
    whichever device the PREVIOUS turn's reason had resolved to -- a real,
    executable call, but one that answers "how many total events for that
    device" instead of "which device has the most <the corrected reason>".
    Only looks at the immediately preceding turn, same "last turn only, not
    the whole thread" scoping as _primary_identifier_from_last_turn, and
    prefers whatever the CURRENT bare text itself resolves to (a correction
    usually names a new value) over blindly reusing the previous reason."""
    if _wants_ranking(question):
        resolved, _note = _resolve_anomaly_reason(question)
        if resolved:
            return resolved
    if (
        history and _is_bare_followup(question)
        and not _is_wireless_specific(question)
        and not _needs_multiple_data_points(question)
        and _detect_anomaly_reason(history[-1].question) is not None
    ):
        # The wireless-specific exclusion applies here too: inheriting the
        # PREVIOUS turn's resolved reason is only reasonable when the
        # current bare text adds no new information of its own (e.g. "and
        # yesterday?") -- but "wireless not ethernet" very much DOES add
        # new information (it's naming a different, wireless-specific link
        # the previous reason's real detector doesn't cover at all -- see
        # _resolve_anomaly_reason's own wireless exclusion), so inheriting
        # the old reason here would be exactly the same mistake in a
        # different shape. Falls through to None instead, same as a fresh
        # wireless-specific question -- the general agent loop (now able to
        # fuzzy-resolve `program` for a question like this) is a better fit
        # than a fixed anomaly category that doesn't cover it.
        #
        # The comparison exclusion (_needs_multiple_data_points) is the same
        # idea for a different kind of new information: confirmed live,
        # "compare yesterday and today" right after "...with ethernet
        # flapping" inherited interface_flapping (it's bare and not
        # wireless-specific) and answered with the SAME all-time cumulative
        # number as before, silently ignoring the comparison entirely --
        # anomaly_summary has no time-scoping at all, so it can never
        # actually honor a comparison request regardless of which reason is
        # in play. A question that clearly wants two data points compared
        # is adding new information just as much as a correction does, so
        # it's excluded here the same way, left for the general loop.
        resolved, _note = _resolve_anomaly_reason(question)
        return resolved or _detect_anomaly_reason(history[-1].question)
    return None


def _anomaly_summary_ranked_rows(result: dict) -> tuple[str | None, list[dict]]:
    key = next((k for k in ("devices_ranked_by_reason_count", "vendors_ranked_by_reason_count") if k in result), None)
    return key, (result.get(key, []) if key else [])


def _anomaly_summary_plain_answer(result: dict) -> str:
    """Builds the final answer directly from a resolved anomaly_summary
    result, bypassing any further model call entirely -- no restate
    instruction asking the model to phrase it, however simple.

    An earlier version of this fix (since replaced) handed the model a
    'state this exactly, don't call again' instruction instead, the same
    pattern count_events's deterministic overrides use. That still wasn't
    enough: on a normal (not force-resolved) anomaly_summary call, the
    model called the right tool with the right reason, got the real top
    entry (74,933 events) handed back, and the final answer still stated a
    DIFFERENT, stale number from an earlier turn's history instead of the
    one it was just given -- the existing count-claim grounding check
    caught the mismatch, but only after the fact. Simplifying the
    instruction to a single pre-extracted sentence didn't fully fix it
    either: in a live sequence right after that change, the model still
    took a FURTHER ~3 minutes to respond to the simplified instruction, and
    that response was yet another (correctly refused) tool call rather than
    the requested restatement -- pushing the whole request past the UI's
    timeout. Every extra round-trip to this CPU-only model costs tens of
    seconds to minutes (confirmed repeatedly on the same live question:
    14:49:16 -> 14:50:06 -> 14:53:04). Once the real answer is already
    known with certainty, asking the model to merely restate it in English
    adds no information and is pure latency/reliability risk -- so this
    skips that step entirely instead of hoping a better-worded instruction
    lands before the client gives up waiting."""
    key, rows = _anomaly_summary_ranked_rows(result)
    reason = result.get("reason", "this anomaly type")
    if not rows:
        return f"No devices/vendors have any anomalies for reason '{reason}'."
    top = rows[0]
    label = top.get("hostname") or top.get("vendor")
    count = top.get("event_count")
    is_vendor = key == "vendors_ranked_by_reason_count"
    kind = "vendor" if is_vendor else "device"
    # Same "top 10" breakdown treatment as _concept_ranking_plain_answer --
    # confirmed live as a real inconsistency: identical phrasing ("top 10
    # devices with X") returned a full 10-entry breakdown when X resolved
    # to a general concept, but only the single top entry when X resolved
    # to one of the 8 fixed anomaly categories (e.g. "ethernet flapping").
    # rows already reflects whatever limit the tool call itself used.
    breakdown = "; ".join(f"{(r.get('vendor') if is_vendor else r.get('hostname'))}: {r.get('event_count')}" for r in rows)
    return (
        f"The top {kind} for anomaly_reason='{reason}' is {label}, with {count} events (cumulative, all-time). "
        f"Full breakdown by {kind} (busiest first): {breakdown}."
    )


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
    if tool_name == "search_logs":
        # Confirmed on net-flow this blind spot let a real incident through:
        # search_logs returned matching_rows=[] (a redundant keyword filter
        # had excluded the one real matching row), but the final answer
        # still said "1" anyway -- not fabricated, just silently echoed from
        # conversation history rather than drawn from this turn's actual
        # (contradicting) tool result. With search_logs never populating
        # grounded_counts at all, the grounding check below was blind to
        # this regardless of what the model claimed. len(matching_rows) is
        # exactly what this turn's tool call actually found, so it's a
        # legitimate, exact number to ground a stated count against --
        # unlike count_events/list_devices, that's the only thing worth
        # extracting here (there's no other standalone count field).
        rows = result.get("matching_rows")
        return {len(rows)} if isinstance(rows, list) else set()
    if tool_name == "anomaly_summary":
        # Covers both the reason-filtered rows (*_ranked_by_reason_count)
        # and the unfiltered totals (*_ranked_by_total_anomalies) -- whichever
        # shape this particular call produced -- under whichever field name
        # that shape uses for the count (event_count vs. anomaly_event_count).
        counts: set[int] = set()
        for key in (
            "devices_ranked_by_reason_count", "vendors_ranked_by_reason_count",
            "devices_ranked_by_total_anomalies", "vendors_ranked_by_total_anomalies",
        ):
            for row in result.get(key, []):
                value = row.get("event_count", row.get("anomaly_event_count"))
                if isinstance(value, int):
                    counts.add(value)
        return counts
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
    elif tool_name == "anomaly_summary":
        for key in (
            "devices_ranked_by_reason_count", "devices_ranked_by_total_anomalies", "device_breakdown_by_reason",
        ):
            for row in result.get(key, []):
                ids.update(v for v in (row.get("hostname"), row.get("source_ip")) if isinstance(v, str) and len(v) >= 3)
    return ids


# Matches a number next to a count-ish word in either order ("14 events",
# "a total of 122,319") -- deliberately anchored to those words rather than
# any bare digit, so a stray timestamp or port number in the answer text
# doesn't get mistaken for a claimed count. Hostnames/IPs are stripped from
# the text before this runs (see _identifiers_from_result) -- without that,
# this still mismatched a hostname's embedded digits for the real count.
# The first alternative allows up to 20 non-digit chars between the number
# and the word (not just \s*) -- confirmed on net-flow that "1 warning-
# severity log" otherwise didn't match at all (the real phrasing has a
# qualifier between the digit and "log"), silently skipping the grounding
# check entirely rather than correctly flagging the mismatch it was added
# to catch.
_COUNT_CLAIM_RE = re.compile(
    r"(\d[\d,]*)\D{0,20}?(?:events?|logs?|log lines?|lines?|entries|occurrences?|times?)\b"
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


# A number the question itself used as a requested limit ("top 10", "first
# 5"), not a claim about real data -- confirmed as a grounding-check false
# positive: asked for "the top 10 log[s] for anjar MKT" (a hostname that,
# being an informal nickname rather than the real
# 'PTP_Ksara_to_Chams_Anjar', correctly matched zero rows), the model
# honestly answered that it couldn't find enough information -- but its
# answer's own "top 10 logs" phrasing, merely echoing the question, still
# got picked up by _COUNT_CLAIM_RE as a claimed count of 10 and compared
# against the real grounded result (0), producing an unwarranted "doesn't
# match" caveat on an already-honest, correct answer.
_REQUESTED_LIMIT_RE = re.compile(r"\b(?:top|first|last|give me|show me)\s+(\d{1,4})\b", re.IGNORECASE)


def _requested_limit_numbers(question: str) -> set[int]:
    return {int(n) for n in _REQUESTED_LIMIT_RE.findall(question)}

_AGENT_INSTRUCTIONS = (
    "You have tools that query this network's real, current log data. ALWAYS call a tool to get "
    "real data before answering any question involving a count, a comparison ('noisiest', "
    "'busiest', 'most'), or specific log content -- never guess or estimate from memory, and never "
    "answer from a tool's result until you've actually called it. Use list_devices for 'which "
    "device is noisiest/busiest/most active' questions (it returns devices sorted by event count "
    "already -- the first one is the answer), or to look up/disambiguate a device by a partial or "
    "casual name via its optional hostname parameter (a case-insensitive substring match). Once you "
    "know a device's exact real hostname, though, use count_events/search_logs for its actual counts "
    "or log content -- never substitute list_devices' event_count for a real count_events call. Use "
    "anomaly_summary for 'which device/vendor has the most anomalies' or 'what anomaly reasons are "
    "most common' -- it is a cumulative, ALL-TIME view (not scoped to a time period you'd give it "
    "start/end for), and never claims acknowledgment status. Use alert_rules for 'is there an alert "
    "for X' or 'what alerts are configured' -- it's CONFIGURATION, not a live count. Use "
    "silent_devices for 'which devices have gone quiet' or 'is X still reporting' -- every row in it "
    "is currently silent right now, so a device's absence from it means it IS reporting normally. Use "
    "audit_log for 'who changed/created/deleted X' or 'what changed recently' -- it NEVER contains "
    "secret values. Use relay_source_ips for 'is X IP a relay' or 'what relay IPs are configured'. For "
    "'how many events/logs' for a specific device, "
    "severity, or filter -- including comparing two time periods -- use count_events once PER time "
    "period being asked about (e.g. once for today, once for yesterday); it returns an exact total, "
    "never estimate or reuse a number from a different tool call. Use search_logs only when the "
    "actual log lines themselves are needed (not just a count), for 'show me', 'did X happen', or "
    "exact keyword questions. Use semantic_search only for 'what's going on with/related to <topic>' "
    "questions where you don't have an exact keyword to filter on. Use aggregate_events for 'how many "
    "X broken down by Y' or 'what's the split of Z' questions not covered by a more specific tool -- "
    "e.g. 'break down today's events by severity' or 'events per program for device X'. It returns "
    "exact counts already sorted, so its first entry answers a 'which <group> has the most' question "
    "too -- but prefer anomaly_summary for an anomaly-reason breakdown and list_devices for 'which "
    "device is busiest' specifically, since those already exist and are more direct. A number in your final answer must "
    "come from a tool result for that SAME device/filter/time period -- never attribute one tool "
    "call's result to a different device or period than what it was actually called with. Once every "
    "number the question needs has been retrieved, give a plain, direct final answer in your own "
    "words -- do not call another tool after that, and do not call the same tool twice with the same "
    "arguments.\n\n"
    "If a question's topic doesn't match any tool's fixed options (not a real severity/program/vendor "
    "value, not one of anomaly_summary's 8 real reason categories), do NOT guess a filter value and do "
    "NOT give up and say it can't be answered. Call semantic_search FIRST with the question's own "
    "wording to find real example log lines about that topic -- it matches by MEANING, not exact "
    "words, so it works even when nothing in the database literally says what the question says. Then "
    "look at the real `program` and `message` text those hits actually contain, and make a SECOND call "
    "-- count_events/search_logs/aggregate_events with a `keyword` copied from what those real messages "
    "actually say (and `program` set to what they actually show, if consistent) -- to get an exact, "
    "authoritative count or row set. Never answer a count/ranking for this kind of question from the "
    "semantic_search hits alone (a short top-K sample is not a real total); it only exists to tell you "
    "what real keyword/program to filter on next.\n\n"
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
                    "hostname": {"type": "string", "description": "Optional: find devices whose hostname contains this text (case-insensitive substring match) -- use this to look up or disambiguate a device by a partial/casual name (e.g. 'anjar' finds every device with 'anjar' anywhere in its name). Omit entirely for a plain busiest-first ranking."},
                    "limit": {"type": "integer", "description": "Max devices to return. Default 10."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "anomaly_summary",
            "description": (
                "Returns TWO lists about anomalies -- a CUMULATIVE, ALL-TIME view (not scoped to any "
                "time window, matching the Anomaly Summary page), since acknowledgment review needs a "
                "stable count from the beginning, not a rolling one: (1) *_ranked_by_total_anomalies -- "
                "one row per device/vendor, already sorted by its TRUE total anomalous-event count; for "
                "'which device/vendor has the most anomalies', the first entry IS the answer, no further "
                "math needed. (2) *_breakdown_by_reason -- one row per device/vendor PER anomaly_reason "
                "(the same entity can appear several times); use this only for 'what anomaly reasons "
                "does X have' or 'what reasons are most common' -- NEVER sum or compare its numbers to "
                "answer a 'which has the most' question, since one entity's total is split across "
                "several of its rows there. Does NOT include acknowledgment status (whether someone has "
                "already reviewed/dismissed it) -- don't claim to know that from this. For 'which device/"
                "vendor has the most <a specific anomaly type>' (e.g. 'ethernet flapping', 'volume "
                "spike', 'rare templates'), set the `reason` parameter instead of guessing a keyword for "
                "search_logs -- an anomaly type is a fixed CATEGORY label applied by the ML pipeline, "
                "not necessarily a phrase that appears in the raw log message, so search_logs will "
                "usually find nothing even when the real data has plenty of matching anomalies. Do NOT "
                "use this tool, or guess a `reason`, for a concept that isn't one of the 8 real "
                "categories (e.g. 'wireless disconnections', 'deauth attacks') -- there is no category "
                "for everything; use semantic_search first to find real example messages about it, then "
                "aggregate_events or count_events with a keyword/program copied from what those real "
                "messages actually say instead."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "group_by": {"type": "string", "enum": ["device", "vendor"], "description": "'device' (default) or 'vendor'."},
                    "reason": {"type": "string", "description": "Optional: restrict to one anomaly type -- pass it in your own words ('ethernet flapping', 'volume spike'), it will be matched to the real category for you. When set, the result is already filtered AND sorted for just this type, so its first entry is the answer to 'which has the most'. If the concept isn't one of the 8 real categories, do NOT guess/pass it here (see this tool's own description for the real alternative)."},
                    "limit": {"type": "integer", "description": "Max rows to return per list. Default 10."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "alert_rules",
            "description": (
                "Lists configured alert rules -- name, enabled/disabled, the filters each one watches "
                "(hostname/source_ip/program/severity/predicted_category/only_anomalies), its window/"
                "threshold/cooldown, and when it last fired (last_triggered_at, null if never). Use for "
                "'is there an alert for X', 'what alerts are set up', or 'has the Y alert fired "
                "recently' (check last_triggered_at). This is CONFIGURATION, not live event data -- it "
                "does not itself count anything; for an actual count use count_events/anomaly_summary."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Optional: only rules whose name contains this text (case-insensitive). Omit to list all."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "silent_devices",
            "description": (
                "Lists devices that have gone quiet -- stopped logging past their own expected "
                "interval. Each row: hostname/source_ip, how long it's normally expected to report "
                "(expected_interval_minutes), last_seen_at, and silence_started_at (when it went quiet). "
                "Every row here IS currently silent (this list only ever holds devices presently in that "
                "state -- a device that logs again is removed from it immediately), so finding a device "
                "in this result already answers 'is X silent/quiet right now' on its own. Use for 'which "
                "devices have gone quiet/silent', 'when did X last report', or 'is X still reporting'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hostname": {"type": "string", "description": "Optional: only devices whose hostname contains this text (case-insensitive). Omit to list all currently-silent devices."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "audit_log",
            "description": (
                "Lists recent admin actions on this web app -- who did what, and when (e.g. "
                "'alert_rule.create', 'anomaly.acknowledge', 'credential.update', 'relay_source_ip."
                "delete'). NEVER includes secret values (SNMP credentials themselves are never "
                "logged, only that a credential for some IP was changed). Use for 'who created/"
                "deleted/changed X', 'what changed recently', or 'has anyone acknowledged this "
                "anomaly'. Most recent first."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "contains": {"type": "string", "description": "Optional: only entries whose action or target contains this text (case-insensitive), e.g. 'alert_rule' or an IP/hostname. Omit to list all recent actions."},
                    "start": {"type": "string", "description": "ISO 8601 UTC start -- only entries at or after this time. Omit for no time limit (just the most recent, per limit)."},
                    "limit": {"type": "integer", "description": "Max entries to return. Default 20."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "relay_source_ips",
            "description": (
                "Lists the source IPs configured to relay/forward syslog on behalf of other devices "
                "(with an optional note explaining each one) -- configuration, not live traffic. Use "
                "for 'is X IP a relay', 'what relay IPs are configured'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Optional: only entries whose IP contains this text. Omit to list all."},
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
                    "vendor": {"type": "string"},
                    "severity": {"type": "string", "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"], "description": "Omit entirely if the question does not ask about a specific severity -- these 8 values are the ONLY valid ones, never 'none' or 'any'."},
                    "program": {"type": "string", "description": "The syslog process/service name (e.g. 'sshd', 'kernel') -- NEVER a hostname or device name."},
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
                    "vendor": {"type": "string"},
                    "severity": {"type": "string", "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"], "description": "Omit entirely if the question does not ask about a specific severity -- these 8 values are the ONLY valid ones, never 'none' or 'any'."},
                    "program": {"type": "string", "description": "The syslog process/service name (e.g. 'sshd', 'kernel') -- NEVER a hostname or device name."},
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
                "e.g. 'authentication failures' can match a line that says 'login rejected'. This is "
                "the GENERAL fallback for any topic that doesn't match an exact field/category/keyword "
                "you already know -- use it FIRST, before concluding a topic 'isn't in the database' or "
                "guessing a filter value. Its hits are a small relevance-ranked SAMPLE, not a real "
                "count -- never answer a count/ranking question from these hits alone. Instead, read "
                "the real `program` and `message` text the hits actually contain, then make a SECOND "
                "call (count_events/search_logs/aggregate_events) with a `keyword`/`program` copied "
                "from what those real messages say, to get an exact, authoritative total."
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
    {
        "type": "function",
        "function": {
            "name": "aggregate_events",
            "description": (
                "Flexible grouped count over ALL log events -- use for any 'how many X broken down "
                "by Y' or 'what's the split of Z' question not covered by a more specific tool. "
                "Examples: 'break down today's events by severity', 'how many events per program for "
                "device X', 'what's the split of predicted categories this week', 'count of events by "
                "vendor'. Returns each group's exact count, already sorted busiest first -- the first "
                "entry IS the answer to 'which <group> has the most'. Prefer a more specific tool when "
                "one exists: count_events for a single total with no breakdown, anomaly_summary for "
                "'which device/vendor has the most anomalies' or a breakdown by anomaly reason, "
                "list_devices for 'which device is busiest'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "group_by": {
                        "type": "array",
                        "items": {"type": "string", "enum": list(log_search_service.GROUP_BY_COLUMNS)},
                        "description": "1-3 columns to break the count down by, e.g. ['severity'] or ['vendor', 'program'].",
                    },
                    "hostname": {"type": "string"},
                    "source_ip": {"type": "string"},
                    "vendor": {"type": "string"},
                    "severity": {"type": "string", "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"], "description": "Omit entirely if the question does not ask about a specific severity -- these 8 values are the ONLY valid ones, never 'none' or 'any'."},
                    "program": {"type": "string", "description": "The syslog process/service name (e.g. 'sshd', 'kernel') -- NEVER a hostname or device name."},
                    "predicted_category": {"type": "string"},
                    "reason": {"type": "string", "description": "Optional: restrict to one anomaly type, in your own words ('ethernet flapping') -- matched to the real category for you, same as anomaly_summary's reason parameter."},
                    "keyword": {"type": "string", "description": "Substring to match in the log message"},
                    "only_anomalies": {"type": "boolean"},
                    "start": {"type": "string", "description": "ISO 8601 UTC start"},
                    "end": {"type": "string", "description": "ISO 8601 UTC end"},
                    "limit": {"type": "integer", "description": "Max groups to return. Default 20."},
                },
                "required": ["group_by"],
            },
        },
    },
]

# Real tool names, derived rather than duplicated, so a token matching one
# of these (e.g. 'list_devices' itself, mentioned in a model's narrated
# fake tool-call text -- see the data_tool_calls == 0 grounding check
# below) isn't mistaken for a claimed device/identifier.
_TOOL_NAMES = frozenset(t["function"]["name"] for t in TOOL_DEFINITIONS)


def _relative_time_bounds(now: datetime) -> dict[str, tuple[datetime, datetime]]:
    """Real Python arithmetic for the relative-time phrases this app's
    questions actually use, computed once and shared by both the prompt
    hint below (for the model to copy) and _detect_comparison_periods
    (which bypasses the model entirely for a detected today/yesterday/this
    week comparison) -- see both call sites for why neither trusts the
    model to derive these itself.

    'last week' is a genuinely DIFFERENT window from 'this week' -- the 7
    days immediately before it, i.e. days 8-14 ago -- not just another
    name for the same trailing week. Confirmed as a real gap while
    building trend questions ("is traffic increasing this week vs last
    week"): 'last week' used to be grouped as an ALIAS of 'this week' in
    _PERIOD_PHRASE_ALIASES (alongside 'past week', which genuinely IS a
    synonym for the same trailing-7-days window), so a question naming
    both 'this week' and 'last week' only ever matched ONE period, not
    two -- _detect_comparison_periods needs 2+ matches, so this fell
    through to the fully unguided generic path with no deterministic
    handling at all, for what is arguably the single most natural
    week-over-week trend question there is."""
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    week_start = now - timedelta(days=7)
    last_week_start = now - timedelta(days=14)
    # "this month"/"last month" and "this hour"/"last hour" -- confirmed
    # live as a real gap: neither granularity was covered at all, so a
    # question naming either fell through to the model's own date
    # arithmetic with no precomputed hint and no deterministic comparison
    # detection, the exact failure mode ("this week vs last week" getting
    # the subtraction backwards) this whole mechanism exists to prevent.
    # Trailing windows, same semantics as this week/last week above (NOT
    # calendar-month/hour-aligned) -- "this month" is the last 30 days, not
    # the 1st of the current calendar month.
    month_start = now - timedelta(days=30)
    last_month_start = now - timedelta(days=60)
    hour_start = now - timedelta(hours=1)
    last_hour_start = now - timedelta(hours=2)
    return {
        "today": (today_start, now),
        "yesterday": (yesterday_start, today_start),
        "this week": (week_start, now),
        "last week": (last_week_start, week_start),
        "this month": (month_start, now),
        "last month": (last_month_start, month_start),
        "this hour": (hour_start, now),
        "last hour": (last_hour_start, hour_start),
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
    last_week_start, last_week_end = bounds["last week"]
    return (
        f"today: start={today_start.strftime(fmt)}, end={today_end.strftime(fmt)}\n"
        f"yesterday: start={yesterday_start.strftime(fmt)}, end={yesterday_end.strftime(fmt)}\n"
        f"this week / past week: start={week_start.strftime(fmt)}, end={week_end.strftime(fmt)}\n"
        f"last week (a DIFFERENT, earlier 7-day window than 'this week'): "
        f"start={last_week_start.strftime(fmt)}, end={last_week_end.strftime(fmt)}"
    )


# Phrase aliases that map onto the same _relative_time_bounds() key -- "this
# week" and "past week" are genuine synonyms for the same trailing-7-days
# window (see the original noisiest-device incident, which used "this
# week"). "last week" is its own, separate entry below -- it names a
# DIFFERENT window (the 7 days before "this week"'s), not another name for
# the same one; see _relative_time_bounds' docstring for the trend-question
# incident that gap caused.
_PERIOD_PHRASE_ALIASES: list[tuple[str, tuple[str, ...]]] = [
    ("today", ("today",)),
    ("yesterday", ("yesterday",)),
    ("this week", ("this week", "past week")),
    ("last week", ("last week",)),
    ("this month", ("this month", "past month")),
    ("last month", ("last month",)),
    ("this hour", ("this hour", "past hour")),
    ("last hour", ("last hour",)),
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
# \d{1,4} (not {1,3}) to allow the bound below (up to 3650) to actually be
# reachable -- a 3-digit cap on the regex silently truncated any 4+ digit
# day count before _MAX_N_DAYS_AGO ever got a chance to validate it.
_N_DAYS_AGO_RE = re.compile(
    r"\b(\d{1,4}|" + "|".join(_NUMBER_WORDS) + r")\s+days?\s+(?:ago|before|back)\b", re.IGNORECASE,
)
# `events` has no TTL (retained indefinitely by explicit design choice -- see
# clickhouse/init.sql) so there's no principled reason to reject a count
# further back than 365 days. Confirmed on net-flow as a real gap, not just
# a theoretical one: "how many events 400 days ago" fell outside the old
# 1-365 bound, so NONE of the deterministic machinery below (or even the
# precomputed today/yesterday/this-week hints) applied, and the model was
# left to invent its own window -- it produced a 3-month span in entirely
# the wrong part of the calendar (nowhere near 400 real days before now).
# The answer still came back 0 and so LOOKED fine, purely because this young
# deployment has no data in either the real or the fabricated window -- with
# real historical data, this would have confidently answered the wrong
# question with no grounding-check mismatch to catch it (the model honestly
# echoed what its own, wrongly-windowed tool call returned). 3650 (10 years)
# is a generous bound that covers any realistic query while still rejecting
# pathological input that could otherwise overflow datetime arithmetic.
_MAX_N_DAYS_AGO = 3650


def _parse_n_days_ago(question: str, now: datetime) -> tuple[str, datetime, datetime] | None:
    match = _N_DAYS_AGO_RE.search(question.lower())
    if not match:
        return None
    raw = match.group(1)
    n = int(raw) if raw.isdigit() else _NUMBER_WORDS[raw]
    if not 1 <= n <= _MAX_N_DAYS_AGO:
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

# Confirmed as a real, reproduced bug on net-flow: "top n for today with
# ethernet flapping" is answered via _anomaly_summary_plain_answer, whose
# own template literally writes "anomaly_reason='interface_flapping'" into
# the answer text (see that function below). That answer then sits in
# conversation history like any other turn -- and the underscore in
# "anomaly_reason" is exactly the separator _looks_like_identifier_token
# was widened to accept for real hostnames like 'PTP_Ksara_to_Chams_Anjar'.
# A later bare follow-up ("what about last month") swept that schema field
# name up as if it were the device the previous turn was about, and
# count_events was then called with hostname='anomaly_reason' -- a
# deterministically-computed but nonsense answer (0 events), not even a
# model hallucination. These are our own internal field names, not
# anything a real hostname/IP could ever collide with, so they're excluded
# outright rather than patching each template that might echo one.
#
# Excluding just "anomaly_reason" isn't enough on its own: with that token
# gone, the SAME text's next identifier-shaped token is the quoted VALUE
# right after it ("interface_flapping", an anomaly CATEGORY, not a
# hostname either) -- confirmed by re-running the reproduction after the
# first fix attempt. _VALID_ANOMALY_REASONS (defined below) is excluded
# for the same reason: every one of its values is exactly the kind of
# underscore-separated, 4+ char token this check exists to accept for real
# hostnames, and every one of them routinely appears in our own answer/note
# text precisely because that's what this feature discloses anomaly
# categories by.
_SCHEMA_FIELD_TOKENS = frozenset({
    "anomaly_reason", "anomaly_reasons", "anomaly_event_count",
    "event_count", "device_count",
})


def _looks_like_identifier_token(tok: str) -> bool:
    """A hostname/IP/device-id token, as opposed to an ordinary English word
    that happens to match _IDENTIFIER_TOKEN_RE's shape. Originally required
    a digit AND a letter (hostnames 'routinely' mix both, e.g.
    'SF-200-POE-DBN-01') -- confirmed wrong on net-flow (Test 7) for a
    purely alphabetic, underscore-separated hostname
    ('PTP_Ksara_to_Chams_Anjar'): it never satisfied the digit requirement,
    so it was silently invisible to every identifier-tracking path that
    uses this check, including the one meant to carry it across a
    follow-up turn. A token now also qualifies via a separator character
    (_, -, .) instead of a digit -- still excludes plain prose words like
    'today'/'events', which have neither digits nor separators. Also
    excludes _SCHEMA_FIELD_TOKENS and _VALID_ANOMALY_REASONS (forward
    reference -- defined later in this module, but only looked up when this
    function is actually called, by which point the module is fully
    loaded) -- see _SCHEMA_FIELD_TOKENS's comment for the live bug this
    closes.
    """
    return (
        len(tok) >= 4
        and tok.lower() not in _SCHEMA_FIELD_TOKENS
        and tok.lower() not in _VALID_ANOMALY_REASONS
        and any(c.isalpha() for c in tok)
        and (any(c.isdigit() for c in tok) or any(c in "_-." for c in tok))
    )


def _strip_trailing_punctuation(tok: str) -> str:
    """A plain prose word directly followed by sentence punctuation
    ('today.', at the end of a sentence) is swept up by _IDENTIFIER_TOKEN_RE
    (its char class includes '.') and, since a trailing '.' alone now
    satisfies _looks_like_identifier_token's separator check, would
    otherwise false-positive as a device-id-shaped token. Stripped before
    that check runs so only real embedded separators ('SW-42-Beirut',
    'PTP_Ksara_to_Chams_Anjar') still qualify."""
    return tok.rstrip(".,!?;:")


def _identifiers_from_history(history: list[ConversationTurn]) -> set[str]:
    out: set[str] = set()
    for turn in history:
        for text in (turn.question, turn.answer):
            for raw_tok in _IDENTIFIER_TOKEN_RE.findall(text):
                tok = _strip_trailing_punctuation(raw_tok)
                if _looks_like_identifier_token(tok):
                    out.add(tok)
    return out


def _describe_trend(
    labeled_counts: list[dict], comparison_periods: list[tuple[str, datetime, datetime]],
) -> str | None:
    """A pre-computed, deterministic change-over-time description for a
    two-period comparison -- built for 'is traffic increasing/decreasing'
    trend questions, but applies to any two-period comparison. Confirmed
    necessary by this whole session's pattern, not just convenient: handed
    two correct, grounded counts, the model would otherwise have to
    compute a percentage change and a direction itself -- exactly the kind
    of mental arithmetic already shown repeatedly unreliable here (digit
    transcription, cross-row summation). Orders by the periods' ACTUAL
    start time, not list/mention order, which isn't necessarily
    chronological -- e.g. 'today' is listed before 'yesterday' in
    _PERIOD_PHRASE_ALIASES despite being the later period -- so "increased"
    always means earlier-period-to-later-period, regardless of which
    order the question named them in or which order count_events was
    called for them.
    """
    if len(labeled_counts) != 2 or len(comparison_periods) != 2:
        return None
    by_start = sorted(zip(comparison_periods, labeled_counts), key=lambda pair: pair[0][1])
    (earlier_label, _, _), earlier_entry = by_start[0]
    (later_label, _, _), later_entry = by_start[1]
    earlier_count, later_count = earlier_entry["count"], later_entry["count"]
    delta = later_count - earlier_count
    if earlier_count:
        pct_str = f"{abs(delta) / earlier_count * 100:.1f}%"
    else:
        pct_str = "undefined (0 in the earlier period)" if delta else "0%"
    if delta > 0:
        direction = f"increased by {delta} ({pct_str})"
    elif delta < 0:
        direction = f"decreased by {abs(delta)} ({pct_str})"
    else:
        direction = "stayed exactly the same"
    return f"From {earlier_entry['period']} ({earlier_count}) to {later_entry['period']} ({later_count}): {direction}."


def _describe_filter_scope(filter_args: dict) -> str | None:
    """Human-readable summary of which device/vendor a deterministic
    override's count is actually scoped to, for folding into the
    instruction the override hands back to the model. Confirmed as a real
    gap: scoped to source_ip=172.20.17.68 via an explicit UI filter (a
    real, grounded, correctly-filtered count), the model's own final
    answer still phrased it as "events on the network today" -- implying
    unfiltered -- because nothing in the override's result told it this
    was scoped to one device rather than the whole network. Returns None
    when nothing scopes the query (a genuine network-wide count), so the
    caller can state that plainly instead of naming an empty scope."""
    parts = [
        f"{field}={value}"
        for field, value in (
            ("hostname", filter_args.get("hostname")),
            ("source_ip", filter_args.get("source_ip")),
            ("vendor", filter_args.get("vendor")),
        )
        if value
    ]
    return ", ".join(parts) if parts else None


def _filter_args_for_period_override(
    query: LogAssistantQuery, model_filter_args: dict,
) -> dict:
    """What a deterministic period override (single-period or comparison)
    should actually filter count_events by: the model's own call
    arguments (or, in the tool-less force-resolve path, this turn's
    best-effort attempted_filter_args) -- UNLESS this is a bare follow-up,
    in which case the ENTIRE filter is replaced with just the entity from
    the turn directly before it (see _primary_identifier_from_last_turn).
    A bare follow-up has no topical content of its own, so nothing this
    turn's call guessed -- or an earlier, unrelated turn's leftover filter
    -- can be trusted over the immediately preceding turn's own topic.

    EXCEPT when query.source_ip/query.vendor is set -- an explicit,
    structural filter the user picked in the UI's filter panel for THIS
    request, not text the model or an earlier turn produced. Confirmed as
    a real bug: with the UI's Source IP filter set, a bare "how many
    events today" (4 words, so "bare" by word count despite having real
    topical content) discarded that explicit filter entirely in favor of a
    hostname guessed from an unrelated older turn's text -- happened to be
    the same device here, so the count still came out right, but it would
    silently scope to the WRONG device the moment the UI filter pointed
    somewhere else. An explicit per-request filter always wins over a
    text-inferred one, bare follow-up or not.

    Falls back to model_filter_args unchanged when no last-turn identifier
    is found and no explicit filter is set (nothing better to go on).
    """
    if query.source_ip or query.vendor:
        explicit = dict(model_filter_args)
        if query.source_ip:
            explicit["source_ip"] = query.source_ip
        if query.vendor:
            explicit["vendor"] = query.vendor
        return explicit
    if _is_bare_followup(query.question):
        hint = _primary_identifier_from_last_turn(query.history)
        if hint:
            return {"hostname": hint}
    return model_filter_args


def _primary_identifier_from_last_turn(history: list[ConversationTurn]) -> str | None:
    """For a bare follow-up ("and yesterday?") with no topical content of
    its own, the entity it refers to is whatever the IMMEDIATELY PRECEDING
    turn was about -- not just anything mentioned anywhere earlier in a
    long thread. Confirmed on net-flow as a real bug (Test 7): the thread
    also contained an earlier, unrelated turn about network-wide
    authentication failures; when "and yesterday?" followed a turn about
    one specific device, the model's own tool call carried over a
    `keyword="authentication failure"` filter from that EARLIER topic
    instead of the device from the turn directly before it, and the
    deterministic period override (which only corrects start/end, not
    hostname/keyword/severity/program) executed that stale filter
    verbatim -- a real, grounded count, for entirely the wrong question.
    Scoped to ONLY the last turn (not swept across the whole history as a
    set) so the most recent topic always wins over an older one.
    """
    if not history:
        return None
    last = history[-1]
    for text in (last.answer, last.question):
        for raw_tok in _IDENTIFIER_TOKEN_RE.findall(text):
            tok = _strip_trailing_punctuation(raw_tok)
            if _looks_like_identifier_token(tok):
                return tok
    return None


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


# Mirrors web/frontend/src/pages/Logs.tsx's SEVERITY_OPTIONS -- the real,
# fixed set of values the `severity` column actually holds (see
# clickhouse/init.sql). Kept here rather than imported since this is a
# backend service importing from a frontend source file; duplication is
# the lesser evil (flagged in both places' comments pointing at each
# other), not a reason to skip validating against it.
_VALID_SEVERITIES = frozenset({"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"})

# Mirrors web/frontend/src/pages/Logs.tsx's ANOMALY_REASON_OPTIONS -- the
# real, fixed set of values the `anomaly_reasons` array column actually
# holds (see ml/anomaly_signals.py). Same duplication trade-off as
# _VALID_SEVERITIES above.
_VALID_ANOMALY_REASONS = (
    "rare_template", "always_severe", "security_content", "severity_spike",
    "volume_spike", "unusual_template_mix", "unusual_transition", "interface_flapping",
)

# History here, briefly: a synonym list once mapped "wireless"/"wifi"/
# "radio" onto interface_flapping too, reasoned from that category's own
# docstring claiming link-layer-agnostic coverage ("covers wired AND
# wireless interface up/down flapping"). Confirmed live this was wrong in
# practice -- interface_flapping's ACTUAL detector (_INTERFACE_SIGNATURES
# in ml/interface_flap_anomaly.py) recognizes exactly one pattern,
# RouterOS's Ethernet-only `ether<N> link up/down`, and nothing wireless at
# all. Routing a wireless-specific question there hid real, directly
# relevant data (program='wireless,debug' events genuinely exist -- see
# _resolve_program_fuzzy) behind an honest-but-unhelpful Ethernet caveat,
# rather than ever letting the model reach for the real data. Now
# deliberately EXCLUDED below (see _is_wireless_specific) -- a question
# naming a wireless-specific link no longer resolves to this category via
# the synonym list at all, even though the plain "flapping"/"interface"
# word-overlap match above still does (so "ethernet flapping" is
# unaffected). This caveat itself stays, for the remaining case where
# interface_flapping IS still the right category (a plain "flapping" or
# "ethernet flapping" question, or an explicit 'reason=interface_flapping'
# call) -- it's still worth disclosing that even a non-wireless-phrased
# question only reflects this one RouterOS Ethernet pattern, not every
# possible interface type. Not fixed by guessing a wireless regex here:
# this project's own stated methodology (see that module's docstring) is
# evidence-based pattern matching against real traffic, and no confirmed
# wireless up/down message format exists in this deployment yet to match
# against.
_INTERFACE_FLAPPING_CAVEAT = (
    "Note: in this deployment, interface_flapping is currently only detected for RouterOS "
    "Ethernet interfaces (the literal 'ether<N> link up/down' message) -- no wireless-specific "
    "up/down signature is implemented yet, so this reflects Ethernet flapping, not a verified "
    "wireless-specific count, regardless of how the question was phrased."
)

# Confirmed live: "top n for today with ethernet flapping" silently answered
# with the all-time cumulative total, completely ignoring "today" -- not a
# bug in the force-resolve logic, but an undisclosed one: anomaly_summary
# has no time-range parameter at all (by design, matching the Anomaly
# Summary page's own semantics -- see its module docstring), so a named
# time period in the question can never actually be honored by this tool,
# whichever path reaches it. Silently answering a DIFFERENT question than
# the one asked is worse than answering the real one with a clear caveat.
_ANOMALY_SUMMARY_ALL_TIME_CAVEAT = (
    "Note: anomaly_summary has no time-scoping -- the number above is a cumulative, all-time "
    "total, not limited to the time period named in the question."
)


def _annotate_resolved_reason(reason: str, note: str | None) -> tuple[str, str | None]:
    if reason == "interface_flapping":
        note = f"{note} {_INTERFACE_FLAPPING_CAVEAT}" if note else _INTERFACE_FLAPPING_CAVEAT
    return reason, note


_ANOMALY_REASON_SYNONYMS: dict[str, tuple[str, ...]] = {
    "interface_flapping": (
        "disconnect", "disconnects", "disconnection", "disconnections",
        "dropout", "dropouts", "drop", "drops", "link down", "goes down", "going down",
        # "wireless"/"wifi"/"radio" deliberately removed (were here briefly --
        # see git history): reasoned from interface_flapping's own docstring
        # claiming link-layer-agnostic coverage, but confirmed live this was
        # actively counterproductive. The real data has genuine wireless
        # activity (program='wireless,debug', e.g. 'wlan1: failed to select
        # network'), invisible to this anomaly category (its one real
        # detector pattern is RouterOS's Ethernet-only 'ether<N> link
        # up/down' -- see ml/interface_flap_anomaly.py), but very much
        # findable via aggregate_events/count_events/search_logs now that
        # _resolve_program_fuzzy exists. Routing a "wireless" question to
        # this category hid real, directly relevant data behind an honest
        # caveat instead of ever letting the model reach for it. The general
        # lesson, not just a wireless-specific one: don't force a topic into
        # one of these 8 fixed categories on an assumption about what it
        # covers -- only word-overlap with the category's OWN name (handled
        # above) or a genuinely synonymous phrase for the same real signal
        # belongs here.
    ),
}

_WIRELESS_SPECIFIC_MARKERS = ("wireless", "wifi", "wi-fi", "radio")


def _is_wireless_specific(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _WIRELESS_SPECIFIC_MARKERS)


def _resolve_anomaly_reason(value: str) -> tuple[str | None, str | None]:
    """Maps a casual anomaly-type phrase onto the real, fixed anomaly_reason
    category it almost certainly means. Confirmed as a real gap: asked for
    'the top device with ethernet flapping', the model had no way to know
    the actual stored category is 'interface_flapping' -- a category label
    applied by the ML pipeline, not raw text -- so it guessed a free-text
    keyword for search_logs instead, which correctly found nothing since
    that literal phrase was never stored as message text.

    Deliberately does NOT resolve a wireless-specific phrase ('wireless',
    'wifi', 'radio') to interface_flapping -- see _is_wireless_specific's
    call site below. interface_flapping's real detector only recognizes
    RouterOS's Ethernet-only 'ether<N> link up/down' pattern (see
    ml/interface_flap_anomaly.py); a wireless-specific question is better
    answered by aggregate_events/count_events with a `program` filter
    (program values like 'wireless,debug' are real, see
    _resolve_program_fuzzy), not this fixed anomaly category.

    Matches by shared underscore-separated word (so 'flapping' alone
    matches 'interface_flapping') rather than requiring the real value
    verbatim or an exact substring either direction.

    Returns (resolved_reason, note): resolved_reason is the one real
    category matched (None if zero or multiple matched -- never guess
    between several plausible categories); note explains a no-match or
    ambiguous-match case so the model can relay it instead of silently
    giving up or picking one arbitrarily.
    """
    lowered = value.strip().lower()
    if lowered in _VALID_ANOMALY_REASONS:
        return _annotate_resolved_reason(lowered, None)
    words = set(re.findall(r"[a-z]+", lowered))
    # Scored by NUMBER of shared words, not just "any shared word" --
    # confirmed as a real precision gap: 'volume spike' shares the word
    # 'spike' with BOTH 'severity_spike' and 'volume_spike', which a plain
    # any-overlap check reports as a false ambiguity between them, when it
    # unambiguously also shares 'volume' with only one of the two. Only
    # candidates tied at the single highest overlap count are kept, so a
    # clearly-stronger match always wins over a weaker, coincidental one.
    #
    # A shared word is exact OR a >=4-char prefix either direction (plural/
    # verb-form tolerant, e.g. 'flap' <-> 'flapping', 'templates' <->
    # 'template') -- confirmed needed live: 'ethernet flap' (no 'ping')
    # matched NOTHING under exact-only matching and fell through to a
    # generic keyword search for the single word 'down', which -- with no
    # category and no program to scope it -- matched 85,092 unrelated
    # events fleet-wide instead of the real, evidence-based
    # interface_flapping definition (RouterOS's specific 3-downs-in-15-
    # minutes window). The 4-char floor keeps this from over-matching on
    # short, generic word fragments.
    def _word_overlap(category: str) -> int:
        return sum(
            1 for cw in category.split("_")
            if any(
                qw == cw or (len(qw) >= 4 and len(cw) >= 4 and (cw.startswith(qw) or qw.startswith(cw)))
                for qw in words
            )
        )

    scored = [(r, _word_overlap(r)) for r in _VALID_ANOMALY_REASONS]
    scored = [(r, score) for r, score in scored if score > 0]
    best = max((score for _, score in scored), default=0)
    matches = [r for r, score in scored if score == best]
    if len(matches) == 1:
        return _annotate_resolved_reason(
            matches[0], f"'{value}' isn't an exact anomaly category -- matched to the real category '{matches[0]}'."
        )
    if len(matches) > 1:
        return None, (
            f"'{value}' could mean more than one real anomaly category ({', '.join(matches)}) -- "
            "ask the user which one is meant, don't guess."
        )
    # Zero word-overlap matches -- try the curated synonym list before
    # giving up (see _ANOMALY_REASON_SYNONYMS) -- EXCEPT when the text
    # explicitly names a wireless-specific link (wireless/wifi/radio):
    # interface_flapping's only real detector is RouterOS's Ethernet-only
    # 'ether<N> link up/down' (see ml/interface_flap_anomaly.py), so
    # resolving a wireless-specific question to it via the generic
    # disconnect-family synonyms would claim coverage that doesn't exist --
    # confirmed live as actively counterproductive (it hid real wireless
    # data, findable via aggregate_events/count_events now that
    # _resolve_program_fuzzy exists, behind an honest-but-unhelpful
    # Ethernet caveat). A plain 'flapping'/'interface' word-overlap match
    # above is unaffected by this -- "ethernet flapping" or literally
    # "interface flapping" still resolves correctly regardless.
    if _is_wireless_specific(lowered):
        # Confirmed live as a real gap: this error message alone, just
        # listing the 8 valid categories, led the model to conclude it
        # simply couldn't answer the question and stop -- rather than
        # realizing a DIFFERENT tool (not anomaly_summary at all) could.
        # Pointing directly at the real alternative, right at the point of
        # failure, is far more likely to be followed than a general
        # instruction stated once, earlier, in a long system prompt (the
        # same lesson every deterministic override in this file is built
        # on -- but this is a case the deterministic override deliberately
        # does NOT intercept, see _is_wireless_specific's other call site,
        # so the model has to get there on its own with this nudge).
        return None, (
            f"'{value}' isn't a real anomaly category -- there is no wireless-specific category. "
            "Do not retry anomaly_summary with a different wireless-related guess. Instead, call "
            "semantic_search with the original question's wording to find real example wireless log "
            "messages, then use the real `program`/message text those hits contain with "
            "aggregate_events or count_events to get an exact count -- real wireless-tagged log data "
            "exists under the `program` field even though you don't know its exact value yet."
        )
    for reason, synonyms in _ANOMALY_REASON_SYNONYMS.items():
        if any(s in lowered for s in synonyms):
            return _annotate_resolved_reason(
                reason, f"'{value}' isn't an exact anomaly category -- matched to the real category '{reason}' via a known synonym for it."
            )
    return None, (
        f"'{value}' doesn't match any real anomaly category. The only real values are: "
        f"{', '.join(_VALID_ANOMALY_REASONS)}."
    )


# GENERAL "which device/vendor has the most <concept>" resolver, for any
# <concept> that ISN'T one of the 8 fixed anomaly_reason categories --
# superseding an earlier version of this fix that hardcoded exactly one
# such concept (wireless disconnections). That version worked, but only
# for that one exact phrase -- confirmed, live, as not what was actually
# wanted: the whole point was a Log Assistant that can answer "any question
# that can be found in the database" without a new hardcoded bypass for
# every new phrase that trips up the model. "Wireless disconnections" was
# simply the first one found this way; "deauth attacks", "SSL certificate
# errors", or anything else not yet asked are exactly as unresolvable via
# the fixed 8 categories, and none of them should need their own dedicated
# function the way wireless disconnections first did.
#
# This mirrors, in code, the exact manual process used to find the real
# answer for wireless disconnections by hand: (1) find real example
# messages about the concept via semantic_search (embedding similarity, so
# it works even when the question's own wording never appears verbatim in
# any message -- unlike a keyword guess); (2) ask the model ONE short,
# heavily-grounded question -- naming the literal substring real retrieved
# messages share -- not an open-ended tool-routing decision, since this
# model has repeatedly proven unreliable at the latter but a narrow,
# example-grounded extraction is a much easier task; (3) verify that
# substring actually appears in the real messages before trusting it (same
# grounding-check discipline as every other model-derived value in this
# file -- never trusted un-verified); (4) run an authoritative
# aggregate_events COUNT over ALL matching data using that verified
# keyword, plus the hits' majority `program` if one exists (confirmed
# necessary on net-flow: a bare keyword search with no program filter once
# pulled in unrelated non-wireless "disconnected" events from an
# unresolved-hostname IP with 112,182 events, more than 18x the real
# answer -- the same cross-contamination risk applies to any keyword, not
# just that one).
#
# Falls through to the normal tool-calling loop (returns None) at any step
# that doesn't produce a verified result, rather than ever answering with
# an unverified guess -- the caller treats that exactly as if this
# mechanism didn't exist for this question.
_ALL_TIME_START = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Generic question scaffolding words -- stripped before checking whether a
# ranking OR count question names an actual CONCEPT beyond its own
# scaffolding ("which device is most/top/highest/worst", "how many events
# happened" -- both already have correct, working answer paths for the
# no-concept case and need no semantic discovery at all). Deliberately just
# scaffolding words, not any topic -- adding a new topic/concept to the
# database never requires touching this list.
_GENERIC_QUESTION_WORDS = frozenset({
    "most", "top", "which", "who", "whose", "device", "devices", "vendor", "vendors",
    "highest", "worst", "busiest", "active", "noisiest", "the", "a", "an", "is", "for",
    "with", "by", "of", "has", "have", "give", "me", "what", "show", "and", "to", "in", "that",
    "how", "many", "much", "count", "number", "total", "events", "happened", "occur",
    "occurred", "there", "were", "was", "did", "logs",
    # Time-phrase words -- a time reference alone is never the CONCEPT a
    # count/ranking question is about (see _detect_single_period/
    # _detect_comparison_periods, which already handle the time dimension
    # separately); confirmed needed: "how many events happened today"
    # otherwise left "today" as the only remaining word and was wrongly
    # treated as naming a real concept to run semantic discovery for.
    "today", "yesterday", "tomorrow", "week", "month", "year", "this", "last", "next", "ago",
    # Filler/intensifier words -- confirmed live as a real, user-facing
    # regression: "which device is busiest right now" left "right" as the
    # only remaining word after stripping ranking scaffolding (it's 5
    # letters, over the len>=4 floor, and names no real concept at all),
    # wrongly routing an everyday, already-correctly-handled question
    # ("which device is busiest" -> list_devices) into the slow
    # semantic-search discovery path instead -- the request timed out.
    # These words pad a question without ever naming its actual topic.
    "right", "now", "currently", "presently", "actually", "really", "just",
    "simply", "basically", "immediately", "still", "please", "overall",
})


def _extract_concept(question: str) -> str | None:
    # len(w) >= 4 excludes short filler/typos ("ist", "any", "did") from
    # counting as a concept -- confirmed needed: a garbled bare follow-up
    # like "ist the top" after an UNRELATED prior turn would otherwise still
    # look like it names a (nonsense) concept of its own, triggering a
    # wasted semantic_search + extraction round-trip before falling through
    # to the normal loop anyway. Every real concept word seen so far
    # (wireless, disconnections, deauth, attacks, volume) is comfortably
    # longer than this.
    words = re.findall(r"[a-z']+", question.lower())
    remaining = [w for w in words if w not in _GENERIC_QUESTION_WORDS and len(w) >= 4]
    return " ".join(remaining) if remaining else None


def _unresolved_ranking_concept(question: str, history: list["ConversationTurn"] | None = None) -> str | None:
    """Returns the effective question text to run concept discovery against
    (see _resolve_concept_ranking), or None if this question doesn't need
    it -- either because it isn't a ranking question, because
    _detect_anomaly_reason already resolved it to one of the 8 fixed
    categories (that path is already correct and doesn't need semantic
    discovery), or because stripping generic scaffolding words leaves
    nothing (a plain "which device is busiest" with no concept of its own,
    correctly left to list_devices).

    The CURRENT question's own text is checked FIRST, before any
    bare-follow-up inheritance -- confirmed live as necessary, not just
    theoretical: "top device with ethernet flap" is a genuine, substantive,
    self-contained question, but it happens to be exactly 5 words, which
    satisfies _is_bare_followup's own word-count threshold. Checking
    inheritance first would have let a real question's own topic
    ("ethernet flap") be silently discarded in favor of stale context from
    an unrelated earlier turn (confirmed live: it answered with the
    PREVIOUS turn's wireless-disconnections ranking instead). A real
    concept extracted from the current text always wins; only when the
    current text yields NOTHING on its own (see _extract_concept's own
    len>=4 filter, which is what actually keeps a garbled follow-up like
    "ist the top" from wrongly counting as having a concept of its own) does
    this fall back to the previous turn -- same as _detect_anomaly_reason's
    own bare-followup handling, which also inherits unconditionally rather
    than requiring the short follow-up text to re-state the ranking/count
    language itself (confirmed needed too: "nd the vendor" carries no
    ranking marker of its own, only "which vendor has the most wireless
    disconnections" two turns back does). Only looks at the immediately
    preceding turn, same "last turn only" scoping throughout this file.

    Inheritance additionally requires _extract_concept(question) to be
    EMPTY, not just _is_bare_followup -- confirmed live as a second,
    distinct regression from the same root cause: "how many wireless
    disconnections happened" is also exactly 5 words (so _is_bare_followup
    alone would call it a follow-up), isn't ranking-shaped itself
    (_wants_ranking is False, so the branch above never matches), and so
    was falling straight into blind inheritance -- answering a plain COUNT
    question with the unrelated PREVIOUS turn's ranking result entirely.
    Word count alone was never a reliable signal that a question has "no
    content of its own"; requiring its own concept-extraction to also come
    up empty is what actually distinguishes a true contentless follow-up
    ("ist the top", "nd the vendor") from a short but fully self-contained
    question that simply isn't shaped like a ranking."""
    if (
        _wants_ranking(question)
        and _detect_anomaly_reason(question, history) is None
        and _extract_concept(question)
    ):
        return question
    if history and _is_bare_followup(question) and not _extract_concept(question):
        return _unresolved_ranking_concept(history[-1].question)
    return None


def _unresolved_count_concept(question: str, history: list["ConversationTurn"] | None = None) -> str | None:
    """Same idea as _unresolved_ranking_concept (see its docstring for why
    the current question's own text is checked before any bare-follow-up
    inheritance), generalized to a plain 'how many <concept> happened'
    question instead of a ranking one -- covers the next most common
    question shape this Log Assistant gets after ranking, reusing the
    identical discovery machinery (_resolve_concept_count below) rather
    than a new bypass. Mutually exclusive with the ranking path by
    construction (requires _wants_count and NOT _wants_ranking) -- a
    question combining both language forms is rare and, if it happens, is
    better served by the ranking path, which runs first in ask().

    Checks _resolve_anomaly_reason directly rather than going through
    _detect_anomaly_reason -- that helper only ever resolves a RANKING-
    shaped question (it's gated on _wants_ranking internally), so "how many
    events for interface flapping" would otherwise slip past it undetected
    and get a keyword-search count instead of the real
    anomaly_reason-tagged one -- a materially different, and likely wrong,
    number for a category with a real evidence-based detector (e.g.
    interface_flapping's 3-down-transitions-in-15-minutes window, which a
    plain 'link'/'flapping' keyword match would not reproduce).

    Inheritance additionally requires _extract_concept(question) to be
    EMPTY, not just _is_bare_followup -- see _unresolved_ranking_concept's
    docstring for the confirmed live regression this closes (a 5-word,
    fully self-contained question is not "contentless" just because it's
    short)."""
    if (
        _wants_count(question)
        and not _wants_ranking(question)
        and _resolve_anomaly_reason(question)[0] is None
        and _extract_concept(question)
    ):
        return question
    if history and _is_bare_followup(question) and not _extract_concept(question):
        return _unresolved_count_concept(history[-1].question)
    return None


def _significant_programs(hits: list[LogHit], min_fraction: float = 0.2, max_programs: int = 3) -> list[str]:
    """Programs the retrieved hits meaningfully agree the concept lives
    under -- deliberately not just the single top ("majority") one.
    Confirmed live as a real, not theoretical, gap: for the IDENTICAL
    concept ("wireless disconnections"), a strict majority-of-hits program
    picked 'wireless,info' on one call and an unrelated-looking
    'Mimosa_C5x' on the very next -- ordinary variance in which hits a
    hybrid/embedding search happens to retrieve, not a code bug -- and
    whichever program lost out was silently discarded even though its
    events were just as real, producing a confidently wrong zero count the
    second time. Real wireless hardware from different vendors can
    legitimately tag the same kind of event under different `program`
    values (this deployment alone has at least 'wireless,info' and
    apparently 'Mimosa_C5x'), so querying every program the sample
    meaningfully supports -- not betting everything on a single plurality
    -- is the correct fix, not a tighter threshold on the same flawed
    single-value approach. Returns [] (meaning "don't filter by program at
    all") only when hits carry no program info whatsoever."""
    programs = [h.program for h in hits if h.program]
    if not programs:
        return []
    counts = Counter(programs)
    total = len(programs)
    return [p for p, c in counts.most_common(max_programs) if c / total >= min_fraction]


# Generic log-message scaffolding -- shared by almost every wireless/network
# message regardless of its actual event type, so none of these identify a
# CONCEPT on their own and would only dilute the candidate list below.
_GENERIC_MESSAGE_WORDS = frozenset({
    "wlan", "wlan1", "wlan2", "info", "debug", "warning", "error", "notice", "the", "and",
    "for", "with", "from", "data", "device", "unknown", "that", "this", "received", "link",
    "sent", "send", "message", "event",
    # Schema/metadata field names -- defense in depth alongside searching
    # with the extracted concept (_discover_concept_keyword) rather than
    # the raw question: confirmed live that "vendor" won as the sole
    # candidate for a "which vendor..." question when a few retrieved
    # messages happened to contain it literally (e.g. real device/vendor
    # description text), even though it identifies no event type at all.
    "vendor", "hostname", "severity", "program", "category", "source", "anomaly",
})


def _candidate_concept_tokens(messages: list[str], min_count: int) -> list[str]:
    """Literal words shared across at least `min_count` of the sample
    messages -- deterministic, no model involved. This is what actually
    distinguishes the DOMINANT event type in the sample from a rare one:
    confirmed live, a free-form extraction validated against just ONE
    sample message picked 'disabling' -- a real but minority message buried
    among mostly '...disconnected...' hits -- over the actual dominant
    pattern, undercounting the real answer by roughly 700x (9 vs. the real
    6,178). Restricting the model's later choice to only words already
    cross-confirmed across several real messages (not letting it freely
    generate/copy from any single one) closes that gap by construction.
    MAC addresses, IPs, and pure numbers are naturally excluded by the
    length->=4-letters-only pattern, not because they're explicitly
    blocked."""
    counts: Counter = Counter()
    for message in messages:
        words = {w.lower() for w in re.findall(r"[A-Za-z][A-Za-z']{3,}", message)}
        for w in words - _GENERIC_MESSAGE_WORDS:
            counts[w] += 1
    return [w for w, c in counts.most_common() if c >= min_count]


async def _choose_concept_keyword(concept_question: str, candidates: list[str], sample_messages: list[str]) -> str | None:
    """The one, narrow, heavily-constrained model call this mechanism makes
    -- deliberately NOT a tool-routing decision (this model's confirmed
    failure mode all session) and NOT open-ended free-text extraction
    either (see _candidate_concept_tokens' docstring for why that alone
    once picked a rare, wrong word). The model's only job here is to pick
    the best-fitting entry from a short list of words ALREADY confirmed to
    recur across multiple real messages -- a much narrower, easier task,
    and the validation below rejects anything that isn't literally one of
    those pre-vetted candidates."""
    prompt = (
        "A question about network log events, and a list of CANDIDATE words that each appear "
        "repeatedly across real log messages related to it, are below. Reply with ONLY the single "
        "candidate word that best identifies this type of event -- copy it EXACTLY as listed, no "
        "other text. If none of the candidates fit the question, reply with exactly: NONE\n\n"
        f"Question: {concept_question}\n\nCandidates: {', '.join(candidates)}\n\n"
        "Example messages, for context only:\n"
        + "\n".join(f"- {_truncate(m, 200)}" for m in sample_messages)
    )
    try:
        body = await asyncio.to_thread(
            _post_chat_sync,
            f"{settings.ollama_url}/api/chat",
            {
                "model": settings.ollama_chat_model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"num_predict": 16, "num_thread": settings.ollama_chat_num_thread},
            },
            settings.ollama_timeout_seconds,
        )
    except Exception:
        log.exception("Concept-ranking keyword choice call failed -- falling back to the normal agent loop")
        return None
    raw = (body.get("message", {}).get("content") or "").strip().strip("'\"").strip().lower()
    if not raw or raw == "none":
        return None
    # Never trust the choice un-verified -- same grounding discipline as
    # every other model-derived value in this file. Only an EXACT match to
    # one of the pre-vetted candidates is accepted, not a substring/fuzzy
    # match -- a model padding its answer with extra words should fail
    # closed (fall through to the normal loop), not be guessed at.
    return raw if raw in candidates else None


async def _discover_concept_keyword(os_client: OpenSearch, concept_question: str) -> tuple[str, list[str]] | None:
    """The shared discovery step behind both _resolve_concept_ranking and
    _resolve_concept_count: semantic_search for real examples, reduce to
    candidates that actually recur, then a narrow constrained choice if
    there's more than one. Returns (keyword, significant_programs -- see
    _significant_programs, [] meaning "no program filter"), or None if any
    step fails to produce a verified result.

    Searches with the EXTRACTED concept (_extract_concept), not the raw
    question text -- confirmed live as a real, serious gap: semantic_search
    is a HYBRID query (see its own docstring/_build_query), so its BM25
    clause literally matches the full question text against the message
    field, not just its embedding. Passing "which vendor has the most
    deauth attacks" verbatim let messages that merely contain the generic
    scaffolding word "vendor" outscore genuinely relevant ones, and
    "vendor" then won as the sole dominant candidate -- answering with a
    nonsense keyword scored by its own search prompt's wording, not the
    actual concept asked about. Stripping to "deauth attacks" first keeps
    both the embedding and the BM25 clause focused on the real topic."""
    search_phrase = _extract_concept(concept_question) or concept_question
    try:
        hits = await semantic_search(os_client, LogAssistantQuery(question=search_phrase[:1000], limit=15))
    except Exception:
        log.exception("Concept discovery semantic_search failed -- falling back to the normal agent loop")
        return None
    if not hits:
        return None

    sample_messages = [h.message for h in hits if h.message][:15]
    if not sample_messages:
        return None

    # Requires a word to recur across roughly a third of the sample (at
    # least 2 either way) before it's even offered as a candidate -- a
    # word seen only once is exactly the "rare minority message" failure
    # this whole mechanism exists to avoid trusting.
    min_count = max(2, (len(sample_messages) + 2) // 3)
    candidates = _candidate_concept_tokens(sample_messages, min_count)
    if not candidates:
        return None
    # A single clearly-dominant candidate needs no model call at all --
    # faster and strictly more reliable than asking the model to confirm
    # the only option.
    keyword = candidates[0] if len(candidates) == 1 else await _choose_concept_keyword(concept_question, candidates, sample_messages)
    if not keyword:
        return None
    return keyword, _significant_programs(hits)


async def _resolve_concept_ranking(
    os_client: OpenSearch, ch_client, concept_question: str, is_vendor: bool, now: datetime,
) -> dict | None:
    discovered = await _discover_concept_keyword(os_client, concept_question)
    if not discovered:
        return None
    keyword, programs = discovered
    group_key = "vendor" if is_vendor else "hostname"
    # One call PER significant program (never a single filtered call) --
    # see _significant_programs' docstring for the confirmed live incident
    # this closes: discarding every program but one real contributor
    # silently loses real events, not just a formatting nicety. A wide
    # per-call limit (the service's own max) means merging afterward
    # doesn't lose a group that would only rank highly once its counts
    # across programs are combined; final truncation happens after the
    # merge, not before it.
    #
    # Sequential, not asyncio.gather -- confirmed live (500, "Attempt to
    # execute concurrent queries within the same session"): clickhouse_
    # connect's Client raises a ProgrammingError when two queries run
    # concurrently on the SAME client instance, even each wrapped in its
    # own to_thread (see the identical, pre-existing lesson at this same
    # ch_client's other concurrent-use site in _execute_tool). Every
    # program here shares this one ch_client, so they must run one at a
    # time regardless of how harmless concurrent reads might look.
    per_program_rows = [
        await asyncio.to_thread(
            log_search_service.aggregate_events, ch_client, group_by=[group_key], keyword=keyword,
            program=p, start=_ALL_TIME_START, end=now, limit=log_search_service.AGGREGATE_MAX_LIMIT,
        )
        for p in (programs or [None])
    ]
    totals: dict[str, int] = {}
    for rows in per_program_rows:
        for row in rows:
            key = row.get(group_key)
            totals[key] = totals.get(key, 0) + row.get("event_count", 0)
    merged = sorted(
        ({group_key: k, "event_count": v} for k, v in totals.items()),
        key=lambda r: r["event_count"], reverse=True,
    )[:10]
    return {"rows": merged, "keyword": keyword, "programs": programs}


def _concept_ranking_plain_answer(rows: list[dict], is_vendor: bool, keyword: str, programs: list[str]) -> str:
    # `programs` (the internal syslog `program` field value(s) actually
    # queried, e.g. 'wireless,info') is deliberately NOT shown here --
    # confirmed live as genuinely confusing to a user asking a plain
    # question ("why is there 'wireless,info'... it is not
    # comprehensible"). It's still logged (see the FORCE-RESOLVED log line
    # in ask()) for anyone auditing what was actually matched.
    kind = "vendor" if is_vendor else "device"
    qualifier = f"messages containing '{keyword}'"
    if not rows:
        return f"No {kind} has any events matching {qualifier}."
    top = rows[0]
    label = top.get("vendor") if is_vendor else top.get("hostname")
    count = top.get("event_count")
    # The single top entry answers "which X has the MOST" but not "what
    # X's are affected at all" -- confirmed live as a real, distinct
    # question ("if i want to know the type of devices that has this
    # disconnections"). `rows` already holds the full merged-and-sorted
    # breakdown (see _resolve_concept_ranking), so showing all of it costs
    # nothing extra and answers both questions in one response instead of
    # requiring a second, differently-phrased round trip.
    breakdown = "; ".join(f"{(r.get('vendor') if is_vendor else r.get('hostname'))}: {r.get('event_count')}" for r in rows)
    return (
        f"The top {kind} for {qualifier} is {label}, with {count} matching events (cumulative, all-time). "
        f"Full breakdown by {kind} (busiest first): {breakdown}."
    )


async def _resolve_concept_count(
    os_client: OpenSearch, ch_client, concept_question: str, start: datetime, end: datetime,
) -> dict | None:
    discovered = await _discover_concept_keyword(os_client, concept_question)
    if not discovered:
        return None
    keyword, programs = discovered
    # Sum across every significant program, same reasoning as
    # _resolve_concept_ranking. Sequential, not asyncio.gather -- same
    # confirmed-live ch_client concurrency restriction as there (this was
    # in fact the exact call that raised the 500 in production the one
    # time this ran concurrently).
    counts = [
        await asyncio.to_thread(log_search_service.count_events, ch_client, keyword=keyword, program=p, start=start, end=end)
        for p in (programs or [None])
    ]
    return {"count": sum(counts), "keyword": keyword, "programs": programs}


def _concept_count_plain_answer(count: int, keyword: str, programs: list[str], period_label: str | None) -> str:
    # See _concept_ranking_plain_answer's comment -- `programs` is kept as
    # a parameter (logged by the caller) but deliberately left out of the
    # user-facing text.
    qualifier = f"messages containing '{keyword}'"
    period = f" {period_label}" if period_label else " (cumulative, all-time)"
    return f"There have been {count} events matching {qualifier}{period}."


# Loose enough to catch a real dotted-quad before it's used as a literal
# `hostname =` equality match (which is all this guards against -- an
# actual malformed IP still fails at the database as "no such value",
# exactly as today, just via source_ip instead of hostname).
_IPV4_SHAPE_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Module-level (not local to _sanitize_equality_filters) so other optional-
# filter call sites can reuse it -- confirmed needed: asked "which devices
# have gone quiet" (no specific name given), the model passed
# hostname='*' to silent_devices rather than omitting the argument. A
# plain substring filter treats '*' as a literal character (no real
# hostname contains one), so this would have silently matched nothing even
# with real silent devices present -- it only happened not to matter
# because the real result was already empty before filtering. Same
# underlying pattern as 'none'/'null'/'None' elsewhere, just a glob-style
# placeholder instead of a word.
_PLACEHOLDER_STRINGS = frozenset({"none", "null", "n/a", "na", "unknown", "any", "unset", "*", "all", ""})


def _is_real_filter_value(value) -> bool:
    """True if `value` looks like an actual filter someone meant, not a
    placeholder the model sent instead of simply omitting an optional
    argument (see _PLACEHOLDER_STRINGS)."""
    return isinstance(value, str) and value.strip().lower() not in _PLACEHOLDER_STRINGS


def _sanitize_equality_filters(args: dict) -> dict:
    """Guards confirmed net-flow failure modes in the model's own tool-call
    arguments, none caught by _parse_tool_bool/_parse_tool_int since all
    are valid-shaped strings, not an obviously-wrong type:
    (1) a severity value the model invented instead of omitting the
    argument -- confirmed: the literal string 'none' (not one of the 8 real
    severities above) for 'how many events ... yesterday', which
    _build_conditions' `if value:` check still treats as a real filter,
    silently forcing count=0 regardless of the real answer; (2)
    duplicating the hostname's own value into an unrelated equality field
    -- confirmed: 'how many events today for PTP_Ksara_to_Chams_Anjar'
    called count_events with program='PTP_Ksara_to_Chams_Anjar' as well as
    hostname=(the same value), but `program` holds a process/service name
    (e.g. 'sshd'), never a hostname, so that condition can also never
    match any row -- again silently forcing count=0 on what should have
    been a real, non-zero count; (3) a generic placeholder word in place of
    simply omitting an optional argument -- confirmed: a redirected
    semantic_search call during a UI-filter test carried vendor='None' (the
    literal string, not Python None) straight through from the model's own
    JSON. `vendor` has no fixed enum to validate against the way severity
    does, but it's open-ended free text describing a real vendor name
    ('mikrotik', 'cisco', ...), and no real vendor is ever literally the
    word 'none'/'null'/etc, so these are always a placeholder rather than a
    genuine filter whatever field they show up in; (4) an IP address put in
    `hostname` instead of `source_ip` -- confirmed: with the UI's Source IP
    filter set to 172.20.17.68, the model's own tool call put that value
    under `hostname` (no `source_ip` key at all). The `hostname` column
    holds names like 'PTP_Ksara_to_Chams_Anjar', never a raw IP string, so
    that equality condition matched zero rows -- a busy device's real,
    non-zero count silently came back 0. Moved to `source_ip` instead
    whenever `hostname` is IP-shaped and `source_ip` isn't already set to
    something else (never overwrites a source_ip the model separately,
    correctly provided). (5) the model names the argument `device` instead
    of the tool schema's actual parameter name `hostname` -- confirmed:
    asked "what about the devices that showed wireless disconnections
    today" (a question whose own text says "devices"), the model's
    count_events call carried `device='ND_SAIDA1-LGB[SAIDA] | IBL[SAIDA]'`.
    `device` isn't a real parameter (see the count_events tool schema --
    only `hostname` exists), so it was silently ignored entirely: the call
    executed completely UNSCOPED, returning a whole-network count instead
    of the one real per-device count that was actually available, and nothing
    downstream had any way to tell the model's filter intent had been lost.
    Promoted into `hostname` whenever `hostname` isn't already set to a
    real value of its own (never overwrites a correctly-named hostname the
    model also provided). Returns a copy with any such field moved,
    promoted, or cleared to None; everything else passes through
    unchanged."""
    out = dict(args)
    device_alias = out.pop("device", None)
    if _is_real_filter_value(device_alias) and not _is_real_filter_value(out.get("hostname")):
        out["hostname"] = device_alias
    hostname = out.get("hostname")
    if isinstance(hostname, str) and _IPV4_SHAPE_RE.match(hostname.strip()):
        # Always cleared -- an IP-shaped value is never a valid `hostname`
        # filter regardless of what source_ip already holds. Only BACKFILLS
        # source_ip when it's not already set to something else, so a
        # separately-correct source_ip the model also provided is never
        # overwritten by this recovery path.
        if not out.get("source_ip"):
            out["source_ip"] = hostname.strip()
        out["hostname"] = None
    severity = out.get("severity")
    if isinstance(severity, str) and severity.strip().lower() not in _VALID_SEVERITIES:
        out["severity"] = None
    for field in ("hostname", "source_ip", "vendor", "program", "keyword"):
        value = out.get(field)
        if isinstance(value, str) and value.strip().lower() in _PLACEHOLDER_STRINGS:
            out[field] = None
    hostname = out.get("hostname")
    if isinstance(hostname, str) and hostname.strip():
        for field in ("program", "vendor", "source_ip", "keyword"):
            value = out.get(field)
            if isinstance(value, str) and value.strip().lower() == hostname.strip().lower():
                out[field] = None
    return out


async def _resolve_hostname_fuzzy(ch_client: Client, hostname: str) -> tuple[str | None, str | None]:
    """If `hostname` doesn't exactly match any real device, try a case-
    insensitive SUBSTRING match via device_service.list_devices -- which
    already supports exactly this (see its own docstring: hostname is
    matched with positionCaseInsensitive, not equality) -- before accepting
    a count_events/search_logs zero as genuine. Searches a generous year of
    history independent of whatever window the actual count/search is
    scoped to, since resolving a NAME is a different question from "did
    this device have activity in this window".

    Confirmed as a real gap, not hypothetical: "give the top 10 logs for
    anjar MKT" (a casual, partial reference -- the real hostname is
    'PTP_Ksara_to_Chams_Anjar') returned a correct-but-unhelpful zero via
    exact match, when a substring search finds the real device immediately
    and unambiguously. Deliberately NOT changing count_events/search_logs
    themselves to fuzzy-match -- those also back the plain Log Search page,
    where an operator typing a deliberately narrow, exact hostname should
    get an exact answer, not a surprise substring expansion.

    Tries the WHOLE string as a substring first, then falls back to each
    individual word in it (split on whitespace/underscore/hyphen, 3+ chars)
    -- confirmed necessary, not just defensive: "anjar MKT" doesn't
    substring-match 'PTP_Ksara_to_Chams_Anjar' as a WHOLE phrase at all
    (there's no "MKT" anywhere in the real name -- "MKT" was the user's own
    shorthand for the vendor, mikrotik, concatenated onto the device
    nickname, not part of it), so a single whole-string search found
    nothing and never resolved. Searching "anjar" and "MKT" separately
    lets the real device-name fragment match on its own even when mixed
    with unrelated words in the same casual phrase.

    Returns (resolved_hostname, note): resolved_hostname is the real
    hostname when EXACTLY one real device matched (None otherwise -- zero
    matches means genuinely no such device even loosely; more than one
    DISTINCT device is ambiguous and must not be guessed at). note is
    non-None whenever this is worth relaying to the model (a resolution
    happened, or the match was ambiguous), so the final answer can say so
    instead of silently substituting or silently staying at an unexplained
    zero.

    The whole-string search is resolved FIRST, on its own, before ever
    trying the word-split fallback -- confirmed as a real, reproduced bug
    on net-flow: a bare follow-up truncated the real hostname
    'MKT_SOC-MUTUELLE_link2[SNFL]_TO_SNFL' to 'MKT_SOC-MUTUELLE_link2' (the
    identifier regex stops at '['), and the whole-string search alone
    correctly, UNAMBIGUOUSLY matched that one real device -- but the
    original code went on to ALSO search every split word unconditionally
    and merged everything into one pool, and the generic word 'MKT' (a
    vendor-name fragment shared with the unrelated real device
    'MKT-NETPRO[ZAHLE]-MGMT') joined the pool too, turning an already-
    resolved single match into a false "ambiguous, matches 2 devices"
    verdict -- which silently left the caller's count at the real zero
    from the ORIGINAL (unresolved, truncated) query, with no visible
    explanation. Splitting into words is now tried only when the whole
    string itself matched nothing at all, preserving the original
    motivating case ('anjar MKT' doesn't substring-match the real device
    name as a whole phrase, so word-splitting is still what finds it).
    """
    async def _search(term: str) -> dict[str, object]:
        candidates = await asyncio.to_thread(
            device_service.list_devices,
            ch_client,
            hostname=term,
            start=datetime.now(timezone.utc) - timedelta(days=365),
            limit=5,
        )
        return {d.hostname: d for d in candidates.items}

    def _verdict(matches: dict[str, object]) -> tuple[str | None, str | None] | None:
        if len(matches) == 1:
            resolved = next(iter(matches))
            return resolved, f"'{hostname}' isn't an exact device name -- resolved to the real device '{resolved}'."
        if len(matches) > 1:
            names = ", ".join(matches)
            return None, (
                f"'{hostname}' isn't an exact device name and matches more than one real device "
                f"({names}) -- tell the user which devices matched and ask them to pick one, don't guess."
            )
        return None

    whole_string_verdict = _verdict(await _search(hostname))
    if whole_string_verdict is not None:
        return whole_string_verdict

    matches: dict[str, object] = {}
    for word in (w for w in re.split(r"[\s_-]+", hostname) if len(w) >= 3):
        matches.update(await _search(word))
        if len(matches) > 4:
            # Already clearly too broad to narrow down further (e.g. a
            # short, common word) -- stop early rather than keep searching.
            break
    return _verdict(matches) or (None, None)


async def _resolve_program_fuzzy(ch_client: Client, program: str) -> tuple[str | None, str | None]:
    """If `program` doesn't exactly match any real value, try a case-
    insensitive SUBSTRING match against the distinct program values
    actually in use (log_search_service.get_filter_options' own
    groupUniqArray(program), already built for the Log Search page's
    dropdown) before accepting a count_events/search_logs/aggregate_events
    zero as genuine.

    Confirmed as a real gap, not hypothetical: asked 'top device with
    wireless disconnections', the real data plainly contains wireless
    activity (program='wireless,debug', message 'wlan1: failed to select
    network') -- but `program` is an EXACT-equality filter (see
    _build_conditions), and RouterOS (and similar vendors) write a
    comma-separated list of facility/category tags into this field rather
    than a single clean process name like 'sshd', so neither a human nor
    the model would ever guess the literal string 'wireless,debug' to
    query by. A plain 'wireless' query against an exact-match filter
    silently returns zero, indistinguishable from "no wireless activity at
    all" -- exactly the failure mode _resolve_hostname_fuzzy already
    solves for hostnames, applied here to the identical problem for
    program.

    Deliberately NOT changing log_search_service._build_conditions itself
    to substring-match program -- that also backs the human-facing Log
    Search page, where an operator picking an exact value from the filter
    dropdown should get an exact answer, not a surprise expansion (same
    reasoning _resolve_hostname_fuzzy's own docstring gives for not
    changing search_logs/count_events directly for hostname).

    Returns (resolved_program, note) -- resolved_program is the one real
    value matched (None if zero or multiple matched -- never guess between
    several plausible values, same policy as every other resolver here)."""
    options = await asyncio.to_thread(log_search_service.get_filter_options, ch_client)
    lowered = program.strip().lower()
    matches = [p for p in options.programs if lowered in p.lower()]
    if len(matches) == 1:
        return matches[0], f"'{program}' isn't an exact program value -- matched to the real value '{matches[0]}'."
    if len(matches) > 1:
        values = ", ".join(matches)
        return None, (
            f"'{program}' isn't an exact program value and matches more than one real value "
            f"({values}) -- tell the user which matched and ask them to pick one, don't guess."
        )
    return None, None


async def _count_events_resolving_hostname(
    ch_client: Client, *, hostname: str | None, program: str | None = None, **kwargs,
) -> tuple[int, str | None, str | None]:
    """log_search_service.count_events with the _resolve_hostname_fuzzy AND
    _resolve_program_fuzzy fallbacks applied -- see their docstrings.
    Returns (count, effective_hostname, note) -- effective_hostname is
    whichever hostname actually produced `count` (unchanged, or the
    fuzzy-resolved name), so a caller resolving the SAME hostname across
    multiple periods (a comparison) can reuse it on subsequent calls
    instead of re-resolving (and re-querying device_service) every time.
    program is resolved too when needed, but only internally (folded into
    `note`, not returned separately) -- unlike hostname, nothing in ask()
    currently needs to reuse a resolved program across repeated calls."""
    count = await asyncio.to_thread(log_search_service.count_events, ch_client, hostname=hostname, program=program, **kwargs)
    if count:
        return count, hostname, None
    notes = []
    effective_hostname = hostname
    if hostname:
        resolved, note = await _resolve_hostname_fuzzy(ch_client, hostname)
        if note:
            notes.append(note)
        if resolved:
            effective_hostname = resolved
            count = await asyncio.to_thread(log_search_service.count_events, ch_client, hostname=effective_hostname, program=program, **kwargs)
    if not count and program:
        resolved, note = await _resolve_program_fuzzy(ch_client, program)
        if note:
            notes.append(note)
        if resolved:
            count = await asyncio.to_thread(log_search_service.count_events, ch_client, hostname=effective_hostname, program=resolved, **kwargs)
    return count, effective_hostname, (" ".join(notes) or None)


async def _search_logs_resolving_hostname(ch_client: Client, *, hostname: str | None, program: str | None = None, **kwargs):
    """log_search_service.search_logs with the _resolve_hostname_fuzzy AND
    _resolve_program_fuzzy fallbacks applied -- see their docstrings.
    Returns (LogSearchResponse, note)."""
    result = await asyncio.to_thread(log_search_service.search_logs, ch_client, hostname=hostname, program=program, **kwargs)
    if result.items:
        return result, None
    notes = []
    effective_hostname = hostname
    if hostname:
        resolved, note = await _resolve_hostname_fuzzy(ch_client, hostname)
        if note:
            notes.append(note)
        if resolved:
            effective_hostname = resolved
            result = await asyncio.to_thread(log_search_service.search_logs, ch_client, hostname=effective_hostname, program=program, **kwargs)
    if not result.items and program:
        resolved, note = await _resolve_program_fuzzy(ch_client, program)
        if note:
            notes.append(note)
        if resolved:
            result = await asyncio.to_thread(log_search_service.search_logs, ch_client, hostname=effective_hostname, program=resolved, **kwargs)
    return result, (" ".join(notes) or None)


async def _aggregate_events_resolving_hostname(
    ch_client: Client, *, hostname: str | None, program: str | None = None, **kwargs,
) -> tuple[list[dict], str | None]:
    """log_search_service.aggregate_events with the _resolve_hostname_fuzzy
    AND _resolve_program_fuzzy fallbacks applied -- see their docstrings.
    Returns (rows, note)."""
    rows = await asyncio.to_thread(log_search_service.aggregate_events, ch_client, hostname=hostname, program=program, **kwargs)
    if rows:
        return rows, None
    notes = []
    effective_hostname = hostname
    if hostname:
        resolved, note = await _resolve_hostname_fuzzy(ch_client, hostname)
        if note:
            notes.append(note)
        if resolved:
            effective_hostname = resolved
            rows = await asyncio.to_thread(log_search_service.aggregate_events, ch_client, hostname=effective_hostname, program=program, **kwargs)
    if not rows and program:
        resolved, note = await _resolve_program_fuzzy(ch_client, program)
        if note:
            notes.append(note)
        if resolved:
            rows = await asyncio.to_thread(log_search_service.aggregate_events, ch_client, hostname=effective_hostname, program=resolved, **kwargs)
    return rows, (" ".join(notes) or None)


async def _execute_tool(
    name: str, arguments: dict, os_client: OpenSearch, ch_client: Client, db: AsyncSession,
) -> tuple[dict, list[LogHit]]:
    """Returns (JSON-able result for the model, LogHits to surface as this
    response's cited sources -- only semantic_search produces any)."""
    arguments = _sanitize_equality_filters(arguments)
    if name == "list_devices":
        hostname_filter = arguments.get("hostname")
        if not _is_real_filter_value(hostname_filter):
            hostname_filter = None
        start = _parse_tool_datetime(arguments.get("start"))
        if hostname_filter and not start:
            # A name lookup/disambiguation, not a "busiest in a recent
            # window" ranking -- widen the search so a device with no
            # traffic in list_devices' own default 24h window still turns
            # up by name, same reasoning as _resolve_hostname_fuzzy's own
            # 365-day lookback.
            start = datetime.now(timezone.utc) - timedelta(days=365)
        result = await asyncio.to_thread(
            device_service.list_devices,
            ch_client,
            hostname=hostname_filter,
            start=start,
            end=_parse_tool_datetime(arguments.get("end")),
            limit=min(_parse_tool_int(arguments.get("limit"), 10), 50),
        )
        list_result = {
            "devices_sorted_busiest_first": [
                {"ip": d.ip, "hostname": d.hostname, "vendor": d.vendor, "event_count": d.event_count,
                 "resolution_method": d.resolution_method, "last_seen": d.last_seen.isoformat()}
                for d in result.items
            ],
        }
        if hostname_filter:
            # Confirmed as a real bug, not hypothetical: asked "which devices
            # have anjar in the name" right after an earlier turn's ambiguity
            # note had listed BOTH anjar-matching AND unrelated MKT-matching
            # devices (from a previous two-word "anjar MKT" search), the
            # model's final answer merged this turn's clean, correct 3-device
            # result with those unrelated MKT devices from the EARLIER note --
            # fabricating 5 devices that were never part of THIS call's
            # result. Nothing told it this result was complete and
            # exhaustive on its own; it's easy for a small model to treat an
            # explicit list shown earlier in the same conversation as still
            # relevant. Spelled out explicitly to close that gap.
            list_result["note"] = (
                f"These are the ONLY devices matching hostname containing '{hostname_filter}' -- "
                "do not add any other device mentioned earlier in this conversation, even if it also "
                "seemed related."
            )
        return list_result, []

    if name == "anomaly_summary":
        limit = min(_parse_tool_int(arguments.get("limit"), 10), 50)
        reason_filter = arguments.get("reason")
        resolved_reason, reason_note = (
            _resolve_anomaly_reason(reason_filter) if _is_real_filter_value(reason_filter) else (None, None)
        )
        if reason_filter and not resolved_reason:
            # Couldn't confidently map the given phrase to one real category
            # (no match, or ambiguous between several) -- say so rather than
            # silently falling back to an unfiltered/wrong-reason result.
            return {"error": reason_note}, []
        if resolved_reason:
            is_vendor = arguments.get("group_by") == "vendor"
            breakdown = await asyncio.to_thread(
                anomaly_summary_service.list_vendor_summary if is_vendor else anomaly_summary_service.list_device_summary,
                ch_client,
            )
            filtered = [r for r in breakdown if (r.anomaly_reason if is_vendor else r["anomaly_reason"]) == resolved_reason]
            key = "vendors_ranked_by_reason_count" if is_vendor else "devices_ranked_by_reason_count"
            rows = (
                [{"vendor": r.vendor, "device_count": r.device_count, "event_count": r.event_count,
                  "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat()}
                 for r in filtered[:limit]]
                if is_vendor else
                [{"hostname": r["hostname"], "source_ip": r["source_ip"], "vendor": r["vendor"],
                  "event_count": r["event_count"], "first_seen": r["first_seen"].isoformat(),
                  "last_seen": r["last_seen"].isoformat()}
                 for r in filtered[:limit]]
            )
            return {
                key: rows,
                "reason": resolved_reason,
                "note": (
                    f"Already filtered to anomaly_reason='{resolved_reason}' and sorted by event_count "
                    "descending -- the first entry IS the answer to 'which has the most', no further "
                    "filtering or math needed. Cumulative, ALL-TIME total (not scoped to any time "
                    "window)." + (f" {reason_note}" if reason_note else "")
                ),
            }, []
        note = (
            "Cumulative, ALL-TIME totals (not scoped to any time window) -- do not describe this as "
            "'today' or 'this week'. Does not include acknowledgment status. For 'which has the MOST "
            "anomalies', use ONLY the *_ranked_by_total_anomalies list -- it's already sorted, so the "
            "first entry is the answer. The *_breakdown_by_reason list is PER REASON (one entity can "
            "appear in it several times, once per reason) -- NEVER sum or compare its event_count "
            "values to answer a 'which has the most' question, that double-counts an entity with "
            "multiple reasons; it's only for 'what reasons does X have' style questions."
        )
        if arguments.get("group_by") == "vendor":
            # Sequential, not asyncio.gather -- confirmed live:
            # clickhouse_connect's Client raises ProgrammingError ("Attempt
            # to execute concurrent queries within the same session") when
            # two queries run concurrently on the SAME client instance, even
            # each wrapped in its own to_thread. Unlike
            # list_device_summary_with_acks' concurrent gather elsewhere in
            # this file, which is safe because it pairs a ClickHouse query
            # with a SEPARATE Postgres connection, both queries here share
            # this one ch_client.
            totals = await asyncio.to_thread(anomaly_summary_service.list_vendor_total_anomalies, ch_client)
            breakdown = await asyncio.to_thread(anomaly_summary_service.list_vendor_summary, ch_client)
            return {
                "vendors_ranked_by_total_anomalies": [
                    {"vendor": r["vendor"], "device_count": r["device_count"],
                     "anomaly_event_count": r["anomaly_event_count"],
                     "first_seen": r["first_seen"].isoformat(), "last_seen": r["last_seen"].isoformat()}
                    for r in totals[:limit]
                ],
                "vendor_breakdown_by_reason": [
                    {"vendor": r.vendor, "anomaly_reason": r.anomaly_reason, "device_count": r.device_count,
                     "event_count": r.event_count, "first_seen": r.first_seen.isoformat(),
                     "last_seen": r.last_seen.isoformat()}
                    for r in breakdown[:limit]
                ],
                "note": note,
            }, []
        # Sequential for the same reason as the vendor branch above.
        totals = await asyncio.to_thread(anomaly_summary_service.list_device_total_anomalies, ch_client)
        breakdown = await asyncio.to_thread(anomaly_summary_service.list_device_summary, ch_client)
        return {
            "devices_ranked_by_total_anomalies": [
                {"hostname": r["hostname"], "source_ip": r["source_ip"], "vendor": r["vendor"],
                 "anomaly_event_count": r["anomaly_event_count"],
                 "first_seen": r["first_seen"].isoformat(), "last_seen": r["last_seen"].isoformat()}
                for r in totals[:limit]
            ],
            "device_breakdown_by_reason": [
                {"hostname": r["hostname"], "source_ip": r["source_ip"], "vendor": r["vendor"],
                 "anomaly_reason": r["anomaly_reason"], "event_count": r["event_count"],
                 "first_seen": r["first_seen"].isoformat(), "last_seen": r["last_seen"].isoformat()}
                for r in breakdown[:limit]
            ],
            "note": note,
        }, []

    if name == "alert_rules":
        name_filter = arguments.get("name")
        rules = await alert_service.list_rules(db)
        if _is_real_filter_value(name_filter):
            rules = [r for r in rules if name_filter.lower() in r.name.lower()]
        return {
            "alert_rules": [
                {
                    "name": r.name, "enabled": r.enabled, "hostname": r.hostname, "source_ip": r.source_ip,
                    "program": r.program, "severity": r.severity, "predicted_category": r.predicted_category,
                    "only_anomalies": r.only_anomalies, "window_minutes": r.window_minutes,
                    "threshold": r.threshold, "cooldown_minutes": r.cooldown_minutes,
                    "last_triggered_at": r.last_triggered_at.isoformat() if r.last_triggered_at else None,
                }
                for r in rules
            ],
        }, []

    if name == "silent_devices":
        hostname_filter = arguments.get("hostname")
        devices = await device_silence_service.list_silent_devices(db)
        if _is_real_filter_value(hostname_filter):
            devices = [d for d in devices if d.hostname and hostname_filter.lower() in d.hostname.lower()]
        return {
            "currently_silent_devices": [
                {
                    "hostname": d.hostname, "source_ip": d.source_ip,
                    "expected_interval_minutes": d.expected_interval_minutes,
                    "last_seen_at": d.last_seen_at.isoformat(),
                    "silence_started_at": d.silence_started_at.isoformat() if d.silence_started_at else None,
                }
                for d in devices
            ],
            "note": "Every row here is currently, presently silent -- absence from this list means the device IS reporting normally.",
        }, []

    if name == "audit_log":
        contains_filter = arguments.get("contains")
        entries = await audit_service.list_audit_log(
            db,
            since=_parse_tool_datetime(arguments.get("start")),
            limit=min(_parse_tool_int(arguments.get("limit"), 20), 100),
        )
        if _is_real_filter_value(contains_filter):
            needle = contains_filter.lower()
            entries = [e for e in entries if needle in e.action.lower() or needle in e.target.lower()]
        return {
            "audit_log_most_recent_first": [
                {
                    "actor": e.actor_username or "system", "action": e.action, "target": e.target,
                    "details": e.details, "created_at": e.created_at.isoformat(),
                }
                for e in entries
            ],
        }, []

    if name == "relay_source_ips":
        ip_filter = arguments.get("ip")
        rows = await relay_service.list_relay_source_ips(db)
        if _is_real_filter_value(ip_filter):
            rows = [r for r in rows if ip_filter.lower() in r.ip.lower()]
        return {
            "relay_source_ips": [{"ip": r.ip, "note": r.note} for r in rows],
        }, []

    if name == "count_events":
        # _count_events_resolving_hostname always returns a 3-tuple
        # (count, effective_hostname, note) -- confirmed live as a severe,
        # pre-existing bug: unpacking into only 2 names here raised
        # "ValueError: too many values to unpack" on EVERY count_events
        # tool call, unconditionally, regardless of arguments. The
        # resolved hostname itself isn't needed again after this one-off
        # call (unlike the period-comparison call sites elsewhere in this
        # file, which reuse it across repeated calls for the same
        # hostname), so it's discarded here, same as before this fix in
        # effect -- only the unpacking arity was wrong.
        count, _resolved_hostname, hostname_note = await _count_events_resolving_hostname(
            ch_client,
            hostname=arguments.get("hostname"),
            source_ip=arguments.get("source_ip"),
            vendor=arguments.get("vendor"),
            severity=arguments.get("severity"),
            program=arguments.get("program"),
            keyword=arguments.get("keyword"),
            only_anomalies=_parse_tool_bool(arguments.get("only_anomalies")),
            start=_parse_tool_datetime(arguments.get("start")),
            end=_parse_tool_datetime(arguments.get("end")),
        )
        result = {"count": count}
        if hostname_note:
            result["note"] = hostname_note
        return result, []

    if name == "search_logs":
        result, hostname_note = await _search_logs_resolving_hostname(
            ch_client,
            hostname=arguments.get("hostname"),
            source_ip=arguments.get("source_ip"),
            vendor=arguments.get("vendor"),
            severity=arguments.get("severity"),
            program=arguments.get("program"),
            keyword=arguments.get("keyword"),
            only_anomalies=_parse_tool_bool(arguments.get("only_anomalies")),
            start=_parse_tool_datetime(arguments.get("start")),
            end=_parse_tool_datetime(arguments.get("end")),
            limit=min(_parse_tool_int(arguments.get("limit"), 20), 50),
        )
        # Surfaced in the UI's "Cited log lines" table, same as
        # semantic_search's hits -- previously search_logs's rows were only
        # ever shown to the MODEL (as JSON text) and never to the user, so
        # "Cited log lines: No related log lines were found" displayed even
        # when the model's answer was built from real rows it had actually
        # seen, with nothing to actually verify it against. score=1.0 is a
        # sentinel (an exact filter match, not a fuzzy semantic-similarity
        # value), not a value comparable to semantic_search's real scores.
        hits = [
            LogHit(
                event_time=i.event_time, source_ip=i.source_ip, hostname=i.hostname, vendor=i.vendor,
                severity=i.severity, program=i.program, predicted_category=i.predicted_category,
                message=i.message, is_anomaly=i.is_anomaly, anomaly_reasons=i.anomaly_reasons, score=1.0,
            )
            for i in result.items
        ]
        search_result = {
            "has_more_beyond_this_page": result.has_more,
            "matching_rows": [
                {"event_time": i.event_time.isoformat(), "hostname": i.hostname, "source_ip": i.source_ip,
                 "severity": i.severity, "program": i.program,
                 "message": _truncate(i.message, _MAX_MESSAGE_CHARS_IN_PROMPT),
                 "is_anomaly": i.is_anomaly, "anomaly_reasons": i.anomaly_reasons}
                for i in result.items
            ],
        }
        if hostname_note:
            search_result["note"] = hostname_note
        return search_result, hits

    if name == "aggregate_events":
        group_by = arguments.get("group_by")
        if isinstance(group_by, str):
            # Confirmed-pattern-consistent defensive handling (same class of
            # issue _parse_tool_bool/_parse_tool_int guard elsewhere): a
            # model sending a bare string instead of a one-item list for a
            # schema-typed array argument.
            group_by = [group_by]
        group_by = [g for g in (group_by or []) if isinstance(g, str)]
        if not group_by:
            return {"error": "group_by is required -- specify 1-3 columns to break the count down by."}, []
        invalid = [g for g in group_by if g not in log_search_service.GROUP_BY_COLUMNS]
        if invalid:
            return {
                "error": (
                    f"Invalid group_by column(s): {', '.join(invalid)}. Valid columns: "
                    f"{', '.join(log_search_service.GROUP_BY_COLUMNS)}."
                ),
            }, []
        reason_filter = arguments.get("reason") or arguments.get("anomaly_reason")
        resolved_reason = None
        if _is_real_filter_value(reason_filter):
            resolved_reason, reason_note = _resolve_anomaly_reason(reason_filter)
            if not resolved_reason:
                return {"error": reason_note}, []
        rows, hostname_note = await _aggregate_events_resolving_hostname(
            ch_client,
            group_by=group_by,
            hostname=arguments.get("hostname"),
            source_ip=arguments.get("source_ip"),
            vendor=arguments.get("vendor"),
            severity=arguments.get("severity"),
            program=arguments.get("program"),
            predicted_category=arguments.get("predicted_category"),
            anomaly_reason=resolved_reason,
            keyword=arguments.get("keyword"),
            only_anomalies=_parse_tool_bool(arguments.get("only_anomalies")),
            start=_parse_tool_datetime(arguments.get("start")),
            end=_parse_tool_datetime(arguments.get("end")),
            limit=min(_parse_tool_int(arguments.get("limit"), 20), log_search_service.AGGREGATE_MAX_LIMIT),
        )
        agg_result = {
            "breakdown_sorted_busiest_first": rows,
            "grouped_by": group_by,
            "note": "Already sorted by event_count descending -- the first entry IS the answer to 'which <group> has the most'.",
        }
        if hostname_note:
            agg_result["note"] += f" {hostname_note}"
        return agg_result, []

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


async def ask(os_client: OpenSearch, ch_client, query: LogAssistantQuery, db: AsyncSession) -> AskResponse:
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

    # See _unresolved_ranking_concept's docstring for what this covers: ANY
    # "which device/vendor has the most <concept>" question not already
    # handled by one of the 8 fixed anomaly_reason categories -- general by
    # construction, not a bypass tailored to one specific phrase. Only
    # commits to this path's answer once _resolve_concept_ranking has
    # actually verified a real, grounded keyword against real retrieved
    # messages; otherwise (None) this falls through to the normal
    # tool-calling loop below exactly as if it had never run.
    concept_question = _unresolved_ranking_concept(query.question, query.history)
    if concept_question:
        is_vendor = _wants_vendor_grouping(query.question)
        resolved = await _resolve_concept_ranking(os_client, ch_client, concept_question, is_vendor, now)
        if resolved:
            answer = _concept_ranking_plain_answer(resolved["rows"], is_vendor, resolved["keyword"], resolved["programs"])
            log.info(
                "Log Assistant FORCE-RESOLVED a concept ranking via semantic-search discovery + a "
                "grounded keyword, no full tool-calling round-trip: concept=%r keyword=%r programs=%r -> %s",
                concept_question, resolved["keyword"], resolved["programs"], _truncate(json.dumps(resolved["rows"]), 1000),
            )
            return AskResponse(answer=answer, sources=[], model=settings.ollama_chat_model)

    # Same mechanism, generalized to a plain "how many <concept> happened"
    # question -- see _unresolved_count_concept's docstring. Scoped to at
    # most ONE named time period (or none, meaning all-time): a
    # two-period COMPARISON of a novel concept would need two separate
    # count_events calls, which the existing comparison-period machinery
    # further down already handles once a tool/keyword is known -- adding
    # that here too is unnecessary complexity for a case the normal loop,
    # now instructed to use semantic_search first (see _AGENT_INSTRUCTIONS),
    # can already attempt reasonably.
    count_concept_question = _unresolved_count_concept(query.question, query.history)
    if count_concept_question and not _detect_comparison_periods(query.question, now):
        single_period_for_concept = _detect_single_period(query.question, now)
        period_label, concept_start, concept_end = (
            single_period_for_concept if single_period_for_concept else (None, _ALL_TIME_START, now)
        )
        resolved = await _resolve_concept_count(os_client, ch_client, count_concept_question, concept_start, concept_end)
        if resolved:
            answer = _concept_count_plain_answer(resolved["count"], resolved["keyword"], resolved["programs"], period_label)
            log.info(
                "Log Assistant FORCE-RESOLVED a concept count via semantic-search discovery + a "
                "grounded keyword, no full tool-calling round-trip: concept=%r keyword=%r programs=%r "
                "period=%r -> %s",
                count_concept_question, resolved["keyword"], resolved["programs"], period_label, resolved["count"],
            )
            return AskResponse(answer=answer, sources=[], model=settings.ollama_chat_model)

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
    # regardless of question phrasing). Requires a POSITIVE signal that the
    # question actually wants a count -- explicit counting language, a
    # comparison, or being a bare follow-up with no topical content of its
    # own -- rather than just the absence of a "wants rows" phrase; see
    # _is_bare_followup's docstring for why a negative-only exclusion list
    # already proved insufficient once.
    #
    # A third instance of that exact lesson, confirmed live on net-flow:
    # "top noisiest device today" is 4 words, so _is_bare_followup's
    # word-count heuristic calls it bare -- but it has real, standalone
    # ranking intent of its own ('top'/'noisiest'), not a topic-free
    # continuation like "and yesterday?". enforce_count_tool fired anyway,
    # and the force-resolve backstop below answered with "the hostname
    # ...today is 0" -- a device carried over from unrelated earlier
    # conversation history, not even a ranking result, for a question that
    # should have gone to list_devices/anomaly_summary entirely. Excluded
    # unconditionally, the same way _wants_log_rows already is: a ranking
    # question is never this gate's job, regardless of which positive
    # signal (count language, comparison, or bare word count) would
    # otherwise have triggered it -- see _wants_ranking and the
    # _detect_anomaly_reason-based forcing mechanism below, which is the
    # actual right place for ranking intent to be handled.
    enforce_count_tool = bool(
        (comparison_periods or single_period)
        and not _wants_log_rows(query.question)
        and not _wants_ranking(query.question)
        and (needs_multiple or _wants_count(query.question) or _is_bare_followup(query.question))
    )
    # Same idea as enforce_count_tool, for "which device/vendor has the most
    # <anomaly type>" questions -- see _detect_anomaly_reason's docstring
    # for the confirmed net-flow incident this closes.
    forced_anomaly_reason = _detect_anomaly_reason(query.question, query.history)
    anomaly_reason_resolved = False
    periods_resolved = False
    data_tool_calls = 0
    # Separate from data_tool_calls (which counts every ATTEMPT, including
    # one that comes back {"error": ...} -- an invalid anomaly_summary
    # reason or aggregate_events group_by, say): this counts only calls
    # that actually returned usable data. Confirmed as a real distinction,
    # not a redundant one: the zero_tool_nudged check below originally used
    # data_tool_calls == 0 and never fired for the exact case it was built
    # for, because the model's FIRST attempt (anomaly_summary with an
    # invalid reason) had already incremented data_tool_calls to 1 despite
    # producing zero real data.
    successful_tool_calls = 0
    grounded_counts: set[int] = set()
    known_identifiers: set[str] = _identifiers_from_history(query.history)
    # Separate from known_identifiers (which deliberately mixes in history so
    # a bare follow-up can inherit a device from an earlier turn) -- this
    # tracks ONLY identifiers a list_devices call actually returned THIS
    # turn, so a device-listing answer can be checked against exactly what
    # was just fetched, not anything merely mentioned earlier in the thread.
    # See the grounding check below for the confirmed incident this guards:
    # "which devices have anjar in the name" correctly called
    # list_devices(hostname='anjar') and got back 4 real matches, but the
    # model's final answer added 5 more devices straight out of an EARLIER,
    # differently-scoped turn's candidate list.
    list_devices_results_this_turn: set[str] = set()
    # Confirmed live, immediately after deploying _annotate_resolved_reason's
    # caveat (12ac03a): the tool result's own "note" field DID contain the
    # Ethernet-only disclosure, but the model's final answer dropped it
    # entirely and stated the number as if it were a confirmed wireless
    # count. The exact same "prompting alone isn't reliable" lesson this
    # whole file is built around -- a note handed to the model is not the
    # same as the model actually relaying it. Tracked here so the final
    # answer gets the caveat appended deterministically if the model didn't
    # already include it, the same pattern as every other grounding check
    # in this function.
    interface_flapping_caveat_needed = False
    # Separate from anomaly_reason_resolved (which means "we know the right
    # reason/tool", set the moment that's decided -- possibly in the SAME
    # iteration that then goes on to actually execute it) -- this tracks
    # whether anomaly_summary has actually RUN this turn, so the refusal
    # guard below can tell "the call about to happen is the first real one"
    # from "a repeat". Confirmed as a real, reproduced cost on net-flow, not
    # just a theoretical one: after a tool-less force-resolve already
    # returned the real, grounded ranking, the model called anomaly_summary
    # a THIRD time anyway (ignoring the "do not call any tool again"
    # instruction) -- nothing stopped it from executing again, costing
    # another full round-trip to a slow CPU-only LLM on top of the two
    # already spent, and the request timed out in the UI before ever
    # reaching a final answer. count_events already refuses a repeat call
    # once periods_resolved -- this closes the identical gap for
    # anomaly_summary.
    anomaly_summary_executed_this_turn = False
    nudged = False
    # Confirmed live as a distinct, general failure mode -- not specific to
    # any one question topic: given a tool-calling nudge, the model
    # sometimes NARRATES an intention ("I will call the list_devices
    # tool...") in plain text instead of ever emitting a real tool_calls
    # field, then stops without completing either a real call or a real
    # answer. Unlike the fabrication case _TOOL_NAMES/claimed_identifiers
    # guards against (a confident, specific, invented claim), this one
    # often makes no identifiable claim at all, so that check doesn't catch
    # it either -- it's simply an incomplete, unhelpful response. Gives the
    # model ONE chance to actually execute a real tool call before
    # accepting whatever it said as final, same bounded-retry pattern as
    # `nudged` above (not an unconditional nudge on every zero-tool
    # response -- that would add a costly extra round-trip on this
    # CPU-only model to perfectly fine conversational answers that
    # correctly needed no tool at all, e.g. a plain refusal or a greeting).
    zero_tool_nudged = False
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
            # Same tool-less-fabrication risk as the count/period case below,
            # reproduced live for this question shape specifically: asked
            # "...with wireless disconnections" right after an identically-
            # shaped prior turn, the model answered with NO tool call at all,
            # just restating the previous turn's device/number from the
            # conversation history text. Force-resolve the real answer
            # ourselves rather than trust a retry to happen.
            if forced_anomaly_reason and not anomaly_reason_resolved:
                anomaly_reason_resolved = True
                is_vendor = _wants_vendor_grouping(query.question)
                result, _ = await _execute_tool(
                    "anomaly_summary",
                    {"reason": forced_anomaly_reason, "group_by": "vendor" if is_vendor else "device"},
                    os_client, ch_client, db,
                )
                data_tool_calls += 1
                successful_tool_calls += 1
                anomaly_summary_executed_this_turn = True
                grounded_counts |= _grounded_counts_from_result("anomaly_summary", result)
                known_identifiers |= _identifiers_from_result("anomaly_summary", result)
                log.info(
                    "Log Assistant FORCE-RESOLVED anomaly reason ranking after a tool-less answer "
                    "(answering directly, skipping a further model round-trip given this question "
                    "shape's confirmed latency/timeout cost): reason=%s -> %s",
                    forced_anomaly_reason, _truncate(json.dumps(result), 1000),
                )
                answer = _anomaly_summary_plain_answer(result)
                if result.get("reason") == "interface_flapping":
                    answer += f"\n\n({_INTERFACE_FLAPPING_CAVEAT})"
                if single_period or comparison_periods:
                    answer += f"\n\n({_ANOMALY_SUMMARY_ALL_TIME_CAVEAT})"
                return AskResponse(answer=answer, sources=sources, model=settings.ollama_chat_model)
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
                filter_args = _sanitize_equality_filters(
                    _filter_args_for_period_override(query, attempted_filter_args)
                )
                # The known_identifiers sweep is a last resort, deliberately NOT
                # consulted when source_ip/vendor already scope this query: the
                # same thread-wide, unordered-set ambiguity Test 7 fixed for a
                # bare follow-up's PRIMARY identifier choice still applies here
                # one layer down (next(iter(...)) can surface ANY identifier
                # ever mentioned in the thread, including an unrelated one from
                # a much earlier turn) -- confirmed live in Test 12 ("and this
                # week?" with an explicit UI source_ip filter already active):
                # adding an unrelated hostname on top of an already-sufficient
                # source_ip would have formed an impossible AND, forcing a false
                # zero on what should have been a real, non-zero count.
                hostname_hint = filter_args.get("hostname")
                if not hostname_hint and not filter_args.get("source_ip") and not filter_args.get("vendor"):
                    hostname_hint = next(iter(known_identifiers), None)
                periods_to_resolve = comparison_periods or [single_period]
                labeled_counts = []
                hostname_resolution_note = None
                for label, period_start, period_end in periods_to_resolve:
                    count, hostname_hint, note = await _count_events_resolving_hostname(
                        ch_client,
                        hostname=hostname_hint,
                        source_ip=filter_args.get("source_ip"),
                        vendor=filter_args.get("vendor"),
                        severity=filter_args.get("severity"),
                        program=filter_args.get("program"),
                        keyword=filter_args.get("keyword"),
                        only_anomalies=_parse_tool_bool(filter_args.get("only_anomalies")),
                        start=period_start,
                        end=period_end,
                    )
                    hostname_resolution_note = hostname_resolution_note or note
                    labeled_counts.append({"period": label, "count": count})
                    grounded_counts.add(count)
                    data_tool_calls += 1
                    successful_tool_calls += 1
                if hostname_hint:
                    known_identifiers.add(hostname_hint)
                    filter_args["hostname"] = hostname_hint
                messages.append(message)
                messages.append({
                    "role": "user",
                    "content": (
                        "You answered without calling count_events for this question. Here are the "
                        f"exact, already-verified counts instead: {json.dumps(labeled_counts)}"
                        + (
                            f" -- scoped to {_describe_filter_scope(filter_args)}, say so explicitly, "
                            "not the whole network, and do not mention any OTHER device, IP, or filter"
                            if _describe_filter_scope(filter_args) else
                            " -- for the WHOLE NETWORK (no device/vendor filter applied), say so "
                            "explicitly, do not attribute it to any single device"
                        )
                        + (f" {hostname_resolution_note}" if hostname_resolution_note else "")
                        + ". State these exactly as given -- do not call any tool again, and do not "
                        "state a different number."
                        + (
                            f" For any increase/decrease/trend claim, use ONLY this pre-computed figure, "
                            f"stated exactly: {_describe_trend(labeled_counts, comparison_periods)}"
                            if comparison_periods and _describe_trend(labeled_counts, comparison_periods) else ""
                        )
                    ),
                })
                # Logs the actual filter_args/hostname_hint used, same reasoning
                # as the other two overrides' logging fix -- this exact gap made
                # Test 12 unverifiable from the log alone (no way to tell whether
                # hostname_hint silently added a wrong device on top of the
                # explicit source_ip filter already in play).
                log.info(
                    "Log Assistant FORCE-RESOLVED period(s) after a tool-less answer: "
                    "filter=%s hostname_hint=%s -> %s",
                    filter_args, hostname_hint, labeled_counts,
                )
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
            if (
                successful_tool_calls == 0 and not zero_tool_nudged
                and (_wants_ranking(query.question) or _wants_count(query.question) or _wants_log_rows(query.question))
            ):
                # Gated on the question's own shape actually needing real
                # data (same ranking/count/rows markers used elsewhere in
                # this file) -- a vague or conversational question that
                # genuinely needs no tool must not pay for an extra,
                # expensive round-trip on this CPU-only model just because
                # it happened not to call one.
                zero_tool_nudged = True
                messages.append(message)
                messages.append({
                    "role": "user",
                    "content": (
                        "You haven't actually executed any tool this turn -- describing a tool call in "
                        "words is not the same as calling it, and gives an answer with no real data "
                        "behind it. This question needs real data: call the appropriate tool NOW using "
                        "the actual function-calling mechanism, not a description of it. Only give a "
                        "plain-text final answer once you've done that, or if you're certain no tool "
                        "can answer this."
                    ),
                })
                continue
            claims = _extract_count_claims(answer, known_identifiers) - _requested_limit_numbers(query.question)
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
            if data_tool_calls == 0:
                # Confirmed live as a new, distinct failure mode from every
                # other grounding check above: with no forced override in
                # play (a plain, undetected question), the model fabricated
                # an ENTIRE fake ReAct trace in its own prose -- "I will call
                # the tool `list_devices`... Here is the tool call: ...
                # The result is: <device name>" -- without ever emitting a
                # real tool_calls field. Nothing executed, data_tool_calls
                # stayed 0, and neither check above catches it: there's no
                # number for the count-claim check to flag, and
                # list_devices_results_this_turn is empty precisely because
                # nothing real ran. The device/value named is 100%
                # invented. _TOOL_NAMES excludes the tool names themselves
                # (e.g. 'list_devices') from being mistaken for a claimed
                # device -- they're exactly what a narrated fake trace like
                # this mentions. known_identifiers still includes anything
                # genuinely established in conversation HISTORY (a real
                # tool call from an earlier turn), so only a claim with
                # zero grounding anywhere, not just this turn, is flagged.
                claimed_identifiers = {
                    tok for raw_tok in _IDENTIFIER_TOKEN_RE.findall(answer)
                    for tok in (_strip_trailing_punctuation(raw_tok),)
                    if _looks_like_identifier_token(tok) and tok not in known_identifiers and tok not in _TOOL_NAMES
                }
                if claimed_identifiers:
                    answer += (
                        "\n\n(Note: no tool was actually called for this question -- the value(s) "
                        f"mentioned above ({', '.join(sorted(claimed_identifiers))}) may be fabricated "
                        "rather than drawn from real data; double-check before relying on it.)"
                    )
            if list_devices_results_this_turn:
                # Same idea, for device NAMES instead of counts. Confirmed on
                # net-flow: "which devices have anjar in the name" correctly
                # called list_devices(hostname='anjar') and got back 4 real
                # matches, with the tool result's own note explicitly saying
                # "these are the ONLY devices... do not add any other device
                # mentioned earlier in this conversation" -- the model still
                # added 5 more devices straight out of an EARLIER, differently
                # -scoped turn's candidate list anyway. The instruction alone
                # didn't survive against salient prior context, same lesson as
                # the count-claim check above. this_turn_result_tokens excludes
                # anything that's actually part of a name THIS turn's call
                # returned, so a legitimately-repeated device isn't flagged --
                # only a leftover from strictly earlier in the thread is.
                this_turn_result_tokens = {
                    tok for name in list_devices_results_this_turn
                    for tok in _IDENTIFIER_TOKEN_RE.findall(name)
                }
                stale_identifiers = _identifiers_from_history(query.history) - this_turn_result_tokens
                mentioned_stale = {ident for ident in stale_identifiers if ident.lower() in answer.lower()}
                if mentioned_stale:
                    answer += (
                        "\n\n(Note: this answer mentions something that isn't part of this turn's "
                        f"actual device search result ({', '.join(sorted(mentioned_stale))}) -- it may be "
                        "left over from earlier in this conversation; double-check before relying on it.)"
                    )
            # Confirmed live: the model's final answer dropped the Ethernet-
            # only disclosure even though the tool result it was handed
            # explicitly contained it (see interface_flapping_caveat_needed's
            # own comment) -- appended deterministically rather than trusted
            # to the model's own prose, unless it already said so itself.
            if interface_flapping_caveat_needed and "RouterOS Ethernet" not in answer:
                answer += f"\n\n({_INTERFACE_FLAPPING_CAVEAT})"
            return AskResponse(answer=answer, sources=sources, model=settings.ollama_chat_model)

        messages.append(message)
        for call in tool_calls:
            fn = call["function"]
            arguments = fn.get("arguments") or {}
            attempted_filter_args.update(
                {k: v for k, v in arguments.items() if k not in ("start", "end", "limit", "phrase") and v}
            )

            # Confirmed on net-flow: "show me warning logs ... yesterday" (an
            # explicit row-listing request, not a count -- enforce_count_tool
            # is correctly False for it) got search_logs called with
            # start==end for "yesterday", the exact zero-width-window bug
            # already fixed for count_events -- but that fix only ever
            # corrected count_events's own arguments. search_logs and
            # semantic_search take the identical start/end arguments and are
            # equally vulnerable to the same unreliable date arithmetic;
            # nothing was correcting theirs. count_events is excluded here
            # since it already gets its own, more thorough override below
            # (which also fetches/labels the result, not just the dates).
            if single_period and not comparison_periods and fn["name"] in ("search_logs", "semantic_search", "list_devices"):
                _, period_start, period_end = single_period
                fmt = "%Y-%m-%dT%H:%M:%S"
                arguments["start"] = period_start.strftime(fmt)
                arguments["end"] = period_end.strftime(fmt)

            if forced_anomaly_reason and not anomaly_reason_resolved and fn["name"] != "anomaly_summary":
                # Confirmed on net-flow: asked "which device has the most
                # <anomaly type>", the model called list_devices with a
                # hostname carried over from conversation history instead --
                # a real, executable tool call, but for the wrong question.
                # Refuse it and force a retry with the right tool, same
                # pattern as the count_events wrong-tool-redirect below.
                result = {
                    "error": (
                        f"This question asks which device/vendor has the most '{forced_anomaly_reason}' "
                        f"anomalies -- call anomaly_summary with reason='{forced_anomaly_reason}' for "
                        f"this, not {fn['name']}."
                    ),
                }
                hits = []
                log.info(
                    "Log Assistant tool call REDIRECTED (wrong tool for an anomaly-reason ranking "
                    "question): %s(%s) -> forcing anomaly_summary(reason=%s)",
                    fn["name"], arguments, forced_anomaly_reason,
                )
                messages.append({"role": "tool", "content": json.dumps(result)})
                continue

            if forced_anomaly_reason and not anomaly_reason_resolved and fn["name"] == "anomaly_summary":
                # Trust our own deterministic resolution over whatever
                # phrasing the model itself passed as `reason` -- it's
                # already been resolved once (including via the synonym
                # fallback _resolve_anomaly_reason's own word-overlap
                # matching alone wouldn't have caught), so there's no reason
                # to let the model's own, possibly-different reason argument
                # override it. group_by/limit are left as the model chose.
                arguments["reason"] = forced_anomaly_reason
                anomaly_reason_resolved = True

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
                filter_args = _sanitize_equality_filters(_filter_args_for_period_override(
                    query,
                    {k: v for k, v in arguments.items() if k not in ("start", "end")},
                ))
                labeled_counts = []
                hostname_resolution_note = None
                for label, period_start, period_end in comparison_periods:
                    count, resolved_hostname, note = await _count_events_resolving_hostname(
                        ch_client,
                        hostname=filter_args.get("hostname"),
                        source_ip=filter_args.get("source_ip"),
                        vendor=filter_args.get("vendor"),
                        severity=filter_args.get("severity"),
                        program=filter_args.get("program"),
                        keyword=filter_args.get("keyword"),
                        only_anomalies=_parse_tool_bool(filter_args.get("only_anomalies")),
                        start=period_start,
                        end=period_end,
                    )
                    filter_args["hostname"] = resolved_hostname
                    hostname_resolution_note = hostname_resolution_note or note
                    labeled_counts.append({"period": label, "count": count})
                    grounded_counts.add(count)
                    data_tool_calls += 1
                    successful_tool_calls += 1
                scope = _describe_filter_scope(filter_args)
                trend = _describe_trend(labeled_counts, comparison_periods)
                result = {
                    "note": (
                        "These are the exact, already-verified counts for every period being compared, "
                        f"scoped to {scope} -- say explicitly that they're for {scope}, not the whole "
                        "network, and do not mention any OTHER device, IP, or filter. "
                        if scope else
                        "These are the exact, already-verified counts for every period being compared, "
                        "for the WHOLE NETWORK (no device/vendor filter applied) -- say so explicitly, "
                        "do not attribute them to any single device. "
                    ) + (f"{hostname_resolution_note} " if hostname_resolution_note else "") + (
                        "State them exactly as labeled -- do not call count_events again for this "
                        "comparison, and do not swap or relabel which number belongs to which period."
                        + (f" For any increase/decrease/trend claim, use ONLY this pre-computed figure, "
                           f"stated exactly: {trend}" if trend else "")
                    ),
                    "results": labeled_counts,
                }
                hits: list[LogHit] = []
                known_identifiers |= {
                    v for v in (filter_args.get("hostname"), filter_args.get("source_ip")) if isinstance(v, str) and len(v) >= 3
                }
                # Logs the ACTUAL filter/windows used (filter_args + comparison_periods),
                # not just the model's raw, now-discarded `arguments` -- confirmed on
                # net-flow that logging only `arguments` here was actively misleading
                # during a later investigation: the real, deterministic start/end this
                # override used is invisible in that case, so a correct answer and
                # the model's own (irrelevant) date-math mistake were indistinguishable
                # from the log alone.
                log.info(
                    "Log Assistant tool call OVERRIDDEN (deterministic period comparison): "
                    "model_args=%s -> filter=%s periods=%s -> %s",
                    arguments, filter_args, comparison_periods, result,
                )
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
                filter_args = _sanitize_equality_filters(_filter_args_for_period_override(
                    query,
                    {k: v for k, v in arguments.items() if k not in ("start", "end")},
                ))
                count, resolved_hostname, hostname_note = await _count_events_resolving_hostname(
                    ch_client,
                    hostname=filter_args.get("hostname"),
                    source_ip=filter_args.get("source_ip"),
                    vendor=filter_args.get("vendor"),
                    severity=filter_args.get("severity"),
                    program=filter_args.get("program"),
                    keyword=filter_args.get("keyword"),
                    only_anomalies=_parse_tool_bool(filter_args.get("only_anomalies")),
                    start=period_start,
                    end=period_end,
                )
                filter_args["hostname"] = resolved_hostname
                grounded_counts.add(count)
                data_tool_calls += 1
                successful_tool_calls += 1
                scope = _describe_filter_scope(filter_args)
                result = {
                    "note": (
                        "This is the exact, already-verified count for the period asked about, "
                        f"scoped to {scope}. Say explicitly that it's for {scope}, not the whole "
                        "network, and do not mention any OTHER device, IP, or filter. "
                        + (f"{hostname_note} " if hostname_note else "")
                        + "State the number exactly as given."
                        if scope else
                        "This is the exact, already-verified count for the period asked about, "
                        "for the WHOLE NETWORK (no device/vendor filter applied). Say so explicitly "
                        "-- do not attribute it to any single device. State the number exactly as given."
                    ),
                    "period": label,
                    "count": count,
                }
                hits = []
                known_identifiers |= {
                    v for v in (filter_args.get("hostname"), filter_args.get("source_ip")) if isinstance(v, str) and len(v) >= 3
                }
                # See the comparison override above for why this logs the actual
                # filter_args/period_start/period_end used, not just the model's
                # raw (discarded) `arguments`.
                log.info(
                    "Log Assistant tool call OVERRIDDEN (deterministic single period): "
                    "model_args=%s -> filter=%s period=%s(%s to %s) -> %s",
                    arguments, filter_args, label, period_start, period_end, result,
                )
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
                # Re-states the scope description here too, not just where periods
                # were first resolved -- confirmed on net-flow that it doesn't
                # survive the model making further (refused) tool-call attempts
                # afterward: a comparison scoped to vendor=mikrotik still said "on
                # the network" in its FINAL answer once this refusal fired in
                # between, because the original scope instruction was by then
                # several messages back. Repeating it right before the model's
                # last chance to answer keeps it close enough to actually stick.
                resolved_scope = _describe_filter_scope(filter_args)
                result = {
                    "error": (
                        "Already answered -- use the labeled today/yesterday/this-week results already "
                        "given above"
                        + (f" (scoped to {resolved_scope}, say so explicitly)" if resolved_scope else
                           " (for the WHOLE NETWORK, say so explicitly)")
                        + ". Do not call count_events again for this question."
                    ),
                }
                hits = []
                log.info("Log Assistant tool call REFUSED (periods already resolved): %s(%s)", fn["name"], arguments)
                messages.append({"role": "tool", "content": json.dumps(result)})
                continue

            if fn["name"] == "anomaly_summary" and anomaly_summary_executed_this_turn:
                result = {
                    "error": (
                        "Already answered -- use the anomaly_summary result already given above. "
                        "Do not call anomaly_summary again for this question."
                    ),
                }
                hits = []
                log.info("Log Assistant tool call REFUSED (anomaly_summary already executed this turn): %s(%s)", fn["name"], arguments)
                messages.append({"role": "tool", "content": json.dumps(result)})
                continue

            result, hits = await _execute_tool(fn["name"], arguments, os_client, ch_client, db)
            # Temporary diagnostic: the only way to see what the model actually
            # asked for and what came back, since the old plain access-log line
            # (POST /api/log-assistant/ask 200) hides both -- a 200 here says
            # nothing about whether the tool call itself found real data.
            log.info("Log Assistant tool call: %s(%s) -> %s", fn["name"], arguments, _truncate(json.dumps(result), 1000))
            data_tool_calls += 1
            if "error" not in result:
                successful_tool_calls += 1
            if fn["name"] == "anomaly_summary":
                anomaly_summary_executed_this_turn = True
                if result.get("reason") == "interface_flapping":
                    interface_flapping_caveat_needed = True
            grounded_counts |= _grounded_counts_from_result(fn["name"], result)
            # From the result (hostnames/IPs the tool found) AND from the call's
            # own arguments -- count_events/search_logs never echo the hostname
            # filter back in their result, only in what was asked for, so the
            # result alone misses the exact case that originally motivated this
            # (a hostname filter argument, not a result field, polluting the
            # digit extraction below).
            known_identifiers |= _identifiers_from_result(fn["name"], result)
            if fn["name"] == "list_devices":
                list_devices_results_this_turn |= {
                    d.get("hostname") for d in result.get("devices_sorted_busiest_first", [])
                    if isinstance(d.get("hostname"), str)
                }
            known_identifiers |= {
                v for v in (arguments.get("hostname"), arguments.get("source_ip")) if isinstance(v, str) and len(v) >= 3
            }
            sources.extend(hits)
            messages.append({"role": "tool", "content": json.dumps(result)})
            if fn["name"] == "anomaly_summary" and forced_anomaly_reason:
                # Same reasoning as the tool-less force-resolve path above
                # (see _anomaly_summary_plain_answer's docstring): the model
                # called the right tool itself here, so the real answer is
                # already known with certainty -- asking it for one more
                # round-trip to phrase it in English is pure latency risk on
                # this CPU-only model, confirmed repeatedly to sometimes cost
                # minutes and push the request past the UI's timeout, for a
                # step that adds no information.
                answer = _anomaly_summary_plain_answer(result)
                if result.get("reason") == "interface_flapping":
                    answer += f"\n\n({_INTERFACE_FLAPPING_CAVEAT})"
                if single_period or comparison_periods:
                    answer += f"\n\n({_ANOMALY_SUMMARY_ALL_TIME_CAVEAT})"
                return AskResponse(answer=answer, sources=sources, model=settings.ollama_chat_model)

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
