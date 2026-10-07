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
from app.schemas.log_assistant import AskResponse, LogAssistantQuery, LogHit
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


def _relative_time_ranges_hint(now: datetime) -> str:
    """Precomputed start/end literals for common relative-time phrases, for
    the model to copy verbatim instead of computing itself -- confirmed on
    net-flow that giving it only the current date/time and a rule to apply
    ('subtract 7 days') isn't enough: it still got the arithmetic backwards
    (added 7 days, landing on a future date) and separately produced a
    zero-width start==end window for 'today'. Real arithmetic, done once
    here in Python, removes that failure mode entirely."""
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    week_start = now - timedelta(days=7)
    fmt = "%Y-%m-%dT%H:%M:%S"
    return (
        f"today: start={today_start.strftime(fmt)}, end={now.strftime(fmt)}\n"
        f"yesterday: start={yesterday_start.strftime(fmt)}, end={today_start.strftime(fmt)}\n"
        f"this week / past week: start={week_start.strftime(fmt)}, end={now.strftime(fmt)}"
    )


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
            limit=min(int(arguments.get("limit") or 10), 50),
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
            only_anomalies=bool(arguments.get("only_anomalies", False)),
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
            only_anomalies=bool(arguments.get("only_anomalies", False)),
            start=_parse_tool_datetime(arguments.get("start")),
            end=_parse_tool_datetime(arguments.get("end")),
            limit=min(int(arguments.get("limit") or 20), 50),
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
            limit=min(int(arguments.get("limit") or 10), 50),
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
    opening = (
        f"{_SYSTEM_PROMPT}\n\n{_AGENT_INSTRUCTIONS}\n\nThe current date/time is "
        f"{now.strftime('%Y-%m-%dT%H:%M:%S')} UTC. Precomputed start/end values for common time "
        f"periods (copy the matching pair exactly, do not recompute):\n{_relative_time_ranges_hint(now)}"
        f"\n\n---\n\nQuestion: {query.question}"
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
    data_tool_calls = 0
    grounded_counts: set[int] = set()
    known_identifiers: set[str] = set()
    nudged = False

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
