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
import logging
import pathlib

import httpx
from opensearchpy import OpenSearch

from app.core.config import settings
from app.schemas.log_assistant import AskResponse, LogAssistantQuery, LogHit

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
            json={"model": settings.ollama_embed_model, "input": question},
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


def _build_prompt(question: str, hits: list[LogHit]) -> str:
    if not hits:
        return f"Question: {question}\n\nNo related log lines were found in the index."
    lines = [
        f"- [{h.event_time.isoformat()}] {h.hostname} ({h.vendor}) {h.severity}/{h.program}: "
        f"{_truncate(h.message, _MAX_MESSAGE_CHARS_IN_PROMPT)}"
        + (f" [flagged: {', '.join(h.anomaly_reasons)}]" if h.is_anomaly else "")
        for h in hits
    ]
    return "Log excerpts (most semantically relevant first):\n" + "\n".join(lines) + f"\n\nQuestion: {question}"


async def ask(os_client: OpenSearch, query: LogAssistantQuery) -> AskResponse:
    hits = await semantic_search(os_client, query)
    prompt = _build_prompt(query.question, hits)
    # A separate system-role message is the "correct" way to do this per
    # Ollama's/OpenAI's chat API shape, but confirmed on net-flow (via a
    # raw request directly to Ollama, bypassing this service entirely) that
    # OLLAMA_CHAT_MODEL=llama3.2:3b-instruct-q4_K_M hangs indefinitely
    # whenever the request includes a system-role message at all -- with
    # ANY content, even a single trivial user question and no system
    # message otherwise, still completes in under a second. Folding the
    # system instructions into the one user message instead is a known,
    # safe workaround for exactly this class of chat-template bug, and
    # confirmed working here (~30s including prompt processing, nowhere
    # near ollama_timeout_seconds). If OLLAMA_CHAT_MODEL is ever changed,
    # re-verify this is still needed -- it may be specific to this one
    # model's packaged template, not a general Ollama issue.
    combined_prompt = f"{_SYSTEM_PROMPT}\n\n---\n\n{prompt}"
    async with httpx.AsyncClient(timeout=settings.ollama_timeout_seconds) as client:
        response = await client.post(
            f"{settings.ollama_url}/api/chat",
            json={
                "model": settings.ollama_chat_model,
                "messages": [
                    {"role": "user", "content": combined_prompt},
                ],
                "stream": False,
                # Bounds worst-case generation time -- see config.py's
                # ollama_num_predict comment for why this matters on
                # CPU-only hardware independent of any other contention.
                "options": {"num_predict": settings.ollama_num_predict},
            },
        )
        response.raise_for_status()
        answer = response.json()["message"]["content"]
    return AskResponse(answer=answer, sources=hits, model=settings.ollama_chat_model)
