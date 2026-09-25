"""
Log Assistant indexer (runs as the syslog-ml-log-assistant-indexer systemd
service): keeps an OpenSearch index of log-line embeddings up to date, so
the web backend's semantic search and "ask" (RAG) features have something
to query. See README's "Log Assistant" section for the full picture.

This is a separate process from consumer.py on purpose: embedding calls to
Ollama are comparatively slow (even a small model takes tens of
milliseconds per line on CPU, and this indexer batches many lines per
cycle), and there's no reason to let that latency sit in the classifier's
hot ingest path. Instead this tails ClickHouse itself, on its own poll
loop, from an independent checkpoint.

Checkpointed on `received_at`, not `event_time`: event_time is whatever
timestamp the device itself reported, which can arrive out of order across
devices (clock drift, relayed traffic, retries) -- received_at is set by
ClickHouse at insert time (see clickhouse/init.sql), so it only moves
forward, which is what a simple ">last checkpoint" resume needs to never
skip a row. The checkpoint is a local file (same atomic write-tmp-then-
rename idiom as consumer.py's FileTailer offset), not a ClickHouse table,
since only this one process ever reads or writes it.

Each OpenSearch document's _id is a deterministic hash of the event's own
content (see `_doc_id`), not an autoincrement -- so re-indexing the same
row after a crash-before-checkpoint-save restart overwrites the same
document instead of creating a duplicate. The one edge case this doesn't
fully cover: two distinct events from the same device with byte-identical
program/pid/template/message inside the same millisecond hash to the same
id and one is silently dropped from the index -- acceptable here since
this index only feeds search/explanation, never the anomaly pipeline or
any count that must be exact.
"""
import hashlib
import logging
import os
import time
from datetime import datetime

import clickhouse_connect
import requests
from opensearchpy import OpenSearch, helpers

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("log_assistant_indexer")

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")
OPENSEARCH_INDEX = os.environ.get("OPENSEARCH_INDEX", "syslog_ml_log_events")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
# Must match EMBEDDING_DIM in opensearch/setup_index.py -- nomic-embed-text
# outputs 768-dim vectors. Swapping models means recreating the index (a
# knn_vector field's dimension can't be changed in place).
OLLAMA_EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
# Confirmed on net-flow: Ollama loading even this small (274MB) embedding
# model for the first time can take far longer than a normal single-batch
# embed call once warm, especially on a CPU-only host (no GPU) also running
# other CPU-bound services -- 30s was not enough even before accounting for
# that cold-load cost. See README's Log Assistant section for the
# recommended pre-warm step that avoids paying this cost inside a request.
OLLAMA_TIMEOUT_SECONDS = float(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "60"))

BATCH_SIZE = int(os.environ.get("INDEXER_BATCH_SIZE", "200"))
# Deliberately short, not "batch efficiently every so often" -- the point of
# this being a separate process from consumer.py (see this module's own
# docstring) is that embedding latency never touches the hot ingest path,
# which frees this poll loop to run often without that tradeoff. A new
# event should become searchable within a few seconds, not up to half a
# minute later. Still a poll, not a true push/subscribe, since ClickHouse
# has no native change-notification mechanism this could hook into instead.
POLL_SECONDS = float(os.environ.get("INDEXER_POLL_SECONDS", "5"))
# Only consulted on a cold start (no checkpoint file yet) -- how far back to
# begin backfilling. Later restarts always resume from the saved checkpoint
# regardless of this value.
BACKFILL_DAYS = int(os.environ.get("INDEXER_BACKFILL_DAYS", "7"))
CHECKPOINT_FILE = os.environ.get(
    "LOG_ASSISTANT_CHECKPOINT_FILE", "/var/lib/syslog-ml/log_assistant_indexer.checkpoint"
)

# Opt-in, not a universal default: on capable hardware, embedding every
# event is the more valuable and originally-intended behavior. This exists
# for hosts where the real numbers don't work out otherwise -- confirmed on
# net-flow (no AVX2/FMA -- see README's Log Assistant section): once warm,
# embedding throughput measured at ~1.2 msg/sec, while that host's own
# ordinary traffic runs ~2-4.6 msg/sec. Indexing everything on such a host
# means the backlog only ever grows, never catches up. Indexing only
# is_anomaly=1 events cuts the required rate to net-flow's own measured
# ~0.33 msg/sec -- comfortably within the ~1.2 msg/sec budget -- and lines
# up with how this feature is actually used (the "Explain with AI" links
# are anomaly-focused already, not general log browsing).
INDEXER_ANOMALIES_ONLY = os.environ.get("INDEXER_ANOMALIES_ONLY", "false").lower() == "true"

# Opt-in, default off: during a large backfill (e.g. after a checkpoint
# reset), run_cycle's inner while-loop below fetches and embeds batch after
# batch back-to-back with no pause between them -- POLL_SECONDS only applies
# once it's caught up (the loop hits an empty batch). On a CPU-only host
# that's also serving interactive "ask" chat completions (see
# web/backend/app/services/log_assistant_service.py), that back-to-back
# embedding traffic competes for the same cores and can starve a chat
# request for minutes (confirmed on net-flow: see README's Log Assistant
# section). Setting this gives interactive requests a periodic opening at
# the cost of a longer backfill; leave at 0 on hardware with CPU to spare.
INDEXER_BATCH_SLEEP_SECONDS = float(os.environ.get("INDEXER_BATCH_SLEEP_SECONDS", "0"))

_EVENT_COLUMNS = [
    "event_time", "received_at", "source_ip", "hostname", "vendor", "severity", "program",
    "pid", "message", "template_id", "predicted_category", "is_anomaly", "anomaly_reasons",
]


def _load_checkpoint() -> datetime | None:
    try:
        with open(CHECKPOINT_FILE) as f:
            return datetime.fromisoformat(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def _save_checkpoint(received_at: datetime):
    os.makedirs(os.path.dirname(CHECKPOINT_FILE), exist_ok=True)
    tmp_path = CHECKPOINT_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(received_at.isoformat())
    os.replace(tmp_path, CHECKPOINT_FILE)


def _embedding_text(row: dict) -> str:
    """Short natural-language rendering of one event, for the embedding
    model to turn into a vector -- concise on purpose, since retrieval
    quality benefits more from a focused representation than from stuffing
    in every column."""
    bits = [f"[{row['severity']}] {row['program']} on {row['hostname']} ({row['vendor']})"]
    if row["predicted_category"]:
        bits.append(f"category={row['predicted_category']}")
    if row["is_anomaly"]:
        reasons = ",".join(row["anomaly_reasons"]) or "unknown"
        bits.append(f"anomaly({reasons})")
    return f"{' '.join(bits)}: {row['message']}"


def _doc_id(row: dict) -> str:
    key = "|".join([
        row["event_time"].isoformat(), row["source_ip"], row["program"],
        str(row["pid"]), row["template_id"], row["message"],
    ])
    return hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()


def _embed_batch(texts: list[str]) -> list[list[float]]:
    """Calls Ollama's batch embeddings endpoint. NOTE: verify this endpoint
    name/shape against the installed Ollama version's docs at deploy time
    -- this was written against Ollama's current documented `/api/embed`
    batch API (superseding the older single-string `/api/embeddings`), but
    this project's sandbox couldn't reach ollama.com to install and
    exercise it live (see README's Log Assistant section)."""
    response = requests.post(
        f"{OLLAMA_URL}/api/embed",
        json={"model": OLLAMA_EMBED_MODEL, "input": texts},
        timeout=OLLAMA_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()["embeddings"]


def _anomaly_clause() -> str:
    return " AND is_anomaly = 1" if INDEXER_ANOMALIES_ONLY else ""


def _fetch_batch(client, checkpoint: datetime | None) -> list[dict]:
    # +1: a lookahead row, purely to detect whether the LIMIT below cut off
    # in the middle of a group of rows sharing the exact same received_at
    # (see _trim_ambiguous_tail for why that happens and why it matters).
    fetch_limit = BATCH_SIZE + 1
    params: dict = {"batch_size": fetch_limit}
    if checkpoint is not None:
        condition = "received_at > %(checkpoint)s"
        params["checkpoint"] = checkpoint
    else:
        # Cold start, no checkpoint file yet: seed from BACKFILL_DAYS ago.
        # The first batch's own max(received_at) becomes the checkpoint, so
        # every later cycle takes the `checkpoint is not None` branch above.
        condition = f"received_at >= now() - INTERVAL {BACKFILL_DAYS} DAY"
    condition += _anomaly_clause()

    query = f"""
        SELECT {', '.join(_EVENT_COLUMNS)}
        FROM syslog_ml.events
        WHERE {condition}
        ORDER BY received_at ASC
        LIMIT %(batch_size)s
    """
    result = client.query(query, parameters=params)
    rows = [dict(zip(_EVENT_COLUMNS, row)) for row in result.result_rows]
    return _trim_ambiguous_tail(client, rows)


def _fetch_exact_timestamp(client, ts: datetime) -> list[dict]:
    """Every row sharing one received_at value, no LIMIT -- used only by
    _trim_ambiguous_tail's rare fallback. A tie this wide only happens
    because `events.received_at DEFAULT now64(3)` (see clickhouse/init.sql)
    is left for ClickHouse to fill in rather than supplied per row (see
    consumer.py's INSERT_COLUMNS, which omits it) -- ClickHouse evaluates a
    non-deterministic default like now64(3) once per inserted block, not
    once per row, so every row in one of consumer.py's own batch inserts
    (up to BATCH_SIZE there, default 500) can land with the identical
    millisecond timestamp. A tie's size is bounded by that pipeline's own
    batch size, not by traffic volume in general, so an unbounded query
    here is fine."""
    query = f"""
        SELECT {', '.join(_EVENT_COLUMNS)}
        FROM syslog_ml.events
        WHERE received_at = %(ts)s{_anomaly_clause()}
        ORDER BY received_at ASC
    """
    result = client.query(query, parameters={"ts": ts})
    return [dict(zip(_EVENT_COLUMNS, row)) for row in result.result_rows]


def _trim_ambiguous_tail(client, rows: list[dict]) -> list[dict]:
    """`_fetch_batch` asks for one row more than BATCH_SIZE specifically so
    this can tell whether the LIMIT cut off in the middle of a group of
    rows sharing one received_at value (see _fetch_exact_timestamp's
    docstring for why that happens). A plain `LIMIT BATCH_SIZE` would
    silently index only part of such a group and never see the rest --
    the checkpoint would already have moved past them by the next cycle's
    `received_at > checkpoint`. Trimming the whole ambiguous group off the
    tail instead (it's picked up complete next cycle, since the checkpoint
    only advances past what this method returns) means the checkpoint only
    ever advances past a timestamp this process is sure it captured every
    row for."""
    if len(rows) <= BATCH_SIZE:
        return rows
    boundary_ts = rows[BATCH_SIZE]["received_at"]  # the lookahead row itself
    cutoff = BATCH_SIZE
    while cutoff > 0 and rows[cutoff - 1]["received_at"] == boundary_ts:
        cutoff -= 1
    if cutoff == 0:
        # The tie is wider than BATCH_SIZE+1 itself -- fetch it in full
        # rather than guessing where it ends.
        return _fetch_exact_timestamp(client, boundary_ts)
    return rows[:cutoff]


def _index_batch(os_client: OpenSearch, rows: list[dict]) -> datetime:
    texts = [_embedding_text(row) for row in rows]
    embeddings = _embed_batch(texts)

    actions = []
    for row, text, embedding in zip(rows, texts, embeddings):
        actions.append({
            "_index": OPENSEARCH_INDEX,
            "_id": _doc_id(row),
            "_source": {
                "event_time": row["event_time"].isoformat(),
                "source_ip": row["source_ip"],
                "hostname": row["hostname"],
                "vendor": row["vendor"],
                "program": row["program"],
                "severity": row["severity"],
                "predicted_category": row["predicted_category"],
                "is_anomaly": bool(row["is_anomaly"]),
                "anomaly_reasons": list(row["anomaly_reasons"]),
                "message": row["message"],
                "embedding_text": text,
                "embedding": embedding,
            },
        })
    _, errors = helpers.bulk(os_client, actions, raise_on_error=False)
    if errors:
        # A single malformed document (e.g. an embedding whose length
        # somehow doesn't match the index's configured dimension) would
        # otherwise raise BulkIndexError (helpers.bulk's default) and abort
        # the whole batch -- but the OTHER documents in it already
        # succeeded server-side by that point, and the checkpoint below
        # would never advance, so every later cycle would keep re-fetching
        # and re-embedding the same batch forever. Log and move on instead;
        # a permanently-failing row stays permanently unindexed (visible
        # here in the logs), not a permanent block on everything after it.
        log.error(
            "Log Assistant indexer: %d of %d document(s) failed to index (showing up to 3): %s",
            len(errors), len(rows), errors[:3],
        )
    return max(row["received_at"] for row in rows)


def run_cycle(ch_client, os_client: OpenSearch, checkpoint: datetime | None) -> datetime | None:
    total_indexed = 0
    while True:
        rows = _fetch_batch(ch_client, checkpoint)
        if not rows:
            break
        try:
            checkpoint = _index_batch(os_client, rows)
        except Exception:
            log.exception("Failed to embed/index a batch of %d event(s), will retry next cycle", len(rows))
            break
        _save_checkpoint(checkpoint)
        total_indexed += len(rows)
        if INDEXER_BATCH_SLEEP_SECONDS:
            time.sleep(INDEXER_BATCH_SLEEP_SECONDS)
        # No "len(rows) < BATCH_SIZE means caught up" shortcut here on
        # purpose -- _trim_ambiguous_tail can legitimately return fewer
        # than BATCH_SIZE rows while more are still waiting (the trimmed
        # tail), so that comparison would exit early and delay them until
        # next cycle. Looping until an actually-empty batch costs one
        # cheap extra query in the steady state, in exchange for not
        # needing to reason about that interaction.
    if total_indexed:
        log.info("Indexed %d event(s), checkpoint now %s", total_indexed, checkpoint)
    return checkpoint


def main():
    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
    )
    os_client = OpenSearch(hosts=[OPENSEARCH_URL])
    checkpoint = _load_checkpoint()
    log.info(
        "Log Assistant indexer starting (checkpoint=%s, backfill_days=%d if no checkpoint)",
        checkpoint, BACKFILL_DAYS,
    )
    while True:
        try:
            checkpoint = run_cycle(ch_client, os_client, checkpoint)
        except Exception:
            log.exception("Log Assistant indexer cycle failed, will retry after the poll interval")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
