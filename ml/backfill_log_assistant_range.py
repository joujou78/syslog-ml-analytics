"""
One-off backfill for a specific [start, end) range the Log Assistant
indexer (log_assistant_indexer.py) never covered -- e.g. a gap left
behind by manually jumping LOG_ASSISTANT_CHECKPOINT_FILE forward to skip
a stuck/slow stretch (see README's "Log Assistant" section). Run this
once, separately from the live indexer service, to fill that specific
window in afterward without disturbing real-time indexing.

Deliberately its own script, not a flag on log_assistant_indexer.py: a
bounded, run-to-completion backfill and an unbounded, poll-forever live
tailer are different enough shapes (this needs a start AND an end; the
live indexer only ever has a lower bound and no natural stopping point)
that forcing them into one script and one checkpoint file risked the
live indexer's own real-time tracking getting clobbered by a backfill
run, or vice versa. Uses its own checkpoint file
(BACKFILL_CHECKPOINT_FILE) for the same crash-resume safety as the live
indexer, entirely separate from LOG_ASSISTANT_CHECKPOINT_FILE -- safe to
run this while the live indexer keeps running, since neither ever
touches the other's checkpoint or (beyond writing to the same,
content-hash-deduplicated OpenSearch index) state.

Reuses log_assistant_indexer's own fetch/trim/index building blocks
as-is (including the chunked-embedding fix in _index_batch, and the
literal-not-parameterized datetime comparisons in ch_time.py) rather
than re-implementing them -- this range can contain the exact same kind
of wide received_at tie the live indexer hit, and needs the exact same
handling for it.
"""
import argparse
import logging
import os
import time
from datetime import datetime

import clickhouse_connect
from opensearchpy import OpenSearch

import log_assistant_indexer as m

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("backfill_log_assistant_range")

BACKFILL_CHECKPOINT_FILE = os.environ.get(
    "BACKFILL_CHECKPOINT_FILE", "/var/lib/syslog-ml/log_assistant_backfill.checkpoint"
)


def _load_checkpoint(start: datetime) -> datetime:
    try:
        with open(BACKFILL_CHECKPOINT_FILE) as f:
            return datetime.fromisoformat(f.read().strip())
    except (FileNotFoundError, ValueError):
        return start


def _save_checkpoint(received_at: datetime):
    os.makedirs(os.path.dirname(BACKFILL_CHECKPOINT_FILE), exist_ok=True)
    tmp_path = BACKFILL_CHECKPOINT_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(received_at.isoformat())
    os.replace(tmp_path, BACKFILL_CHECKPOINT_FILE)


def _fetch_range_batch(client, checkpoint: datetime, end: datetime) -> list[dict]:
    """Same shape as log_assistant_indexer._fetch_batch, plus an upper
    bound so this stops at `end` instead of running forever -- both
    edges are literals, not bound parameters, for the same reason as
    everywhere else in this project (see ch_time.py)."""
    fetch_limit = m.BATCH_SIZE + 1
    condition = f"received_at > '{m.ch_literal(checkpoint)}' AND received_at <= '{m.ch_literal(end)}'"
    condition += m._anomaly_clause()
    query = f"""
        SELECT {', '.join(m._EVENT_COLUMNS)}
        FROM syslog_ml.events
        WHERE {condition}
        ORDER BY received_at ASC
        LIMIT %(batch_size)s
    """
    result = client.query(query, parameters={"batch_size": fetch_limit})
    rows = [dict(zip(m._EVENT_COLUMNS, row)) for row in result.result_rows]
    # Reused as-is: a tie can span this range exactly as it can the live
    # indexer's, and _fetch_exact_timestamp's own query has no upper
    # bound -- harmless here since every row it can return already has
    # received_at == boundary_ts, which by construction is <= end (rows
    # themselves were fetched under that bound above).
    return m._trim_ambiguous_tail(client, rows)


def run(start: datetime, end: datetime):
    ch_client = clickhouse_connect.get_client(
        host=m.CLICKHOUSE_HOST, port=m.CLICKHOUSE_PORT,
        username=m.CLICKHOUSE_USER, password=m.CLICKHOUSE_PASSWORD,
    )
    os_client = OpenSearch(hosts=[m.OPENSEARCH_URL])

    checkpoint = _load_checkpoint(start)
    log.info("Backfill starting: range (%s, %s], resuming from %s", start, end, checkpoint)

    total_indexed = 0
    while checkpoint < end:
        rows = _fetch_range_batch(ch_client, checkpoint, end)
        if not rows:
            break
        try:
            checkpoint = m._index_batch(os_client, rows)
        except Exception:
            log.exception(
                "Failed to embed/index a batch of %d event(s) at checkpoint %s -- "
                "stopping so this can be re-run safely from here", len(rows), checkpoint,
            )
            return
        _save_checkpoint(checkpoint)
        total_indexed += len(rows)
        log.info("Backfill progress: indexed %d so far, checkpoint now %s", total_indexed, checkpoint)
        if m.INDEXER_BATCH_SLEEP_SECONDS:
            time.sleep(m.INDEXER_BATCH_SLEEP_SECONDS)

    log.info("Backfill complete: %d event(s) indexed for range (%s, %s]", total_indexed, start, end)


def _parse_dt(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise argparse.ArgumentTypeError(f"'{value}' has no timezone -- pass an explicit UTC offset, e.g. ...+00:00")
    return dt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", required=True, type=_parse_dt, help="ISO datetime, exclusive lower bound, e.g. 2026-09-29T05:54:04.930000+00:00")
    parser.add_argument("--end", required=True, type=_parse_dt, help="ISO datetime, inclusive upper bound, e.g. 2026-09-29T17:49:50.790673+00:00")
    args = parser.parse_args()
    if args.end <= args.start:
        parser.error("--end must be after --start")
    run(args.start, args.end)
