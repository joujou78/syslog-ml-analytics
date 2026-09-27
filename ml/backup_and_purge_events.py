"""
Periodic worker (run via a systemd timer, e.g. once daily): backs up, then
drops, each daily partition of `syslog_ml.events` older than
EVENTS_RETENTION_DAYS. clickhouse/init.sql's own comment on this table
documents unbounded retention as an explicit choice ("no TTL... disk
usage grows without bound... monitor free disk yourself") -- this script
is what turns that into a bounded, backed-up choice instead of either
unbounded growth or a bare TTL that would just silently delete old data
with nothing kept.

Partition-drop, not row-by-row DELETE: `events` is already
PARTITION BY toYYYYMMDD(event_time) (see clickhouse/init.sql), so a whole
day's data can be dropped as a single near-instant metadata operation
(ALTER TABLE ... DROP PARTITION) instead of a heavy mutation that
rewrites parts. Partition IDs from system.parts are exactly the
YYYYMMDD integer the table is partitioned by, so a partition's age is
read directly off its own ID, no extra query needed.

Safety ordering matters here: a partition is only ever dropped AFTER its
backup file is confirmed written and non-empty. A failed or partial
backup leaves that partition's data untouched in ClickHouse to retry
next run, rather than risk dropping data nobody actually backed up yet.

Export is done in bounded-size pages (EXPORT_PAGE_SIZE rows at a time,
ordered by the table's own sort key so pagination is stable and gapless)
straight into a gzip file, not by loading a whole partition into memory
at once -- a day's partition can be a large number of rows.

Only `syslog_ml.events` is covered for now, not the smaller
`device_window_anomalies`/`device_sequence_anomalies` tables (also
documented as unbounded in clickhouse/init.sql) -- `events` is the actual
disk-growth driver; the same approach can be extended to those two later
if their own growth ever becomes a real concern.
"""
import csv
import gzip
import logging
import os
from datetime import datetime, timedelta, timezone

import clickhouse_connect

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("backup_and_purge_events")

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DATABASE = os.environ.get("CLICKHOUSE_DATABASE", "syslog_ml")
CLICKHOUSE_TABLE = os.environ.get("CLICKHOUSE_EVENTS_TABLE_NAME", "events")

# How long a daily partition stays in ClickHouse before being backed up
# and dropped.
EVENTS_RETENTION_DAYS = int(os.environ.get("EVENTS_RETENTION_DAYS", "90"))
# Where backup files land. Must exist and be writable by whatever user
# runs this (see systemd/syslog-ml-backup-events.service) -- created here
# with exist_ok=True as a convenience, but the parent directory's
# ownership is still the operator's to set up correctly.
EVENTS_BACKUP_DIR = os.environ.get("EVENTS_BACKUP_DIR", "/var/backups/syslog-ml/events")
# Rows fetched per page during export -- bounds memory to one page
# regardless of how large a day's partition is.
EXPORT_PAGE_SIZE = int(os.environ.get("EVENTS_EXPORT_PAGE_SIZE", "50000"))
# Matches the table's own ORDER BY (see clickhouse/init.sql) so paginating
# with LIMIT/OFFSET is stable and gapless -- ClickHouse doesn't guarantee
# row order across pages without an explicit, index-aligned ORDER BY.
EXPORT_ORDER_BY = "event_time, hostname, severity"


def list_partitions(ch_client) -> list[str]:
    result = ch_client.query(
        "SELECT DISTINCT partition FROM system.parts "
        "WHERE database = %(db)s AND table = %(table)s AND active = 1",
        parameters={"db": CLICKHOUSE_DATABASE, "table": CLICKHOUSE_TABLE},
    )
    return [row[0] for row in result.result_rows]


def partition_date(partition: str) -> datetime:
    """Partition IDs here are exactly toYYYYMMDD(event_time)'s output --
    parsed directly rather than re-querying event_time from the table."""
    return datetime.strptime(partition, "%Y%m%d").replace(tzinfo=timezone.utc)


def backup_partition(ch_client, partition: str) -> str | None:
    """Exports every row in `partition` to a gzip CSV file, paginated so
    memory use stays bounded to one page. Returns the backup file path if
    the export produced at least one data row, else None (an empty/
    all-malformed partition isn't worth a backup file, and isn't safe to
    treat as "confirmed backed up" either -- see its caller)."""
    os.makedirs(EVENTS_BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(
        EVENTS_BACKUP_DIR, f"{CLICKHOUSE_DATABASE}.{CLICKHOUSE_TABLE}.{partition}.csv.gz"
    )
    # Written to a .part path first and only renamed to its final name once
    # fully flushed and closed -- so a crash mid-export leaves an
    # unambiguous partial file (.part) rather than something that looks
    # like a complete, valid backup at its real filename.
    tmp_path = backup_path + ".part"

    rows_written = 0
    try:
        with gzip.open(tmp_path, "wt", newline="", encoding="utf-8") as gz_file:
            writer = None
            offset = 0
            while True:
                result = ch_client.query(
                    f"""
                    SELECT * FROM {CLICKHOUSE_DATABASE}.{CLICKHOUSE_TABLE}
                    WHERE toYYYYMMDD(event_time) = %(partition)s
                    ORDER BY {EXPORT_ORDER_BY}
                    LIMIT %(limit)s OFFSET %(offset)s
                    """,
                    parameters={"partition": int(partition), "limit": EXPORT_PAGE_SIZE, "offset": offset},
                )
                if writer is None:
                    writer = csv.writer(gz_file)
                    writer.writerow(result.column_names)
                if not result.result_rows:
                    break
                writer.writerows(result.result_rows)
                rows_written += len(result.result_rows)
                if len(result.result_rows) < EXPORT_PAGE_SIZE:
                    break
                offset += EXPORT_PAGE_SIZE
    except Exception:
        log.exception("Failed exporting partition %s, leaving it in place", partition)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return None

    if rows_written == 0:
        # Nothing to back up (an empty partition shouldn't exist in
        # practice, but failing safe here rather than dropping a
        # partition on the strength of an empty file).
        os.remove(tmp_path)
        return None

    os.rename(tmp_path, backup_path)
    return backup_path


def drop_partition(ch_client, partition: str):
    ch_client.command(
        f"ALTER TABLE {CLICKHOUSE_DATABASE}.{CLICKHOUSE_TABLE} DROP PARTITION {partition}"
    )


def main():
    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD
    )
    cutoff = datetime.now(timezone.utc) - timedelta(days=EVENTS_RETENTION_DAYS)

    partitions = list_partitions(ch_client)
    due = sorted(p for p in partitions if partition_date(p) < cutoff)
    log.info("%d partition(s) older than %d days (of %d total)", len(due), EVENTS_RETENTION_DAYS, len(partitions))

    for partition in due:
        backup_path = backup_partition(ch_client, partition)
        if backup_path is None:
            log.warning("Skipping partition %s this run -- backup did not complete, will retry next run", partition)
            continue
        backup_size = os.path.getsize(backup_path)
        if backup_size <= 0:
            log.warning("Backup for partition %s is empty (%s), not dropping it", partition, backup_path)
            continue
        try:
            drop_partition(ch_client, partition)
        except Exception:
            log.exception(
                "Backed up partition %s to %s but failed to drop it -- backup is safe, will retry the drop next run",
                partition, backup_path,
            )
            continue
        log.info("Partition %s backed up to %s (%d bytes) and dropped", partition, backup_path, backup_size)


if __name__ == "__main__":
    main()
