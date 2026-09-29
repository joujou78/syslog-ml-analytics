"""
Shared helper for putting a datetime into a ClickHouse WHERE clause.

Every ml/ script that filters syslog_ml.events (or a table with the same
DateTime64(3) columns) on event_time/received_at used to bind the datetime
as a clickhouse_connect query parameter (`event_time >= %(start)s`,
parameters={"start": start}). Root-caused on net-flow via direct A/B
testing against production data: that binding is unreliable for a
DateTime64(3) column, and not just for exact equality (the first,
narrower case found -- see log_assistant_indexer.py's git history for
that one). `>` was ALSO measurably wrong: the same comparison written as
a bound parameter returned 731074 rows, while the identical comparison
written as a literal string in the SQL text returned 731080 -- a 6-row
gap exactly matching a tie's width at the boundary. This is what left the
Log Assistant indexer's checkpoint permanently stuck: every cycle
re-selected a batch bounded by the same wrongly-excluded rows, re-embedded
already-indexed content (harmless -- its _doc_id is content-hashed, so
re-indexing overwrites the same OpenSearch document instead of
duplicating), and saved back the exact checkpoint it started with --
looking completely healthy in its own logs (steady successful requests,
zero errors) while making zero real progress.

Every literal-string comparison in that same investigation was correct.
So instead of special-casing each affected operator, every datetime used
in a ClickHouse WHERE clause across this project is now formatted with
`ch_literal()` below and embedded directly in the SQL text, never bound
as a query parameter.

Safe to embed directly (no SQL-injection risk): every value passed
through here is a datetime this project's own code produced -- loaded
from a checkpoint file, computed as `datetime.now(timezone.utc)`, or
returned by ClickHouse itself in an earlier query -- never anything
derived from external/user-supplied input. (Contrast with e.g.
log_search_service.py's free-text filters, which stay parameterized for
exactly that reason.)
"""
from datetime import datetime, timezone


def ch_literal(dt: datetime) -> str:
    """'YYYY-MM-DD HH:MM:SS.mmm' -- millisecond precision, for a
    DateTime64(3) column (matching its own on-disk precision, see
    clickhouse/init.sql) and no timezone suffix (this project treats
    every timestamp as UTC throughout -- confirmed via `SELECT
    timezone()` on net-flow: Etc/UTC). A tz-aware `dt` is converted to
    UTC first so an accidental non-UTC value still lands in the column
    correctly rather than silently shifting.

    Do NOT use this for a plain DateTime column (second precision, no
    fractional part -- e.g. device_window_anomalies.window_start, the
    one such column in this schema): confirmed on net-flow that
    ClickHouse's DateTime type rejects a literal string with a '.mmm'
    suffix outright (`Cannot convert string '...' to type DateTime`,
    TYPE_MISMATCH) rather than truncating it -- use
    `ch_literal_seconds()` for those instead."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def ch_literal_seconds(dt: datetime) -> str:
    """'YYYY-MM-DD HH:MM:SS' -- second precision, no fractional part, for
    a plain DateTime column. See ch_literal()'s docstring for why this is
    a separate function rather than one that always includes fractional
    seconds: a plain DateTime column errors on the '.mmm' form instead of
    tolerating/truncating it."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%d %H:%M:%S")
