"""
Shared helper for putting a datetime into a ClickHouse WHERE clause.

Every service in this app that filters syslog_ml.events (or a table with
the same DateTime64(3) columns) on a datetime used to bind it as a
clickhouse_connect query parameter (`event_time >= %(start)s`,
parameters={"start": start}). Root-caused on net-flow via direct A/B
testing against production data (see ml/ch_time.py, the equivalent helper
for the ml/ pipeline's own scripts, for the full incident this uncovered):
that binding is unreliable for a DateTime64(3) column -- `>` measurably
returned fewer rows than the identical comparison written as a literal
string in the SQL text (731074 vs 731080 on real data, a gap exactly
matching a tie's width at the boundary). Literal-string comparisons were
correct in every check run.

So every datetime used in a ClickHouse WHERE clause in this app is now
formatted with `ch_literal()` below and embedded directly in the SQL
text, never bound as a query parameter.

Safe to embed directly (no SQL-injection risk): every value passed
through here is a datetime this app itself produced -- a request query
parameter already validated/parsed into a `datetime` by FastAPI/Pydantic
before it ever reaches a service function, `datetime.now(timezone.utc)`,
or a value ClickHouse itself returned in an earlier query -- never a raw
string spliced in from user input. (Contrast with e.g.
log_search_service.py's free-text filters, which stay parameterized for
exactly that reason.)
"""
from datetime import datetime, timezone


def ch_literal(dt: datetime) -> str:
    """'YYYY-MM-DD HH:MM:SS.mmm' -- millisecond precision (matching
    DateTime64(3)'s own on-disk precision, see clickhouse/init.sql) and no
    timezone suffix (this project treats every timestamp as UTC
    throughout -- confirmed via `SELECT timezone()` on net-flow: Etc/UTC).
    A tz-aware `dt` is converted to UTC first so an accidental non-UTC
    value still lands in the column correctly rather than silently
    shifting."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
