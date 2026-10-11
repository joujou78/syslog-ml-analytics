from datetime import datetime, timedelta, timezone

from clickhouse_connect.driver.client import Client

from app.core.ch_time import ch_literal
from app.schemas.device import DeviceListResponse, DeviceRead, ResolutionSummary

DEFAULT_WINDOW = "INTERVAL 1 DAY"
DEFAULT_LOOKBACK = timedelta(hours=24)
MAX_LIMIT = 1000


def list_devices(
    client: Client,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    hostname: str | None = None,
    ip: str | None = None,
    vendor: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> DeviceListResponse:
    """
    Every device seen in the window, with its most recent known identity —
    deliberately built from `events`, not just `device_inventory` (which
    only holds the SNMP-resolved subset), so unresolved/syslog_reported
    devices show up here too and can be triaged.

    hostname/vendor are case-insensitive substring matches against each
    device's most-recently-seen identity, applied in an OUTER query against
    the already-aggregated plain columns -- NOT a HAVING clause re-invoking
    argMax() on the raw columns, which was the original approach here and
    is confirmed broken: `argMax(hostname, event_time)` inside HAVING
    collides with this SELECT's own `AS hostname` alias for that identical
    expression, and ClickHouse's analyzer resolves the bare `hostname`
    reference in HAVING back through that alias, producing a nested
    `argMax(argMax(hostname, event_time), event_time)` -- which ClickHouse
    rejects outright (Code 184, ILLEGAL_AGGREGATION: "Aggregate function
    ... is found inside another aggregate function"). This had apparently
    never actually been exercised with a real hostname/vendor value before
    (nothing in this codebase called list_devices with one) until the Log
    Assistant's fuzzy hostname resolution became the first real caller --
    it crashed the whole request with a 500 the moment it ran, and would
    crash the Devices page's own hostname search filter identically.
    Wrapping the aggregation in a subquery and filtering the OUTER query's
    plain (non-aggregate) columns sidesteps the ambiguity entirely while
    keeping identical filtering semantics (substring match against the
    most-recently-seen identity the inner argMax already picked). ip
    matches against the raw, un-aggregated source_ip column, so it stays a
    WHERE condition on the inner query.

    Paginated the same way as log search: fetches one row past `limit` to
    derive has_more instead of a separate COUNT(*), since with hundreds of
    devices active per window this GROUP BY is already real query work,
    not worth doubling for a total count nothing here needs.
    """
    limit = max(1, min(limit, MAX_LIMIT))
    offset = max(0, offset)
    end = end or datetime.now(timezone.utc)
    start = start or (end - DEFAULT_LOOKBACK)

    # start/end embedded as literals, not bound as query parameters -- see
    # app/core/ch_time.py.
    conditions = [f"event_time >= '{ch_literal(start)}'", f"event_time <= '{ch_literal(end)}'"]
    params: dict = {"fetch_limit": limit + 1, "offset": offset}

    if ip:
        conditions.append("positionCaseInsensitive(source_ip, %(ip)s) > 0")
        params["ip"] = ip

    outer_conditions = []
    if hostname:
        outer_conditions.append("positionCaseInsensitive(hostname, %(hostname)s) > 0")
        params["hostname"] = hostname
    if vendor:
        outer_conditions.append("positionCaseInsensitive(vendor, %(vendor)s) > 0")
        params["vendor"] = vendor
    outer_where = f"WHERE {' AND '.join(outer_conditions)}" if outer_conditions else ""

    query = f"""
        SELECT * FROM (
            SELECT
                source_ip,
                argMax(hostname, event_time) AS hostname,
                argMax(vendor, event_time) AS vendor,
                argMax(vendor_source, event_time) AS vendor_source,
                argMax(model, event_time) AS model,
                argMax(resolution_method, event_time) AS resolution_method,
                min(event_time) AS first_seen_in_window,
                max(event_time) AS last_seen,
                count() AS event_count
            FROM syslog_ml.events
            WHERE {" AND ".join(conditions)}
            GROUP BY source_ip
        )
        {outer_where}
        ORDER BY event_count DESC
        LIMIT %(fetch_limit)s OFFSET %(offset)s
    """
    result = client.query(query, parameters=params)
    rows = result.result_rows
    has_more = len(rows) > limit
    rows = rows[:limit]

    items = [
        DeviceRead(
            ip=row[0], hostname=row[1], vendor=row[2], vendor_source=row[3], model=row[4],
            resolution_method=row[5], first_seen_in_window=row[6], last_seen=row[7], event_count=row[8],
        )
        for row in rows
    ]
    return DeviceListResponse(items=items, limit=limit, offset=offset, has_more=has_more)


def resolution_summary(client: Client, window: str = DEFAULT_WINDOW) -> list[ResolutionSummary]:
    query = f"""
        SELECT resolution_method, count(DISTINCT source_ip) AS device_count
        FROM syslog_ml.events
        WHERE event_time >= now() - {window}
        GROUP BY resolution_method
    """
    result = client.query(query)
    return [ResolutionSummary(resolution_method=row[0], device_count=row[1]) for row in result.result_rows]
