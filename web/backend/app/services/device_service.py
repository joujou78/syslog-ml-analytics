from datetime import datetime, timedelta, timezone

from clickhouse_connect.driver.client import Client

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
    device's most-recently-seen identity, so they're applied in HAVING
    (after the argMax aggregation) rather than WHERE; ip matches against
    the raw, un-aggregated source_ip column, so it's a WHERE condition.

    Paginated the same way as log search: fetches one row past `limit` to
    derive has_more instead of a separate COUNT(*), since with hundreds of
    devices active per window this GROUP BY is already real query work,
    not worth doubling for a total count nothing here needs.
    """
    limit = max(1, min(limit, MAX_LIMIT))
    offset = max(0, offset)
    end = end or datetime.now(timezone.utc)
    start = start or (end - DEFAULT_LOOKBACK)

    conditions = ["event_time >= %(start)s", "event_time <= %(end)s"]
    params: dict = {"start": start, "end": end, "fetch_limit": limit + 1, "offset": offset}

    if ip:
        conditions.append("positionCaseInsensitive(source_ip, %(ip)s) > 0")
        params["ip"] = ip

    having_conditions = []
    if hostname:
        having_conditions.append("positionCaseInsensitive(argMax(hostname, event_time), %(hostname)s) > 0")
        params["hostname"] = hostname
    if vendor:
        having_conditions.append("positionCaseInsensitive(argMax(vendor, event_time), %(vendor)s) > 0")
        params["vendor"] = vendor
    having_clause = f"HAVING {' AND '.join(having_conditions)}" if having_conditions else ""

    query = f"""
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
        {having_clause}
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
