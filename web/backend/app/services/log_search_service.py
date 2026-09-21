from datetime import datetime, timedelta, timezone

from clickhouse_connect.driver.client import Client

from app.schemas.log_search import LogEntry, LogSearchResponse

DEFAULT_LOOKBACK = timedelta(hours=24)
MAX_LIMIT = 1000

_EQUALITY_FILTERS = ("hostname", "source_ip", "program", "severity", "predicted_category")


def search_logs(
    client: Client,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    hostname: str | None = None,
    source_ip: str | None = None,
    program: str | None = None,
    severity: str | None = None,
    predicted_category: str | None = None,
    keyword: str | None = None,
    only_anomalies: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> LogSearchResponse:
    """
    Filtered, paginated search over syslog_ml.events.

    Fetches one row past `limit` to derive has_more instead of a separate
    COUNT(*): on a table sized for high-volume retention, an unbounded
    count over a wide time range is exactly the kind of full-column scan
    the skip indexes (see clickhouse/init.sql) exist to help avoid, not
    something worth running on every search.

    `keyword` uses positionCaseInsensitive rather than the tokenbf_v1 index
    on `message` directly -- that index only reliably accelerates
    case-sensitive whole-token predicates (equals/like/hasToken), and log
    messages vary in case, so this favors correct results over guaranteed
    index use.
    """
    limit = max(1, min(limit, MAX_LIMIT))
    offset = max(0, offset)
    end = end or datetime.now(timezone.utc)
    start = start or (end - DEFAULT_LOOKBACK)

    filter_values = {
        "hostname": hostname,
        "source_ip": source_ip,
        "program": program,
        "severity": severity,
        "predicted_category": predicted_category,
    }

    conditions = ["event_time >= %(start)s", "event_time <= %(end)s"]
    params: dict = {"start": start, "end": end}

    for field in _EQUALITY_FILTERS:
        value = filter_values[field]
        if value:
            conditions.append(f"{field} = %({field})s")
            params[field] = value

    if keyword:
        conditions.append("positionCaseInsensitive(message, %(keyword)s) > 0")
        params["keyword"] = keyword

    if only_anomalies:
        conditions.append("is_anomaly = 1")

    params["fetch_limit"] = limit + 1
    params["offset"] = offset

    query = f"""
        SELECT
            event_time, source_ip, hostname, vendor, severity, program, pid,
            message, predicted_category, predicted_confidence, is_anomaly,
            anomaly_reasons, resolution_method
        FROM syslog_ml.events
        WHERE {" AND ".join(conditions)}
        ORDER BY event_time DESC
        LIMIT %(fetch_limit)s OFFSET %(offset)s
    """

    result = client.query(query, parameters=params)
    rows = result.result_rows
    has_more = len(rows) > limit
    rows = rows[:limit]

    items = [
        LogEntry(
            event_time=row[0],
            source_ip=row[1],
            hostname=row[2],
            vendor=row[3],
            severity=row[4],
            program=row[5],
            pid=row[6],
            message=row[7],
            predicted_category=row[8],
            predicted_confidence=row[9],
            is_anomaly=bool(row[10]),
            anomaly_reasons=list(row[11]),
            resolution_method=row[12],
        )
        for row in rows
    ]
    return LogSearchResponse(items=items, limit=limit, offset=offset, has_more=has_more)
