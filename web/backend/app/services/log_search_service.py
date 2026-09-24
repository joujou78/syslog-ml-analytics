import csv
import io
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

from clickhouse_connect.driver.client import Client

from app.schemas.log_search import LogEntry, LogSearchResponse

DEFAULT_LOOKBACK = timedelta(hours=24)
MAX_LIMIT = 1000
# Export isn't paginated -- it's a one-shot "give me everything matching" --
# so it needs its own, much higher cap rather than reusing MAX_LIMIT. Still
# bounded: an unbounded export over a wide time range on a table sized for
# high-volume retention could otherwise return millions of rows in one
# response.
EXPORT_MAX_ROWS = 50_000

_EQUALITY_FILTERS = ("hostname", "source_ip", "vendor", "program", "severity", "predicted_category")

_EXPORT_COLUMNS = [
    "event_time", "source_ip", "hostname", "vendor", "severity", "program", "pid",
    "message", "predicted_category", "predicted_confidence", "is_anomaly",
    "anomaly_reasons", "resolution_method",
]


def _build_conditions(
    *,
    start: datetime | None,
    end: datetime | None,
    hostname: str | None,
    source_ip: str | None,
    vendor: str | None,
    program: str | None,
    severity: str | None,
    predicted_category: str | None,
    anomaly_reason: str | None,
    keyword: str | None,
    only_anomalies: bool,
) -> tuple[list[str], dict, datetime, datetime]:
    """
    Shared WHERE-clause construction for both search_logs (paginated) and
    export_logs (one-shot, uncapped-by-page). Keeping this in one place
    means a filter added to one can't silently drift from the other.
    """
    end = end or datetime.now(timezone.utc)
    start = start or (end - DEFAULT_LOOKBACK)

    filter_values = {
        "hostname": hostname,
        "source_ip": source_ip,
        "vendor": vendor,
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

    # anomaly_reasons is an array column -- has() checks membership, not
    # equality, so it's handled separately from the plain-equality fields
    # above (an event can carry more than one reason at once).
    if anomaly_reason:
        conditions.append("has(anomaly_reasons, %(anomaly_reason)s)")
        params["anomaly_reason"] = anomaly_reason

    if keyword:
        conditions.append("positionCaseInsensitive(message, %(keyword)s) > 0")
        params["keyword"] = keyword

    if only_anomalies:
        conditions.append("is_anomaly = 1")

    return conditions, params, start, end


def search_logs(
    client: Client,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    hostname: str | None = None,
    source_ip: str | None = None,
    vendor: str | None = None,
    program: str | None = None,
    severity: str | None = None,
    predicted_category: str | None = None,
    anomaly_reason: str | None = None,
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
    conditions, params, start, end = _build_conditions(
        start=start, end=end, hostname=hostname, source_ip=source_ip, vendor=vendor, program=program,
        severity=severity, predicted_category=predicted_category, anomaly_reason=anomaly_reason,
        keyword=keyword, only_anomalies=only_anomalies,
    )

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


def _rows_to_csv(rows: list) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_EXPORT_COLUMNS)
    for row in rows:
        (event_time, source_ip, hostname, vendor, severity, program, pid,
         message, category, confidence, is_anomaly, anomaly_reasons, resolution_method) = row
        writer.writerow([
            event_time.isoformat(), source_ip, hostname, vendor, severity, program,
            pid if pid is not None else "", message, category, f"{confidence:.4f}",
            int(bool(is_anomaly)), "|".join(anomaly_reasons), resolution_method,
        ])
    return buf.getvalue().encode("utf-8")


def _rows_to_xml(rows: list) -> bytes:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<logs>"]
    for row in rows:
        (event_time, source_ip, hostname, vendor, severity, program, pid,
         message, category, confidence, is_anomaly, anomaly_reasons, resolution_method) = row
        lines.append("  <log>")
        lines.append(f"    <event_time>{event_time.isoformat()}</event_time>")
        lines.append(f"    <source_ip>{escape(source_ip)}</source_ip>")
        lines.append(f"    <hostname>{escape(hostname)}</hostname>")
        lines.append(f"    <vendor>{escape(vendor)}</vendor>")
        lines.append(f"    <severity>{escape(severity)}</severity>")
        lines.append(f"    <program>{escape(program)}</program>")
        lines.append(f"    <pid>{pid if pid is not None else ''}</pid>")
        lines.append(f"    <message>{escape(message)}</message>")
        lines.append(f"    <predicted_category>{escape(category)}</predicted_category>")
        lines.append(f"    <predicted_confidence>{confidence:.4f}</predicted_confidence>")
        lines.append(f"    <is_anomaly>{int(bool(is_anomaly))}</is_anomaly>")
        lines.append(f"    <anomaly_reasons>{escape('|'.join(anomaly_reasons))}</anomaly_reasons>")
        lines.append(f"    <resolution_method>{escape(resolution_method)}</resolution_method>")
        lines.append("  </log>")
    lines.append("</logs>")
    return "\n".join(lines).encode("utf-8")


def export_logs(
    client: Client,
    *,
    format: str,
    start: datetime | None = None,
    end: datetime | None = None,
    hostname: str | None = None,
    source_ip: str | None = None,
    vendor: str | None = None,
    program: str | None = None,
    severity: str | None = None,
    predicted_category: str | None = None,
    anomaly_reason: str | None = None,
    keyword: str | None = None,
    only_anomalies: bool = False,
) -> tuple[bytes, str, str, bool]:
    """
    Same filters as search_logs, but a single uncapped-by-page fetch (up to
    EXPORT_MAX_ROWS) serialized whole to CSV or XML, for downloading rather
    than browsing. Returns (content, content_type, filename, truncated) --
    `truncated` is True if there were more matching rows than
    EXPORT_MAX_ROWS, so the caller can flag an incomplete export instead of
    silently returning a partial one.
    """
    conditions, params, start, end = _build_conditions(
        start=start, end=end, hostname=hostname, source_ip=source_ip, vendor=vendor, program=program,
        severity=severity, predicted_category=predicted_category, anomaly_reason=anomaly_reason,
        keyword=keyword, only_anomalies=only_anomalies,
    )
    params["fetch_limit"] = EXPORT_MAX_ROWS + 1

    query = f"""
        SELECT
            event_time, source_ip, hostname, vendor, severity, program, pid,
            message, predicted_category, predicted_confidence, is_anomaly,
            anomaly_reasons, resolution_method
        FROM syslog_ml.events
        WHERE {" AND ".join(conditions)}
        ORDER BY event_time DESC
        LIMIT %(fetch_limit)s
    """
    result = client.query(query, parameters=params)
    rows = result.result_rows
    truncated = len(rows) > EXPORT_MAX_ROWS
    rows = rows[:EXPORT_MAX_ROWS]

    timespan = f"{start:%Y%m%d%H%M%S}-{end:%Y%m%d%H%M%S}"
    if format == "xml":
        return _rows_to_xml(rows), "application/xml", f"logs_{timespan}.xml", truncated
    return _rows_to_csv(rows), "text/csv", f"logs_{timespan}.csv", truncated
