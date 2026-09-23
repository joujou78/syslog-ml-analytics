from datetime import datetime, timedelta, timezone

from clickhouse_connect.driver.client import Client

from app.schemas.anomaly_window import AnomalyWindowListResponse, AnomalyWindowRead

DEFAULT_LOOKBACK = timedelta(hours=24)
MAX_LIMIT = 1000


def list_anomaly_windows(
    client: Client,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    source_ip: str | None = None,
    vendor: str | None = None,
    only_anomalies: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> AnomalyWindowListResponse:
    """
    Scored (device, window) rows from the template-mix detector (see
    ml/template_mix_anomaly.py), most recent first.

    `FINAL` on device_window_anomalies: it's a ReplacingMergeTree keyed on
    (source_ip, window_start) that gets rewritten as new retrain cycles
    rescore recent windows, so an unmerged duplicate is possible between
    merges. Fine to force here (unlike on `events`) -- this table is a
    tiny fraction of the size and not on the hot ingest path.

    hostname isn't stored on device_window_anomalies itself (a device's
    resolved identity can change after the fact); joined from `events`
    the same way device_service already derives "current" identity.
    """
    limit = max(1, min(limit, MAX_LIMIT))
    offset = max(0, offset)
    end = end or datetime.now(timezone.utc)
    start = start or (end - DEFAULT_LOOKBACK)

    conditions = ["w.window_start >= %(start)s", "w.window_start <= %(end)s"]
    params: dict = {"start": start, "end": end, "fetch_limit": limit + 1, "offset": offset}

    if only_anomalies:
        conditions.append("w.is_anomaly = 1")
    if source_ip:
        conditions.append("w.source_ip = %(source_ip)s")
        params["source_ip"] = source_ip
    if vendor:
        conditions.append("w.vendor = %(vendor)s")
        params["vendor"] = vendor

    query = f"""
        SELECT
            w.window_start, w.source_ip, coalesce(h.hostname, w.source_ip) AS hostname, w.vendor,
            w.model_scope, w.anomaly_score, w.is_anomaly, w.event_count
        FROM syslog_ml.device_window_anomalies AS w FINAL
        LEFT JOIN (
            SELECT source_ip, argMax(hostname, event_time) AS hostname
            FROM syslog_ml.events
            WHERE event_time >= now() - INTERVAL 7 DAY
            GROUP BY source_ip
        ) AS h ON w.source_ip = h.source_ip
        WHERE {" AND ".join(conditions)}
        ORDER BY w.window_start DESC
        LIMIT %(fetch_limit)s OFFSET %(offset)s
    """
    result = client.query(query, parameters=params)
    rows = result.result_rows
    has_more = len(rows) > limit
    rows = rows[:limit]

    items = [
        AnomalyWindowRead(
            window_start=row[0], source_ip=row[1], hostname=row[2], vendor=row[3],
            model_scope=row[4], anomaly_score=row[5], is_anomaly=bool(row[6]), event_count=row[7],
        )
        for row in rows
    ]
    return AnomalyWindowListResponse(items=items, limit=limit, offset=offset, has_more=has_more)
