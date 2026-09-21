from clickhouse_connect.driver.client import Client

from app.schemas.device import DeviceRead, ResolutionSummary

DEFAULT_WINDOW = "INTERVAL 1 DAY"


def list_devices(client: Client, window: str = DEFAULT_WINDOW, limit: int = 500) -> list[DeviceRead]:
    """
    Every device seen in the window, with its most recent known identity —
    deliberately built from `events`, not just `device_inventory` (which
    only holds the SNMP-resolved subset), so unresolved/syslog_reported
    devices show up here too and can be triaged.
    """
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
        WHERE event_time >= now() - {window}
        GROUP BY source_ip
        ORDER BY event_count DESC
        LIMIT {int(limit)}
    """
    result = client.query(query)
    return [
        DeviceRead(
            ip=row[0], hostname=row[1], vendor=row[2], vendor_source=row[3], model=row[4],
            resolution_method=row[5], first_seen_in_window=row[6], last_seen=row[7], event_count=row[8],
        )
        for row in result.result_rows
    ]


def resolution_summary(client: Client, window: str = DEFAULT_WINDOW) -> list[ResolutionSummary]:
    query = f"""
        SELECT resolution_method, count(DISTINCT source_ip) AS device_count
        FROM syslog_ml.events
        WHERE event_time >= now() - {window}
        GROUP BY resolution_method
    """
    result = client.query(query)
    return [ResolutionSummary(resolution_method=row[0], device_count=row[1]) for row in result.result_rows]
