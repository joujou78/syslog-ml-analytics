from datetime import datetime

from clickhouse_connect.driver.client import Client

from app.core.ch_time import ch_literal

# How close together (in minutes) two anomalous events have to be for the
# second to extend the same incident rather than start a new one. Chosen
# to match GeakMinds' own reporting cadence (24h dashboards, no finer
# granularity disclosed) loosely scaled down to something that still
# groups a genuine burst without merging unrelated anomalies hours apart
# -- not tuned against this deployment's real data yet; revisit once this
# has been tried against a live incident.
DEFAULT_GAP_MINUTES = 10

# A cluster of anomalies spanning only ONE device is not a cross-device
# "incident" in the sense this feature exists for -- that's already what
# anomaly_summary's own per-device breakdown shows. Only a cluster that
# touches at least this many distinct devices is reported here.
MIN_DEVICES_FOR_INCIDENT = 2

MAX_INCIDENTS = 10
MAX_EVENTS_PER_INCIDENT = 50


def _query(client: Client, *, start: datetime, end: datetime, vendor: str | None) -> list[dict]:
    # event_time is a DateTime64(3) column -- embedded as a literal, never
    # bound as a query parameter (see app/core/ch_time.py's ch_literal
    # docstring for the confirmed-live incident that makes this mandatory,
    # not stylistic). `vendor` stays parameterized since it's user/model-
    # supplied free text, not a value this app produced itself.
    conditions = [
        "is_anomaly = 1",
        f"event_time >= '{ch_literal(start)}'",
        f"event_time <= '{ch_literal(end)}'",
    ]
    params: dict = {}
    if vendor:
        conditions.append("vendor = %(vendor)s")
        params["vendor"] = vendor
    result = client.query(
        "SELECT event_time, hostname, source_ip, vendor, anomaly_reasons "
        f"FROM syslog_ml.events WHERE {' AND '.join(conditions)} "
        "ORDER BY event_time",
        parameters=params,
    )
    return [
        {"event_time": row[0], "hostname": row[1], "source_ip": row[2], "vendor": row[3], "anomaly_reasons": row[4]}
        for row in result.result_rows
    ]


def correlate_incidents(
    client: Client, *, start: datetime, end: datetime, vendor: str | None = None,
    gap_minutes: int = DEFAULT_GAP_MINUTES,
) -> list[dict]:
    """Groups anomalous events that happen close together in time across
    MULTIPLE devices into a single likely "incident", instead of leaving
    them as unrelated per-device rows the way anomaly_summary_service's
    own breakdowns do.

    This is a TEMPORAL CO-OCCURRENCE heuristic, not real root-cause
    analysis: the schema (see clickhouse/init.sql) has no network topology
    (no parent/uplink relationship between devices), so there is no way
    to know that one device's failure actually CAUSED another's. The
    "root cause" this returns is only the earliest event in a cluster --
    a reasonable guess (whatever happened first is more likely to be the
    trigger than a symptom), not a verified causal link. Callers/answer
    text must not overstate this as confirmed causation.

    Clusters by walking events in time order and starting a new cluster
    whenever the gap since the previous event exceeds `gap_minutes` --
    the same "session window" idea used informally in log analytics
    generally (and the closest buildable match to the "event grouping by
    correlation analysis" GeakMinds' case study claims without ever
    describing the actual method). A cluster touching only one device is
    dropped (see MIN_DEVICES_FOR_INCIDENT) -- that's not a cross-device
    incident, it's just that device's own anomaly history, already
    covered by the existing per-device views.

    Returns at most MAX_INCIDENTS clusters, busiest (by distinct device
    count, then event count) first; each cluster lists at most
    MAX_EVENTS_PER_INCIDENT individual events (root cause plus the
    earliest others) to keep the result bounded for a burst spanning
    thousands of events.
    """
    rows = _query(client, start=start, end=end, vendor=vendor)
    if not rows:
        return []

    gap = gap_minutes * 60
    clusters: list[list[dict]] = []
    current: list[dict] = [rows[0]]
    for row in rows[1:]:
        if (row["event_time"] - current[-1]["event_time"]).total_seconds() > gap:
            clusters.append(current)
            current = []
        current.append(row)
    clusters.append(current)

    incidents = []
    for cluster in clusters:
        devices = {r["hostname"] for r in cluster}
        if len(devices) < MIN_DEVICES_FOR_INCIDENT:
            continue
        reasons: set[str] = set()
        for r in cluster:
            reasons.update(r["anomaly_reasons"] or [])
        root = cluster[0]
        incidents.append({
            "incident_start": cluster[0]["event_time"],
            "incident_end": cluster[-1]["event_time"],
            "event_count": len(cluster),
            "devices_affected": sorted(devices),
            "anomaly_reasons_seen": sorted(reasons),
            "root_cause": {
                "hostname": root["hostname"], "source_ip": root["source_ip"],
                "vendor": root["vendor"], "anomaly_reasons": root["anomaly_reasons"],
                "event_time": root["event_time"],
            },
            "related_events": [
                {
                    "hostname": r["hostname"], "source_ip": r["source_ip"], "vendor": r["vendor"],
                    "anomaly_reasons": r["anomaly_reasons"], "event_time": r["event_time"],
                }
                for r in cluster[1:MAX_EVENTS_PER_INCIDENT]
            ],
        })

    incidents.sort(key=lambda i: (len(i["devices_affected"]), i["event_count"]), reverse=True)
    return incidents[:MAX_INCIDENTS]
