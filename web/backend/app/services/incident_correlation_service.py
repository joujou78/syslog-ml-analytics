from datetime import datetime, timedelta
from statistics import median

from clickhouse_connect.driver.client import Client

from app.core.ch_time import ch_literal

# Fixed discrete time buckets, not gap-based event chaining -- confirmed
# live as a necessary redesign, not a style choice: a gap-based "chain
# events, start a new cluster when the gap since the last one exceeds a
# threshold" approach was tried first and broke completely at this
# deployment's real density. With ~579 devices producing anomalies, the
# whole fleet never goes anywhere near 10 minutes without SOME device
# somewhere firing SOME anomaly, so a global gap-based chain never found a
# gap wide enough to split on at all -- the entire day chained into one
# meaningless "incident" spanning the whole network and every anomaly
# type mixed together (interface flapping, volume spikes, rare templates,
# security content, all treated as one correlated event). Fixed buckets
# compared against their OWN historical baseline don't have this failure
# mode: a bucket either looks unusual relative to what's normal for a
# bucket of this size, or it doesn't, regardless of how continuously busy
# the fleet is in between -- "busy as always" and "busy" are not the same
# thing as "busier than normal right now."
BUCKET_MINUTES = 10

# How far back to look for "what's normal" for a bucket of this size --
# long enough to average out a single unusual day, short enough that
# genuine week-to-week drift (a busier work week vs a quiet weekend) is
# still mostly captured rather than smoothed away. Not tuned against this
# deployment's real data yet -- revisit once this has been tried live.
BASELINE_LOOKBACK_DAYS = 7

# A bucket is "elevated" -- worth treating as a possible incident -- only
# when its distinct-device count is at least this many times its own
# historical median for buckets of this size. Mirrors ml/consumer.py's
# existing VOLUME_SPIKE_MULTIPLIER convention (a per-device baseline
# multiplier for the identical "is this unusually busy" question), just
# applied here to DISTINCT DEVICE COUNT across the whole fleet/vendor
# scope instead of one device's own event rate. Lower than volume_spike's
# 5x since cross-device correlation is meant to be a broader, earlier
# signal, not confirmation of one already-severe spike -- not tuned
# against this deployment's real data yet.
ELEVATION_MULTIPLIER = 3

# Absolute floor regardless of multiplier -- confirmed necessary: a
# baseline near zero (a quiet vendor scope, or simply no historical data
# yet) would otherwise flag any bucket with just 1-2 devices as
# "unboundedly elevated" (anything divided by ~0 looks huge), which is
# exactly the kind of noise this feature exists to filter OUT, not
# surface.
MIN_ABSOLUTE_DEVICES = 5

MAX_INCIDENTS = 10
MAX_EVENTS_PER_INCIDENT = 50


def _bucket_start(dt: datetime) -> datetime:
    floor_minute = (dt.minute // BUCKET_MINUTES) * BUCKET_MINUTES
    return dt.replace(minute=floor_minute, second=0, microsecond=0)


def _vendor_condition(vendor: str | None, conditions: list[str], params: dict) -> None:
    if vendor:
        conditions.append("vendor = %(vendor)s")
        params["vendor"] = vendor


def _anomalous_events(client: Client, *, start: datetime, end: datetime, vendor: str | None) -> list[dict]:
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
    _vendor_condition(vendor, conditions, params)
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


def _baseline_devices_per_bucket(
    client: Client, *, lookback_start: datetime, lookback_end: datetime, vendor: str | None,
) -> float:
    """Historical median distinct-device count per BUCKET_MINUTES window,
    over the lookback period -- the grouping/counting runs server-side in
    ClickHouse (only the resulting per-bucket counts, at most
    BASELINE_LOOKBACK_DAYS*24*60/BUCKET_MINUTES rows, come back for the
    median in Python). Returns 0.0 when there's no historical data at all
    (a brand-new deployment, or a vendor scope with no prior anomalies) --
    MIN_ABSOLUTE_DEVICES then does the real work of deciding what counts
    as elevated in that case."""
    conditions = [
        "is_anomaly = 1",
        f"event_time >= '{ch_literal(lookback_start)}'",
        f"event_time <= '{ch_literal(lookback_end)}'",
    ]
    params: dict = {}
    _vendor_condition(vendor, conditions, params)
    result = client.query(
        f"SELECT toStartOfInterval(event_time, INTERVAL {BUCKET_MINUTES} MINUTE) AS bucket, "
        "uniqExact(hostname) AS device_count "
        f"FROM syslog_ml.events WHERE {' AND '.join(conditions)} "
        "GROUP BY bucket",
        parameters=params,
    )
    counts = [row[1] for row in result.result_rows]
    return median(counts) if counts else 0.0


def correlate_incidents(client: Client, *, start: datetime, end: datetime, vendor: str | None = None) -> list[dict]:
    """Groups anomalous events that happen close together in time across
    MULTIPLE devices into a single likely "incident", instead of leaving
    them as unrelated per-device rows the way anomaly_summary_service's
    own breakdowns do.

    This is a TEMPORAL CO-OCCURRENCE heuristic, not real root-cause
    analysis: the schema (see clickhouse/init.sql) has no network topology
    (no parent/uplink relationship between devices), so there is no way
    to know that one device's failure actually CAUSED another's. The
    "root cause" this returns is only the earliest event in an elevated
    span -- a reasonable guess (whatever happened first is more likely to
    be the trigger than a symptom), not a verified causal link. Callers/
    answer text must not overstate this as confirmed causation.

    Buckets anomalous events into fixed BUCKET_MINUTES windows and flags a
    bucket as part of an incident only when its distinct-device count is
    elevated relative to its own historical baseline (see
    _baseline_devices_per_bucket, ELEVATION_MULTIPLIER, MIN_ABSOLUTE_
    DEVICES) -- NOT by chaining consecutive events with a gap threshold.
    Confirmed live as a necessary redesign from an earlier gap-based
    version: at this deployment's real anomaly density (~579 devices,
    tens of thousands of anomalous events per day), there is essentially
    never a 10-minute gap anywhere in the global event stream, so gap-
    based chaining merged the ENTIRE day into one meaningless "incident"
    spanning every device and every anomaly type. Comparing each bucket
    to its own baseline instead asks "is this busier than normal," which
    doesn't break just because the fleet is continuously busy in general.

    Consecutive elevated buckets are merged into one incident span (a
    real event spanning 25 minutes shouldn't show up as three separate
    incidents). Returns at most MAX_INCIDENTS spans, highest peak-devices-
    in-a-single-bucket first; each lists at most MAX_EVENTS_PER_INCIDENT
    individual events to keep the result bounded for a span covering
    thousands of events.
    """
    rows = _anomalous_events(client, start=start, end=end, vendor=vendor)
    if not rows:
        return []

    baseline = _baseline_devices_per_bucket(
        client, lookback_start=start - timedelta(days=BASELINE_LOOKBACK_DAYS), lookback_end=start, vendor=vendor,
    )
    threshold = max(MIN_ABSOLUTE_DEVICES, baseline * ELEVATION_MULTIPLIER)

    buckets: dict[datetime, list[dict]] = {}
    for row in rows:
        buckets.setdefault(_bucket_start(row["event_time"]), []).append(row)

    elevated = sorted(
        b for b, bucket_rows in buckets.items()
        if len({r["hostname"] for r in bucket_rows}) >= threshold
    )
    if not elevated:
        return []

    spans: list[list[datetime]] = [[elevated[0]]]
    for b in elevated[1:]:
        if (b - spans[-1][-1]).total_seconds() <= BUCKET_MINUTES * 60:
            spans[-1].append(b)
        else:
            spans.append([b])

    incidents = []
    for span in spans:
        span_rows = sorted((r for b in span for r in buckets[b]), key=lambda r: r["event_time"])
        devices = {r["hostname"] for r in span_rows}
        reasons: set[str] = set()
        for r in span_rows:
            reasons.update(r["anomaly_reasons"] or [])
        root = span_rows[0]
        peak_devices = max(len({r["hostname"] for r in buckets[b]}) for b in span)
        incidents.append({
            "incident_start": span_rows[0]["event_time"],
            "incident_end": span_rows[-1]["event_time"],
            "event_count": len(span_rows),
            "devices_affected": sorted(devices),
            "anomaly_reasons_seen": sorted(reasons),
            "baseline_devices_per_bucket": round(baseline, 1),
            "peak_devices_in_a_single_bucket": peak_devices,
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
                for r in span_rows[1:MAX_EVENTS_PER_INCIDENT]
            ],
        })

    incidents.sort(key=lambda i: i["peak_devices_in_a_single_bucket"], reverse=True)
    return incidents[:MAX_INCIDENTS]
