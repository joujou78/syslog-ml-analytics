"""
Periodic worker (run via a systemd timer, e.g. every 10 minutes): flags a
device as "silent" when it has gone quiet for far longer than its own
historical logging pattern would predict, and clears that flag once it
logs again. Fires a webhook on both transitions (went silent / recovered).

Every anomaly signal elsewhere in this project (rare_template,
always_severe, security_content, severity_spike, volume_spike,
unusual_template_mix -- see consumer.py and template_mix_anomaly.py)
detects a device logging too much or unusually. None of them detect a
device that stops logging entirely -- for a security appliance or
network switch, that can mean it crashed, lost connectivity, or was
tampered with, and today it's invisible. This fills that specific gap.

Kept as a separate process for the same reason as evaluate_alerts.py and
resolve_pending.py: per-device ClickHouse queries and outbound webhook
POSTs must never share a process with the hot log-ingestion path.

Why a device-relative threshold, not a fixed timeout: a busy firewall
logging every few seconds and a quiet switch logging every few hours are
both "silent" at wildly different absolute gaps -- a single global
timeout would false-positive on legitimately quiet devices and under-
detect on chatty ones. Instead this computes each device's own average
inter-arrival time from SILENCE_BASELINE_WINDOW_DAYS of history, and
flags silence only once the actual gap exceeds SILENCE_MULTIPLIER times
that baseline (with SILENCE_MIN_MINUTES as an absolute floor, so a
device with a very tight baseline -- e.g. one event every few seconds --
doesn't get flagged for a normal few-minutes' pause).

State lives in Postgres (device_silence_state, one row per device,
upserted -- see web/backend/app/db/models.py), not ClickHouse: it's this
script's own small amount of control state (is this device currently
flagged, when did we last notify), not log data.
"""
import logging
import os
from datetime import datetime, timedelta, timezone

import clickhouse_connect
import psycopg2
import psycopg2.extras
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("detect_silent_devices")

DATABASE_URL = os.environ["DATABASE_URL"]
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_EVENTS_TABLE = os.environ.get("CLICKHOUSE_EVENTS_TABLE", "syslog_ml.events")
WEBHOOK_URL = os.environ.get("SILENCE_WEBHOOK_URL", "")
WEBHOOK_TIMEOUT_SECONDS = float(os.environ.get("WEBHOOK_TIMEOUT_SECONDS", "5"))

# How far back to look to learn a device's normal logging rhythm.
SILENCE_BASELINE_WINDOW_DAYS = int(os.environ.get("SILENCE_BASELINE_WINDOW_DAYS", "7"))
# A device needs at least this many events in that window before its
# average inter-arrival time is trusted at all -- a device that only
# logged twice has no meaningful "normal rhythm" to compare against.
# Floored at 2, not just documented as such: expected_interval_minutes()
# divides by (event_count - 1), and first_seen == last_seen when
# event_count == 1 -- an operator setting this to 0 or 1 would otherwise
# hit a real ZeroDivisionError instead of a config validation error.
SILENCE_MIN_BASELINE_EVENTS = max(2, int(os.environ.get("SILENCE_MIN_BASELINE_EVENTS", "20")))
# Flag silence once the actual gap since last-seen exceeds this many
# times the device's own average inter-arrival time.
SILENCE_MULTIPLIER = float(os.environ.get("SILENCE_MULTIPLIER", "10"))
# ...but never below this many minutes regardless of multiplier, so a
# device with a very tight baseline (e.g. one event every few seconds)
# doesn't get flagged over an ordinary few-minute pause.
SILENCE_MIN_MINUTES = float(os.environ.get("SILENCE_MIN_MINUTES", "30"))
# Once a device is already flagged silent, don't re-fire the webhook on
# every single run while it stays silent -- only after this much time
# since the last notification for it.
SILENCE_RENOTIFY_MINUTES = float(os.environ.get("SILENCE_RENOTIFY_MINUTES", "240"))


def fetch_device_activity(ch_client, now: datetime):
    """One row per device with enough history to have a trusted baseline:
    its average inter-arrival time over the window, and when it was last
    seen. Devices with too little history (SILENCE_MIN_BASELINE_EVENTS)
    are excluded here, not filtered in Python, so the threshold is one
    number instead of two things that could drift apart."""
    query = f"""
        SELECT
            source_ip,
            any(hostname) AS hostname,
            count() AS event_count,
            min(event_time) AS first_seen,
            max(event_time) AS last_seen
        FROM {CLICKHOUSE_EVENTS_TABLE}
        WHERE event_time >= %(window_start)s
        GROUP BY source_ip
        HAVING event_count >= %(min_events)s
    """
    result = ch_client.query(
        query,
        parameters={
            "window_start": now - timedelta(days=SILENCE_BASELINE_WINDOW_DAYS),
            "min_events": SILENCE_MIN_BASELINE_EVENTS,
        },
    )
    return [
        dict(zip(["source_ip", "hostname", "event_count", "first_seen", "last_seen"], row))
        for row in result.result_rows
    ]


def _as_aware_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def expected_interval_minutes(row: dict) -> float:
    """Average time between events over the baseline window. event_count
    is >= SILENCE_MIN_BASELINE_EVENTS, which is floored at 2 (see its own
    definition above), so event_count-1 is always positive -- no need to
    guard the division."""
    span_minutes = (_as_aware_utc(row["last_seen"]) - _as_aware_utc(row["first_seen"])).total_seconds() / 60
    return span_minutes / (row["event_count"] - 1)


def is_silent(row: dict, now: datetime) -> tuple[bool, float, float]:
    """Returns (silent, silence_minutes, expected_interval_minutes)."""
    interval = expected_interval_minutes(row)
    silence_minutes = (now - _as_aware_utc(row["last_seen"])).total_seconds() / 60
    threshold = max(SILENCE_MIN_MINUTES, interval * SILENCE_MULTIPLIER)
    return silence_minutes > threshold, silence_minutes, interval


def notify_webhook(event: str, row: dict, silence_minutes: float, expected_interval: float) -> tuple[bool, str | None]:
    """Returns (notified, error). notified=True with no URL configured
    just means there was nothing to deliver, not that delivery
    succeeded -- same convention as evaluate_alerts.py's notify_webhook."""
    if not WEBHOOK_URL:
        return True, None
    payload = {
        "event": event,  # "device_silent" | "device_recovered"
        "source_ip": row["source_ip"],
        "hostname": row["hostname"],
        "silence_minutes": round(silence_minutes, 1),
        "expected_interval_minutes": round(expected_interval, 1),
    }
    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=WEBHOOK_TIMEOUT_SECONDS)
        response.raise_for_status()
        return True, None
    except requests.RequestException as exc:
        return False, str(exc)[:1000]


def fetch_state(pg_conn) -> dict[str, dict]:
    with pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM device_silence_state")
        return {row["source_ip"]: row for row in cur.fetchall()}


def upsert_state(
    pg_conn,
    source_ip: str,
    hostname: str | None,
    expected_interval: float,
    last_seen_at: datetime,
    silence_started_at: datetime | None,
    last_notified_at: datetime | None,
):
    with pg_conn, pg_conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO device_silence_state
                (source_ip, hostname, expected_interval_minutes, last_seen_at, silence_started_at, last_notified_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (source_ip) DO UPDATE SET
                hostname = EXCLUDED.hostname,
                expected_interval_minutes = EXCLUDED.expected_interval_minutes,
                last_seen_at = EXCLUDED.last_seen_at,
                silence_started_at = EXCLUDED.silence_started_at,
                last_notified_at = EXCLUDED.last_notified_at
            """,
            (source_ip, hostname, expected_interval, last_seen_at, silence_started_at, last_notified_at),
        )


def clear_state(pg_conn, source_ip: str):
    with pg_conn, pg_conn.cursor() as cur:
        cur.execute("DELETE FROM device_silence_state WHERE source_ip = %s", (source_ip,))


def evaluate_device(pg_conn, row: dict, prior: dict | None, now: datetime):
    silent, silence_minutes, interval = is_silent(row, now)
    last_seen = _as_aware_utc(row["last_seen"])

    if not silent:
        if prior is not None:
            # Recovered: was flagged, now has recent activity again. The
            # outage duration for the notification is the gap between the
            # LAST known-good event before it went silent (prior's own
            # last_seen_at, not this row's, which is the just-arrived
            # recovery event itself) and now -- using `silence_minutes`
            # here would report a near-zero value (the few minutes since
            # the recovery event, not the actual outage).
            outage_minutes = (last_seen - _as_aware_utc(prior["last_seen_at"])).total_seconds() / 60
            notified, error = notify_webhook("device_recovered", row, outage_minutes, interval)
            log.info(
                "Device %s (%s) recovered after %.1f min, notified=%s%s",
                row["source_ip"], row["hostname"], outage_minutes, notified, f", error={error}" if error else "",
            )
            if notified:
                clear_state(pg_conn, row["source_ip"])
            else:
                # Leave the state row untouched (not just skip clearing --
                # don't even refresh last_seen_at) so the next run sees
                # the same prior state, recomputes the same not-silent
                # result, and retries this exact recovery notification --
                # otherwise a transient webhook failure at the moment of
                # recovery would silently lose the only record that this
                # device was ever silent, with no retry and nothing to
                # show in the UI.
                log.warning(
                    "Device %s (%s) recovery notification failed, will retry next run: %s",
                    row["source_ip"], row["hostname"], error,
                )
        return

    if prior is None:
        # Newly silent.
        notified, error = notify_webhook("device_silent", row, silence_minutes, interval)
        log.info(
            "Device %s (%s) newly silent: %.1f min since last seen (expected ~%.1f min), notified=%s%s",
            row["source_ip"], row["hostname"], silence_minutes, interval, notified,
            f", error={error}" if error else "",
        )
        upsert_state(pg_conn, row["source_ip"], row["hostname"], interval, last_seen, now, now)
        return

    # Still silent -- only re-notify past the cooldown, but always refresh
    # last_seen_at/expected_interval_minutes so the state row stays current.
    last_notified = prior["last_notified_at"]
    should_renotify = last_notified is None or (now - _as_aware_utc(last_notified)).total_seconds() >= SILENCE_RENOTIFY_MINUTES * 60
    last_notified_at = prior["last_notified_at"]
    if should_renotify:
        notified, error = notify_webhook("device_silent", row, silence_minutes, interval)
        log.info(
            "Device %s (%s) still silent: %.1f min, re-notified=%s%s",
            row["source_ip"], row["hostname"], silence_minutes, notified,
            f", error={error}" if error else "",
        )
        last_notified_at = now
    upsert_state(pg_conn, row["source_ip"], row["hostname"], interval, last_seen, prior["silence_started_at"], last_notified_at)


def main():
    pg_conn = psycopg2.connect(DATABASE_URL)
    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD
    )
    now = datetime.now(timezone.utc)

    rows = fetch_device_activity(ch_client, now)
    prior_state = fetch_state(pg_conn)
    log.info("Evaluating %d device(s) with an established baseline", len(rows))

    seen_ips = set()
    for row in rows:
        seen_ips.add(row["source_ip"])
        try:
            evaluate_device(pg_conn, row, prior_state.get(row["source_ip"]), now)
        except Exception:
            log.exception("Failed evaluating device %s", row["source_ip"])

    # A device that's dropped out of the baseline query entirely (no
    # events at all in SILENCE_BASELINE_WINDOW_DAYS, not even the stale
    # ones that got it flagged) is the most silent case there is -- but
    # it can't be re-evaluated by the loop above since it's not in `rows`
    # any more. Leave its state row alone rather than silently dropping
    # it: it's still accurate (still silent, nothing new to report), and
    # it will resume being evaluated normally once SILENCE_BASELINE_WINDOW_DAYS
    # has fully elapsed and its last real event ages out of the window.
    for source_ip in prior_state:
        if source_ip not in seen_ips:
            log.debug("Device %s no longer has a baseline in-window; leaving its silent state as-is", source_ip)

    pg_conn.close()


if __name__ == "__main__":
    main()
