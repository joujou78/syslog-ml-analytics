"""
Periodic worker (run via a systemd timer, once daily): emails a plain-text
summary of the last 24 hours -- total events, a breakdown of which of the
8 anomaly signals fired and how often, the noisiest devices, any alert
rules that fired, and devices currently flagged silent. Answers "what
happened in the last day" in one message instead of requiring someone to
go dig through Log Search/Anomaly Summary/Alerts/Devices separately.

Deliberately just the one daily digest for now (not also hourly/weekly --
those are easy to add later as separate timers reusing build_digest()
with a different DIGEST_WINDOW_HOURS, but weren't asked for yet).
"""
import logging
import os
from datetime import datetime, timedelta, timezone

import clickhouse_connect
import psycopg2
import psycopg2.extras

from emailer import parse_recipients, send_email

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("daily_digest")

DATABASE_URL = os.environ["DATABASE_URL"]
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_EVENTS_TABLE = os.environ.get("CLICKHOUSE_EVENTS_TABLE", "syslog_ml.events")

DIGEST_WINDOW_HOURS = float(os.environ.get("DIGEST_WINDOW_HOURS", "24"))
DIGEST_TOP_DEVICES = int(os.environ.get("DIGEST_TOP_DEVICES", "10"))
# Falls back to ALERT_EMAIL_RECIPIENTS (see evaluate_alerts.py) if unset,
# since it's often the same audience -- but kept independently
# overridable in case the digest's audience is broader (e.g. management)
# than who wants every individual alert firing.
DIGEST_EMAIL_RECIPIENTS = parse_recipients(
    os.environ.get("DIGEST_EMAIL_RECIPIENTS") or os.environ.get("ALERT_EMAIL_RECIPIENTS", "")
)


def fetch_event_summary(ch_client, window_start: datetime, now: datetime) -> dict:
    total = ch_client.query(
        f"SELECT count(), countIf(is_anomaly = 1) FROM {CLICKHOUSE_EVENTS_TABLE} "
        f"WHERE event_time >= %(start)s AND event_time <= %(end)s",
        parameters={"start": window_start, "end": now},
    ).result_rows[0]

    reasons = ch_client.query(
        f"SELECT reason, count() FROM ("
        f"  SELECT arrayJoin(anomaly_reasons) AS reason FROM {CLICKHOUSE_EVENTS_TABLE} "
        f"  WHERE event_time >= %(start)s AND event_time <= %(end)s"
        f") GROUP BY reason ORDER BY count() DESC",
        parameters={"start": window_start, "end": now},
    ).result_rows

    top_devices = ch_client.query(
        f"SELECT source_ip, any(hostname) AS hostname, count() AS event_count "
        f"FROM {CLICKHOUSE_EVENTS_TABLE} WHERE event_time >= %(start)s AND event_time <= %(end)s "
        f"GROUP BY source_ip ORDER BY event_count DESC LIMIT %(n)s",
        parameters={"start": window_start, "end": now, "n": DIGEST_TOP_DEVICES},
    ).result_rows

    return {
        "total_events": total[0],
        "anomaly_events": total[1],
        "reason_counts": reasons,
        "top_devices": top_devices,
    }


def fetch_fired_alerts(pg_conn, window_start: datetime, now: datetime) -> list[dict]:
    with pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT ar.name, ae.matched_count, ae.triggered_at
            FROM alert_events ae
            JOIN alert_rules ar ON ar.id = ae.rule_id
            WHERE ae.triggered_at >= %s AND ae.triggered_at <= %s
            ORDER BY ae.triggered_at DESC
            """,
            (window_start, now),
        )
        return cur.fetchall()


def fetch_currently_silent(pg_conn) -> list[dict]:
    # Current state, not "went silent within the window" -- a device
    # that's been silent for a week is still worth surfacing in today's
    # digest, not just on the one day it first went quiet.
    with pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT source_ip, hostname, silence_started_at FROM device_silence_state ORDER BY silence_started_at")
        return cur.fetchall()


def build_digest(ch_client, pg_conn, window_start: datetime, now: datetime) -> str:
    summary = fetch_event_summary(ch_client, window_start, now)
    fired_alerts = fetch_fired_alerts(pg_conn, window_start, now)
    silent_devices = fetch_currently_silent(pg_conn)

    lines = [
        f"syslog-ml daily digest: {window_start.isoformat()} to {now.isoformat()}",
        "",
        f"Total events: {summary['total_events']}",
        f"Anomalous events: {summary['anomaly_events']}",
        "",
        "Anomaly signals fired:",
    ]
    if summary["reason_counts"]:
        for reason, count in summary["reason_counts"]:
            lines.append(f"  {reason}: {count}")
    else:
        lines.append("  (none)")

    lines += ["", f"Top {DIGEST_TOP_DEVICES} noisiest devices:"]
    if summary["top_devices"]:
        for source_ip, hostname, event_count in summary["top_devices"]:
            lines.append(f"  {hostname} ({source_ip}): {event_count} events")
    else:
        lines.append("  (none)")

    lines += ["", "Alert rules fired:"]
    if fired_alerts:
        for alert in fired_alerts:
            lines.append(f"  {alert['triggered_at'].isoformat()} -- {alert['name']} ({alert['matched_count']} matched)")
    else:
        lines.append("  (none)")

    lines += ["", "Currently silent devices:"]
    if silent_devices:
        for device in silent_devices:
            lines.append(
                f"  {device['hostname']} ({device['source_ip']}) -- silent since {device['silence_started_at'].isoformat()}"
            )
    else:
        lines.append("  (none)")

    return "\n".join(lines)


def main():
    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD
    )
    pg_conn = psycopg2.connect(DATABASE_URL)
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=DIGEST_WINDOW_HOURS)

    body = build_digest(ch_client, pg_conn, window_start, now)
    subject = f"[syslog-ml] Daily digest -- {now.date().isoformat()}"
    sent, error = send_email(DIGEST_EMAIL_RECIPIENTS, subject, body)
    log.info("Daily digest %s%s", "sent" if sent else "FAILED to send", f": {error}" if error else "")

    pg_conn.close()


if __name__ == "__main__":
    main()
