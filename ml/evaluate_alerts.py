"""
Periodic worker (run via a systemd timer, e.g. every 1-2 minutes): evaluates
every enabled alert_rules row (Postgres, managed via the web app's "Alerts"
page) against syslog_ml.events in ClickHouse, and fires (records an
alert_events row + POSTs a webhook) when a rule's threshold is met and its
cooldown has elapsed since it last fired.

Kept as a separate process from consumer.py for the same reason as
resolve_pending.py: per-rule ClickHouse queries and outbound webhook POSTs
must never share a process with the hot log-ingestion path.

A rule is deliberately just a count-over-a-window condition (the same
filter shape as log search: hostname/source_ip/program/severity/category,
plus an anomaly-only toggle) rather than a general expression language --
see the AlertRule model's docstring in web/backend/app/db/models.py.
"""
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

import clickhouse_connect
import psycopg2
import psycopg2.extras
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("evaluate_alerts")

# Same Postgres the web app uses -- plain "postgresql://" scheme for
# psycopg2 (sync), same host/db/user/password as the web app's
# SYSLOG_ML_DATABASE_URL which uses "postgresql+asyncpg://" instead.
DATABASE_URL = os.environ["DATABASE_URL"]
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
WEBHOOK_TIMEOUT_SECONDS = float(os.environ.get("WEBHOOK_TIMEOUT_SECONDS", "5"))
SAMPLE_MESSAGE_MAX_LEN = 2000

_EQUALITY_FILTERS = ("hostname", "source_ip", "program", "severity", "predicted_category")


def fetch_enabled_rules(conn):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT id, name, window_minutes, threshold, cooldown_minutes,
                   hostname, source_ip, program, severity, predicted_category,
                   only_anomalies, webhook_url, last_triggered_at
            FROM alert_rules WHERE enabled = true
            """
        )
        return cur.fetchall()


def in_cooldown(rule, now):
    if rule["last_triggered_at"] is None:
        return False
    last = rule["last_triggered_at"]
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (now - last).total_seconds() < rule["cooldown_minutes"] * 60


def build_count_query(rule):
    """
    Same equality-filter shape as web/backend's log_search_service, just
    aggregated to a count + one sample message instead of full rows -- kept
    as its own small copy rather than a shared import since this script and
    the web backend are separate deployable units with separate Python
    environments (ml/requirements.txt vs web/backend/requirements.txt).
    """
    conditions = ["event_time >= %(start)s", "event_time <= %(end)s"]
    params = {}
    for field in _EQUALITY_FILTERS:
        value = rule.get(field)
        if value:
            conditions.append(f"{field} = %({field})s")
            params[field] = value
    if rule.get("only_anomalies"):
        conditions.append("is_anomaly = 1")

    # count()/any() with no GROUP BY always return exactly one row, even
    # when zero events match -- standard SQL aggregate semantics, not
    # something ClickHouse-specific -- so this never needs a "no rows" case.
    query = f"""
        SELECT count() AS matched, any(message) AS sample_message
        FROM syslog_ml.events
        WHERE {" AND ".join(conditions)}
    """
    return query, params


def notify_webhook(rule, matched_count, window_start, window_end, sample_message):
    """Returns (notified, error). notified=True with no webhook_url just
    means there was nothing to deliver, not that delivery succeeded --
    the web UI already shows whether a rule has a webhook configured."""
    if not rule["webhook_url"]:
        return True, None
    payload = {
        "rule": rule["name"],
        "matched_count": matched_count,
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "sample_message": sample_message,
    }
    try:
        response = requests.post(rule["webhook_url"], json=payload, timeout=WEBHOOK_TIMEOUT_SECONDS)
        response.raise_for_status()
        return True, None
    except requests.RequestException as exc:
        return False, str(exc)[:1000]


def evaluate_rule(ch_client, pg_conn, rule, now):
    if in_cooldown(rule, now):
        return

    window_start = now - timedelta(minutes=rule["window_minutes"])
    query, params = build_count_query(rule)
    params["start"] = window_start
    params["end"] = now

    result = ch_client.query(query, parameters=params)
    matched_count, sample_message = result.result_rows[0]
    if matched_count < rule["threshold"]:
        return

    sample_message = (sample_message or "")[:SAMPLE_MESSAGE_MAX_LEN]
    notified, notify_error = notify_webhook(rule, matched_count, window_start, now, sample_message)

    with pg_conn, pg_conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alert_events
                (id, rule_id, window_start, window_end, matched_count, sample_message, notified, notify_error)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (str(uuid.uuid4()), rule["id"], window_start, now, matched_count, sample_message, notified, notify_error),
        )
        cur.execute("UPDATE alert_rules SET last_triggered_at = %s WHERE id = %s", (now, rule["id"]))

    log.info(
        "Rule %r fired: %d matched (threshold %d), notified=%s%s",
        rule["name"], matched_count, rule["threshold"], notified,
        f", error={notify_error}" if notify_error else "",
    )


def main():
    pg_conn = psycopg2.connect(DATABASE_URL)
    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD
    )

    rules = fetch_enabled_rules(pg_conn)
    log.info("Evaluating %d enabled alert rule(s)", len(rules))
    now = datetime.now(timezone.utc)

    for rule in rules:
        try:
            evaluate_rule(ch_client, pg_conn, rule, now)
        except Exception:
            log.exception("Failed evaluating rule %r", rule["name"])

    pg_conn.close()


if __name__ == "__main__":
    main()
