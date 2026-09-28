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

from ch_time import ch_literal
from emailer import parse_recipients, send_email

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
# One global recipient list for every rule that fires, not a per-rule
# column alongside webhook_url -- deliberately simpler than fully
# per-rule email config, which would need a schema change, a new API
# field, and a new frontend field for comparatively little benefit on a
# single-operator deployment. Add per-rule recipients later if that
# stops being true.
ALERT_EMAIL_RECIPIENTS = parse_recipients(os.environ.get("ALERT_EMAIL_RECIPIENTS", ""))

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


def build_count_query(rule, start: datetime, end: datetime):
    """
    Same equality-filter shape as web/backend's log_search_service, just
    aggregated to a count + one sample message instead of full rows -- kept
    as its own small copy rather than a shared import since this script and
    the web backend are separate deployable units with separate Python
    environments (ml/requirements.txt vs web/backend/requirements.txt).

    start/end are embedded as literals, not bound as query parameters --
    see ch_time.py. This is the query that decides whether an alert rule
    fires, so a silently wrong window boundary here isn't a cosmetic bug:
    it's a missed or falsely-fired alert.
    """
    conditions = [f"event_time >= '{ch_literal(start)}'", f"event_time <= '{ch_literal(end)}'"]
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


def notify_email(rule, matched_count, window_start, window_end, sample_message):
    """Returns (sent, error) -- same convention as notify_webhook above.
    Uses the global ALERT_EMAIL_RECIPIENTS list, not a per-rule field."""
    subject = f"[syslog-ml] Alert: {rule['name']} ({matched_count} matched)"
    body = (
        f"Rule: {rule['name']}\n"
        f"Matched: {matched_count} (threshold {rule['threshold']})\n"
        f"Window: {window_start.isoformat()} to {window_end.isoformat()}\n"
        f"Sample message: {sample_message}\n"
    )
    return send_email(ALERT_EMAIL_RECIPIENTS, subject, body)


def evaluate_rule(ch_client, pg_conn, rule, now):
    if in_cooldown(rule, now):
        return

    window_start = now - timedelta(minutes=rule["window_minutes"])
    query, params = build_count_query(rule, window_start, now)

    result = ch_client.query(query, parameters=params)
    matched_count, sample_message = result.result_rows[0]
    if matched_count < rule["threshold"]:
        return

    sample_message = (sample_message or "")[:SAMPLE_MESSAGE_MAX_LEN]
    notified, notify_error = notify_webhook(rule, matched_count, window_start, now, sample_message)
    email_notified, email_notify_error = notify_email(rule, matched_count, window_start, now, sample_message)

    with pg_conn, pg_conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alert_events
                (id, rule_id, window_start, window_end, matched_count, sample_message,
                 notified, notify_error, email_notified, email_notify_error)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                str(uuid.uuid4()), rule["id"], window_start, now, matched_count, sample_message,
                notified, notify_error, email_notified, email_notify_error,
            ),
        )
        # Only start the cooldown clock if at least one channel actually
        # delivered (or had nothing configured to deliver to -- notified/
        # email_notified is True in both cases, see notify_webhook's own
        # docstring). Previously this ran unconditionally: a transient
        # webhook failure still consumed the full cooldown_minutes window,
        # so the next real notification for a persisting condition could
        # be silently delayed by the whole cooldown period even though
        # nothing was ever delivered for this firing.
        if notified or email_notified:
            cur.execute("UPDATE alert_rules SET last_triggered_at = %s WHERE id = %s", (now, rule["id"]))

    log.info(
        "Rule %r fired: %d matched (threshold %d), notified=%s%s, email_notified=%s%s",
        rule["name"], matched_count, rule["threshold"], notified,
        f", error={notify_error}" if notify_error else "",
        email_notified,
        f", error={email_notify_error}" if email_notify_error else "",
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
