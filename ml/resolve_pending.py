"""
Periodic worker (run via a systemd timer, e.g. every 10 minutes): drains the
local queue of source IPs the classifier has seen but couldn't yet identify,
attempts SNMP resolution for any that now have a matching credential row in
the web app's snmp_credentials table (Postgres), and writes results into
ClickHouse's device_inventory table.

Kept as a separate process from consumer.py on purpose: SNMP round-trips
(up to a few seconds on timeout) must never block the hot log-processing
path. consumer.py only ever does a fast local cache lookup; this script
does the slow network calls asynchronously.
"""
import logging
import os
from datetime import datetime, timezone

import clickhouse_connect

import state_db
from device_resolver import load_credentials, find_credential, resolve_via_snmp

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("resolve_pending")

STATE_DB = os.environ.get("STATE_DB", "/var/lib/syslog-ml/state.db")
# Same Postgres the web app uses, and the same encryption key it encrypts
# credentials with -- these two services must agree on both.
DATABASE_URL = os.environ["DATABASE_URL"]
CREDENTIAL_ENCRYPTION_KEY = os.environ["CREDENTIAL_ENCRYPTION_KEY"]
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")

MAX_ATTEMPTS_BEFORE_BACKOFF = 5
NO_CREDENTIAL_RETRY_HOURS = 24
UNREACHABLE_RETRY_HOURS = 24


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def due_for_retry(row, retry_hours):
    if row["last_attempt"] is None:
        return True
    last = datetime.fromisoformat(row["last_attempt"])
    return (datetime.now(timezone.utc) - last).total_seconds() >= retry_hours * 3600


def fetch_due_rows(conn):
    rows = conn.execute(
        "SELECT ip, first_seen, last_attempt, attempt_count, status FROM pending_ips"
    ).fetchall()
    due = []
    for row in rows:
        row = dict(row)
        if row["status"] == "pending":
            due.append(row)
        elif row["status"] == "no_credential" and due_for_retry(row, NO_CREDENTIAL_RETRY_HOURS):
            due.append(row)
        elif row["status"] == "unreachable" and due_for_retry(row, UNREACHABLE_RETRY_HOURS):
            due.append(row)
    return due


def main():
    conn = state_db.connect(STATE_DB)

    credentials = load_credentials(DATABASE_URL, CREDENTIAL_ENCRYPTION_KEY)
    log.info("Loaded %d SNMP credential entries from the credentials database", len(credentials))

    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD
    )

    due_rows = fetch_due_rows(conn)
    log.info("%d IP(s) due for a resolution attempt", len(due_rows))

    for row in due_rows:
        ip = row["ip"]
        credential = find_credential(credentials, ip)

        if credential is None:
            conn.execute(
                "UPDATE pending_ips SET status='no_credential', last_attempt=?, attempt_count=attempt_count+1 WHERE ip=?",
                (now_iso(), ip),
            )
            continue

        result = resolve_via_snmp(ip, credential)
        if result is None:
            attempt_count = row["attempt_count"] + 1
            status = "unreachable" if attempt_count >= MAX_ATTEMPTS_BEFORE_BACKOFF else "pending"
            conn.execute(
                "UPDATE pending_ips SET status=?, last_attempt=?, attempt_count=? WHERE ip=?",
                (status, now_iso(), attempt_count, ip),
            )
            log.warning("SNMP resolution failed for %s (attempt %d)", ip, attempt_count)
            continue

        hostname, vendor, model = result
        ch_client.insert(
            "syslog_ml.device_inventory",
            [[ip, hostname, vendor, model, "snmp", row["first_seen"], now_iso()]],
            column_names=["ip", "hostname", "vendor", "model", "resolution_method", "first_seen", "last_resolved"],
        )
        conn.execute("DELETE FROM pending_ips WHERE ip=?", (ip,))
        log.info("Resolved %s -> hostname=%s vendor=%s", ip, hostname, vendor)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    main()
