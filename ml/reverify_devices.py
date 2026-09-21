"""
Periodic worker (run via a systemd timer, twice daily): re-verifies every
already SNMP-resolved device in ClickHouse's device_inventory, in case its
hostname/vendor/model has changed or (for a credential that was
auto-discovered from a pool) its community string has been rotated.

Tries each device's own saved credential first -- the fast path, since
resolve_pending.py already auto-saved that the first time this device was
seen. If that credential no longer gets a response, falls back to
re-trying the whole matching credential pool exactly like a brand-new
device, and re-saves whichever one now matches. This is what makes an
auto-discovered credential self-heal if the community later changes,
without anyone having to notice and fix it by hand.

Kept as a separate process/timer from resolve_pending.py (which only
handles newly-seen, not-yet-resolved IPs every ~10 minutes) since this
job's job is different: confirming devices that are already considered
"known" are still actually reachable and unchanged.
"""
import logging
import os
from datetime import datetime, timezone

import clickhouse_connect

from device_resolver import (
    find_candidate_credentials,
    is_exact_host_credential,
    load_credentials,
    resolve_with_discovery,
    save_discovered_credential,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("reverify_devices")

DATABASE_URL = os.environ["DATABASE_URL"]
CREDENTIAL_ENCRYPTION_KEY = os.environ["CREDENTIAL_ENCRYPTION_KEY"]
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")


def fetch_resolved_devices(ch_client):
    result = ch_client.query(
        "SELECT ip, first_seen FROM syslog_ml.device_inventory WHERE resolution_method = 'snmp'"
    )
    return result.result_rows


def main():
    credentials = load_credentials(DATABASE_URL, CREDENTIAL_ENCRYPTION_KEY)
    log.info("Loaded %d SNMP credential entries", len(credentials))

    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD
    )

    devices = fetch_resolved_devices(ch_client)
    log.info("Re-verifying %d previously SNMP-resolved device(s)", len(devices))

    refreshed = 0
    unreachable = 0
    # device_inventory's first_seen/last_resolved are DateTime64 columns --
    # clickhouse-connect needs a real datetime object here (it calls
    # .timestamp() on each value), not an ISO string. first_seen comes back
    # from the SELECT below as a real datetime already; last_resolved needs
    # one built the same way.
    now = datetime.now(timezone.utc)

    for ip, first_seen in devices:
        candidates = find_candidate_credentials(credentials, ip)
        if not candidates:
            log.warning("No credential candidates remain for %s (its credential may have been deleted)", ip)
            unreachable += 1
            continue

        result, matched = resolve_with_discovery(ip, candidates)
        if result is None:
            log.warning("%s no longer responds to any of its %d candidate credential(s)", ip, len(candidates))
            unreachable += 1
            continue

        hostname, vendor, model = result
        ch_client.insert(
            "syslog_ml.device_inventory",
            [[ip, hostname, vendor, model, "snmp", first_seen, now]],
            column_names=["ip", "hostname", "vendor", "model", "resolution_method", "first_seen", "last_resolved"],
        )
        refreshed += 1

        if not is_exact_host_credential(matched, ip):
            save_discovered_credential(DATABASE_URL, CREDENTIAL_ENCRYPTION_KEY, ip, matched)

    log.info("Re-verify complete: %d refreshed, %d unreachable", refreshed, unreachable)


if __name__ == "__main__":
    main()
