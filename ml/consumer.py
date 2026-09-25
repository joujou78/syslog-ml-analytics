"""
Real-time pipeline (runs as the syslog-ml-classifier systemd service):

  tail /var/log/syslog-ml/raw.jsonl
    -> device identity lookup (cached, from ClickHouse device_inventory)
    -> Drain3 template mining
    -> ML category classifier
    -> batch insert into ClickHouse

No broker: rsyslog writes straight to a local file (see
rsyslog/60-syslog-ml.conf) and this process tails it, tracking its own
read offset so a restart or logrotate rotation doesn't lose or duplicate
lines.

If MODEL_PATH doesn't exist yet (classifier not trained), falls back to
the weak-supervision rules in labeling_rules.py so the pipeline is useful
from day one.
"""
import ipaddress
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone

import clickhouse_connect
import joblib
import psycopg2
from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

import state_db
from anomaly_signals import is_always_severe, is_security_content
from labeling_rules import weak_label, severity_rank
from sequence_anomaly import SequenceAnomalyDetector
from template_mix_anomaly import TemplateMixAnomalyDetector
from vendor_signatures import detect_vendor

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("consumer")

LOG_FILE = os.environ.get("SYSLOG_ML_LOG_FILE", "/var/log/syslog-ml/raw.jsonl")
OFFSET_FILE = os.environ.get("SYSLOG_ML_OFFSET_FILE", "/var/lib/syslog-ml/consumer.offset")
STATE_DB_PATH = os.environ.get("STATE_DB", "/var/lib/syslog-ml/state.db")
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
MODEL_PATH = os.environ.get("MODEL_PATH", "/var/lib/syslog-ml/classifier.joblib")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "500"))
BATCH_FLUSH_SECONDS = float(os.environ.get("BATCH_FLUSH_SECONDS", "2"))
INVENTORY_REFRESH_SECONDS = float(os.environ.get("INVENTORY_REFRESH_SECONDS", "60"))
POLL_IDLE_SECONDS = 0.5

DRAIN3_STATE_FILE = os.environ.get("DRAIN3_STATE_FILE", "/var/lib/syslog-ml/drain3_state.bin")
DRAIN3_SNAPSHOT_INTERVAL_MINUTES = float(os.environ.get("DRAIN3_SNAPSHOT_INTERVAL_MINUTES", "10"))
# A template is flagged is_anomaly while its Drain3 cluster has matched this
# many messages or fewer (in the cluster's whole lifetime, not per-window) --
# i.e. it's new or still rare, not yet part of this device's normal traffic.
# Unsupervised on purpose: no labeled anomaly data exists yet (see README).
ANOMALY_RARE_THRESHOLD = int(os.environ.get("ANOMALY_RARE_THRESHOLD", "5"))

# How far back DeviceBaselineCache looks to decide what's "normal" for a
# device (severity_spike, volume_spike). A GROUP BY over this whole window
# runs on every refresh, so it's a real ClickHouse query cost, not a free
# lookup like InventoryCache's -- refreshed far less often as a result.
BASELINE_WINDOW_DAYS = int(os.environ.get("ANOMALY_BASELINE_WINDOW_DAYS", "7"))
BASELINE_REFRESH_SECONDS = float(os.environ.get("ANOMALY_BASELINE_REFRESH_SECONDS", "600"))
# A device is "volume spiking" while its rate since the last baseline
# refresh is at least this many times its historical average rate.
VOLUME_SPIKE_MULTIPLIER = float(os.environ.get("ANOMALY_VOLUME_SPIKE_MULTIPLIER", "5"))

# Postgres connection for the admin-managed relay_source_ips table (same
# database/table the web app's "Relay Source IPs" admin page reads and
# writes -- see RelaySourceIpCache below). Empty by default: if unset, the
# cache just never has any entries and every source_ip is treated as a
# direct device, the same as before this feature existed.
DATABASE_URL = os.environ.get("DATABASE_URL", "")
RELAY_LIST_REFRESH_SECONDS = float(os.environ.get("RELAY_LIST_REFRESH_SECONDS", "60"))

# Confirmed on net-flow's real relay traffic: rsyslog's `timereported` for
# some messages forwarded through this relay is 3 hours ahead of the real
# receipt time (event_time ~15:32 vs received_at, the actual insert-time
# now64(), ~12:34 for the same row) -- the legacy BSD syslog format those
# messages use has no timezone field at all, and whatever wrote that copy
# of the timestamp (the relay itself, or the origin devices) appears to
# put local Beirut time (UTC+3) into it, which rsyslog then takes at face
# value instead of converting.
#
# NOT all of this relay's traffic is skewed this way, though (confirmed:
# some of the same device's messages arrive already correct) -- so this
# can't be a blanket "always subtract 3h for this relay" rule, or it
# wrongly shifts already-correct timestamps into the past instead. It's
# applied per-message instead: only when event_time claims to be more
# than RELAY_TIMEZONE_FUTURE_TOLERANCE_MINUTES ahead of the real
# processing time (a message can't legitimately be from the future,
# whereas a merely-delayed/backlogged one is late, not early -- this
# only ever fires in the direction the actual bug produces), and even
# then, only if subtracting RELAY_TIMEZONE_OFFSET_HOURS genuinely brings
# it closer to now instead of further away.
#
# A fixed offset, not a named IANA timezone (no DST handling) -- if that
# turns out wrong, this needs revisiting, but it's what's actually
# observed and what was asked for. Only applied to traffic from a listed
# relay (see RelaySourceIpCache below), since that's the only population
# this has been confirmed against; doesn't touch or retroactively fix
# events already inserted before this was added.
RELAY_TIMEZONE_OFFSET_HOURS = float(os.environ.get("RELAY_TIMEZONE_OFFSET_HOURS", "3"))
RELAY_TIMEZONE_FUTURE_TOLERANCE_MINUTES = float(os.environ.get("RELAY_TIMEZONE_FUTURE_TOLERANCE_MINUTES", "30"))

INSERT_COLUMNS = [
    "event_time", "source_ip", "hostname", "reported_hostname", "relayed_via", "vendor", "vendor_source", "model",
    "resolution_method", "facility", "severity", "severity_num", "program", "pid",
    "message", "template_id", "template", "predicted_category", "predicted_confidence",
    "is_anomaly", "anomaly_reasons", "raw",
]

# Cisco ACS/ISE (TACACS+/RADIUS accounting, TACACS diagnostics, failed
# attempts, etc.) splits any message too long for one UDP syslog datagram
# into multiple separate syslog messages, each carrying the SAME
# "<message-id> <total-segments> <this-segment-index>" prefix (index
# 0-based) so the receiver can stitch them back together. Confirmed on
# net-flow's real ACS traffic (program=CSCOacs_TACACS_Diagnostics /
# CSCOacs_Failed_Attempts / CSCOacs_TACACS_Accounting):
#   " 0001384016 2 0 2026-09-24 ... NetworkDeviceGroups=...PESCO BACKBONE,"
#   " 0001384016 2 1  ServiceSelectionMatchedRule=Rule-2, ... }"
# -- concatenating each segment's content (everything after the 3-number
# prefix, in index order) with NO added separator reproduces the original
# message exactly: the leading space visible before "ServiceSelection..."
# above is itself part of segment 1's own content (ACS resumes mid-string
# at whatever byte the datagram limit cut it off), not a delimiter to
# strip. Without this, every split ACS message shows up in Log Search and
# the Log Assistant's index as 2+ separate, individually meaningless
# partial rows instead of one real message.
ACS_SEGMENT_RE = re.compile(r"^(\d{10}) (\d+) (\d+) (.*)$", re.DOTALL)

# Gates the above on the program name too (Cisco ACS's own convention
# across all its message categories), not just the numeric prefix match,
# so this can never fire on non-ACS traffic that might coincidentally
# start a message with three numbers.
ACS_PROGRAM_PREFIX = "CSCOacs_"

# How long to wait for a lost/delayed segment before giving up and
# emitting whatever segments did arrive (logged as incomplete) instead of
# buffering forever -- a dropped UDP segment must not silently blackhole
# the segments that did make it. All segments of a real split message
# arrive within the same second in practice (see the samples above), so
# this is generous.
ACS_REASSEMBLY_TIMEOUT_SECONDS = float(os.environ.get("ACS_REASSEMBLY_TIMEOUT_SECONDS", "10"))


class AcsMultipartReassembler:
    """
    Buffers Cisco ACS/ISE syslog messages that arrive split across
    multiple lines (see ACS_SEGMENT_RE's comment above) and re-emits one
    merged record per complete group, in place of handing each partial
    segment to to_row() as if it were a whole message on its own. Also
    strips the numeric message-id/total/index prefix from single-segment
    ACS messages (total=1), since they carry the exact same protocol
    plumbing and leaving it on only the non-split ones would be an
    inconsistent Log Search experience.

    Keyed by (source_ip, reported_hostname, message_id), not source_ip
    alone: per RelaySourceIpCache's own docstring, multiple ACS appliances
    relayed through the same collector all share one network-level
    source_ip, so source_ip alone could collide two unrelated appliances'
    message-id counters into one corrupted merge. reported_hostname (ACS's
    own configured name, e.g. "ACSSERVER") is already present on every
    segment and reliably distinguishes them even before resolve_identity()
    runs, the same way the relay-hostname resolution path elsewhere in
    this file already relies on it.

    Not persisted across a consumer.py restart -- an in-flight incomplete
    group is lost on restart, same as anything else this process hasn't
    flushed yet. Acceptable: real segments arrive milliseconds apart, so
    a restart landing exactly inside that window is rare, and the
    alternative (persisting a tiny, short-lived buffer) isn't worth the
    complexity for what it'd save.
    """

    def __init__(self):
        self._groups = {}

    def feed(self, record):
        """Returns a list of zero or more ready-to-process records: the
        input record unchanged (non-ACS or non-matching), a merged record
        (group just completed), or nothing yet (still waiting on more
        segments)."""
        program = record.get("program", "") or ""
        message = record.get("message", "") or ""
        if not program.startswith(ACS_PROGRAM_PREFIX):
            return [record]

        match = ACS_SEGMENT_RE.match(message.lstrip(" "))
        if not match:
            return [record]

        message_id, total_str, index_str, content = match.groups()
        total, index = int(total_str), int(index_str)
        if total < 1:
            return [record]

        key = (record.get("source_ip", "unknown"), record.get("reported_hostname", ""), message_id)
        group = self._groups.setdefault(key, {"total": total, "segments": {}, "first_seen": time.monotonic()})
        group["segments"][index] = (content, record.get("raw", ""))
        if index == 0:
            # Segment 0 carries the record's own metadata (timestamp,
            # severity, program, ...) -- continuation segments repeat the
            # same envelope, so segment 0's record is what the merged
            # record is built from.
            group["record"] = record
        group.setdefault("record", record)

        if len(group["segments"]) >= group["total"]:
            del self._groups[key]
            return [self._merge(group)]
        return []

    def flush_stale(self):
        """Call periodically: emits (best-effort, logged as incomplete)
        any group that's been waiting past ACS_REASSEMBLY_TIMEOUT_SECONDS
        for a segment that never arrived, so one lost UDP datagram doesn't
        bury the segments that did make it."""
        now = time.monotonic()
        stale_keys = [
            key for key, group in self._groups.items()
            if now - group["first_seen"] >= ACS_REASSEMBLY_TIMEOUT_SECONDS
        ]
        ready = []
        for key in stale_keys:
            group = self._groups.pop(key)
            log.warning(
                "Cisco ACS message %s incomplete after %.0fs (%d/%d segments) -- emitting what arrived",
                key[2], now - group["first_seen"], len(group["segments"]), group["total"],
            )
            ready.append(self._merge(group))
        return ready

    @staticmethod
    def _merge(group):
        ordered = [group["segments"][i] for i in sorted(group["segments"])]
        record = dict(group["record"])
        record["message"] = "".join(content for content, _raw in ordered)
        record["raw"] = "\n".join(raw for _content, raw in ordered)
        return record


class FileTailer:
    """Polls a file for new lines, surviving restarts and logrotate rotation."""

    def __init__(self, path, offset_path):
        self.path = path
        self.offset_path = offset_path
        self.file = None
        self.inode = None
        self._open()

    def _load_offset(self):
        try:
            with open(self.offset_path) as f:
                return int(f.read().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def _save_offset(self, offset):
        os.makedirs(os.path.dirname(self.offset_path), exist_ok=True)
        tmp_path = self.offset_path + ".tmp"
        with open(tmp_path, "w") as f:
            f.write(str(offset))
        os.replace(tmp_path, self.offset_path)

    def _open(self):
        while not os.path.exists(self.path):
            log.warning("%s does not exist yet, waiting for rsyslog to create it", self.path)
            time.sleep(2)
        self.file = open(self.path, "r")
        self.inode = os.fstat(self.file.fileno()).st_ino
        offset = self._load_offset()
        try:
            self.file.seek(offset)
        except OSError:
            self.file.seek(0)

    def _rotated(self):
        try:
            current_inode = os.stat(self.path).st_ino
        except FileNotFoundError:
            return False
        return current_inode != self.inode

    def readlines(self):
        if self._rotated():
            log.info("Detected log rotation on %s, reopening", self.path)
            self.file.close()
            self._save_offset(0)
            self.file = open(self.path, "r")
            self.inode = os.fstat(self.file.fileno()).st_ino

        lines = self.file.readlines()
        if lines:
            self._save_offset(self.file.tell())
        return lines


def load_classifier():
    if os.path.exists(MODEL_PATH):
        log.info("Loaded trained classifier from %s", MODEL_PATH)
        return joblib.load(MODEL_PATH)
    log.warning("No trained model at %s yet — using weak-supervision rules until one is trained", MODEL_PATH)
    return None


def build_template_miner():
    # TemplateMinerConfig()'s defaults are already sensible on their own;
    # .load(path) is only for overriding from an actual INI file, and
    # (unlike what its docstring might suggest) does not accept None --
    # configparser.read(None) raises, so just skip calling it entirely.
    config = TemplateMinerConfig()
    config.profiling_enabled = False
    config.snapshot_interval_minutes = DRAIN3_SNAPSHOT_INTERVAL_MINUTES
    # Without persistence, every cluster starts from zero on each restart --
    # is_anomaly would then flag a burst of "new" templates after every
    # restart even for traffic that's actually routine. FilePersistence
    # snapshots cluster state periodically and reloads it on startup
    # (verified: a fresh TemplateMiner pointed at an existing snapshot file
    # resumes prior cluster_size counts rather than starting over).
    os.makedirs(os.path.dirname(DRAIN3_STATE_FILE), exist_ok=True)
    persistence = FilePersistence(DRAIN3_STATE_FILE)
    return TemplateMiner(persistence_handler=persistence, config=config)


def classify(model, message):
    if model is not None:
        try:
            proba = model.predict_proba([message])[0]
            idx = proba.argmax()
            return model.classes_[idx], float(proba[idx])
        except Exception:
            log.exception("Classifier inference failed, falling back to rules")
    return weak_label(message), 0.0


class InventoryCache:
    """In-memory ip -> (hostname, vendor, model, resolution_method), refreshed
    periodically from ClickHouse so the hot path never makes a network call."""

    def __init__(self, client):
        self.client = client
        self._cache = {}
        self._last_refresh = 0.0

    def refresh_if_stale(self):
        if time.monotonic() - self._last_refresh < INVENTORY_REFRESH_SECONDS:
            return
        try:
            result = self.client.query(
                "SELECT ip, hostname, vendor, model, resolution_method FROM syslog_ml.device_inventory"
            )
            self._cache = {row[0]: row[1:] for row in result.result_rows}
            self._last_refresh = time.monotonic()
            log.info("Refreshed device inventory cache: %d known devices", len(self._cache))
        except Exception:
            log.exception("Failed to refresh device inventory cache, keeping previous snapshot")

    def lookup(self, ip):
        return self._cache.get(ip)


class RelaySourceIpCache:
    """
    In-memory set of relay/collector IPs, refreshed periodically from the
    web app's relay_source_ips table (admin-managed via the "Relay Source
    IPs" page) -- same pattern as device_resolver.py reading
    snmp_credentials directly from Postgres, not through the web API.

    For an event whose source_ip is in this set, resolve_identity() checks
    reported_hostname for a distinct, well-formed IP address or a real
    non-generic hostname and, if found, uses it as the event's effective
    identity instead of the relay's network source_ip -- otherwise every
    device relayed through the same collector collapses into one row/one
    baseline. It also gates the timestamp sanity-check for relays that
    timestamp in local time instead of UTC. Explicit opt-in per relay IP,
    not an automatic heuristic applied to all traffic: reported_hostname
    is still just a self-reported, spoofable message-body field (see
    rsyslog/60-syslog-ml.conf's comment on why source_ip is normally
    trusted instead), so this only widens that trust for IPs an admin has
    deliberately identified as relays. See README's "If syslog arrives
    relayed through another server" section.

    If DATABASE_URL isn't set, or Postgres is unreachable, this just stays
    empty (or keeps its last known snapshot) -- a relay-detection outage
    degrades to "treat everything as a direct device", not a crash.
    """

    def __init__(self, database_url):
        self.database_url = database_url
        self._ips = set()
        self._last_refresh = 0.0

    def refresh_if_stale(self):
        if not self.database_url:
            return
        if time.monotonic() - self._last_refresh < RELAY_LIST_REFRESH_SECONDS:
            return
        try:
            conn = psycopg2.connect(self.database_url)
        except psycopg2.OperationalError:
            log.exception("Could not connect to Postgres to refresh the relay source IP list, keeping previous snapshot")
            return
        try:
            with conn, conn.cursor() as cur:
                cur.execute("SELECT ip FROM relay_source_ips")
                self._ips = {row[0] for row in cur.fetchall()}
            self._last_refresh = time.monotonic()
            log.info("Refreshed relay source IP list: %d relay(s)", len(self._ips))
        except Exception:
            log.exception("Failed to refresh relay source IP list, keeping previous snapshot")
        finally:
            conn.close()

    def __contains__(self, ip):
        return ip in self._ips


class DeviceBaselineCache:
    """
    Per-device (keyed by source_ip, not hostname -- stable across a device
    going from unresolved to SNMP-verified, unlike its display hostname)
    baselines for two anomaly signals:

      - severity_spike: this device's severity is worse than anything it
        has logged in the baseline window. `_min_severity_rank` tracks the
        lowest (most severe) severity_num seen per device; a new low is
        both flagged AND immediately folded in-memory, so a burst of
        equally-severe events doesn't all re-trigger "new worst" past the
        first one.
      - volume_spike: this device is currently logging far above its own
        historical average rate. Compares the count seen since the last
        refresh against that device's baseline rate, then resets the
        counter -- coarse (per refresh window, not per message) but simple
        and bounded (O(1) state per device).

    A brand-new device has no baseline yet and triggers neither signal
    until it survives at least one refresh cycle -- "unusual for this
    device" is meaningless before we know anything about it.
    """

    def __init__(self, client):
        self.client = client
        self._min_severity_rank = {}
        self._baseline_rate_per_min = {}
        self._recent_count = {}
        self._spiking = set()
        self._last_refresh = 0.0

    def refresh_if_stale(self):
        if time.monotonic() - self._last_refresh < BASELINE_REFRESH_SECONDS:
            return
        try:
            result = self.client.query(f"""
                SELECT
                    source_ip,
                    min(severity_num) AS min_severity_rank,
                    count() / greatest(dateDiff('minute', min(event_time), max(event_time)), 1) AS rate_per_min
                FROM syslog_ml.events
                WHERE event_time >= now() - INTERVAL {BASELINE_WINDOW_DAYS} DAY
                GROUP BY source_ip
            """)
            new_min_severity = {}
            new_rate = {}
            for source_ip, min_sev, rate in result.result_rows:
                new_min_severity[source_ip] = min_sev
                new_rate[source_ip] = rate

            elapsed_minutes = (
                (time.monotonic() - self._last_refresh) / 60.0 if self._last_refresh else BASELINE_REFRESH_SECONDS / 60.0
            )
            spiking = set()
            for source_ip, count in self._recent_count.items():
                baseline = self._baseline_rate_per_min.get(source_ip)
                if baseline and elapsed_minutes > 0 and (count / elapsed_minutes) >= baseline * VOLUME_SPIKE_MULTIPLIER:
                    spiking.add(source_ip)

            self._min_severity_rank = new_min_severity
            self._baseline_rate_per_min = new_rate
            self._recent_count = {}
            self._spiking = spiking
            self._last_refresh = time.monotonic()
            log.info(
                "Refreshed device baseline cache: %d device(s), %d currently volume-spiking",
                len(new_min_severity), len(spiking),
            )
        except Exception:
            log.exception("Failed to refresh device baseline cache, keeping previous snapshot")

    def record_event(self, source_ip):
        self._recent_count[source_ip] = self._recent_count.get(source_ip, 0) + 1

    def is_severity_spike(self, source_ip, severity_rank_value):
        prior_min = self._min_severity_rank.get(source_ip)
        if prior_min is None or severity_rank_value >= prior_min:
            return False
        self._min_severity_rank[source_ip] = severity_rank_value
        return True

    def is_volume_spiking(self, source_ip):
        return source_ip in self._spiking


def _distinct_relayed_ip(candidate, network_source_ip):
    """
    True/normalized-IP if `candidate` (reported_hostname) is a well-formed
    IP address different from the relay's own network_source_ip -- i.e.
    looks like the real origin device's address, not just an echo of the
    relay or an arbitrary non-IP string.
    """
    if not candidate or candidate == network_source_ip:
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


# Values devices fall back to when they have no real identity configured
# (e.g. a RouterOS device with no /system identity set) -- not
# distinguishing, so never worth treating as a device's identity even
# though they're technically a non-empty, non-IP string. Applies whether
# or not the traffic came through a listed relay: a device that reports
# one of these directly (no relay involved at all) is exactly as
# unidentifying as one that reports it via a relay.
_GENERIC_HOSTNAMES = {"localhost", "localhost.localdomain"}


def _distinct_relayed_hostname(candidate, relay_hostname):
    """
    True if `candidate` (reported_hostname) is a real, distinguishing
    hostname for a relayed event -- not an IP (that's _distinct_relayed_ip's
    job, since only an IP can be SNMP-polled), not empty, not one of the
    generic placeholders above, and not just an echo of the relay's own
    already-known identity.
    """
    if not candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
        return False
    except ValueError:
        pass
    if candidate.lower() in _GENERIC_HOSTNAMES:
        return False
    if relay_hostname and candidate == relay_hostname:
        return False
    return True


def resolve_identity(record, inventory, relay_ips, state_conn, seen_unresolved):
    network_source_ip = record.get("source_ip", "unknown")
    reported_hostname = record.get("reported_hostname", "") or ""

    relayed_via = ""
    source_ip = network_source_ip
    if network_source_ip in relay_ips:
        origin_ip = _distinct_relayed_ip(reported_hostname, network_source_ip)
        if origin_ip is not None:
            relayed_via = network_source_ip
            source_ip = origin_ip
        else:
            relay_known = inventory.lookup(network_source_ip)
            relay_hostname = relay_known[0] if relay_known else None
            if _distinct_relayed_hostname(reported_hostname, relay_hostname):
                # A real, distinguishing hostname (e.g. a Cisco ACS
                # appliance's own name) but not an IP -- nothing to
                # SNMP-poll, so this is a final syslog_reported identity,
                # not a pending resolution candidate like the IP case
                # above. Grouped/keyed by the hostname string itself.
                detected_vendor = detect_vendor(record.get("message", ""))
                vendor_source = "passive" if detected_vendor != "unknown" else "unknown"
                return (
                    reported_hostname, reported_hostname, reported_hostname, network_source_ip,
                    detected_vendor, "", "syslog_reported", vendor_source,
                )

    known = inventory.lookup(source_ip)
    if known is not None:
        hostname, vendor, model, resolution_method = known
        return source_ip, hostname, reported_hostname, relayed_via, vendor, model, resolution_method, "snmp"

    # No SNMP-verified identity yet. Use the device's self-reported hostname
    # as a best-effort fallback if it looks meaningful, otherwise fall back
    # to the bare IP — either way this is flagged, not presented as verified.
    # A generic placeholder (e.g. an unconfigured device's default
    # "localhost.localdomain") is worse than useless here: it's less
    # identifying than the IP it would replace, so it's excluded the same
    # way the relay path already excludes it from _distinct_relayed_hostname.
    if reported_hostname and reported_hostname != source_ip and reported_hostname.lower() not in _GENERIC_HOSTNAMES:
        resolution_method = "syslog_reported"
        hostname = reported_hostname
    else:
        resolution_method = "unresolved"
        hostname = source_ip

    if source_ip not in seen_unresolved:
        seen_unresolved.add(source_ip)
        state_db.mark_seen(state_conn, source_ip)

    # Vendor is still worth a best-effort passive guess even when hostname
    # isn't resolved -- see vendor_signatures.py. vendor_source distinguishes
    # this from an SNMP-verified vendor so nothing downstream treats a
    # message-format guess as confirmed identity.
    detected_vendor = detect_vendor(record.get("message", ""))
    vendor_source = "passive" if detected_vendor != "unknown" else "unknown"

    return source_ip, hostname, reported_hostname, relayed_via, detected_vendor, "", resolution_method, vendor_source


def to_row(record, miner, model, inventory, relay_ips, baselines, state_conn, seen_unresolved):
    message = record.get("message", "")
    cluster = miner.add_log_message(message)
    timestamp = record.get("timestamp")
    try:
        event_time = datetime.fromisoformat(timestamp) if timestamp else datetime.now(timezone.utc)
    except ValueError:
        event_time = datetime.now(timezone.utc)
    if RELAY_TIMEZONE_OFFSET_HOURS and record.get("source_ip") in relay_ips:
        now = datetime.now(timezone.utc)
        if event_time - now > timedelta(minutes=RELAY_TIMEZONE_FUTURE_TOLERANCE_MINUTES):
            candidate = event_time - timedelta(hours=RELAY_TIMEZONE_OFFSET_HOURS)
            if abs((candidate - now).total_seconds()) < abs((event_time - now).total_seconds()):
                event_time = candidate

    category, confidence = classify(model, message)
    severity = record.get("severity", "info")

    pid_raw = record.get("pid")
    try:
        pid = int(pid_raw) if pid_raw not in (None, "") else None
    except (TypeError, ValueError):
        pid = None

    source_ip, hostname, reported_hostname, relayed_via, vendor, dev_model, resolution_method, vendor_source = (
        resolve_identity(record, inventory, relay_ips, state_conn, seen_unresolved)
    )
    severity_num = severity_rank(severity)

    reasons = []
    if cluster["cluster_size"] <= ANOMALY_RARE_THRESHOLD:
        reasons.append("rare_template")
    if is_always_severe(severity):
        reasons.append("always_severe")
    if is_security_content(message):
        reasons.append("security_content")
    if baselines.is_severity_spike(source_ip, severity_num):
        reasons.append("severity_spike")
    if baselines.is_volume_spiking(source_ip):
        reasons.append("volume_spike")
    baselines.record_event(source_ip)

    is_anomaly = 1 if reasons else 0

    return [
        event_time, source_ip, hostname, reported_hostname, relayed_via, vendor, vendor_source, dev_model,
        resolution_method, record.get("facility", "unknown"), severity, severity_num,
        record.get("program", "unknown"), pid, message,
        str(cluster["cluster_id"]), cluster["template_mined"],
        category, confidence, is_anomaly, reasons, record.get("raw", message),
    ]


def parse_record(line):
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        log.warning("Skipping malformed JSON line: %.200s", line)
        return None
    if "message" not in record:
        return None
    return record


def main():
    model = load_classifier()
    miner = build_template_miner()
    state_conn = state_db.connect(STATE_DB_PATH)
    seen_unresolved = set()

    ch_client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD
    )
    inventory = InventoryCache(ch_client)
    baselines = DeviceBaselineCache(ch_client)
    relay_ips = RelaySourceIpCache(DATABASE_URL)
    template_mix = TemplateMixAnomalyDetector(ch_client)
    sequence_anomaly = SequenceAnomalyDetector(ch_client)
    acs_reassembler = AcsMultipartReassembler()

    tailer = FileTailer(LOG_FILE, OFFSET_FILE)

    log.info("Tailing %s -> ClickHouse %s:%s", LOG_FILE, CLICKHOUSE_HOST, CLICKHOUSE_PORT)

    batch = []
    last_flush = time.monotonic()

    while True:
        inventory.refresh_if_stale()
        baselines.refresh_if_stale()
        relay_ips.refresh_if_stale()
        template_mix.refresh_if_stale()
        sequence_anomaly.refresh_if_stale()
        lines = tailer.readlines()

        for line in lines:
            record = parse_record(line)
            if record is None:
                continue
            for ready in acs_reassembler.feed(record):
                batch.append(to_row(ready, miner, model, inventory, relay_ips, baselines, state_conn, seen_unresolved))

        for ready in acs_reassembler.flush_stale():
            batch.append(to_row(ready, miner, model, inventory, relay_ips, baselines, state_conn, seen_unresolved))

        should_flush = len(batch) >= BATCH_SIZE or (time.monotonic() - last_flush) >= BATCH_FLUSH_SECONDS
        if should_flush and batch:
            try:
                ch_client.insert("syslog_ml.events", batch, column_names=INSERT_COLUMNS)
            except Exception:
                log.exception("Failed to insert batch of %d rows", len(batch))
            batch = []
            last_flush = time.monotonic()

        if not lines:
            time.sleep(POLL_IDLE_SECONDS)


if __name__ == "__main__":
    main()
