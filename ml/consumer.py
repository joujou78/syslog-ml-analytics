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
import json
import logging
import os
import time
from datetime import datetime, timezone

import clickhouse_connect
import joblib
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

import state_db
from labeling_rules import weak_label, severity_rank

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

INSERT_COLUMNS = [
    "event_time", "source_ip", "hostname", "reported_hostname", "vendor", "model",
    "resolution_method", "facility", "severity", "severity_num", "program", "pid",
    "message", "template_id", "template", "predicted_category", "predicted_confidence",
    "is_anomaly", "raw",
]


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
    config = TemplateMinerConfig()
    config.load(None)
    config.profiling_enabled = False
    return TemplateMiner(config=config)


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


def resolve_identity(record, inventory, state_conn, seen_unresolved):
    source_ip = record.get("source_ip", "unknown")
    reported_hostname = record.get("reported_hostname", "") or ""

    known = inventory.lookup(source_ip)
    if known is not None:
        hostname, vendor, model, resolution_method = known
        return source_ip, hostname, reported_hostname, vendor, model, resolution_method

    # No SNMP-verified identity yet. Use the device's self-reported hostname
    # as a best-effort fallback if it looks meaningful, otherwise fall back
    # to the bare IP — either way this is flagged, not presented as verified.
    if reported_hostname and reported_hostname != source_ip:
        resolution_method = "syslog_reported"
        hostname = reported_hostname
    else:
        resolution_method = "unresolved"
        hostname = source_ip

    if source_ip not in seen_unresolved:
        seen_unresolved.add(source_ip)
        state_db.mark_seen(state_conn, source_ip)

    return source_ip, hostname, reported_hostname, "unknown", "", resolution_method


def to_row(record, miner, model, inventory, state_conn, seen_unresolved):
    message = record.get("message", "")
    cluster = miner.add_log_message(message)
    timestamp = record.get("timestamp")
    try:
        event_time = datetime.fromisoformat(timestamp) if timestamp else datetime.now(timezone.utc)
    except ValueError:
        event_time = datetime.now(timezone.utc)

    category, confidence = classify(model, message)
    severity = record.get("severity", "info")

    pid_raw = record.get("pid")
    try:
        pid = int(pid_raw) if pid_raw not in (None, "") else None
    except (TypeError, ValueError):
        pid = None

    source_ip, hostname, reported_hostname, vendor, dev_model, resolution_method = resolve_identity(
        record, inventory, state_conn, seen_unresolved
    )

    return [
        event_time, source_ip, hostname, reported_hostname, vendor, dev_model, resolution_method,
        record.get("facility", "unknown"), severity, severity_rank(severity),
        record.get("program", "unknown"), pid, message,
        str(cluster["cluster_id"]), cluster["template_mined"],
        category, confidence, 0, record.get("raw", message),
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

    tailer = FileTailer(LOG_FILE, OFFSET_FILE)

    log.info("Tailing %s -> ClickHouse %s:%s", LOG_FILE, CLICKHOUSE_HOST, CLICKHOUSE_PORT)

    batch = []
    last_flush = time.monotonic()

    while True:
        inventory.refresh_if_stale()
        lines = tailer.readlines()

        for line in lines:
            record = parse_record(line)
            if record is None:
                continue
            batch.append(to_row(record, miner, model, inventory, state_conn, seen_unresolved))

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
