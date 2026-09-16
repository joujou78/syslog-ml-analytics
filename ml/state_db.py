"""
Shared local SQLite state, used by both consumer.py and resolve_pending.py.
Two independent processes touch this file (consumer writes newly-seen
unresolved IPs, the resolver drains them), so every write commits
immediately rather than batching across process boundaries.
"""
import os
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_ips (
    ip             TEXT PRIMARY KEY,
    first_seen     TEXT NOT NULL,
    last_attempt   TEXT,
    attempt_count  INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'pending'
);
"""


def connect(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(SCHEMA)
    conn.commit()
    return conn


def mark_seen(conn, ip):
    """Queues an IP for later SNMP resolution attempts if it isn't already tracked."""
    conn.execute(
        "INSERT OR IGNORE INTO pending_ips (ip, first_seen) VALUES (?, ?)",
        (ip, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
