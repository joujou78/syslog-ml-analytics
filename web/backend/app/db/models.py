import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, JSON, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Role(str, enum.Enum):
    admin = "admin"       # manage users + SNMP credentials
    analyst = "analyst"   # search logs, review/correct ML classifications
    viewer = "viewer"     # read-only


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role, name="user_role"), default=Role.viewer, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SnmpCredential(Base):
    """
    Replaces the earlier flat-file snmp_credentials.csv: same purpose
    (opt-in, per-IP/subnet SNMP creds for the resolver, never a guessed
    default), now with an admin-only UI, audit trail, and encryption at
    rest for community/passphrase fields instead of a plaintext file.

    ip_or_cidr is intentionally NOT unique: a "credential pool" entry
    (many rows sharing one broad ip_or_cidr, e.g. 0.0.0.0/0, each with a
    different community) lets the resolver try each known community
    against a device until one actually authenticates via a real SNMP
    response -- never a blind guess of an unknown/default string, only
    ever from communities the admin has explicitly entered as theirs.
    Once one matches a specific IP, the resolver saves it as that IP's
    own credential (auto_discovered=True) so future cycles query that
    device directly instead of re-trying the whole pool.
    """
    __tablename__ = "snmp_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_or_cidr: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    version: Mapped[str] = mapped_column(String(8), nullable=False)  # v1 | v2c | v3
    auto_discovered: Mapped[bool] = mapped_column(default=False, nullable=False)

    # v1/v2c
    community_encrypted: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # v3
    v3_user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    v3_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    v3_auth_proto: Mapped[str | None] = mapped_column(String(16), nullable=True)
    v3_auth_pass_encrypted: Mapped[str | None] = mapped_column(String(512), nullable=True)
    v3_priv_proto: Mapped[str | None] = mapped_column(String(16), nullable=True)
    v3_priv_pass_encrypted: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    created_by_user: Mapped["User"] = relationship()


class RelaySourceIp(Base):
    """
    Admin-managed allowlist of syslog relay/collector IPs (e.g. an existing
    LogAnalyzer setup) that forward other devices' messages here rather
    than sending their own logs directly. Read directly from Postgres by
    ml/consumer.py's RelaySourceIpCache (same pattern as SnmpCredential
    being read by device_resolver.py) -- not through the web API.

    Deliberately an explicit, admin-curated list rather than applied to
    all traffic: for a listed IP, ml/consumer.py trusts that event's
    self-reported `reported_hostname` field enough to use it as the
    event's identity (recovering per-device analytics that would
    otherwise collapse into one row behind the relay) and applies a
    timestamp sanity-check for relays that timestamp in local time
    instead of UTC. reported_hostname is a self-reported, spoofable
    message-body field (see rsyslog/60-syslog-ml.conf's comment on why
    source_ip is normally trusted instead of it) -- widening that trust
    only makes sense for network sources an admin has deliberately
    identified as relays, never for arbitrary traffic. See README's "If
    syslog arrives relayed through another server" section.
    """
    __tablename__ = "relay_source_ips"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ClassificationFeedback(Base):
    """
    Phase 3 (ML feedback loop) table — schema created now so it doesn't
    require another migration later, but no API/UI reads or writes it yet.
    `event_id` references syslog_ml.events.event_id in ClickHouse (a UUID
    generated at insert time); there's no cross-database foreign key, this
    is a logical reference only.
    """
    __tablename__ = "classification_feedback"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True, nullable=False)
    message: Mapped[str] = mapped_column(String, nullable=False)
    predicted_category: Mapped[str] = mapped_column(String(32), nullable=False)
    corrected_category: Mapped[str] = mapped_column(String(32), nullable=False)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AlertRule(Base):
    """
    A rule is the same shape of filter as log search (hostname/source_ip/
    program/severity/predicted_category, plus an anomaly-only toggle) with
    a count threshold over a trailing window -- deliberately not a general
    expression language, since every condition anyone has asked for so far
    reduces to "N or more matching events in the last M minutes".
    Evaluated by ml/evaluate_alerts.py, not by this web process.
    """
    __tablename__ = "alert_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

    window_minutes: Mapped[int] = mapped_column(nullable=False, default=5)
    threshold: Mapped[int] = mapped_column(nullable=False, default=1)
    cooldown_minutes: Mapped[int] = mapped_column(nullable=False, default=15)

    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    program: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    predicted_category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    only_anomalies: Mapped[bool] = mapped_column(default=False, nullable=False)

    webhook_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AlertEvent(Base):
    """One row per time a rule actually fired (after its cooldown allowed it)."""
    __tablename__ = "alert_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("alert_rules.id"), index=True, nullable=False)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    matched_count: Mapped[int] = mapped_column(nullable=False)
    sample_message: Mapped[str] = mapped_column(String, nullable=False, default="")
    notified: Mapped[bool] = mapped_column(default=False, nullable=False)
    notify_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    rule: Mapped["AlertRule"] = relationship()


class AnomalyAcknowledgment(Base):
    """
    A persistent "we've seen and handled this" flag per (device, anomaly
    type) pair -- e.g. severity_spike on 10.0.0.1 -- surfaced on the
    Anomaly Summary page. Deliberately simple: one row per pair (upserted,
    not append-only), and it stays acknowledged until someone explicitly
    un-acknowledges it -- it does NOT automatically go stale just because
    a new matching event arrives later. That's a real tradeoff (a
    genuinely recurring problem can go unnoticed if nobody thinks to
    re-check an old ack), chosen deliberately over the alternative
    (auto-reset on any new occurrence) because the operator wanted a
    stable "handled" flag rather than one that flips back on every
    recurrence.

    anomaly_reason is one of events.anomaly_reasons' values (rare_template
    | always_severe | security_content | severity_spike | volume_spike |
    unusual_template_mix) but not a DB-level foreign key, since that
    array lives in ClickHouse, not Postgres -- logical reference only,
    same as ClassificationFeedback.event_id.
    """
    __tablename__ = "anomaly_acknowledgments"
    __table_args__ = (UniqueConstraint("source_ip", "anomaly_reason", name="uq_anomaly_ack_device_reason"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    anomaly_reason: Mapped[str] = mapped_column(String(64), nullable=False)
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)

    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DeviceSilenceState(Base):
    """
    Currently-silent devices: a device whose own historical logging rate
    would predict activity by now, but hasn't logged in that long.
    Evaluated by ml/detect_silent_devices.py, not by this web process --
    same reasoning as AlertRule/AlertEvent being evaluated by
    evaluate_alerts.py (see that script's own module docstring for why
    a device-relative threshold is used instead of a fixed timeout).

    One row per currently-silent device (upserted, keyed by source_ip,
    not a surrogate UUID -- there's exactly one live state per device,
    never a history of past silences), deleted entirely once the device
    logs again -- this table always reflects live state, not history,
    same "currently true" semantics as AnomalyAcknowledgment rather than
    AlertEvent's append-only log.
    """
    __tablename__ = "device_silence_state"

    source_ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expected_interval_minutes: Mapped[float] = mapped_column(nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    silence_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
