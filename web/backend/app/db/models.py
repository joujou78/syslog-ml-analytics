import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, JSON, String, func
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
    """
    __tablename__ = "snmp_credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_or_cidr: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    version: Mapped[str] = mapped_column(String(8), nullable=False)  # v1 | v2c | v3

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


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
