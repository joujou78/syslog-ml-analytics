import csv
import io
import uuid
from datetime import datetime
from xml.sax.saxutils import escape

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models import AlertEvent, AlertRule, AuditLog, User
from app.schemas.alert import AlertEventRead, AlertRuleCreate, AlertRuleRead, AlertRuleUpdate


async def _log_audit(db: AsyncSession, actor: User, action: str, target: str) -> None:
    db.add(AuditLog(actor_id=actor.id, action=action, target=target))


async def list_rules(db: AsyncSession) -> list[AlertRuleRead]:
    result = await db.execute(select(AlertRule).order_by(AlertRule.name))
    return [AlertRuleRead.model_validate(r) for r in result.scalars().all()]


async def create_rule(db: AsyncSession, payload: AlertRuleCreate, actor: User) -> AlertRuleRead:
    rule = AlertRule(**payload.model_dump(), created_by=actor.id)
    db.add(rule)
    await _log_audit(db, actor, "alert_rule.create", payload.name)
    await db.commit()
    await db.refresh(rule)
    return AlertRuleRead.model_validate(rule)


async def update_rule(
    db: AsyncSession, rule_id: uuid.UUID, payload: AlertRuleUpdate, actor: User
) -> AlertRuleRead | None:
    rule = await db.get(AlertRule, rule_id)
    if rule is None:
        return None
    for field, value in payload.model_dump().items():
        setattr(rule, field, value)
    await _log_audit(db, actor, "alert_rule.update", rule.name)
    await db.commit()
    await db.refresh(rule)
    return AlertRuleRead.model_validate(rule)


async def delete_rule(db: AsyncSession, rule_id: uuid.UUID, actor: User) -> bool:
    rule = await db.get(AlertRule, rule_id)
    if rule is None:
        return False
    await _log_audit(db, actor, "alert_rule.delete", rule.name)
    await db.delete(rule)
    await db.commit()
    return True


async def list_events(db: AsyncSession, rule_id: uuid.UUID | None = None, limit: int = 100) -> list[AlertEventRead]:
    query = select(AlertEvent).order_by(AlertEvent.triggered_at.desc()).limit(min(limit, 500))
    if rule_id is not None:
        query = query.where(AlertEvent.rule_id == rule_id)
    result = await db.execute(query)
    return [AlertEventRead.model_validate(e) for e in result.scalars().all()]


class AlertEventExportRow(BaseModel):
    rule_name: str
    triggered_at: datetime
    window_start: datetime
    window_end: datetime
    matched_count: int
    sample_message: str
    notified: bool
    notify_error: str | None
    email_notified: bool
    email_notify_error: str | None


_EVENT_EXPORT_COLUMNS = [
    "rule_name", "triggered_at", "window_start", "window_end", "matched_count",
    "sample_message", "notified", "notify_error", "email_notified", "email_notify_error",
]


async def list_events_for_export(db: AsyncSession, rule_id: uuid.UUID | None = None) -> list[AlertEventExportRow]:
    """Every trigger ever recorded, not just the most recent `limit` the
    live history view shows -- a report is meant to be a complete record
    to keep or hand off, not a snapshot of whatever page the UI happened
    to be showing. Eager-loads `rule` (selectinload, not the default lazy
    load) since async SQLAlchemy can't lazy-load a relationship attribute
    after the session's query has returned -- needed here for rule_name,
    which the live page instead looks up client-side against its own
    already-fetched rules list (see Alerts.tsx's ruleName helper)."""
    query = select(AlertEvent).options(selectinload(AlertEvent.rule)).order_by(AlertEvent.triggered_at.desc())
    if rule_id is not None:
        query = query.where(AlertEvent.rule_id == rule_id)
    result = await db.execute(query)
    return [
        AlertEventExportRow(
            rule_name=e.rule.name, triggered_at=e.triggered_at, window_start=e.window_start,
            window_end=e.window_end, matched_count=e.matched_count, sample_message=e.sample_message,
            notified=e.notified, notify_error=e.notify_error, email_notified=e.email_notified,
            email_notify_error=e.email_notify_error,
        )
        for e in result.scalars().all()
    ]


def _fmt(value) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None:
        return ""
    return str(value)


def _export_csv(rows: list, columns: list[str]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    for r in rows:
        writer.writerow([_fmt(getattr(r, col)) for col in columns])
    return buf.getvalue().encode("utf-8")


def _export_xml(rows: list, columns: list[str], root: str) -> bytes:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', f"<{root}>"]
    for r in rows:
        lines.append("  <row>")
        for col in columns:
            lines.append(f"    <{col}>{escape(_fmt(getattr(r, col)))}</{col}>")
        lines.append("  </row>")
    lines.append(f"</{root}>")
    return "\n".join(lines).encode("utf-8")


def export_events_csv(rows: list[AlertEventExportRow]) -> bytes:
    return _export_csv(rows, _EVENT_EXPORT_COLUMNS)


def export_events_xml(rows: list[AlertEventExportRow]) -> bytes:
    return _export_xml(rows, _EVENT_EXPORT_COLUMNS, "alert_events")
