import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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
