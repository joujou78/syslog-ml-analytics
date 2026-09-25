from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog, User
from app.schemas.audit import AuditLogRead


async def list_audit_log(
    db: AsyncSession,
    actor_id: UUID | None = None,
    action: str | None = None,
    since: datetime | None = None,
    limit: int = 200,
) -> list[AuditLogRead]:
    # Outer join, not inner: actor_id is nullable (a system-initiated entry
    # has no actor) and a user can be deleted after the fact without losing
    # the historical record of what they did -- the audit trail must
    # outlive the account, same reasoning as AlertEvent not cascading on
    # AlertRule deletion.
    query = (
        select(AuditLog, User.username)
        .outerjoin(User, AuditLog.actor_id == User.id)
        .order_by(AuditLog.created_at.desc())
        .limit(min(limit, 1000))
    )
    if actor_id is not None:
        query = query.where(AuditLog.actor_id == actor_id)
    if action is not None:
        query = query.where(AuditLog.action == action)
    if since is not None:
        query = query.where(AuditLog.created_at >= since)

    result = await db.execute(query)
    return [
        AuditLogRead(
            id=row.id,
            actor_id=row.actor_id,
            actor_username=username,
            action=row.action,
            target=row.target,
            details=row.details,
            created_at=row.created_at,
        )
        for row, username in result.all()
    ]


async def list_actions(db: AsyncSession) -> list[str]:
    """Distinct action values seen so far, for the frontend's filter
    dropdown -- avoids hardcoding the list in two places (every _log_audit
    call site across alert_service/credential_service/relay_service/
    anomaly_summary_service/query_console already defines its own action
    strings; this just reflects them back)."""
    result = await db.execute(select(AuditLog.action).distinct().order_by(AuditLog.action))
    return list(result.scalars().all())
