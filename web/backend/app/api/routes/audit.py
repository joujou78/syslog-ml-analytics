from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.db.base import get_db
from app.db.models import Role
from app.schemas.audit import AuditLogRead
from app.services import audit_service

router = APIRouter(prefix="/audit", tags=["audit"])

# Admin-only: this is a record of every administrative action across the
# whole system (alert rules, SNMP credentials, relay IPs, anomaly
# acknowledgments, query console usage) -- broader-reaching than any single
# one of those pages, so it gets the strictest existing role rather than
# the analyst-inclusive one alerts/credentials individually use.
_can_view = require_role(Role.admin)


@router.get("", response_model=list[AuditLogRead])
async def list_audit_log(
    db: AsyncSession = Depends(get_db),
    _user=Depends(_can_view),
    actor_id: UUID | None = None,
    action: str | None = None,
    since: datetime | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
):
    return await audit_service.list_audit_log(db, actor_id=actor_id, action=action, since=since, limit=limit)


@router.get("/actions", response_model=list[str])
async def list_actions(db: AsyncSession = Depends(get_db), _user=Depends(_can_view)):
    return await audit_service.list_actions(db)
