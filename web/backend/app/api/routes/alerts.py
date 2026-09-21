import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_role
from app.db.base import get_db
from app.db.models import Role, User
from app.schemas.alert import AlertEventRead, AlertRuleCreate, AlertRuleRead, AlertRuleUpdate
from app.services import alert_service

router = APIRouter(prefix="/alerts", tags=["alerts"])

# Viewing rules/history is fine for any authenticated role (read-only, no
# secrets); only admin/analyst can create rules with side effects (a
# webhook firing, evaluator load) -- same split as /devices vs /credentials,
# but less strict than credentials since a rule has no secret in it.
_authenticated = Depends(get_current_user)
_can_manage = require_role(Role.admin, Role.analyst)


@router.get("/rules", response_model=list[AlertRuleRead])
async def list_rules(_user=_authenticated, db: AsyncSession = Depends(get_db)):
    return await alert_service.list_rules(db)


@router.post("/rules", response_model=AlertRuleRead, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: AlertRuleCreate, db: AsyncSession = Depends(get_db), actor: User = Depends(_can_manage)
):
    try:
        return await alert_service.create_rule(db, payload, actor)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A rule with this name already exists")


@router.put("/rules/{rule_id}", response_model=AlertRuleRead)
async def update_rule(
    rule_id: uuid.UUID,
    payload: AlertRuleUpdate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(_can_manage),
):
    updated = await alert_service.update_rule(db, rule_id, payload, actor)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return updated


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: uuid.UUID, db: AsyncSession = Depends(get_db), actor: User = Depends(_can_manage)):
    deleted = await alert_service.delete_rule(db, rule_id, actor)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")


@router.get("/history", response_model=list[AlertEventRead])
async def list_history(
    _user=_authenticated,
    db: AsyncSession = Depends(get_db),
    rule_id: uuid.UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    return await alert_service.list_events(db, rule_id=rule_id, limit=limit)
