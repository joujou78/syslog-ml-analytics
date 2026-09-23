import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.db.base import get_db
from app.db.models import Role, User
from app.schemas.relay import RelaySourceIpCreate, RelaySourceIpRead
from app.services import relay_service
from app.services.relay_service import DuplicateRelayError

router = APIRouter(prefix="/relays", tags=["relays"])

# Same reasoning as /credentials: this list widens how much the pipeline
# trusts a self-reported field in incoming messages, so only admins should
# be able to add to it.
_admin_only = require_role(Role.admin)


@router.get("", response_model=list[RelaySourceIpRead])
async def list_relays(db: AsyncSession = Depends(get_db), _admin: User = Depends(_admin_only)):
    return await relay_service.list_relay_source_ips(db)


@router.post("", response_model=RelaySourceIpRead, status_code=status.HTTP_201_CREATED)
async def create_relay(
    payload: RelaySourceIpCreate, db: AsyncSession = Depends(get_db), admin: User = Depends(_admin_only)
):
    try:
        return await relay_service.create_relay_source_ip(db, payload, admin)
    except DuplicateRelayError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This IP is already in the relay list")


@router.delete("/{relay_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_relay(relay_id: uuid.UUID, db: AsyncSession = Depends(get_db), admin: User = Depends(_admin_only)):
    deleted = await relay_service.delete_relay_source_ip(db, relay_id, admin)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Relay entry not found")
