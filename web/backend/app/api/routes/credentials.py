import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.db.base import get_db
from app.db.models import Role, User
from app.schemas.credential import CredentialCreate, CredentialPoolImport, CredentialRead, CredentialUpdate
from app.services import credential_service
from app.services.credential_service import DuplicateCredentialError

router = APIRouter(prefix="/credentials", tags=["credentials"])

# SNMP credentials are read/written by admins only — they're what lets the
# resolver authenticate to network devices.
_admin_only = require_role(Role.admin)


@router.get("", response_model=list[CredentialRead])
async def list_credentials(db: AsyncSession = Depends(get_db), _admin: User = Depends(_admin_only)):
    return await credential_service.list_credentials(db)


@router.post("", response_model=CredentialRead, status_code=status.HTTP_201_CREATED)
async def create_credential(
    payload: CredentialCreate, db: AsyncSession = Depends(get_db), admin: User = Depends(_admin_only)
):
    try:
        return await credential_service.create_credential(db, payload, admin)
    except DuplicateCredentialError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A credential for this IP/CIDR already exists")


@router.post("/bulk-pool", status_code=status.HTTP_201_CREATED)
async def import_credential_pool(
    payload: CredentialPoolImport, db: AsyncSession = Depends(get_db), admin: User = Depends(_admin_only)
):
    count = await credential_service.import_pool(db, payload, admin)
    return {"imported": count}


@router.put("/{credential_id}", response_model=CredentialRead)
async def update_credential(
    credential_id: uuid.UUID,
    payload: CredentialUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(_admin_only),
):
    updated = await credential_service.update_credential(db, credential_id, payload, admin)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
    return updated


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    credential_id: uuid.UUID, db: AsyncSession = Depends(get_db), admin: User = Depends(_admin_only)
):
    deleted = await credential_service.delete_credential(db, credential_id, admin)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found")
