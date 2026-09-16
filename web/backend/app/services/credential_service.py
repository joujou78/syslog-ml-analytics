import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_secret
from app.db.models import AuditLog, SnmpCredential, User
from app.schemas.credential import CredentialCreate, CredentialRead, CredentialUpdate


def _to_read_schema(cred: SnmpCredential) -> CredentialRead:
    return CredentialRead(
        id=cred.id,
        ip_or_cidr=cred.ip_or_cidr,
        version=cred.version,
        v3_user=cred.v3_user,
        v3_level=cred.v3_level,
        created_at=cred.created_at,
        updated_at=cred.updated_at,
        has_community=cred.community_encrypted is not None,
        has_v3_auth=cred.v3_auth_pass_encrypted is not None,
        has_v3_priv=cred.v3_priv_pass_encrypted is not None,
    )


async def list_credentials(db: AsyncSession) -> list[CredentialRead]:
    result = await db.execute(select(SnmpCredential).order_by(SnmpCredential.ip_or_cidr))
    return [_to_read_schema(c) for c in result.scalars().all()]


async def _log_audit(db: AsyncSession, actor: User, action: str, target: str) -> None:
    db.add(AuditLog(actor_id=actor.id, action=action, target=target))


async def create_credential(db: AsyncSession, payload: CredentialCreate, actor: User) -> CredentialRead:
    cred = SnmpCredential(
        ip_or_cidr=payload.ip_or_cidr,
        version=payload.version,
        community_encrypted=encrypt_secret(payload.community),
        v3_user=payload.v3_user,
        v3_level=payload.v3_level,
        v3_auth_proto=payload.v3_auth_proto,
        v3_auth_pass_encrypted=encrypt_secret(payload.v3_auth_pass),
        v3_priv_proto=payload.v3_priv_proto,
        v3_priv_pass_encrypted=encrypt_secret(payload.v3_priv_pass),
        created_by=actor.id,
    )
    db.add(cred)
    await _log_audit(db, actor, "credential.create", payload.ip_or_cidr)
    await db.commit()
    await db.refresh(cred)
    return _to_read_schema(cred)


async def update_credential(
    db: AsyncSession, credential_id: uuid.UUID, payload: CredentialUpdate, actor: User
) -> CredentialRead | None:
    cred = await db.get(SnmpCredential, credential_id)
    if cred is None:
        return None

    cred.ip_or_cidr = payload.ip_or_cidr
    cred.version = payload.version
    # Only overwrite a secret if a new value was actually submitted — an
    # empty field means "leave unchanged", never "clear this credential".
    if payload.community:
        cred.community_encrypted = encrypt_secret(payload.community)
    cred.v3_user = payload.v3_user
    cred.v3_level = payload.v3_level
    cred.v3_auth_proto = payload.v3_auth_proto
    if payload.v3_auth_pass:
        cred.v3_auth_pass_encrypted = encrypt_secret(payload.v3_auth_pass)
    cred.v3_priv_proto = payload.v3_priv_proto
    if payload.v3_priv_pass:
        cred.v3_priv_pass_encrypted = encrypt_secret(payload.v3_priv_pass)

    await _log_audit(db, actor, "credential.update", cred.ip_or_cidr)
    await db.commit()
    await db.refresh(cred)
    return _to_read_schema(cred)


async def delete_credential(db: AsyncSession, credential_id: uuid.UUID, actor: User) -> bool:
    cred = await db.get(SnmpCredential, credential_id)
    if cred is None:
        return False
    await _log_audit(db, actor, "credential.delete", cred.ip_or_cidr)
    await db.delete(cred)
    await db.commit()
    return True
