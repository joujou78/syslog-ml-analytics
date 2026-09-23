import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog, RelaySourceIp, User
from app.schemas.relay import RelaySourceIpCreate, RelaySourceIpRead


def _to_read_schema(row: RelaySourceIp) -> RelaySourceIpRead:
    return RelaySourceIpRead(id=row.id, ip=row.ip, note=row.note, created_at=row.created_at)


async def list_relay_source_ips(db: AsyncSession) -> list[RelaySourceIpRead]:
    result = await db.execute(select(RelaySourceIp).order_by(RelaySourceIp.ip))
    return [_to_read_schema(r) for r in result.scalars().all()]


class DuplicateRelayError(Exception):
    pass


async def create_relay_source_ip(db: AsyncSession, payload: RelaySourceIpCreate, actor: User) -> RelaySourceIpRead:
    existing = await db.execute(select(RelaySourceIp).where(RelaySourceIp.ip == payload.ip))
    if existing.scalars().first() is not None:
        raise DuplicateRelayError(payload.ip)

    row = RelaySourceIp(ip=payload.ip, note=payload.note, created_by=actor.id)
    db.add(row)
    db.add(AuditLog(actor_id=actor.id, action="relay_source_ip.create", target=payload.ip))
    await db.commit()
    await db.refresh(row)
    return _to_read_schema(row)


async def delete_relay_source_ip(db: AsyncSession, relay_id: uuid.UUID, actor: User) -> bool:
    row = await db.get(RelaySourceIp, relay_id)
    if row is None:
        return False
    db.add(AuditLog(actor_id=actor.id, action="relay_source_ip.delete", target=row.ip))
    await db.delete(row)
    await db.commit()
    return True
