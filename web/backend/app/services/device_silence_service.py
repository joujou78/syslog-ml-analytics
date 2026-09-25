from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import DeviceSilenceState
from app.schemas.device_silence import DeviceSilenceRead


async def list_silent_devices(db: AsyncSession) -> list[DeviceSilenceRead]:
    # Every row in this table is currently silent by definition (see
    # DeviceSilenceState's docstring -- ml/detect_silent_devices.py
    # deletes a device's row the moment it logs again), so there's no
    # "only show active ones" filter needed the way alert_rules has
    # `enabled`.
    result = await db.execute(select(DeviceSilenceState).order_by(DeviceSilenceState.silence_started_at.desc()))
    return [DeviceSilenceRead.model_validate(r) for r in result.scalars().all()]
