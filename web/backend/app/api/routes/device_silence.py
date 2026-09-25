from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.base import get_db
from app.schemas.device_silence import DeviceSilenceRead
from app.services import device_silence_service

router = APIRouter(prefix="/device-silence", tags=["device-silence"])

# Read-only, no secrets -- same "any authenticated role" posture as
# alerts' rules/history endpoints.
_authenticated = Depends(get_current_user)


@router.get("", response_model=list[DeviceSilenceRead])
async def list_silent_devices(_user=_authenticated, db: AsyncSession = Depends(get_db)):
    return await device_silence_service.list_silent_devices(db)
