from fastapi import APIRouter, Depends
from clickhouse_connect.driver.client import Client

from app.api.deps import get_ch_client, get_current_user
from app.schemas.device import DeviceRead, ResolutionSummary
from app.services import device_service

router = APIRouter(prefix="/devices", tags=["devices"])

# Any authenticated user can view device/resolution status (read-only,
# no credentials exposed here) — only /credentials is admin-gated.
_authenticated = Depends(get_current_user)


@router.get("", response_model=list[DeviceRead])
async def list_devices(_user=_authenticated, client: Client = Depends(get_ch_client)):
    return device_service.list_devices(client)


@router.get("/resolution-summary", response_model=list[ResolutionSummary])
async def resolution_summary(_user=_authenticated, client: Client = Depends(get_ch_client)):
    return device_service.resolution_summary(client)
