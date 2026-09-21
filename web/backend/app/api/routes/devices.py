from datetime import datetime

from fastapi import APIRouter, Depends, Query
from clickhouse_connect.driver.client import Client

from app.api.deps import get_ch_client, get_current_user
from app.schemas.device import DeviceListResponse, ResolutionSummary
from app.services import device_service

router = APIRouter(prefix="/devices", tags=["devices"])

# Any authenticated user can view device/resolution status (read-only,
# no credentials exposed here) — only /credentials is admin-gated.
_authenticated = Depends(get_current_user)


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    _user=_authenticated,
    client: Client = Depends(get_ch_client),
    start: datetime | None = None,
    end: datetime | None = None,
    hostname: str | None = None,
    ip: str | None = None,
    vendor: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    return device_service.list_devices(
        client, start=start, end=end, hostname=hostname, ip=ip, vendor=vendor, limit=limit, offset=offset
    )


@router.get("/resolution-summary", response_model=list[ResolutionSummary])
async def resolution_summary(_user=_authenticated, client: Client = Depends(get_ch_client)):
    return device_service.resolution_summary(client)
