from datetime import datetime

from fastapi import APIRouter, Depends, Query
from clickhouse_connect.driver.client import Client

from app.api.deps import get_ch_client, get_current_user
from app.schemas.anomaly_window import AnomalyWindowListResponse
from app.services import anomaly_window_service

router = APIRouter(prefix="/anomaly-windows", tags=["anomaly-windows"])

# Read-only, same as /devices and /logs -- any authenticated user can view.
_authenticated = Depends(get_current_user)


@router.get("", response_model=AnomalyWindowListResponse)
async def list_anomaly_windows(
    _user=_authenticated,
    client: Client = Depends(get_ch_client),
    start: datetime | None = None,
    end: datetime | None = None,
    source_ip: str | None = None,
    vendor: str | None = None,
    only_anomalies: bool = True,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    return anomaly_window_service.list_anomaly_windows(
        client, start=start, end=end, source_ip=source_ip, vendor=vendor,
        only_anomalies=only_anomalies, limit=limit, offset=offset,
    )
