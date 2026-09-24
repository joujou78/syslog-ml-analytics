from fastapi import APIRouter, Depends, HTTPException, Response, status
from clickhouse_connect.driver.client import Client
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_ch_client, get_current_user, require_role
from app.db.base import get_db
from app.db.models import Role, User
from app.schemas.anomaly_summary import (
    AcknowledgeRequest, DeviceAnomalySummaryRow, DeviceCategorySummaryRow,
    VendorAnomalySummaryRow, VendorCategorySummaryRow,
)
from app.services import anomaly_summary_service

router = APIRouter(prefix="/anomaly-summary", tags=["anomaly-summary"])

# Viewing is fine for any authenticated role (read-only, mirrors
# /anomaly-windows and /devices); acknowledging changes shared state an
# operator relies on, so it's gated the same as alert rule management.
_authenticated = Depends(get_current_user)
_can_manage = require_role(Role.admin, Role.analyst)


@router.get("/devices", response_model=list[DeviceAnomalySummaryRow])
async def device_summary(
    _user=_authenticated, client: Client = Depends(get_ch_client), db: AsyncSession = Depends(get_db)
):
    return await anomaly_summary_service.list_device_summary_with_acks(client, db)


@router.get("/vendors", response_model=list[VendorAnomalySummaryRow])
async def vendor_summary(_user=_authenticated, client: Client = Depends(get_ch_client)):
    return anomaly_summary_service.list_vendor_summary(client)


@router.get("/devices/by-category", response_model=list[DeviceCategorySummaryRow])
async def device_category_summary(_user=_authenticated, client: Client = Depends(get_ch_client)):
    return anomaly_summary_service.list_device_category_summary(client)


@router.get("/vendors/by-category", response_model=list[VendorCategorySummaryRow])
async def vendor_category_summary(_user=_authenticated, client: Client = Depends(get_ch_client)):
    return anomaly_summary_service.list_vendor_category_summary(client)


@router.post("/devices/{source_ip}/{anomaly_reason}/acknowledge", status_code=status.HTTP_204_NO_CONTENT)
async def acknowledge(
    source_ip: str,
    anomaly_reason: str,
    payload: AcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(_can_manage),
):
    await anomaly_summary_service.acknowledge(db, source_ip, anomaly_reason, payload, actor)


@router.delete("/devices/{source_ip}/{anomaly_reason}/acknowledge", status_code=status.HTTP_204_NO_CONTENT)
async def unacknowledge(
    source_ip: str, anomaly_reason: str, db: AsyncSession = Depends(get_db), actor: User = Depends(_can_manage)
):
    removed = await anomaly_summary_service.unacknowledge(db, source_ip, anomaly_reason, actor)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No acknowledgment found for this device/reason")


@router.get("/export")
async def export_summary(
    format: str,
    group_by: str = "device",
    metric: str = "anomaly",
    _user=_authenticated,
    client: Client = Depends(get_ch_client),
    db: AsyncSession = Depends(get_db),
):
    if format not in ("csv", "xml"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="format must be csv or xml")
    if group_by not in ("device", "vendor"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="group_by must be device or vendor")
    if metric not in ("anomaly", "category"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="metric must be anomaly or category")

    svc = anomaly_summary_service
    if metric == "anomaly":
        if group_by == "device":
            rows = await svc.list_device_summary_with_acks(client, db)
            content = svc.export_device_summary_csv(rows) if format == "csv" else svc.export_device_summary_xml(rows)
        else:
            rows = svc.list_vendor_summary(client)
            content = svc.export_vendor_summary_csv(rows) if format == "csv" else svc.export_vendor_summary_xml(rows)
    else:
        if group_by == "device":
            rows = svc.list_device_category_summary(client)
            content = svc.export_device_category_csv(rows) if format == "csv" else svc.export_device_category_xml(rows)
        else:
            rows = svc.list_vendor_category_summary(client)
            content = svc.export_vendor_category_csv(rows) if format == "csv" else svc.export_vendor_category_xml(rows)

    content_type = "text/csv" if format == "csv" else "application/xml"
    filename = f"{metric}_summary_{group_by}.{format}"
    return Response(
        content=content, media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
