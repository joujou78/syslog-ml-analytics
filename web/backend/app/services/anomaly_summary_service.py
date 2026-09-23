import csv
import io
from datetime import datetime
from xml.sax.saxutils import escape

from clickhouse_connect.driver.client import Client
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AnomalyAcknowledgment, AuditLog, User
from app.schemas.anomaly_summary import AcknowledgeRequest, DeviceAnomalySummaryRow, VendorAnomalySummaryRow

# No time filter, by design: this is a cumulative "since this device/type
# pair started producing anomalies at all" view, not a rolling-window one
# like Log Search or Devices -- the whole point is a stable, from-the-
# beginning count that acknowledgment can meaningfully reference.
_DEVICE_SUMMARY_QUERY = """
    SELECT source_ip, reason,
           argMax(hostname, event_time) AS hostname,
           argMax(vendor, event_time) AS vendor,
           count() AS event_count,
           min(event_time) AS first_seen,
           max(event_time) AS last_seen
    FROM (
        SELECT source_ip, hostname, vendor, event_time, arrayJoin(anomaly_reasons) AS reason
        FROM syslog_ml.events
        WHERE is_anomaly = 1
    )
    GROUP BY source_ip, reason
    ORDER BY event_count DESC
"""

_VENDOR_SUMMARY_QUERY = """
    SELECT vendor, reason,
           uniqExact(source_ip) AS device_count,
           count() AS event_count,
           min(event_time) AS first_seen,
           max(event_time) AS last_seen
    FROM (
        SELECT source_ip, vendor, event_time, arrayJoin(anomaly_reasons) AS reason
        FROM syslog_ml.events
        WHERE is_anomaly = 1
    )
    GROUP BY vendor, reason
    ORDER BY event_count DESC
"""

_DEVICE_EXPORT_COLUMNS = [
    "source_ip", "hostname", "vendor", "anomaly_reason", "event_count",
    "first_seen", "last_seen", "acknowledged", "acknowledged_by", "acknowledged_at", "note",
]
_VENDOR_EXPORT_COLUMNS = ["vendor", "anomaly_reason", "device_count", "event_count", "first_seen", "last_seen"]


async def _ack_lookup(db: AsyncSession) -> dict[tuple[str, str], DeviceAnomalySummaryRow]:
    """(source_ip, anomaly_reason) -> ack fields, joined against users for
    the acknowledger's username (the ack table itself only stores the
    user's id)."""
    result = await db.execute(
        select(AnomalyAcknowledgment, User.username)
        .outerjoin(User, User.id == AnomalyAcknowledgment.acknowledged_by)
    )
    return {(ack.source_ip, ack.anomaly_reason): (ack, username) for ack, username in result.all()}


def list_device_summary(client: Client) -> list[dict]:
    result = client.query(_DEVICE_SUMMARY_QUERY)
    return [
        {
            "source_ip": row[0], "anomaly_reason": row[1], "hostname": row[2], "vendor": row[3],
            "event_count": row[4], "first_seen": row[5], "last_seen": row[6],
        }
        for row in result.result_rows
    ]


async def list_device_summary_with_acks(client: Client, db: AsyncSession) -> list[DeviceAnomalySummaryRow]:
    rows = list_device_summary(client)
    acks = await _ack_lookup(db)
    items = []
    for row in rows:
        key = (row["source_ip"], row["anomaly_reason"])
        ack, username = acks.get(key, (None, None))
        items.append(DeviceAnomalySummaryRow(
            **row,
            acknowledged=ack is not None,
            acknowledged_by=username,
            acknowledged_at=ack.acknowledged_at if ack else None,
            note=ack.note if ack else None,
        ))
    return items


def list_vendor_summary(client: Client) -> list[VendorAnomalySummaryRow]:
    result = client.query(_VENDOR_SUMMARY_QUERY)
    return [
        VendorAnomalySummaryRow(
            vendor=row[0], anomaly_reason=row[1], device_count=row[2],
            event_count=row[3], first_seen=row[4], last_seen=row[5],
        )
        for row in result.result_rows
    ]


async def acknowledge(db: AsyncSession, source_ip: str, anomaly_reason: str, payload: AcknowledgeRequest, actor: User) -> None:
    existing = await db.execute(
        select(AnomalyAcknowledgment).where(
            AnomalyAcknowledgment.source_ip == source_ip,
            AnomalyAcknowledgment.anomaly_reason == anomaly_reason,
        )
    )
    row = existing.scalars().first()
    if row is None:
        row = AnomalyAcknowledgment(source_ip=source_ip, anomaly_reason=anomaly_reason)
        db.add(row)
    row.note = payload.note
    row.acknowledged_by = actor.id
    db.add(AuditLog(
        actor_id=actor.id, action="anomaly.acknowledge",
        target=f"{source_ip}:{anomaly_reason}", details={"note": payload.note},
    ))
    await db.commit()


async def unacknowledge(db: AsyncSession, source_ip: str, anomaly_reason: str, actor: User) -> bool:
    result = await db.execute(
        delete(AnomalyAcknowledgment).where(
            AnomalyAcknowledgment.source_ip == source_ip,
            AnomalyAcknowledgment.anomaly_reason == anomaly_reason,
        )
    )
    if result.rowcount:
        db.add(AuditLog(actor_id=actor.id, action="anomaly.unacknowledge", target=f"{source_ip}:{anomaly_reason}"))
        await db.commit()
        return True
    await db.rollback()
    return False


def _fmt(value) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None:
        return ""
    return str(value)


def export_device_summary_csv(rows: list[DeviceAnomalySummaryRow]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_DEVICE_EXPORT_COLUMNS)
    for r in rows:
        writer.writerow([_fmt(getattr(r, col)) for col in _DEVICE_EXPORT_COLUMNS])
    return buf.getvalue().encode("utf-8")


def export_device_summary_xml(rows: list[DeviceAnomalySummaryRow]) -> bytes:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<anomaly_summary>"]
    for r in rows:
        lines.append("  <row>")
        for col in _DEVICE_EXPORT_COLUMNS:
            lines.append(f"    <{col}>{escape(_fmt(getattr(r, col)))}</{col}>")
        lines.append("  </row>")
    lines.append("</anomaly_summary>")
    return "\n".join(lines).encode("utf-8")


def export_vendor_summary_csv(rows: list[VendorAnomalySummaryRow]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_VENDOR_EXPORT_COLUMNS)
    for r in rows:
        writer.writerow([_fmt(getattr(r, col)) for col in _VENDOR_EXPORT_COLUMNS])
    return buf.getvalue().encode("utf-8")


def export_vendor_summary_xml(rows: list[VendorAnomalySummaryRow]) -> bytes:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<anomaly_summary>"]
    for r in rows:
        lines.append("  <row>")
        for col in _VENDOR_EXPORT_COLUMNS:
            lines.append(f"    <{col}>{escape(_fmt(getattr(r, col)))}</{col}>")
        lines.append("  </row>")
    lines.append("</anomaly_summary>")
    return "\n".join(lines).encode("utf-8")
