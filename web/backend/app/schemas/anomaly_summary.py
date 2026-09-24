from datetime import datetime

from pydantic import BaseModel


class AcknowledgeRequest(BaseModel):
    note: str | None = None


class DeviceAnomalySummaryRow(BaseModel):
    """One (device, anomaly type) pair, all-time counts from ClickHouse
    joined with its acknowledgment state from Postgres, if any."""

    source_ip: str
    hostname: str
    vendor: str
    anomaly_reason: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    acknowledged: bool
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None
    note: str | None = None


class VendorAnomalySummaryRow(BaseModel):
    """Same shape, rolled up across every device of a vendor -- a
    read-only aggregate view, not something that's individually
    acknowledged (acknowledgment is per-device, see the pipeline README)."""

    vendor: str
    anomaly_reason: str
    device_count: int
    event_count: int
    first_seen: datetime
    last_seen: datetime


class DeviceCategorySummaryRow(BaseModel):
    """One (device, predicted_category) pair -- ALL events, not just
    anomalies, since a category (AUTH, SECURITY, HARDWARE, ...) is a
    classification of every message, not an anomaly signal. No
    acknowledgment here: unlike an anomaly type, a category isn't
    something to mark as 'handled'."""

    source_ip: str
    hostname: str
    vendor: str
    predicted_category: str
    event_count: int
    first_seen: datetime
    last_seen: datetime


class VendorCategorySummaryRow(BaseModel):
    vendor: str
    predicted_category: str
    device_count: int
    event_count: int
    first_seen: datetime
    last_seen: datetime
