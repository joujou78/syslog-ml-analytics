from datetime import datetime

from pydantic import BaseModel


class LogEntry(BaseModel):
    event_time: datetime
    source_ip: str
    hostname: str
    vendor: str
    severity: str
    program: str
    pid: int | None
    message: str
    predicted_category: str
    predicted_confidence: float
    is_anomaly: bool
    anomaly_reasons: list[str]
    resolution_method: str


class LogSearchResponse(BaseModel):
    items: list[LogEntry]
    limit: int
    offset: int
    has_more: bool


class LogFilterOptions(BaseModel):
    """Distinct values actually present in recent data, for populating the
    Vendor/Program filter dropdowns -- unlike severity or anomaly_reason,
    these aren't a fixed enum defined in code, so they can't just be
    hardcoded in the frontend the way Severity's options already are."""

    vendors: list[str]
    programs: list[str]
