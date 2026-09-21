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
    resolution_method: str


class LogSearchResponse(BaseModel):
    items: list[LogEntry]
    limit: int
    offset: int
    has_more: bool
