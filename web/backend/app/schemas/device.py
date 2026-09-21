from datetime import datetime

from pydantic import BaseModel


class DeviceRead(BaseModel):
    """Derived live from recent events, not just the SNMP-resolved subset in
    device_inventory — this is every device that has actually logged
    something recently, whatever its current resolution_method."""

    ip: str
    hostname: str
    vendor: str
    vendor_source: str
    model: str
    resolution_method: str
    first_seen_in_window: datetime
    last_seen: datetime
    event_count: int = 0


class ResolutionSummary(BaseModel):
    resolution_method: str
    device_count: int
