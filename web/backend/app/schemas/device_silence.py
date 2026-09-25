from datetime import datetime

from pydantic import BaseModel, ConfigDict


class DeviceSilenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_ip: str
    hostname: str | None
    expected_interval_minutes: float
    last_seen_at: datetime
    silence_started_at: datetime | None
    last_notified_at: datetime | None
