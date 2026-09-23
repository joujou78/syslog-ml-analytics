import ipaddress
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class RelaySourceIpCreate(BaseModel):
    ip: str
    note: str | None = None

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"{value!r} is not a valid IP address") from exc
        return value


class RelaySourceIpRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ip: str
    note: str | None
    created_at: datetime
