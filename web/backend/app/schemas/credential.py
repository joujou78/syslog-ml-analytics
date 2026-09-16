import ipaddress
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator


class CredentialBase(BaseModel):
    ip_or_cidr: str
    version: Literal["v1", "v2c", "v3"]

    community: str | None = None

    v3_user: str | None = None
    v3_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] | None = None
    v3_auth_proto: Literal["MD5", "SHA"] | None = None
    v3_auth_pass: str | None = None
    v3_priv_proto: Literal["DES", "AES"] | None = None
    v3_priv_pass: str | None = None

    @field_validator("ip_or_cidr")
    @classmethod
    def validate_network(cls, value: str) -> str:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"{value!r} is not a valid IP address or CIDR range") from exc
        return value


class CredentialCreate(CredentialBase):
    pass


class CredentialUpdate(CredentialBase):
    pass


class CredentialRead(BaseModel):
    """Never includes decrypted secrets — the API is write-only for
    credentials, matching the principle that nobody needs to read a
    community string back out through a web UI once it's saved."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ip_or_cidr: str
    version: str
    v3_user: str | None
    v3_level: str | None
    created_at: datetime
    updated_at: datetime
    has_community: bool = False
    has_v3_auth: bool = False
    has_v3_priv: bool = False
