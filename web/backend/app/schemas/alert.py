import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AlertRuleBase(BaseModel):
    name: str
    enabled: bool = True

    window_minutes: int = Field(default=5, ge=1, le=1440)
    threshold: int = Field(default=1, ge=1)
    cooldown_minutes: int = Field(default=15, ge=1, le=10080)

    hostname: str | None = None
    source_ip: str | None = None
    program: str | None = None
    severity: Literal["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"] | None = None
    predicted_category: str | None = None
    only_anomalies: bool = False

    webhook_url: str | None = None


class AlertRuleCreate(AlertRuleBase):
    pass


class AlertRuleUpdate(AlertRuleBase):
    pass


class AlertRuleRead(AlertRuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    last_triggered_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AlertEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: uuid.UUID
    triggered_at: datetime
    window_start: datetime
    window_end: datetime
    matched_count: int
    sample_message: str
    notified: bool
    notify_error: str | None
