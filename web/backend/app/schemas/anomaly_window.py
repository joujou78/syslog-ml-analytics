from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AnomalyWindowRead(BaseModel):
    """One scored (device, time window) from the template-mix detector --
    see ml/template_mix_anomaly.py. Distinct from per-event anomalies
    (Log Search's own anomaly_reasons filter): this is a windowed,
    multivariate signal over a device's mix of log template types."""

    # model_scope isn't one of Pydantic's own model_* internals -- silence
    # the protected-namespace warning it'd otherwise trigger.
    model_config = ConfigDict(protected_namespaces=())

    window_start: datetime
    source_ip: str
    hostname: str
    vendor: str
    model_scope: str  # 'device' | 'vendor'
    anomaly_score: float
    is_anomaly: bool
    event_count: int


class AnomalyWindowListResponse(BaseModel):
    items: list[AnomalyWindowRead]
    limit: int
    offset: int
    has_more: bool
