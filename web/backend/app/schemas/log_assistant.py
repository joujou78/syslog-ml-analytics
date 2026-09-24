from datetime import datetime

from pydantic import BaseModel, Field


class LogAssistantQuery(BaseModel):
    """Shared request body for both semantic search and the LLM 'ask'
    feature -- 'ask' just does everything search does, then feeds the
    results to the model, so they share the same filters."""

    question: str = Field(min_length=1, max_length=1000)
    source_ip: str | None = None
    vendor: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    limit: int = Field(default=10, ge=1, le=50)


class LogHit(BaseModel):
    event_time: datetime
    source_ip: str
    hostname: str
    vendor: str
    severity: str
    program: str
    predicted_category: str
    message: str
    is_anomaly: bool
    anomaly_reasons: list[str]
    score: float  # OpenSearch's kNN similarity score for this query, not a stored value


class SemanticSearchResponse(BaseModel):
    items: list[LogHit]


class AskResponse(BaseModel):
    answer: str
    sources: list[LogHit]
    model: str
