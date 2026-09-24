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
    # OpenSearch's own relevance score for this query, not a stored value --
    # since log_assistant_service.py's query is a `hybrid` query fused by
    # the index's RRF search pipeline (see opensearch/setup_index.py), this
    # is an RRF rank-fusion score (roughly the sum of 1/(rank_constant+rank)
    # across the BM25 and k-NN sub-queries), NOT a k-NN cosine-similarity
    # value -- small (well under 1) and only meaningful for ordering hits
    # relative to each other in one response, not as an absolute quality
    # threshold or a number comparable across different queries.
    score: float


class SemanticSearchResponse(BaseModel):
    items: list[LogHit]


class AskResponse(BaseModel):
    answer: str
    sources: list[LogHit]
    model: str
