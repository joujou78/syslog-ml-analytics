from datetime import datetime

from pydantic import BaseModel, Field, model_validator


class ConversationTurn(BaseModel):
    """One prior exchange in this chat thread, sent by the frontend (which
    holds the thread's history client-side -- the backend itself stays
    stateless) so a follow-up question like 'what about yesterday?' can be
    answered with context. See log_assistant_service.ask() for how this is
    used, and its explicit instruction that a number from here is context,
    not a fact to assume still current -- time passes between turns, so a
    fresh tool call for the CURRENT question is still required."""

    question: str = Field(min_length=1, max_length=1000)
    answer: str = Field(min_length=1, max_length=4000)


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
    # Bounded to the last few turns -- ask() truncates further (both turn
    # count and each answer's length) before building the prompt, but
    # rejecting an absurdly long history at the API boundary avoids ever
    # parsing/storing one in the first place.
    history: list[ConversationTurn] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def _validate_time_range(self):
        # Confirmed in real use: a mis-set end-before-start range (e.g. a
        # date picker's month rolling over between filling in the two
        # fields) doesn't error -- it silently becomes a ClickHouse/
        # OpenSearch range filter that can never match anything
        # (event_time >= later-timestamp AND event_time <= earlier-
        # timestamp), producing the exact same "No related log lines were
        # found" as a genuine empty result, with nothing to tell them
        # apart. Rejecting it outright at the API boundary is cheap and
        # removes that entire failure mode.
        if self.start and self.end and self.end < self.start:
            raise ValueError("end must not be before start")
        return self


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
    # Set only when `items` is empty AND matching raw rows exist in
    # ClickHouse for the same source_ip/vendor/time filters -- see
    # log_assistant_service.py's build_coverage_note. Distinguishes
    # "genuinely nothing happened" from "it happened but the Log
    # Assistant indexer hasn't embedded it yet", which look identical
    # from an empty `items` list alone.
    coverage_note: str | None = None


class AskResponse(BaseModel):
    answer: str
    sources: list[LogHit]
    model: str
