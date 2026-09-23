from typing import Any

from pydantic import BaseModel


class QueryRequest(BaseModel):
    query: str


class QueryResultResponse(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    row_count: int
    truncated: bool
    is_command: bool  # True for a non-SELECT statement (DDL/mutation) -- no rows, just ran
    message: str | None = None
