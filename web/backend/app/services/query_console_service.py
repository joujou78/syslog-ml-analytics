import re

from clickhouse_connect.driver.client import Client

from app.schemas.query_console import QueryResultResponse

# A results-returning statement needs client.query(); anything else (DDL,
# ALTER, INSERT, mutations) needs client.command() instead -- clickhouse_connect
# doesn't unify these into one call. Detected by the statement's leading
# keyword rather than trying every query both ways, since a failed
# .query() attempt on a DDL statement isn't a reliable way to distinguish
# "wrong method" from "the statement is actually invalid".
_READ_QUERY_PATTERN = re.compile(r"^\s*(SELECT|SHOW|DESCRIBE|DESC|EXPLAIN|WITH)\b", re.IGNORECASE)

MAX_ROWS = 1000
# Full SQL access with no query-shape restriction (by explicit choice, see
# README) still shouldn't let one runaway query tie up a web worker
# indefinitely -- this is a backstop, not a substitute for the admin using
# judgment about what they run.
QUERY_TIMEOUT_SECONDS = 30


def execute_query(client: Client, query: str) -> QueryResultResponse:
    stripped = query.strip().rstrip(";").strip()
    if not stripped:
        raise ValueError("Query is empty")

    settings = {"max_execution_time": QUERY_TIMEOUT_SECONDS}

    if _READ_QUERY_PATTERN.match(stripped):
        result = client.query(stripped, settings=settings)
        rows = result.result_rows
        truncated = len(rows) > MAX_ROWS
        rows = rows[:MAX_ROWS]
        return QueryResultResponse(
            columns=list(result.column_names),
            rows=[list(row) for row in rows],
            row_count=len(rows),
            truncated=truncated,
            is_command=False,
        )

    client.command(stripped, settings=settings)
    return QueryResultResponse(
        columns=[], rows=[], row_count=0, truncated=False,
        is_command=True, message="Command executed.",
    )
