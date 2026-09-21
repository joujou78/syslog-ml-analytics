from datetime import datetime

from clickhouse_connect.driver.client import Client
from fastapi import APIRouter, Depends, Query

from app.api.deps import get_ch_client, get_current_user
from app.schemas.log_search import LogSearchResponse
from app.services import log_search_service

router = APIRouter(prefix="/logs", tags=["logs"])

# Same as /devices: read-only, no credentials involved, so any authenticated
# role can search logs -- only /credentials is admin-gated.
_authenticated = Depends(get_current_user)


@router.get("/search", response_model=LogSearchResponse)
async def search_logs(
    _user=_authenticated,
    client: Client = Depends(get_ch_client),
    start: datetime | None = None,
    end: datetime | None = None,
    hostname: str | None = None,
    source_ip: str | None = None,
    program: str | None = None,
    severity: str | None = None,
    predicted_category: str | None = None,
    q: str | None = Query(default=None, description="Case-insensitive substring match on the log message"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    return log_search_service.search_logs(
        client,
        start=start,
        end=end,
        hostname=hostname,
        source_ip=source_ip,
        program=program,
        severity=severity,
        predicted_category=predicted_category,
        keyword=q,
        limit=limit,
        offset=offset,
    )
