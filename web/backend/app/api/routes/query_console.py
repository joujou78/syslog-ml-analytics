from fastapi import APIRouter, Depends, HTTPException, status
from clickhouse_connect.driver.client import Client
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_ch_client, require_role
from app.db.base import get_db
from app.db.models import AuditLog, Role, User
from app.schemas.query_console import QueryRequest, QueryResultResponse
from app.services import query_console_service

router = APIRouter(prefix="/query-console", tags=["query-console"])

# Full, unrestricted SQL access against ClickHouse (including ALTER/DELETE/
# DROP/TRUNCATE) by explicit request -- see README's "Query Console"
# section for the tradeoff. Admin-only, same as /credentials and /relays,
# both of which are far more limited in what they let an admin actually do.
_admin_only = require_role(Role.admin)


@router.post("/execute", response_model=QueryResultResponse)
async def execute_query(
    payload: QueryRequest,
    client: Client = Depends(get_ch_client),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(_admin_only),
):
    # Logged before execution, not after: the audit trail is this
    # feature's main safety net, and a query that crashes the worker or
    # hangs past the timeout should still leave a record of what was
    # attempted, not just what completed successfully.
    db.add(AuditLog(
        actor_id=admin.id,
        action="query_console.execute",
        target=payload.query[:255],
        details={"query": payload.query},
    ))
    await db.commit()

    try:
        return query_console_service.execute_query(client, payload.query)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
