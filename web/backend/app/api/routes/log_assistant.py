import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from opensearchpy import OpenSearch
from opensearchpy.exceptions import OpenSearchException

from app.api.deps import get_current_user, get_os_client
from app.schemas.log_assistant import AskResponse, LogAssistantQuery, SemanticSearchResponse
from app.services import log_assistant_service

router = APIRouter(prefix="/log-assistant", tags=["log-assistant"])

# Read-only, same as /logs and /anomaly-windows -- any authenticated user
# can view. The LLM call in /ask is slow (CPU inference), not privileged --
# that's a performance concern for whoever asks, not a reason to gate it.
_authenticated = Depends(get_current_user)


def _upstream_error(exc: Exception) -> HTTPException:
    # OpenSearch/Ollama being unreachable or misconfigured isn't the
    # caller's fault -- 502, with the real error, rather than an opaque 500.
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Log Assistant backend error: {exc}")


# httpx.HTTPError/OpenSearchException cover a request failing outright, but
# not a request that "succeeds" with an unexpected shape -- e.g. Ollama's
# response missing the ["message"]["content"] path log_assistant_service.py
# expects (KeyError) or a non-JSON body (json.JSONDecodeError, a ValueError
# subclass). Uncaught, either would surface as a bare 500 with no `detail`
# field -- which the frontend's error handling can't distinguish from a
# genuine network failure any better than it could a 504 (see
# LogAssistant.tsx's logAssistantErrorFallback for the same lesson learned
# about a 504). Treating these as upstream errors too keeps every failure
# mode in this pipeline informative rather than a mystery.
_UPSTREAM_ERRORS = (httpx.HTTPError, OpenSearchException, KeyError, ValueError)


@router.post("/search", response_model=SemanticSearchResponse)
async def search(
    payload: LogAssistantQuery,
    _user=_authenticated,
    os_client: OpenSearch = Depends(get_os_client),
):
    try:
        items = await log_assistant_service.semantic_search(os_client, payload)
    except _UPSTREAM_ERRORS as exc:
        raise _upstream_error(exc)
    return SemanticSearchResponse(items=items)


@router.post("/ask", response_model=AskResponse)
async def ask(
    payload: LogAssistantQuery,
    _user=_authenticated,
    os_client: OpenSearch = Depends(get_os_client),
):
    try:
        return await log_assistant_service.ask(os_client, payload)
    except _UPSTREAM_ERRORS as exc:
        raise _upstream_error(exc)
