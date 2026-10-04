import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings

# No logger in this app was ever configured with a handler -- every log.info()
# call (e.g. log_assistant_service's tool-call diagnostic) was silently
# dropped by Python's default root logger, which only surfaces WARNING+ via
# its last-resort handler. This gives every module's logger a real handler at
# INFO, written to stderr -- gunicorn's `--error-logfile -` already sends
# that to journalctl, so no systemd unit change is needed.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

app = FastAPI(title="Syslog ML Analytics API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/api/health")
async def health():
    return {"status": "ok"}
