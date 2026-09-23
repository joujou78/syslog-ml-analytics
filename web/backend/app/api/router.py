from fastapi import APIRouter

from app.api.routes import (
    alerts, anomaly_summary, anomaly_windows, auth, credentials, devices, logs, query_console, relays, users,
)

api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(credentials.router)
api_router.include_router(relays.router)
api_router.include_router(devices.router)
api_router.include_router(logs.router)
api_router.include_router(alerts.router)
api_router.include_router(anomaly_windows.router)
api_router.include_router(anomaly_summary.router)
api_router.include_router(query_console.router)
