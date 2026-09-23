from fastapi import APIRouter

from app.api.routes import alerts, auth, credentials, devices, logs, relays, users

api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(credentials.router)
api_router.include_router(relays.router)
api_router.include_router(devices.router)
api_router.include_router(logs.router)
api_router.include_router(alerts.router)
