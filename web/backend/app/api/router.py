from fastapi import APIRouter

from app.api.routes import auth, credentials, devices, users

api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(credentials.router)
api_router.include_router(devices.router)
