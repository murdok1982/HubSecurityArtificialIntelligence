from fastapi import APIRouter
from app.api.v1.endpoints import auth, events, dashboard, notifications

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth/device", tags=["auth"])
api_router.include_router(events.router, prefix="/events", tags=["events"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(notifications.router, prefix="/notifications", tags=["notifications"])
