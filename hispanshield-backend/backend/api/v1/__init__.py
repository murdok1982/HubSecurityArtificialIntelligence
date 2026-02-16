from fastapi import APIRouter
from . import auth, samples, analyses, intelligence

api_router = APIRouter()

# Include sub-routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(samples.router, prefix="/samples", tags=["Samples"])
api_router.include_router(analyses.router, prefix="/analyses", tags=["Analyses"])
api_router.include_router(intelligence.router, prefix="/intelligence", tags=["Intelligence"])

# TODO: Add more routers
# api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])

__all__ = ["api_router"]
