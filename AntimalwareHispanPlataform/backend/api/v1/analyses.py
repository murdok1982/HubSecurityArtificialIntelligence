"""
Analysis endpoints: Get status, re-analyze.
"""

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from core.database import get_db
from models.database import Analysis, User, Tenant, Sample
from models.schemas import AnalysisResponse, AnalysisDetailResponse
from api.dependencies import get_current_user, get_current_tenant, PermissionChecker


router = APIRouter()


@router.get("/{analysis_id}", response_model=AnalysisDetailResponse)
async def get_analysis(
    analysis_id: str,
    user: User = Depends(PermissionChecker("analysis:read")),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """Get full analysis details including results."""
    result = await db.execute(
        select(Analysis).where(
            Analysis.id == UUID(analysis_id),
            Analysis.tenant_id == tenant.id
        )
    )
    analysis = result.scalar_one_or_none()
    
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found"
        )
    
    return analysis


@router.get("/sample/{sample_id}", response_model=List[AnalysisResponse])
async def get_sample_analyses(
    sample_id: str,
    user: User = Depends(PermissionChecker("analysis:read")),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """Get all analyses for a specific sample."""
    result = await db.execute(
        select(Analysis)
        .where(
            Analysis.sample_id == UUID(sample_id),
            Analysis.tenant_id == tenant.id
        )
        .order_by(desc(Analysis.created_at))
    )
    return result.scalars().all()
