"""
Samples endpoints: Upload, list, delete.
"""

from typing import List, Optional
from uuid import uuid4
import magic  # To detect mime type

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from core.database import get_db
from models.database import User, Tenant, Sample, Analysis, AnalysisType, AnalysisStatus
from models.schemas import SampleResponse, AnalysisResponse
from api.dependencies import get_current_user, get_current_tenant, PermissionChecker
from services.storage import storage
from core.hashing import calculate_hashes


router = APIRouter()


@router.post("/upload", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED)
async def upload_sample(
    request: Request,
    file: UploadFile = File(...),
    tags: Optional[List[str]] = Query(None),
    force_analyze: bool = False,
    user: User = Depends(PermissionChecker("sample:upload")),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload a sample for analysis.
    If sample exists (same SHA256 in tenant), returns existing analysis unless force_analyze=True.
    """
    # 1. Validate file size (simple check, Nginx/ingress should also limit)
    # MVP Limit: 100MB
    MAX_SIZE = 100 * 1024 * 1024
    
    # We need to read file to calc hash.
    # UploadFile is spooled.
    content = await file.read()
    size = len(content)
    
    if size > MAX_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Max size: {MAX_SIZE} bytes"
        )
    
    if size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file"
        )
        
    # 2. Calculate Hashes
    # Helper expects file-like object with read(), seek(). UploadFile has it.
    # But we already read content into memory. Let's make a bytesIO-like wrapper or just pass content if valid.
    # Let's adapt hashing.py to accept bytes for simplicity here
    import hashlib
    import ssdeep
    
    # Inline calc for now since we have content in memory
    sha256 = hashlib.sha256(content).hexdigest()
    
    # 3. Check Deduplication (Per Tenant)
    existing_sample = await db.execute(
        select(Sample).where(
            Sample.tenant_id == tenant.id,
            Sample.sha256 == sha256
        )
    )
    sample_instance = existing_sample.scalar_one_or_none()
    
    if sample_instance:
        # Sample exists. Check if we need to re-analyze.
        if not force_analyze:
            # Check for latest analysis
            latest_analysis = await db.execute(
                select(Analysis)
                .where(Analysis.sample_id == sample_instance.id)
                .order_by(desc(Analysis.created_at))
                .limit(1)
            )
            analysis = latest_analysis.scalar_one_or_none()
            if analysis:
                return analysis
        
        # If force_analyze OR no analysis found, reuse sample_instance
    else:
        # 4. Create New Sample
        
        # Calc other hashes
        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        sha512 = hashlib.sha512(content).hexdigest()
        try:
            ssdeep_hash = ssdeep.hash(content)
        except:
            ssdeep_hash = None
            
        # Detect Mime Type
        mime_type = magic.from_buffer(content, mime=True)
        
        # Save to Storage
        sample_id = uuid4()
        
        # Reset file cursor for storage service? 
        # Actually storage service expects async read. 
        # Since we have content in memory, writing it directly is easier or wrapping in BytesIO.
        # Let's use the storage service but we might need to seek(0) the UploadFile
        await file.seek(0)
        storage_path = await storage.save_sample(
            file, 
            file.filename, 
            str(tenant.id), 
            str(sample_id)
        )
        
        sample_instance = Sample(
            id=sample_id,
            tenant_id=tenant.id,
            filename=file.filename,
            size_bytes=size,
            mime_type=mime_type,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            sha512=sha512,
            ssdeep=ssdeep_hash,
            storage_path=storage_path,
            uploaded_by=user.id,
            tags=tags or []
        )
        db.add(sample_instance)
        await db.flush()
        
    # 5. Create Analysis Job
    analysis = Analysis(
        id=uuid4(),
        tenant_id=tenant.id,
        sample_id=sample_instance.id,
        analysis_type=AnalysisType.FULL, # Default to Full for MVP
        status=AnalysisStatus.PENDING
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)
    
    # 6. Trigger Background Task (Celery)
    from workers.tasks import static_analysis_task
    # Pass IDs as strings to Celery
    static_analysis_task.delay(str(analysis.id), str(tenant.id))
    
    # Check if request is from HTMX
    if request.headers.get("HX-Request"):
        from fastapi.templating import Jinja2Templates
        from pathlib import Path
        templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent.parent / "templates"))
        return templates.TemplateResponse("components/upload_success.html", {"request": request, "analysis": analysis})

    return analysis


@router.get("/", response_model=List[SampleResponse])
async def list_samples(
    skip: int = 0,
    limit: int = 100,
    user: User = Depends(PermissionChecker("sample:read")),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """List uploaded samples."""
    result = await db.execute(
        select(Sample)
        .where(Sample.tenant_id == tenant.id)
        .order_by(desc(Sample.uploaded_at))
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/{sample_id}", response_model=SampleResponse)
async def get_sample(
    sample_id: str,
    user: User = Depends(PermissionChecker("sample:read")),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """Get sample details."""
    result = await db.execute(
        select(Sample).where(
            Sample.id == uuid4(sample_id),
            Sample.tenant_id == tenant.id
        )
    )
    sample = result.scalar_one_or_none()
    
    if not sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample not found"
        )
    
    return sample
