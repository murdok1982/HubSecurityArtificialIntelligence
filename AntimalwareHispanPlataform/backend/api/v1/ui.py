"""
UI Router for the Antimalware Hispan Platform.
Handles rendering of Jinja2 templates.
"""

from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
import logging

from core.database import get_db
from core.config import settings
from api.dependencies import get_current_user_optional # Need a variant that doesn't raise if not logged in
from models.database import User

logger = logging.getLogger(__name__)

router = APIRouter()

# Setup templates
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Render landing page / dashboard."""
    return templates.TemplateResponse("index.html", {"request": request, "title": "Dashboard - AntimalwareHispan"})

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render login page."""
    return templates.TemplateResponse("auth/login.html", {"request": request, "title": "Inicia Sesin"})

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Render register page."""
    return templates.TemplateResponse("auth/register.html", {"request": request, "title": "Registro"})

@router.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    """Render upload page."""
    return templates.TemplateResponse("samples/upload.html", {"request": request, "title": "Subir Muestra"})

@router.get("/analyses", response_class=HTMLResponse)
async def analyses_page(request: Request):
    """Render analyses list."""
    return templates.TemplateResponse("analyses/list.html", {"request": request, "title": "Historial de Anlisis"})

from core.database import get_db
from models.database import Analysis, Sample, User
from sqlalchemy import select, desc
from uuid import UUID

@router.get("/partials/analysis-table", response_class=HTMLResponse)
async def partial_analysis_table(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Return HTML fragment for the analysis table."""
    # Note: In a real multi-tenant scenario, we would filter by tenant_id
    # For now, we take recent ones.
    result = await db.execute(
        select(Analysis, Sample)
        .join(Sample, Analysis.sample_id == Sample.id)
        .order_by(desc(Analysis.created_at))
        .limit(10)
    )
    rows = result.all()
    
    return templates.TemplateResponse("components/analysis_rows.html", {
        "request": request,
        "rows": rows
    })

@router.get("/partials/analysis-detail/{analysis_id}", response_class=HTMLResponse)
async def partial_analysis_detail(
    request: Request,
    analysis_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Return HTML fragment for analysis detail results."""
    result = await db.execute(
        select(Analysis, Sample)
        .join(Sample, Analysis.sample_id == Sample.id)
        .where(Analysis.id == UUID(analysis_id))
    )
    row = result.first()
    
    if not row:
        return "<p class='p-4 text-accent-red'>Anlisis no encontrado</p>"
        
    analysis, sample = row
    
from models.database import Analysis, Sample, User, AnalysisType, AnalysisStatus

@router.get("/analysis/{analysis_id}", response_class=HTMLResponse)
async def analysis_detail_page(request: Request, analysis_id: str):
    """Render analysis detail shell."""
    return templates.TemplateResponse("analyses/detail.html", {
        "request": request, 
        "analysis_id": analysis_id,
        "title": f"Detalle de Anlisis: {analysis_id}"
    })



