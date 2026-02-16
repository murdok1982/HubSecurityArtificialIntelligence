"""
Pydantic schemas for API request/response validation.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator
import enum


# ===== ENUMS (matching database enums) =====

class TenantTierSchema(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class UserRoleSchema(str, enum.Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"
    SUPER_ADMIN = "super-admin"


class AnalysisStatusSchema(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AnalysisTypeSchema(str, enum.Enum):
    TRIAGE = "triage"
    STATIC = "static"
    DYNAMIC = "dynamic"
    FULL = "full"


# ===== BASE SCHEMAS =====

class BaseSchema(BaseModel):
    """Base configuration for all schemas."""
    model_config = {"from_attributes": True}  # Enable ORM mode (SQLAlchemy)


# ===== AUTHENTICATION =====

class TokenResponse(BaseSchema):
    """JWT token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseSchema):
    """Login credentials."""
    email: EmailStr
    password: str = Field(..., min_length=8)


class RegisterRequest(BaseSchema):
    """User registration."""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    full_name: str = Field(..., min_length=2, max_length=255)
    company: Optional[str] = None


# ===== USER =====

class UserBase(BaseSchema):
    """Shared user attributes."""
    email: EmailStr
    full_name: str


class UserCreate(UserBase):
    """User creation schema."""
    password: str = Field(..., min_length=8)
    role: UserRoleSchema = UserRoleSchema.VIEWER


class UserUpdate(BaseSchema):
    """User update schema."""
    full_name: Optional[str] = None
    role: Optional[UserRoleSchema] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    """User response schema."""
    id: UUID
    tenant_id: UUID
    role: UserRoleSchema
    is_active: bool
    is_email_verified: bool
    last_login: Optional[datetime]
    created_at: datetime


# ===== TENANT =====

class TenantBase(BaseSchema):
    """Shared tenant attributes."""
    name: str
    email: EmailStr
    company: Optional[str] = None


class TenantCreate(TenantBase):
    """Tenant creation schema."""
    slug: str = Field(..., pattern=r"^[a-z0-9-]+$", min_length=3, max_length=100)


class TenantResponse(TenantBase):
    """Tenant response schema."""
    id: UUID
    slug: str
    tier: TenantTierSchema
    is_active: bool
    created_at: datetime
    max_samples_per_month: int
    max_storage_gb: int
    current_month_samples: int
    current_storage_gb: float


# ===== SAMPLE =====

class SampleBase(BaseSchema):
    """Shared sample attributes."""
    filename: str
    size_bytes: int
    mime_type: Optional[str]


class SampleCreate(BaseSchema):
    """Sample creation (file upload handled separately)."""
    tags: List[str] = []


class SampleResponse(Sample Base):
    """Sample response schema."""
    id: UUID
    tenant_id: UUID
    md5: str
    sha1: str
    sha256: str
    ssdeep: Optional[str]
    uploaded_by: UUID
    uploaded_at: datetime
    tags: List[str]


# ===== ANALYSIS =====

class AnalysisCreate(BaseSchema):
    """Analysis creation request."""
    sample_id: UUID
    analysis_type: AnalysisTypeSchema = AnalysisTypeSchema.FULL
    force_reanalyze: bool = False  # Force even if cached


class AnalysisResponse(BaseSchema):
    """Analysis response schema."""
    id: UUID
    tenant_id: UUID
    sample_id: UUID
    analysis_type: AnalysisTypeSchema
    status: AnalysisStatusSchema
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    risk_score: Optional[int]
    malware_family: Optional[str]
    vt_detections: Optional[int]
    sandbox: Optional[str]
    error_message: Optional[str]


class AnalysisDetailResponse(AnalysisResponse):
    """Detailed analysis response with results."""
    static_results: Optional[Dict[str, Any]]
    dynamic_results: Optional[Dict[str, Any]]
    hybrid_results: Optional[Dict[str, Any]]


# ===== REPORT =====

class ReportResponse(BaseSchema):
    """Report response schema."""
    id: UUID
    analysis_id: UUID
    generated_at: datetime
    generated_by_ai: bool
    executive_summary: Optional[str]
    json_export: Optional[Dict[str, Any]]
    pdf_path: Optional[str]
    html_path: Optional[str]


# ===== GENERIC RESPONSES =====

class StatusResponse(BaseSchema):
    """Generic status response."""
    status: str
    message: str


class ErrorResponse(BaseSchema):
    """Error response."""
    detail: str
    error_code: Optional[str] = None


class PaginatedResponse(BaseSchema):
    """Paginated list response."""
    items: List[Any]
    total: int
    page: int
    per_page: int
    pages: int
