"""
Database models for AntimalwareHispan Platform.
Uses SQLAlchemy 2.0 with async support and multi-tenant Row-Level Security.
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float, ForeignKey, Integer,
    JSON, String, Text, BigInteger, Index
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.sql import func
import enum

from core.database import Base


# ===== ENUMS =====

class TenantTier(str, enum.Enum):
    """Tenant subscription tier."""
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class UserRole(str, enum.Enum):
    """User role for RBAC."""
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"
    SUPER_ADMIN = "super-admin"


class AnalysisStatus(str, enum.Enum):
    """Status of analysis."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AnalysisType(str, enum.Enum):
    """Type of analysis performed."""
    TRIAGE = "triage"  # Quick analysis (static + VT only)
    STATIC = "static"
    DYNAMIC = "dynamic"
    FULL = "full"  # Static + Dynamic + Hybrid


# ===== MODELS =====

class Tenant(Base):
    """
    Tenant (organization/customer) model.
    Each tenant has isolated data via Row-Level Security.
    """
    __tablename__ = "tenants"
    
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    tier: Mapped[TenantTier] = mapped_column(Enum(TenantTier), default=TenantTier.FREE)
    
    # Contact
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    company: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Quotas (denormalized for performance)
    max_samples_per_month: Mapped[int] = mapped_column(Integer, default=1000)
    max_storage_gb: Mapped[int] = mapped_column(Integer, default=100)
    max_concurrent_analyses: Mapped[int] = mapped_column(Integer, default=3)
    api_rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=60)
    
    # Usage counters (updated periodically)
    current_month_samples: Mapped[int] = mapped_column(Integer, default=0)
    current_storage_gb: Mapped[float] = mapped_column(Float, default=0.0)
    
    # Relationships
    users: Mapped[List["User"]] = relationship("User", back_populates="tenant")
    samples: Mapped[List["Sample"]] = relationship("Sample", back_populates="tenant")
    
    def __repr__(self):
        return f"<Tenant(id={self.id}, name={self.name}, tier={self.tier})>"


class User(Base):
    """User model with RBAC."""
    __tablename__ = "users"
    
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(FG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Authentication
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    
    # Profile
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.VIEWER)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="users")
    
    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"


class Sample(Base):
    """
    Sample (file) model.
    Stores metadata about uploaded malware samples.
    """
    __tablename__ = "samples"
    
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # File metadata
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100))
    
    # Hashes (for deduplication)
    md5: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    sha1: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    sha512: Mapped[Optional[str]] = mapped_column(String(128))
    ssdeep: Mapped[Optional[str]] = mapped_column(String(255))
    
    # Storage
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)  # S3 key or local path
    
    # User who uploaded
    uploaded_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
    
    # Tags (user-defined labels)
    tags: Mapped[Optional[dict]] = mapped_column(JSONB, default=list)  # ["apt", "ransomware"]
    
    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="samples")
    analyses: Mapped[List["Analysis"]] = relationship("Analysis", back_populates="sample", cascade="all, delete-orphan")
    
    __table_args__ = (
        # Composite index for multi-tenant queries
        Index("idx_tenant_uploaded", "tenant_id", "uploaded_at"),
        # Unique constraint: same hash can exist across tenants, but only once per tenant
        Index("idx_tenant_sha256", "tenant_id", "sha256", unique=True),
    )
    
    def __repr__(self):
        return f"<Sample(id={self.id}, sha256={self.sha256[:16]}..., filename={self.filename})>"


class Analysis(Base):
    """
    Analysis model.
    Represents a single analysis job (static, dynamic, or full).
    """
    __tablename__ = "analyses"
    
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    sample_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Analysis configuration
    analysis_type: Mapped[AnalysisType] = mapped_column(Enum(AnalysisType), nullable=False)
    status: Mapped[AnalysisStatus] = mapped_column(Enum(AnalysisStatus), default=AnalysisStatus.PENDING, index=True)
    
    # Timing
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    # Results summary (denormalized for quick access)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer)  # 0-100
    malware_family: Mapped[Optional[str]] = mapped_column(String(100))
    vt_detections: Mapped[Optional[int]] = mapped_column(Integer)  # e.g., 42/70
    
    # Sandbox used (if dynamic)
    sandbox: Mapped[Optional[str]] = mapped_column(String(50))  # 'cuckoo', 'anyrun', etc.
    
    # Artifacts storage paths
    artifacts_path: Mapped[Optional[str]] = mapped_column(String(512))  # S3 prefix or local dir
    
    # Error handling
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    
    # Full results (JSONB for flexibility)
    static_results: Mapped[Optional[dict]] = mapped_column(JSONB)
    dynamic_results: Mapped[Optional[dict]] = mapped_column(JSONB)
    hybrid_results: Mapped[Optional[dict]] = mapped_column(JSONB)
    
    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant")
    sample: Mapped["Sample"] = relationship("Sample", back_populates="analyses")
    report: Mapped[Optional["Report"]] = relationship("Report", back_populates="analysis", uselist=False)
    
    __table_args__ = (
        Index("idx_tenant_created", "tenant_id", "created_at"),
        Index("idx_tenant_status", "tenant_id", "status"),
    )
    
    def __repr__(self):
        return f"<Analysis(id={self.id}, type={self.analysis_type}, status={self.status}, risk={self.risk_score})>"


class Report(Base):
    """
    Report model.
    Generated reports (technical + executive) for an analysis.
    """
    __tablename__ = "reports"
    
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    analysis_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, unique=True)
    
    # Report content
    technical_content: Mapped[Optional[str]] = mapped_column(JSON)  # Markdown
    executive_summary: Mapped[Optional[str]] = mapped_column(Text)  # Plain text or markdown
    
    # Exports
    json_export: Mapped[Optional[dict]] = mapped_column(JSONB)
    stix_export: Mapped[Optional[dict]] = mapped_column(JSONB)
    
    # File exports (PDFs, HTML)
    pdf_path: Mapped[Optional[str]] = mapped_column(String(512))
    html_path: Mapped[Optional[str]] = mapped_column(String(512))
    
    # Generation metadata
    generated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    generated_by_ai: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant")
    analysis: Mapped["Analysis"] = relationship("Analysis", back_populates="report")
    
    def __repr__(self):
        return f"<Report(id={self.id}, analysis_id={self.analysis_id})>"


class IndicatorType(str, enum.Enum):
    """Type of threat indicator."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class ThreatIndicator(Base):
    """
    Threat Intelligence Indicator (IoC) model.
    Stores indicators from external feeds and internal detections.
    """
    __tablename__ = "threat_indicators"
    
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    type: Mapped[IndicatorType] = mapped_column(Enum(IndicatorType), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50) # 0-100
    
    tags: Mapped[Optional[dict]] = mapped_column(JSONB, default=list)
    description: Mapped[Optional[str]] = mapped_column(Text)
    
    # Coverage/Context
    mitre_techniques: Mapped[Optional[dict]] = mapped_column(JSONB, default=list) # ["T1476"]
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
    first_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    def __repr__(self):
        return f"<ThreatIndicator(id={self.id}, type={self.type}, value={self.value[:32]}...)>"


# ===== Row-Level Security (RLS) Setup =====
# These will be created via Alembic migrations, not in model definitions

# Example RLS policy (executed in migration):
# 
# ALTER TABLE samples ENABLE ROW LEVEL SECURITY;
# 
# CREATE POLICY tenant_isolation ON samples
#     USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
