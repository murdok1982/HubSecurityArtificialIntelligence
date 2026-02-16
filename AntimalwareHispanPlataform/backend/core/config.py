"""
Core configuration for AntimalwareHispan Platform.
Uses Pydantic Settings for type-safe configuration from environment variables.
"""

from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = "AntimalwareHispan Platform"
    app_version: str = "0.1.0-mvp"
    environment: str = Field(default="development", pattern="^(development|staging|production)$")
    debug: bool = False
    log_level: str = "INFO"
    
    # Database
    database_url: str = Field(..., description="PostgreSQL connection string")
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_echo: bool = False
    
    # Redis
    redis_url: str = Field(..., description="Redis connection string")
    redis_max_connections: int = 50
    
    # Celery
    celery_broker_url: str = Field(default="redis://localhost:6379/1")
    celery_result_backend: str = Field(default="redis://localhost:6379/2")
    celery_task_always_eager: bool = False  # True for synchronous testing
    
    # Meilisearch
    meilisearch_url: str = "http://localhost:7700"
    meilisearch_api_key: Optional[str] = None
    
    # JWT Authentication
    jwt_secret_key: str = Field(..., min_length=32, description="Secret key for JWT signing")
    jwt_algorithm: str = "HS256"  # HS256 for MVP, RS256 for production with key rotation
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_days: int = 30
    
    # Security
    secret_key: str = Field(..., min_length=32)
    allowed_hosts: List[str] = ["localhost", "127.0.0.1"]
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    # VirusTotal
    virustotal_api_key: Optional[str] = None
    virustotal_api_url: str = "https://www.virustotal.com/api/v3"
    virustotal_rate_limit: int = 4  # requests per minute (free tier)
    
    # Cuckoo CAPE
    cuckoo_api_url: Optional[str] = "http://localhost:8090"
    cuckoo_api_token: Optional[str] = None
    cuckoo_timeout: int = 600  # seconds
    
    # Storage
    storage_backend: str = Field(default="local", pattern="^(local|s3|gcs)$")
    local_storage_path: str = "./storage"
    
    # S3 (if storage_backend=s3)
    s3_bucket: Optional[str] = None
    s3_region: str = "eu-west-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    s3_endpoint_url: Optional[str] = None  # For MinIO
    
    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_storage_url: str = "redis://localhost:6379/3"
    
    # YARA
    yara_rules_path: str = "./yara-rules"
    yara_rules_auto_update: bool = True
    
    # AI (v1 feature)
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o"
    openai_max_tokens: int = 4000
    ai_enabled: bool = False
    
    # Monitoring
    sentry_dsn: Optional[str] = None
    prometheus_enabled: bool = True
    metrics_port: int = 9090
    
    # Default Quotas
    default_max_samples_per_month: int = 1000
    default_max_storage_gb: int = 100
    default_max_concurrent_analyses: int = 3
    default_api_rate_limit_per_minute: int = 60
    
    # Model configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"  # Ignore extra env vars
    )
    
    @field_validator("cors_origins", "allowed_hosts", mode="before")
    @classmethod
    def parse_list(cls, v):
        """Parse comma-separated string to list."""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",")]
        return v
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == "development"


# Global settings instance
settings = Settings()
