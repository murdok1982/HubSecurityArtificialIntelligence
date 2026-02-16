"""
Database connection and session management.
SQLAlchemy 2.0 async engine with connection pooling.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool, QueuePool

from .config import settings


# Create async engine
# Convert postgresql:// to postgresql+asyncpg://
database_url = settings.database_url.replace("postgresql://", "postgresql+asyncpg://")

engine = create_async_engine(
    database_url,
    echo=settings.db_echo,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,  # Verify connections before using
    pool_recycle=3600,  # Recycle connections after 1 hour
    # Use QueuePool in production, NullPool for testing
    poolclass=QueuePool if not settings.celery_task_always_eager else NullPool
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

# Base class for models
Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency para FastAPI endpoints.
    Provides a database session and ensures it's closed after use.
    
    Usage:
        @app.get("/samples")
        async def get_samples(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(Sample))
            return result.scalars().all()
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def set_tenant_context(db: AsyncSession, tenant_id: str) -> None:
    """
    Set tenant context for Row-Level Security (RLS).
    Must be called before any tenant-scoped queries.
    
    Args:
        db: Database session
        tenant_id: UUID of the tenant
    """
    await db.execute(f"SET LOCAL app.current_tenant_id = '{tenant_id}'")


async def init_db() -> None:
    """
    Initialize database: create all tables.
    Only for development. Use Alembic migrations in production.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close database connection pool."""
    await engine.dispose()
