"""
Initialize database with sample data for development/testing.
Run with: python backend/scripts/init_db.py
"""

import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import init_db, AsyncSessionLocal
from core.security import hash_password
from models.database import Tenant, User, TenantTier, UserRole
import uuid


async def create_sample_ data():
    """Create sample tenant and users."""
    async with AsyncSessionLocal() as db:
        try:
            # Create default tenant
            tenant = Tenant(
                id=uuid.uuid4(),
                name="Demo Organization",
                slug="demo-org",
                email="admin@demo.local",
                company="Demo Corp",
                tier=TenantTier.PRO,
                is_active=True
            )
            db.add(tenant)
            await db.flush()
            
            # Create admin user
            admin_user = User(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                email="admin@demo.local",
                hashed_password=hash_password("Admin123!"),  # CHANGE IN PRODUCTION
                full_name="Admin User",
                role=UserRole.ADMIN,
                is_active=True,
                is_email_verified=True
            )
            db.add(admin_user)
            
            # Create analyst user
            analyst_user = User(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                email="analyst@demo.local",
                hashed_password=hash_password("Analyst123!"),
                full_name="Analyst User",
                role=UserRole.ANALYST,
                is_active=True,
                is_email_verified=True
            )
            db.add(analyst_user)
            
            # Create viewer user
            viewer_user = User(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                email="viewer@demo.local",
                hashed_password=hash_password("Viewer123!"),
                full_name="Viewer User",
                role=UserRole.VIEWER,
                is_active=True,
                is_email_verified=True
            )
            db.add(viewer_user)
            
            await db.commit()
            
            print("✅ Sample data created successfully!")
            print("\n📋 Demo Users:")
            print(f"  Admin:   admin@demo.local / Admin123!")
            print(f"  Analyst: analyst@demo.local / Analyst123!")
            print(f"  Viewer:  viewer@demo.local / Viewer123!")
            print(f"\n🏢 Tenant: {tenant.name} (slug: {tenant.slug})")
            print(f"  ID: {tenant.id}")
            
        except Exception as e:
            print(f"❌ Error creating sample data: {e}")
            await db.rollback()
            raise


async def main():
    """Main initialization function."""
    print("🚀 Initializing database...")
    
    # Create tables (ONLY in development - use Alembic in production)
    print("Creating tables...")
    await init_db()
    print("✅ Tables created")
    
    # Create sample data
    print("\nCreating sample data...")
    await create_sample_data()
    
    print("\n✨ Database initialization complete!")
    print("\n🔗 Next steps:")
    print("  1. Start the API: cd backend && uvicorn main:app --reload")
    print("  2. Visit http://localhost:8000/docs for API documentation")
    print("  3. Login with one of the demo users above")


if __name__ == "__main__":
    asyncio.run(main())
