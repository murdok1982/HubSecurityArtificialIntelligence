"""
Dependency functions for FastAPI endpoints.
Handles authentication, tenant extraction, and permission checking.
"""

from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db, set_tenant_context
from core.security import decode_token, check_permission
from models.database import User, Tenant


# HTTP Bearer token scheme
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Dependency to get current authenticated user from JWT token.
    
    Raises:
        HTTPException: 401 if token is invalid or user not found
    """
    token = credentials.credentials
    payload = decode_token(token)
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    # Fetch user from database
    result = await db.execute(
        select(User).where(User.id == UUID(user_id))
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    return user


async def get_current_tenant(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Tenant:
    """
    Get current user's tenant and set tenant context for RLS.
    
    Returns:
        Tenant object
    
    Raises:
        HTTPException: 403 if tenant is inactive
    """
    result = await db.execute(
        select(Tenant).where(Tenant.id == user.tenant_id)
    )
    tenant = result.scalar_one_or_none()
    
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )
    
    if not tenant.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant account is disabled"
        )
    
    # Set tenant context for Row-Level Security
    await set_tenant_context(db, str(tenant.id))
    
    return tenant


class RoleChecker:
    """
    Dependency class to check if user has required role.
    
    Usage:
        @router.get("/admin")
        async def admin_endpoint(user: User = Depends(RoleChecker(["admin", "super-admin"]))):
            pass
    """
    
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles
    
    async def __call__(self, user: User = Depends(get_current_user)) -> User:
        if user.role.value not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Required roles: {self.allowed_roles}"
            )
        return user


class PermissionChecker:
    """
    Dependency class to check if user has required permission.
    
    Usage:
        @router.post("/samples")
        async def upload_sample(user: User = Depends(PermissionChecker("sample:create"))):
            pass
    """
    
    def __init__(self, required_permission: str):
        self.required_permission = required_permission
    
    async def __call__(self, user: User = Depends(get_current_user)) -> User:
        check_permission([user.role.value], self.required_permission)
        return user


# Common combinations for convenience
current_viewer = Depends(RoleChecker(["viewer", "analyst", "admin", "super-admin"]))
current_analyst = Depends(RoleChecker(["analyst", "admin", "super-admin"]))
current_admin = Depends(RoleChecker(["admin", "super-admin"]))
current_super_admin = Depends(RoleChecker(["super-admin"]))
