"""
Security utilities: password hashing, JWT, RBAC.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from uuid import UUID

from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import HTTPException, status

from .config import settings


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create JWT access token.
    
    Args:
        data: Payload data (должно включать subject, tenant_id, roles)
        expires_delta: Token expiration time
    
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    
    return jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )


def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create JWT refresh token with longer expiration."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.jwt_refresh_token_expire_days)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    
    return jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate JWT token.
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded payload
    
    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )


class RBACChecker:
    """
    Role-Based Access Control checker.
    Verifies if user has required permission.
    """
    
    # Permission format: "resource:action"
    PERMISSIONS = {
        "viewer": [
            "sample:read",
            "analysis:read",
            "report:read",
            "report:download",
            "ioc:read"
        ],
        "analyst": [
            # All viewer permissions +
            "sample:read", "analysis:read", "report:read", "report:download", "ioc:read",
            # Plus:
            "sample:create",
            "sample:upload",
            "analysis:create",
            "analysis:reanalyze",
            "report:export",
            "ioc:search"
        ],
        "admin": [
            # All analyst permissions +
            "sample:read", "analysis:read", "report:read", "report:download", "ioc:read",
            "sample:create", "sample:upload", "analysis:create", "analysis:reanalyze",
            "report:export", "ioc:search",
            # Plus:
            "sample:delete",
            "user:create",
            "user:update",
            "user:delete",
            "project:create",
            "project:update",
            "project:delete",
            "quota:view",
            "quota:edit",
            "audit_log:read"
        ],
        "super-admin": ["*"]  # All permissions (platform operators)
    }
    
    @classmethod
    def has_permission(cls, roles: List[str], permission: str) -> bool:
        """
        Check if any of the user's roles grants the required permission.
        
        Args:
            roles: List of user's roles
            permission: Required permission (e.g., "sample:create")
        
        Returns:
            True if user has permission, False otherwise
        """
        for role in roles:
            role_perms = cls.PERMISSIONS.get(role, [])
            
            # super-admin has all permissions
            if "*" in role_perms:
                return True
            
            # Check if permission in role's permissions
            if permission in role_perms:
                return True
        
        return False
    
    @classmethod
    def require_permission(cls, permission: str):
        """
        Decorator for endpoints to enforce permission check.
        
        Usage:
            @router.post("/samples")
            @RBACChecker.require_permission("sample:create")
            async def upload_sample(...):
                pass
        """
        def decorator(func):
            # This will be implemented as FastAPI dependency
            # For now, return function as-is
            # TODO: Implement as FastAPI dependency injector
            return func
        return decorator


def check_permission(user_roles: List[str], required_permission: str) -> None:
    """
    Check permission and raise exception if not authorized.
    
    Args:
        user_roles: List of user roles
        required_permission: Required permission
    
    Raises:
        HTTPException: 403 Forbidden if user lacks permission
    """
    if not RBACChecker.has_permission(user_roles, required_permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permissions. Required: {required_permission}"
        )
