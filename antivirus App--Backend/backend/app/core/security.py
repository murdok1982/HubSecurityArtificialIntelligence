from datetime import datetime, timedelta
from typing import Optional
import hashlib
import secrets

class SecurityManager:
    """
    Security utilities for JWT, hashing, and token management.
    In production: use python-jose for JWT, integrate with proper secret management.
    """
    
    def __init__(self):
        self.secret_key = "CHANGE_THIS_IN_PRODUCTION_USE_ENV_VARS"
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
    
    def create_device_token(self, device_id: str) -> str:
        """
        Create a simple token for device authentication.
        In production: use JWT with proper signing.
        """
        timestamp = datetime.utcnow().isoformat()
        raw_token = f"{device_id}:{timestamp}:{self.secret_key}"
        token = hashlib.sha256(raw_token.encode()).hexdigest()
        return token
    
    def verify_device_token(self, token: str, device_id: str) -> bool:
        """
        Verify device token.
        Placeholder implementation.
        """
        # In production: proper JWT verification
        return len(token) == 64  # SHA-256 length
    
    def hash_sensitive_data(self, data: str) -> str:
        """Hash sensitive data (phone numbers, etc.) for privacy."""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def generate_api_key(self) -> str:
        """Generate secure API key."""
        return secrets.token_urlsafe(32)
    
    def rate_limit_check(self, device_id: str, limit: int = 100) -> bool:
        """
        Check rate limiting for device.
        In production: use Redis for distributed rate limiting.
        """
        # Placeholder - always allow for MVP
        return True

# Singleton instance
security_manager = SecurityManager()
