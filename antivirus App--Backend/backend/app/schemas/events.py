from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

# SMS Event Schema
class SmsEventCreate(BaseModel):
    sender_hash: str = Field(..., description="SHA-256 hash of sender number")
    extracted_urls: List[str] = Field(default_factory=list)
    timestamp: datetime
    is_suspicious_local_score: float = Field(ge=0.0, le=1.0)
    message_length: int
    
class SmsEvent(SmsEventCreate):
    id: str
    device_id: str
    processed: bool = False

    class Config:
        from_attributes = True

# Call Event Schema
class CallEventCreate(BaseModel):
    caller_hash: str = Field(..., description="SHA-256 hash of caller number")
    call_type: str = Field(..., description="incoming, outgoing, missed")
    duration: int = Field(default=0, description="Duration in seconds")
    timestamp: datetime
    is_blocked: bool = False

class CallEvent(CallEventCreate):
    id: str
    device_id: str
    risk_score: Optional[float] = None

    class Config:
        from_attributes = True

# App Event Schema
class AppEventCreate(BaseModel):
    package_name: str
    version_code: int
    signature_digest: str = Field(..., description="SHA-256 of APK signature")
    installer_source: Optional[str] = None
    permissions: List[str]
    install_time: datetime

class AppEvent(AppEventCreate):
    id: str
    device_id: str
    threat_level: str = "unknown"  # safe, low, medium, high, critical
    mitre_techniques: List[str] = Field(default_factory=list)

    class Config:
        from_attributes = True
