from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class DeviceBase(BaseModel):
    manufacturer: str
    model: str
    os_version: str
    android_id: Optional[str] = None

class DeviceCreate(DeviceBase):
    pass

class Device(DeviceBase):
    id: str
    registered_at: datetime
    is_active: bool

    class Config:
        from_attributes = True
