from fastapi import APIRouter
from app.schemas.device import DeviceCreate, Device
from datetime import datetime
import uuid

router = APIRouter()

# Mock database for MVP
fake_devices_db = {}

@router.post("/register", response_model=Device)
def register_device(device_in: DeviceCreate):
    # MVP: Mock registration
    # In production: JWT generation + DB storage
    device_id = str(uuid.uuid4())
    device = Device(
        id=device_id,
        registered_at=datetime.utcnow(),
        is_active=True,
        **device_in.model_dump()
    )
    fake_devices_db[device_id] = device
    return device
