from fastapi import APIRouter, HTTPException, Header
from app.schemas.events import SmsEventCreate, CallEventCreate, AppEventCreate
from typing import List
import uuid

router = APIRouter()

# Mock storage (in production: use DB + message queue)
events_db = {
    "sms": [],
    "calls": [],
    "apps": []
}

@router.post("/sms")
async def ingest_sms_event(
    event: SmsEventCreate,
    device_id: str = Header(..., alias="X-Device-ID")
):
    """Ingest SMS event from mobile device."""
    event_id = str(uuid.uuid4())
    event_data = event.model_dump()
    event_data.update({"id": event_id, "device_id": device_id, "processed": False})
    events_db["sms"].append(event_data)
    
    return {"status": "received", "event_id": event_id}

@router.post("/call")
async def ingest_call_event(
    event: CallEventCreate,
    device_id: str = Header(..., alias="X-Device-ID")
):
    """Ingest call event from mobile device."""
    event_id = str(uuid.uuid4())
    event_data = event.model_dump()
    event_data.update({"id": event_id, "device_id": device_id})
    events_db["calls"].append(event_data)
    
    return {"status": "received", "event_id": event_id}

@router.post("/apps")
async def ingest_app_events(
    events: List[AppEventCreate],
    device_id: str = Header(..., alias="X-Device-ID")
):
    """Ingest batch of installed apps from device."""
    received_ids = []
    for event in events:
        event_id = str(uuid.uuid4())
        event_data = event.model_dump()
        event_data.update({"id": event_id, "device_id": device_id, "threat_level": "unknown"})
        events_db["apps"].append(event_data)
        received_ids.append(event_id)
    
    return {"status": "received", "count": len(received_ids), "event_ids": received_ids}

@router.get("/stats")
async def get_event_stats():
    """Get statistics about received events (for debugging)."""
    return {
        "sms_count": len(events_db["sms"]),
        "call_count": len(events_db["calls"]),
        "app_count": len(events_db["apps"])
    }
