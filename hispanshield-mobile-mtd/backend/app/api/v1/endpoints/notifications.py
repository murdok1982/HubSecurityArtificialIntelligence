from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from app.services.notifications.fcm_service import fcm_service
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import database_models as models

router = APIRouter()

class FCMTokenUpdate(BaseModel):
    fcm_token: str

class NotificationRequest(BaseModel):
    title: str
    body: str
    data: Optional[dict] = None

@router.post("/register-token")
def register_fcm_token(
    token_data: FCMTokenUpdate,
    device_id: str = Header(..., alias="X-Device-ID"),
    db: Session = Depends(get_db)
):
    """Register or update FCM token for a device."""
    device = db.query(models.Device).filter(
        models.Device.id == device_id
    ).first()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Store FCM token in device record
    # Note: You need to add fcm_token column to Device model
    # device.fcm_token = token_data.fcm_token
    # db.commit()
    
    return {
        "status": "success",
        "message": "FCM token registered successfully"
    }

@router.post("/send")
def send_notification(
    notification: NotificationRequest,
    device_id: str = Header(..., alias="X-Device-ID"),
    db: Session = Depends(get_db)
):
    """Send push notification to a specific device."""
    device = db.query(models.Device).filter(
        models.Device.id == device_id
    ).first()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Get FCM token from device
    # fcm_token = device.fcm_token
    # For demo purposes, using a placeholder
    fcm_token = "DEMO_FCM_TOKEN"
    
    success = fcm_service.send_notification(
        fcm_token=fcm_token,
        title=notification.title,
        body=notification.body,
        data=notification.data
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to send notification")
    
    return {
        "status": "sent",
        "device_id": device_id
    }

@router.post("/test")
def send_test_notification(
    device_id: str = Header(..., alias="X-Device-ID")
):
    """Send a test notification."""
    # In production, get FCM token from database
    return {
        "status": "test_mode",
        "message": "Configure FCM token to receive notifications"
    }
