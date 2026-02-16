from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db
from app.models import database_models as models
from typing import Dict, List
from datetime import datetime, timedelta

router = APIRouter()

@router.get("/stats/overview")
def get_overview_stats(db: Session = Depends(get_db)) -> Dict:
    """Get platform overview statistics."""
    total_devices = db.query(func.count(models.Device.id)).scalar()
    active_devices = db.query(func.count(models.Device.id)).filter(
        models.Device.is_active == True
    ).scalar()
    
    total_alerts = db.query(func.count(models.Alert.id)).scalar()
    critical_alerts = db.query(func.count(models.Alert.id)).filter(
        models.Alert.severity == "critical"
    ).scalar()
    
    total_threats = db.query(func.count(models.ThreatIndicator.id)).filter(
        models.ThreatIndicator.is_active == True
    ).scalar()
    
    return {
        "devices": {
            "total": total_devices,
            "active": active_devices
        },
        "alerts": {
            "total": total_alerts,
            "critical": critical_alerts
        },
        "threat_indicators": total_threats
    }

@router.get("/stats/events/timeline")
def get_events_timeline(
    days: int = 7,
    db: Session = Depends(get_db)
) -> List[Dict]:
    """Get event timeline for the last N days."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    # Aggregate events by day
    sms_events = db.query(
        func.date(models.SmsEvent.created_at).label('date'),
        func.count(models.SmsEvent.id).label('count')
    ).filter(models.SmsEvent.created_at >= cutoff_date).group_by('date').all()
    
    call_events = db.query(
        func.date(models.CallEvent.created_at).label('date'),
        func.count(models.CallEvent.id).label('count')
    ).filter(models.CallEvent.created_at >= cutoff_date).group_by('date').all()
    
    return {
        "sms": [{"date": str(date), "count": count} for date, count in sms_events],
        "calls": [{"date": str(date), "count": count} for date, count in call_events]
    }

@router.get("/alerts/recent")
def get_recent_alerts(
    limit: int = 10,
    db: Session = Depends(get_db)
) -> List[Dict]:
    """Get recent alerts."""
    alerts = db.query(models.Alert).order_by(
        models.Alert.created_at.desc()
    ).limit(limit).all()
    
    return [
        {
            "id": alert.id,
            "device_id": alert.device_id,
            "type": alert.alert_type,
            "severity": alert.severity,
            "title": alert.title,
            "created_at": alert.created_at.isoformat()
        }
        for alert in alerts
    ]

@router.get("/threats/top")
def get_top_threats(
    limit: int = 10,
    db: Session = Depends(get_db)
) -> List[Dict]:
    """Get top threat indicators."""
    threats = db.query(models.ThreatIndicator).filter(
        models.ThreatIndicator.is_active == True
    ).order_by(
        models.ThreatIndicator.confidence.desc()
    ).limit(limit).all()
    
    return [
        {
            "type": threat.type,
            "value": threat.value,
            "confidence": threat.confidence,
            "source": threat.source,
            "tags": threat.tags
        }
        for threat in threats
    ]

@router.get("/ml/models")
def get_ml_models(db: Session = Depends(get_db)) -> List[Dict]:
    """Get ML model information."""
    models_list = db.query(models.MLModel).order_by(
        models.MLModel.trained_at.desc()
    ).all()
    
    return [
        {
            "name": model.name,
            "version": model.version,
            "type": model.model_type,
            "metrics": model.metrics,
            "trained_at": model.trained_at.isoformat(),
            "is_active": model.is_active
        }
        for model in models_list
    ]
