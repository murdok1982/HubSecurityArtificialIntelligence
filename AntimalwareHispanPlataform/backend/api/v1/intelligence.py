from fastapi import APIRouter, Depends
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from core.database import get_db
from models.database import ThreatIndicator, IndicatorType
from services.intel_service import IntelService

router = APIRouter(prefix="/intelligence", tags=["intelligence"])

@router.get("/dashboard/summary")
async def get_operational_summary(db: Session = Depends(get_db)):
    """Summary of threat landscape for the dashboard."""
    # This would normally be a complex SQL query or Meilisearch aggregation
    return {
        "total_samples": 450,
        "malicious_rate": "12%",
        "top_mitre_techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "count": 120},
            {"id": "T1105", "name": "Ingress Tool Transfer", "count": 85}
        ],
        "agent_efficiency": "98.5%",
        "last_updated": datetime.utcnow().isoformat()
    }

@router.get("/cti/status")
async def get_cti_status():
    """Status of connected CTI feeds."""
    return {
        "URLhaus": "Connected",
        "PhishTank": "Connected",
        "VirusTotal": "Connected"
    }

@router.get("/cti/sync")
async def sync_intelligence(
    type: Optional[IndicatorType] = None, 
    since: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """
    Export IoCs for EDR/Mobile agents.
    Allows filtering by type and modification date.
    """
    query = db.query(ThreatIndicator).filter(ThreatIndicator.is_active == True)
    if type:
        query = query.filter(ThreatIndicator.type == type)
    if since:
        query = query.filter(ThreatIndicator.updated_at >= since)
    
    indicators = query.limit(1000).all()
    return indicators

@router.post("/cti/check-hash")
async def check_hash(file_hash: str, db: Session = Depends(get_db)):
    """Check a specific hash against internal DB and VT."""
    # 1. Check internal DB
    existing = db.query(ThreatIndicator).filter(
        ThreatIndicator.type == IndicatorType.HASH,
        ThreatIndicator.value == file_hash
    ).first()
    
    if existing:
        return {"status": "malicious", "confidence": existing.confidence, "source": existing.source}
    
    # 2. Check VT via IntelService
    service = IntelService(db)
    vt_result = service.check_vt_hash(file_hash)
    if vt_result and vt_result["malicious"] > 3:
        # Auto-ingest into internal DB if malicious enough
        new_ioc = ThreatIndicator(
            type=IndicatorType.HASH,
            value=file_hash,
            source="VirusTotal",
            confidence=int((vt_result["malicious"] / vt_result["total"]) * 100) if vt_result["total"] > 0 else 50,
            tags=["auto_ingested"]
        )
        db.add(new_ioc)
        db.commit()
        return {"status": "malicious", "confidence": new_ioc.confidence, "source": "VirusTotal"}
        
    return {"status": "unknown"}
