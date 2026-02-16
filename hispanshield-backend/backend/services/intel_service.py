import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from models.database import ThreatIndicator 
from core.config import settings

logger = logging.getLogger(__name__)

class IntelService:
    """
    Centralized Threat Intelligence Service for HispanShield.
    Aggregates indicators from multiple feeds and provides a unified interface.
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        
    async def fetch_urlhaus(self) -> int:
        """Fetch and ingest recent malware URLs from URLhaus."""
        logger.info("Syncing with URLhaus...")
        try:
            response = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=30)
            response.raise_for_status()
            
            lines = response.text.split('\n')
            new_count = 0
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue
                parts = line.split(',')
                if len(parts) < 4: continue
                
                url = parts[2].strip('"')
                existing = self.db.query(ThreatIndicator).filter(ThreatIndicator.value == url).first()
                if not existing:
                    indicator = ThreatIndicator(
                        type="url",
                        value=url,
                        source="urlhaus",
                        confidence=80,
                        tags=["malware", "csv_recent"],
                        created_at=datetime.utcnow()
                    )
                    self.db.add(indicator)
                    new_count += 1
            self.db.commit()
            return new_count
        except Exception as e:
            logger.error(f"URLhaus sync failed: {e}")
            return 0

    async def fetch_phishtank(self) -> int:
        """Fetch and ingest recent phishing URLs from PhishTank."""
        logger.info("Syncing with PhishTank...")
        try:
            response = requests.get("http://data.phishtank.com/data/online-valid.json", timeout=60)
            if response.status_code != 200: return 0
            
            data = response.json()
            new_count = 0
            for entry in data[:500]: # Limit for performance
                url = entry.get("url")
                if not url: continue
                
                existing = self.db.query(ThreatIndicator).filter(ThreatIndicator.value == url).first()
                if not existing:
                    indicator = ThreatIndicator(
                        type="url",
                        value=url,
                        source="phishtank",
                        confidence=90,
                        tags=["phishing"],
                        created_at=datetime.utcnow()
                    )
                    self.db.add(indicator)
                    new_count += 1
            self.db.commit()
            return new_count
        except Exception as e:
            logger.error(f"PhishTank sync failed: {e}")
            return 0

    def check_vt_hash(self, file_hash: str) -> Optional[Dict]:
        """Check a file hash against VirusTotal."""
        if not self.vt_api_key:
            return None
            
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_api_key}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                attr = data.get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "total": sum(stats.values())
                }
        except Exception as e:
            logger.error(f"VT lookup failed: {e}")
        return None
