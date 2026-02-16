import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import database_models as models
from app.core.config import settings

logger = logging.getLogger(__name__)

class RealCTIFeedIntegrator:
    """
    Integration with real CTI feeds.
    Supports: VirusTotal, URLhaus, AbuseIPDB, PhishTank.
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.virustotal_api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
        self.abuseipdb_api_key = getattr(settings, 'ABUSEIPDB_API_KEY', None)
    
    def ingest_urlhaus_feed(self) -> int:
        """
        Ingest malicious URLs from URLhaus (free, no API key needed).
        https://urlhaus.abuse.ch/
        """
        logger.info("Fetching URLhaus feed...")
        
        try:
            response = requests.get(
                "https://urlhaus.abuse.ch/downloads/csv_recent/",
                timeout=30
            )
            response.raise_for_status()
            
            lines = response.text.split('\n')
            iocs_added = 0
            
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue
                
                parts = line.split(',')
                if len(parts) < 4:
                    continue
                
                url = parts[2].strip('"')
                threat_type = parts[4].strip('"') if len(parts) > 4 else "malware"
                
                # Check if already exists
                existing = self.db.query(models.ThreatIndicator).filter(
                    models.ThreatIndicator.value == url
                ).first()
                
                if not existing:
                    indicator = models.ThreatIndicator(
                        type="url",
                        value=url,
                        confidence=85,
                        source="urlhaus",
                        tags=[threat_type, "malicious_url"],
                        mitre_techniques=["T1476"],
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        is_active=True
                    )
                    self.db.add(indicator)
                    iocs_added += 1
                else:
                    existing.last_seen = datetime.utcnow()
            
            self.db.commit()
            logger.info(f"Ingested {iocs_added} URLs from URLhaus")
            return iocs_added
            
        except Exception as e:
            logger.error(f"Error fetching URLhaus feed: {e}")
            return 0
    
    def query_virustotal_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Query VirusTotal for file hash analysis.
        Requires API key.
        """
        if not self.virustotal_api_key:
            logger.warning("VirusTotal API key not configured")
            return None
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.virustotal_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                malicious_count = stats.get("malicious", 0)
                total_engines = sum(stats.values())
                
                if malicious_count > 0:
                    confidence = int((malicious_count / total_engines) * 100)
                    
                    return {
                        "is_malicious": True,
                        "confidence": confidence,
                        "detections": malicious_count,
                        "total_engines": total_engines
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Error querying VirusTotal: {e}")
            return None
    
    def ingest_phishtank_feed(self) -> int:
        """
        Ingest phishing URLs from PhishTank (free).
        """
        logger.info("Fetching PhishTank feed...")
        
        try:
            # PhishTank requires registration for API key
            # Using public feed for demo
            response = requests.get(
                "http://data.phishtank.com/data/online-valid.json",
                timeout=60
            )
            
            if response.status_code != 200:
                return 0
            
            data = response.json()
            iocs_added = 0
            
            for entry in data[:1000]:  # Limit to first 1000
                url = entry.get("url", "")
                
                if not url:
                    continue
                
                existing = self.db.query(models.ThreatIndicator).filter(
                    models.ThreatIndicator.value == url
                ).first()
                
                if not existing:
                    indicator = models.ThreatIndicator(
                        type="url",
                        value=url,
                        confidence=90,
                        source="phishtank",
                        tags=["phishing", "verified"],
                        mitre_techniques=["T1476"],
                        first_seen=datetime.utcnow(),
                        is_active=True
                    )
                    self.db.add(indicator)
                    iocs_added += 1
            
            self.db.commit()
            logger.info(f"Ingested {iocs_added} phishing URLs from PhishTank")
            return iocs_added
            
        except Exception as e:
            logger.error(f"Error fetching PhishTank feed: {e}")
            return 0
    
    def run_all_feeds(self) -> Dict:
        """Run all CTI feed ingestions."""
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "feeds": {}
        }
        
        # URLhaus
        urlhaus_count = self.ingest_urlhaus_feed()
        results["feeds"]["urlhaus"] = urlhaus_count
        
        # PhishTank
        phishtank_count = self.ingest_phishtank_feed()
        results["feeds"]["phishtank"] = phishtank_count
        
        results["total_iocs"] = urlhaus_count + phishtank_count
        
        return results

# Celery task for scheduled CTI feed updates
def scheduled_cti_update_task():
    """
    Scheduled task to update CTI feeds.
    Run daily via Celery beat.
    """
    from app.core.database import SessionLocal
    
    db = SessionLocal()
    try:
        integrator = RealCTIFeedIntegrator(db)
        results = integrator.run_all_feeds()
        logger.info(f"CTI feed update completed: {results}")
    finally:
        db.close()
