import logging
from typing import Dict, Any, List
from enum import Enum

logger = logging.getLogger(__name__)

class TriageLevel(str, Enum):
    CLEAN = "Clean"
    LOW = "Low Risk"
    SUSPICIOUS = "Suspicious"
    MALICIOUS = "Malicious"
    CRITICAL = "Critical"

class TriageService:
    """Automates the triage of malware samples based on multiple engine scores."""
    
    def __init__(self):
        self.thresholds = {
            "critical": 90,
            "malicious": 70,
            "suspicious": 40,
            "low": 10
        }
        
    def calculate_score(self, 
                       vt_score: int = 0, 
                       yara_hits: int = 0, 
                       static_risk: int = 0,
                       cti_hits: int = 0) -> int:
        """Weighted scoring engine."""
        score = (vt_score * 0.4) + (yara_hits * 10) + (static_risk * 0.3) + (cti_hits * 15)
        return min(int(score), 100)
        
    def get_triage_level(self, score: int) -> TriageLevel:
        if score >= self.thresholds["critical"]:
            return TriageLevel.CRITICAL
        if score >= self.thresholds["malicious"]:
            return TriageLevel.MALICIOUS
        if score >= self.thresholds["suspicious"]:
            return TriageLevel.SUSPICIOUS
        if score >= self.thresholds["low"]:
            return TriageLevel.LOW
        return TriageLevel.CLEAN

triage_service = TriageService()
