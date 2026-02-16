import logging
from typing import Dict, Any, List, Optional
from OTXv2 import OTXv2
from core.config import settings

logger = logging.getLogger(__name__)

class CTIManager:
    """Manages integration with multiple CTI feeds."""
    
    def __init__(self):
        self.otx_key = getattr(settings, "otx_api_key", None)
        self.otx = OTXv2(self.otx_key) if self.otx_key else None
        
    async def get_otx_report(self, indicator: str, type: str = "file") -> Dict[str, Any]:
        """Query AlienVault OTX for an indicator."""
        if not self.otx:
            return {"error": "OTX not configured"}
            
        try:
            # Note: OTXv2 is synchronous, in a production app we'd wrap this
            if type == "file":
                results = self.otx.get_indicator_details_full(indicator_type="file", indicator=indicator)
            else:
                results = self.otx.get_indicator_details_full(indicator_type="unknown", indicator=indicator)
            return results
        except Exception as e:
            logger.error(f"OTX Error: {e}")
            return {"error": str(e)}

    async def query_all_feeds(self, indicator: str) -> Dict[str, Any]:
        """Consolidate findings from all CTI feeds."""
        results = {
            "OTX": await self.get_otx_report(indicator),
            # Add more feeds here (ThreatFox, etc.)
        }
        return results

cti_manager = CTIManager()
