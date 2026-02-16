"""
VirusTotal API Integration.
"""

import aiohttp
import logging
from typing import Dict, Any, Optional

from core.config import settings

logger = logging.getLogger(__name__)

class VirusTotalClient:
    """Client for VirusTotal API v3."""
    
    BASE_URL = settings.virustotal_api_url
    
    def __init__(self):
        self.api_key = settings.virustotal_api_key
        
    async def get_file_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get file report by hash (MD5, SHA1, SHA256).
        Returns None if not found or API error.
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None
            
        headers = {
            "x-apikey": self.api_key
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                url = f"{self.BASE_URL}/files/{file_hash}"
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("data", {}).get("attributes", {})
                    elif response.status == 404:
                        return None # Not found in VT
                    else:
                        logger.error(f"VT API Error {response.status}: {await response.text()}")
                        return None
            except Exception as e:
                logger.error(f"VT Request failed: {e}")
                return None

# Global instance
vt_client = VirusTotalClient()
