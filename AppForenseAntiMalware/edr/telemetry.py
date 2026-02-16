import requests
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class TelemetryClient:
    """
    Handles communication between the EDR Agent and the HispanShield Backend.
    """
    def __init__(self, backend_url: str, api_key: str, device_id: str):
        self.backend_url = backend_url.rstrip('/')
        self.api_key = api_key
        self.device_id = device_id
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "X-Device-ID": self.device_id,
            "Content-Type": "application/json"
        })

    def send_event(self, event_type: str, data: Dict[str, Any]):
        """Send a security event to the backend."""
        url = f"{self.backend_url}/api/v1/events/edr"
        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "data": data,
            "device_id": self.device_id
        }
        try:
            response = self.session.post(url, json=payload, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to send telemetry event: {e}")
            return False

    def fetch_intelligence(self) -> List[Dict[str, Any]]:
        """Fetch latest IoCs from the CTI Hub."""
        url = f"{self.backend_url}/api/v1/intelligence/cti/sync"
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to sync intelligence: {e}")
            return []

    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check if a hash is known to be malicious."""
        url = f"{self.backend_url}/api/v1/intelligence/cti/check-hash"
        try:
            response = self.session.post(url, params={"file_hash": file_hash}, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"Hash check failed: {e}")
        return {"status": "unknown"}
