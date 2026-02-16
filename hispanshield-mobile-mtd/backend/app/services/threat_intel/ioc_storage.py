from typing import List, Dict, Optional
from datetime import datetime

class IOCStorage:
    """In-memory IOC storage (replace with Redis/PostgreSQL in production)."""
    
    def __init__(self):
        self.iocs = {
            "domain": {},
            "url": {},
            "hash": {},
            "phone": {},
            "package": {}
        }
    
    def add_ioc(self, ioc_type: str, value: str, metadata: Dict):
        """Add an IOC to storage."""
        if ioc_type not in self.iocs:
            return False
        
        self.iocs[ioc_type][value] = {
            "value": value,
            "type": ioc_type,
            "confidence": metadata.get("confidence", 50),
            "source": metadata.get("source", "unknown"),
            "tags": metadata.get("tags", []),
            "mitre_techniques": metadata.get("mitre_techniques", []),
            "first_seen": metadata.get("first_seen", datetime.utcnow().isoformat()),
            "last_seen": datetime.utcnow().isoformat()
        }
        return True
    
    def query_ioc(self, ioc_type: str, value: str) -> Optional[Dict]:
        """Query IOC database."""
        if ioc_type not in self.iocs:
            return None
        return self.iocs[ioc_type].get(value)
    
    def bulk_query(self, ioc_type: str, values: List[str]) -> List[Dict]:
        """Query multiple IOCs at once."""
        results = []
        for value in values:
            result = self.query_ioc(ioc_type, value)
            if result:
                results.append(result)
        return results
    
    def get_stats(self) -> Dict:
        """Get IOC database statistics."""
        return {
            "total_iocs": sum(len(v) for v in self.iocs.values()),
            "by_type": {k: len(v) for k, v in self.iocs.items()}
        }

# Singleton instance
ioc_storage = IOCStorage()

# Seed with some example IOCs
ioc_storage.add_ioc("domain", "malicious-phishing.com", {
    "confidence": 95,
    "source": "public_feed",
    "tags": ["phishing", "banking"],
    "mitre_techniques": ["T1476"]
})

ioc_storage.add_ioc("package", "com.fake.bank", {
    "confidence": 90,
    "source": "google_play_protect",
    "tags": ["trojan", "banking"],
    "mitre_techniques": ["T1478", "T1412"]
})
