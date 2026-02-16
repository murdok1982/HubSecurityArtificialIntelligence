from typing import List, Dict
from app.services.threat_intel.ioc_storage import ioc_storage
from app.services.threat_intel.mitre_mapper import mitre_mapper

class CorrelationEngine:
    """Correlates events with threat intelligence."""
    
    def correlate_sms_event(self, sms_data: Dict) -> Dict:
        """Correlate SMS event with threat intel."""
        urls = sms_data.get("extracted_urls", [])
        sender_hash = sms_data.get("sender_hash", "")
        
        threats_found = []
        mitre_techniques = []
        
        # Check URLs against IOC database
        for url in urls:
            ioc = ioc_storage.query_ioc("url", url)
            if ioc:
                threats_found.append({
                    "type": "malicious_url",
                    "value": url,
                    "confidence": ioc["confidence"],
                    "tags": ioc["tags"]
                })
                mitre_techniques.extend(ioc.get("mitre_techniques", []))
        
        # Check sender against known spam numbers
        sender_ioc = ioc_storage.query_ioc("phone", sender_hash)
        if sender_ioc:
            threats_found.append({
                "type": "spam_number",
                "confidence": sender_ioc["confidence"]
            })
        
        # Apply MITRE mapping
        sms_techniques = mitre_mapper.map_sms_to_techniques(
            urls, 
            sms_data.get("is_suspicious_local_score", 0.0)
        )
        mitre_techniques.extend(sms_techniques)
        
        return {
            "threat_detected": len(threats_found) > 0,
            "threats": threats_found,
            "mitre_techniques": list(set(mitre_techniques)),
            "risk_score": self._calculate_risk_score(threats_found)
        }
    
    def correlate_app_event(self, app_data: Dict) -> Dict:
        """Correlate app installation with threat intel."""
        package_name = app_data.get("package_name", "")
        signature = app_data.get("signature_digest", "")
        permissions = app_data.get("permissions", [])
        
        threats_found = []
        
        # Check package name
        pkg_ioc = ioc_storage.query_ioc("package", package_name)
        if pkg_ioc:
            threats_found.append({
                "type": "malicious_package",
                "confidence": pkg_ioc["confidence"],
                "tags": pkg_ioc["tags"]
            })
        
        # Check signature hash
        hash_ioc = ioc_storage.query_ioc("hash", signature)
        if hash_ioc:
            threats_found.append({
                "type": "malicious_signature",
                "confidence": hash_ioc["confidence"]
            })
        
        # Map to MITRE techniques
        mitre_techniques = mitre_mapper.map_app_to_techniques(
            package_name, 
            permissions
        )
        
        threat_level = "safe"
        if len(threats_found) > 0:
            threat_level = "critical"
        elif len(mitre_techniques) > 3:
            threat_level = "medium"
        
        return {
            "threat_level": threat_level,
            "threats": threats_found,
            "mitre_techniques": mitre_techniques,
            "explanation": mitre_mapper.generate_alert_description(mitre_techniques)
        }
    
    def _calculate_risk_score(self, threats: List[Dict]) -> float:
        """Calculate overall risk score."""
        if not threats:
            return 0.0
        
        max_confidence = max([t.get("confidence", 0) for t in threats])
        return max_confidence / 100.0

# Singleton instance
correlation_engine = CorrelationEngine()
