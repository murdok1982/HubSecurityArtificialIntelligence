import re
from typing import List, Dict, Optional

class RulesEngine:
    """Basic static rules engine for threat detection."""
    
    def __init__(self):
        # Phishing URL patterns
        self.phishing_patterns = [
            r'bit\.ly',
            r'tinyurl\.com',
            r'goo\.gl',
            r'login.*verify',
            r'secure.*account',
            r'urgent.*action',
        ]
        
        # Suspicious SMS keywords
        self.smishing_keywords = [
            'premio', 'ganador', 'urgente', 'verificar cuenta',
            'haz clic aquí', 'confirma tu identidad', 'banco',
            'tarjeta bloqueada', 'suspendida', 'prize', 'winner',
            'urgent', 'verify', 'click here', 'confirm identity'
        ]
        
        # Known malicious package prefixes
        self.malicious_packages = [
            'com.example.malware',
            'com.fake.bank',
        ]
        
        # High-risk permission combinations
        self.risky_permission_combos = [
            {'android.permission.READ_SMS', 'android.permission.SEND_SMS', 'android.permission.INTERNET'},
            {'android.permission.CAMERA', 'android.permission.RECORD_AUDIO', 'android.permission.ACCESS_FINE_LOCATION'},
        ]
    
    def analyze_sms(self, sender_hash: str, urls: List[str], message_length: int) -> Dict:
        """Analyze SMS for threats."""
        score = 0.0
        reasons = []
        
        # Check URLs
        for url in urls:
            for pattern in self.phishing_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    score += 0.3
                    reasons.append(f"Suspicious URL pattern: {pattern}")
        
        # Short messages with URLs are suspicious
        if urls and message_length < 50:
            score += 0.2
            reasons.append("Short message with URL")
        
        return {
            "risk_score": min(score, 1.0),
            "threat_detected": score > 0.5,
            "reasons": reasons
        }
    
    def analyze_app(self, package_name: str, permissions: List[str]) -> Dict:
        """Analyze app for threats."""
        threat_level = "safe"
        reasons = []
        mitre_techniques = []
        
        # Check package name
        for malicious in self.malicious_packages:
            if package_name.startswith(malicious):
                threat_level = "critical"
                reasons.append("Known malicious package")
                mitre_techniques.append("T1478")  # Install Insecure Application
        
        # Check permission combinations
        perm_set = set(permissions)
        for risky_combo in self.risky_permission_combos:
            if risky_combo.issubset(perm_set):
                if threat_level == "safe":
                    threat_level = "medium"
                reasons.append(f"Risky permission combination detected")
                mitre_techniques.append("T1430")  # Location Tracking
        
        # Excessive permissions
        if len(permissions) > 20:
            if threat_level == "safe":
                threat_level = "low"
            reasons.append("Excessive permissions requested")
        
        return {
            "threat_level": threat_level,
            "reasons": reasons,
            "mitre_techniques": list(set(mitre_techniques))
        }
    
    def analyze_call(self, caller_hash: str, call_type: str) -> Dict:
        """Analyze call for threats (placeholder)."""
        # In production: check against known spam number databases
        return {
            "risk_score": 0.0,
            "is_spam": False,
            "reasons": []
        }

# Singleton instance
rules_engine = RulesEngine()
