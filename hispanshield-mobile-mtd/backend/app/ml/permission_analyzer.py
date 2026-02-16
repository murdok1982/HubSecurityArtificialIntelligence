from typing import List, Dict, Set

class PermissionAnalyzer:
    """
    Analyzes app permissions for anomalies.
    Uses baseline comparison and isolation scoring.
    """
    
    def __init__(self):
        # Expected permissions per app category
        self.category_baselines = {
            "calculator": {"android.permission.INTERNET"},
            "flashlight": {"android.permission.CAMERA", "android.permission.FLASHLIGHT"},
            "game": {
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.VIBRATE"
            },
            "social": {
                "android.permission.INTERNET",
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION"
            }
        }
        
        # High-risk permissions
        self.critical_permissions = {
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION"
        }
    
    def analyze(self, package_name: str, permissions: List[str]) -> Dict:
        """Analyze app permissions for anomalies."""
        perm_set = set(permissions)
        category = self._guess_category(package_name)
        
        anomalies = []
        risk_score = 0.0
        
        # Check for excessive permissions
        if len(permissions) > 15:
            risk_score += 0.2
            anomalies.append("Excessive permissions requested")
        
        # Check for critical permissions
        critical_used = perm_set.intersection(self.critical_permissions)
        if critical_used:
            risk_score += 0.1 * len(critical_used)
            anomalies.append(f"Requests {len(critical_used)} critical permissions")
        
        # Category-based baseline comparison
        if category in self.category_baselines:
            expected = self.category_baselines[category]
            unexpected = perm_set - expected
            if unexpected:
                risk_score += 0.3
                anomalies.append(f"Unexpected permissions for {category} app")
        
        # SMS + Internet = potential exfiltration
        if {"android.permission.READ_SMS", "android.permission.INTERNET"}.issubset(perm_set):
            risk_score += 0.4
            anomalies.append("Can read SMS and send data over network (exfiltration risk)")
        
        return {
            "risk_score": min(risk_score, 1.0),
            "is_anomalous": risk_score > 0.5,
            "anomalies": anomalies,
            "critical_permissions": list(critical_used),
            "category": category
        }
    
    def _guess_category(self, package_name: str) -> str:
        """Guess app category from package name."""
        if 'calculator' in package_name.lower():
            return 'calculator'
        elif 'flashlight' in package_name.lower() or 'torch' in package_name.lower():
            return 'flashlight'
        elif 'game' in package_name.lower():
            return 'game'
        elif any(social in package_name.lower() for social in ['facebook', 'twitter', 'instagram', 'whatsapp']):
            return 'social'
        return 'unknown'

# Singleton instance
permission_analyzer = PermissionAnalyzer()
