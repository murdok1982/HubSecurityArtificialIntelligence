from typing import List, Dict, Set

class MitreMapper:
    """Maps security events to MITRE ATT&CK for Mobile techniques."""
    
    def __init__(self):
        # MITRE ATT&CK Mobile Techniques Mapping
        self.technique_db = {
            # Initial Access
            "T1476": {
                "name": "Deliver Malicious App via Other Means",
                "tactic": "Initial Access",
                "description": "App delivered via phishing or social engineering"
            },
            "T1478": {
                "name": "Install Insecure or Malicious App",
                "tactic": "Initial Access",
                "description": "Installation from unknown sources"
            },
            
            # Persistence
            "T1624": {
                "name": "Event Triggered Execution",
                "tactic": "Persistence",
                "description": "Using broadcast receivers for persistence"
            },
            
            # Collection
            "T1432": {
                "name": "Access Contact List",
                "tactic": "Collection",
                "description": "App accesses contact information"
            },
            "T1433": {
                "name": "Access Call Log",
                "tactic": "Collection",
                "description": "App accesses call history"
            },
            "T1412": {
                "name": "Capture SMS Messages",
                "tactic": "Collection",
                "description": "App reads or intercepts SMS"
            },
            "T1430": {
                "name": "Location Tracking",
                "tactic": "Collection",
                "description": "App tracks device location"
            },
            
            # Impact
            "T1582": {
                "name": "SMS Control",
                "tactic": "Impact",
                "description": "Malicious SMS operations"
            },
        }
    
    def map_app_to_techniques(self, package_name: str, permissions: List[str]) -> List[str]:
        """Map installed app to MITRE techniques based on permissions."""
        techniques = set()
        
        # Contact access
        if 'android.permission.READ_CONTACTS' in permissions:
            techniques.add('T1432')
        
        # Call log access
        if 'android.permission.READ_CALL_LOG' in permissions:
            techniques.add('T1433')
        
        # SMS access
        sms_perms = {'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS', 
                     'android.permission.SEND_SMS'}
        if sms_perms.intersection(set(permissions)):
            techniques.add('T1412')
            if 'android.permission.SEND_SMS' in permissions:
                techniques.add('T1582')
        
        # Location tracking
        location_perms = {'android.permission.ACCESS_FINE_LOCATION', 
                         'android.permission.ACCESS_COARSE_LOCATION'}
        if location_perms.intersection(set(permissions)):
            techniques.add('T1430')
        
        return list(techniques)
    
    def map_sms_to_techniques(self, urls: List[str], score: float) -> List[str]:
        """Map SMS event to MITRE techniques."""
        techniques = []
        
        if score > 0.5:  # High suspicion
            techniques.append('T1476')  # Phishing delivery
        
        return techniques
    
    def get_technique_info(self, technique_id: str) -> Dict:
        """Get detailed information about a MITRE technique."""
        return self.technique_db.get(technique_id, {
            "name": "Unknown",
            "tactic": "Unknown",
            "description": "No description available"
        })
    
    def generate_alert_description(self, techniques: List[str]) -> str:
        """Generate human-readable alert description."""
        if not techniques:
            return "No specific threats identified."
        
        descriptions = []
        for tech_id in techniques:
            tech_info = self.get_technique_info(tech_id)
            descriptions.append(f"{tech_info['name']} ({tech_id})")
        
        return "Detected: " + ", ".join(descriptions)

# Singleton instance
mitre_mapper = MitreMapper()
