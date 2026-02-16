import re
from typing import Dict, List
import math

class URLDetector:
    """
    ML-based URL maliciousness detector.
    Uses feature extraction + heuristic scoring.
    In production: replace with trained Random Forest or Neural Network.
    """
    
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'secure', 'update',
            'suspended', 'blocked', 'urgent', 'winner', 'prize'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        
    def extract_features(self, url: str) -> Dict:
        """Extract features from URL for classification."""
        features = {}
        
        # Length features
        features['url_length'] = len(url)
        features['domain_length'] = len(self._extract_domain(url))
        
        # Character features
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # Entropy (randomness)
        features['entropy'] = self._calculate_entropy(url)
        
        # Keyword presence
        features['has_suspicious_keyword'] = any(
            kw in url.lower() for kw in self.suspicious_keywords
        )
        
        # TLD check
        features['has_suspicious_tld'] = any(
            url.endswith(tld) for tld in self.suspicious_tlds
        )
        
        # IP address in URL
        features['has_ip_address'] = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))
        
        return features
    
    def predict(self, url: str) -> Dict:
        """Predict if URL is malicious."""
        features = self.extract_features(url)
        score = 0.0
        reasons = []
        
        # Heuristic scoring (replace with ML model predict in production)
        if features['url_length'] > 75:
            score += 0.2
            reasons.append("Unusually long URL")
        
        if features['entropy'] > 4.0:
            score += 0.15
            reasons.append("High entropy (randomness)")
        
        if features['has_suspicious_keyword']:
            score += 0.3
            reasons.append("Contains phishing keywords")
        
        if features['has_suspicious_tld']:
            score += 0.25
            reasons.append("Suspicious top-level domain")
        
        if features['has_ip_address']:
            score += 0.2
            reasons.append("URL contains IP address")
        
        if features['num_hyphens'] > 3:
            score += 0.1
            reasons.append("Excessive hyphens")
        
        is_malicious = score > 0.5
        
        return {
            "is_malicious": is_malicious,
            "confidence": min(score, 1.0),
            "features": features,
            "reasons": reasons
        }
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', url)
        return match.group(1) if match else url
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy."""
        if not text:
            return 0.0
        
        entropy = 0.0
        for char in set(text):
            p_x = text.count(char) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy

# Singleton instance
url_detector = URLDetector()
