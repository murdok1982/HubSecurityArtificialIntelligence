import re
from typing import Dict, List

class SmsClassifier:
    """
    NLP-based SMS classifier for smishing detection.
    Uses keyword analysis and pattern matching.
    In production: replace with fine-tuned BERT/DistilBERT.
    """
    
    def __init__(self):
        self.urgency_keywords = [
            'urgente', 'urgent', 'inmediato', 'immediate', 'ahora', 'now',
            'rápido', 'quick', 'fast', 'pronto'
        ]
        
        self.financial_keywords = [
            'banco', 'bank', 'tarjeta', 'card', 'cuenta', 'account',
            'dinero', 'money', 'pago', 'payment', 'transferencia', 'transfer',
            'premio', 'prize', 'ganador', 'winner'
        ]
        
        self.action_keywords = [
            'haz clic', 'click here', 'verificar', 'verify', 'confirmar', 'confirm',
            'actualizar', 'update', 'restablecer', 'reset', 'desbloquear', 'unlock'
        ]
        
        self.phishing_patterns = [
            r'http[s]?://\S+',  # URLs
            r'(?:verificar|verify|confirmar|confirm)\s+(?:cuenta|account|identidad|identity)',
            r'(?:premio|prize|ganador|winner)',
            r'(?:suspendida|suspended|bloqueada|blocked)'
        ]
    
    def classify(self, message: str) -> Dict:
        """Classify SMS message."""
        message_lower = message.lower()
        
        scores = {
            'urgency': 0.0,
            'financial': 0.0,
            'action': 0.0,
            'pattern': 0.0
        }
        
        features = []
        
        # Urgency detection
        urgency_count = sum(1 for kw in self.urgency_keywords if kw in message_lower)
        if urgency_count > 0:
            scores['urgency'] = min(urgency_count / 2, 1.0)
            features.append(f"Contains {urgency_count} urgency keywords")
        
        # Financial context
        financial_count = sum(1 for kw in self.financial_keywords if kw in message_lower)
        if financial_count > 0:
            scores['financial'] = min(financial_count / 2, 1.0)
            features.append(f"Contains {financial_count} financial keywords")
        
        # Action requests
        action_count = sum(1 for kw in self.action_keywords if kw in message_lower)
        if action_count > 0:
            scores['action'] = min(action_count / 2, 1.0)
            features.append(f"Requests {action_count} actions")
        
        # Pattern matching
        pattern_count = sum(1 for pattern in self.phishing_patterns if re.search(pattern, message_lower))
        if pattern_count > 0:
            scores['pattern'] = min(pattern_count / 2, 1.0)
            features.append(f"Matches {pattern_count} phishing patterns")
        
        # Calculate overall score
        overall_score = sum(scores.values()) / len(scores)
        
        # Classification
        if overall_score > 0.6:
            category = "phishing"
        elif overall_score > 0.3:
            category = "spam"
        else:
            category = "safe"
        
        return {
            "category": category,
            "confidence": overall_score,
            "scores": scores,
            "features": features,
            "is_dangerous": category == "phishing"
        }

# Singleton instance
sms_classifier = SmsClassifier()
