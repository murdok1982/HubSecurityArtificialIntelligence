import firebase_admin
from firebase_admin import credentials, messaging
import logging
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class FCMService:
    """
    Firebase Cloud Messaging service for push notifications.
    """
    
    def __init__(self):
        self.initialized = False
        self._initialize_firebase()
    
    def _initialize_firebase(self):
        """Initialize Firebase Admin SDK."""
        try:
            # Path to Firebase service account JSON
            cred_path = Path("firebase-credentials.json")
            
            if not cred_path.exists():
                logger.warning("Firebase credentials not found. Using mock mode.")
                return
            
            cred = credentials.Certificate(str(cred_path))
            firebase_admin.initialize_app(cred)
            self.initialized = True
            logger.info("Firebase Admin SDK initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Firebase: {e}")
    
    def send_notification(
        self,
        fcm_token: str,
        title: str,
        body: str,
        data: Optional[Dict] = None
    ) -> bool:
        """
        Send push notification to a single device.
        
        Args:
            fcm_token: Device FCM registration token
            title: Notification title
            body: Notification body
            data: Additional data payload
        """
        if not self.initialized:
            logger.warning("FCM not initialized. Notification not sent.")
            return False
        
        try:
            message = messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=body,
                ),
                data=data or {},
                token=fcm_token,
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        icon='ic_notification',
                        color='#667eea',
                        sound='default',
                        channel_id='threat_alerts'
                    )
                )
            )
            
            response = messaging.send(message)
            logger.info(f"Notification sent successfully: {response}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
            return False
    
    def send_threat_alert(
        self,
        fcm_token: str,
        threat_type: str,
        severity: str,
        description: str
    ) -> bool:
        """Send threat-specific alert notification."""
        
        severity_icons = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "⚡",
            "low": "ℹ️"
        }
        
        icon = severity_icons.get(severity, "🛡️")
        title = f"{icon} {severity.upper()} Threat Detected"
        
        data = {
            "type": "threat_alert",
            "threat_type": threat_type,
            "severity": severity,
            "timestamp": str(int(messaging.utils.utc_now().timestamp()))
        }
        
        return self.send_notification(fcm_token, title, description, data)
    
    def send_batch_notifications(
        self,
        tokens: List[str],
        title: str,
        body: str,
        data: Optional[Dict] = None
    ) -> Dict:
        """
        Send notifications to multiple devices.
        
        Returns:
            Dict with success and failure counts
        """
        if not self.initialized:
            return {"success": 0, "failed": len(tokens)}
        
        try:
            message = messaging.MulticastMessage(
                notification=messaging.Notification(
                    title=title,
                    body=body,
                ),
                data=data or {},
                tokens=tokens,
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        icon='ic_notification',
                        color='#667eea'
                    )
                )
            )
            
            response = messaging.send_multicast(message)
            
            return {
                "success": response.success_count,
                "failed": response.failure_count
            }
            
        except Exception as e:
            logger.error(f"Failed to send batch notifications: {e}")
            return {"success": 0, "failed": len(tokens)}

# Singleton instance
fcm_service = FCMService()
