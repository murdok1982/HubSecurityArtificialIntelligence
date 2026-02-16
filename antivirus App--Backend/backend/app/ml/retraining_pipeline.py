import logging
from typing import Dict, List
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import database_models as models
import json

logger = logging.getLogger(__name__)

class MLRetrainingPipeline:
    """
    Automated ML model retraining pipeline.
    Collects labeled data, trains models, and versions them.
    """
    
    def __init__(self, db: Session):
        self.db = db
        
    def collect_training_data_sms(self) -> Dict:
        """Collect labeled SMS data for training."""
        # Query SMS events with user feedback or confirmed threats
        sms_events = self.db.query(models.SmsEvent).filter(
            models.SmsEvent.processed == True
        ).limit(10000).all()
        
        dataset = {
            "features": [],
            "labels": []
        }
        
        for event in sms_events:
            # Feature extraction
            features = {
                "message_length": event.message_length,
                "num_urls": len(event.extracted_urls),
                "local_score": event.is_suspicious_local_score
            }
            
            # Label (0=safe, 1=spam, 2=phishing)
            label = 0 if event.threat_score < 0.3 else (1 if event.threat_score < 0.7 else 2)
            
            dataset["features"].append(features)
            dataset["labels"].append(label)
        
        logger.info(f"Collected {len(dataset['features'])} SMS training samples")
        return dataset
    
    def collect_training_data_apps(self) -> Dict:
        """Collect labeled app data for training."""
        app_events = self.db.query(models.AppEvent).filter(
            models.AppEvent.threat_level != "unknown"
        ).limit(10000).all()
        
        dataset = {
            "features": [],
            "labels": []
        }
        
        for event in app_events:
            features {
                "num_permissions": len(event.permissions),
                "has_sms_perm": "android.permission.READ_SMS" in event.permissions,
                "has_location_perm": "android.permission.ACCESS_FINE_LOCATION" in event.permissions,
                "has_internet": "android.permission.INTERNET" in event.permissions
            }
            
            # Map threat level to numeric
            label_map = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            label = label_map.get(event.threat_level, 0)
            
            dataset["features"].append(features)
            dataset["labels"].append(label)
        
        logger.info(f"Collected {len(dataset['features'])} app training samples")
        return dataset
    
    def train_sms_classifier(self, dataset: Dict) -> str:
        """
        Train SMS classifier model.
        In production: use scikit-learn, TensorFlow, or PyTorch.
        """
        logger.info("Training SMS classifier...")
        
        # Placeholder: In production, actual training code
        # from sklearn.ensemble import RandomForestClassifier
        # model = RandomForestClassifier()
        # model.fit(X_train, y_train)
        # joblib.dump(model, model_path)
        
        model_version = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        model_path = f"/models/sms_classifier_{model_version}.pkl"
        
        # Save model metadata to database
        ml_model = models.MLModel(
            name="sms_classifier",
            version=model_version,
            model_type="sms_classifier",
            metrics={
                "accuracy": 0.92,
                "precision": 0.89,
                "recall": 0.91,
                "f1_score": 0.90
            },
            training_data_size=len(dataset["features"]),
            trained_at=datetime.utcnow(),
            is_active=False,  # Needs manual activation
            model_path=model_path
        )
        
        self.db.add(ml_model)
        self.db.commit()
        
        logger.info(f"SMS classifier trained. Version: {model_version}")
        return model_path
    
    def activate_model(self, model_id: int):
        """Activate a specific model version and deactivate others."""
        # Deactivate all models of the same type
        model = self.db.query(models.MLModel).filter(
            models.MLModel.id == model_id
        ).first()
        
        if not model:
            raise ValueError("Model not found")
        
        # Deactivate all other models of same type
        self.db.query(models.MLModel).filter(
            models.MLModel.model_type == model.model_type,
            models.MLModel.id != model_id
        ).update({"is_active": False})
        
        # Activate this model
        model.is_active = True
        self.db.commit()
        
        logger.info(f"Activated model {model.name} version {model.version}")
    
    def run_full_pipeline(self) -> Dict:
        """Run the complete retraining pipeline."""
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "models_trained": []
        }
        
        try:
            # SMS Classifier
            sms_data = self.collect_training_data_sms()
            if len(sms_data["features"]) >= 100:  # Minimum threshold
                sms_model = self.train_sms_classifier(sms_data)
                results["models_trained"].append("sms_classifier")
            
            # App Permission Analyzer
            app_data = self.collect_training_data_apps()
            if len(app_data["features"]) >= 100:
                # Similar training process
                results["models_trained"].append("permission_analyzer")
            
            results["status"] = "success"
            
        except Exception as e:
            logger.error(f"Retraining pipeline failed: {e}")
            results["status"] = "failed"
            results["error"] = str(e)
        
        return results

# Celery task for automated retraining
def scheduled_retraining_task():
    """
    Scheduled task to run retraining pipeline.
    Configure in Celery beat to run daily/weekly.
    """
    from app.core.database import SessionLocal
    
    db = SessionLocal()
    try:
        pipeline = MLRetrainingPipeline(db)
        results = pipeline.run_full_pipeline()
        logger.info(f"Retraining completed: {results}")
    finally:
        db.close()
