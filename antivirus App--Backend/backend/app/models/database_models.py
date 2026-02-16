from sqlalchemy import Column, String, Integer, DateTime, Boolean, Text, JSON, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(String, primary_key=True, index=True)
    manufacturer = Column(String)
    model = Column(String)
    os_version = Column(String)
    android_id = Column(String, nullable=True)
    registered_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True)
    
    # Relationships
    sms_events = relationship("SmsEvent", back_populates="device")
    call_events = relationship("CallEvent", back_populates="device")
    app_events = relationship("AppEvent", back_populates="device")
    alerts = relationship("Alert", back_populates="device")

class SmsEvent(Base):
    __tablename__ = "sms_events"
    
    id = Column(String, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"))
    sender_hash = Column(String, index=True)
    extracted_urls = Column(JSON)
    timestamp = Column(DateTime(timezone=True))
    is_suspicious_local_score = Column(Float)
    message_length = Column(Integer)
    processed = Column(Boolean, default=False)
    threat_score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    device = relationship("Device", back_populates="sms_events")

class CallEvent(Base):
    __tablename__ = "call_events"
    
    id = Column(String, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"))
    caller_hash = Column(String, index=True)
    call_type = Column(String)
    duration = Column(Integer)
    timestamp = Column(DateTime(timezone=True))
    is_blocked = Column(Boolean, default=False)
    risk_score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    device = relationship("Device", back_populates="call_events")

class AppEvent(Base):
    __tablename__ = "app_events"
    
    id = Column(String, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"))
    package_name = Column(String, index=True)
    version_code = Column(Integer)
    signature_digest = Column(String, index=True)
    installer_source = Column(String, nullable=True)
    permissions = Column(JSON)
    install_time = Column(DateTime(timezone=True))
    threat_level = Column(String, default="unknown")
    mitre_techniques = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    device = relationship("Device", back_populates="app_events")

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String, index=True)  # domain, url, hash, phone, package
    value = Column(String, index=True, unique=True)
    confidence = Column(Integer)
    source = Column(String)
    tags = Column(JSON)
    mitre_techniques = Column(JSON)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True)

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(String, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"))
    alert_type = Column(String)  # sms, call, app
    severity = Column(String)  # low, medium, high, critical
    title = Column(String)
    description = Column(Text)
    mitre_techniques = Column(JSON)
    metadata = Column(JSON)
    is_acknowledged = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    device = relationship("Device", back_populates="alerts")

class MLModel(Base):
    __tablename__ = "ml_models"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True)
    version = Column(String)
    model_type = Column(String)  # url_detector, permission_analyzer, sms_classifier
    metrics = Column(JSON)  # accuracy, precision, recall, etc.
    training_data_size = Column(Integer)
    trained_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=False)
    model_path = Column(String)
