# models.py

# FIX: Added UniqueConstraint to the imports
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Float, LargeBinary, UniqueConstraint
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    slack_webhook_url = Column(String, nullable=True)
    
    # --- Security & Lockout Columns ---
    locked_until = Column(DateTime, nullable=True) 
    is_locked = Column(Boolean, default=False)
    failed_attempts = Column(Integer, default=0)

    # --- Password Reset Columns ---
    reset_token = Column(String, nullable=True)
    reset_token_expires = Column(DateTime, nullable=True) 

    # --- Relationships ---
    domains = relationship("Domain", back_populates="owner")
    monitors = relationship("Monitor", back_populates="owner")
    alert_rules = relationship("AlertRule", back_populates="owner", cascade="all, delete-orphan")

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    attempt_time = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean)
    user = relationship("User")

class Domain(Base):
    __tablename__ = "tracked_domains"

    id = Column(Integer, primary_key=True, index=True)
    
    # FIX: Removed unique=True to allow multiple users to track the same domain.
    # Separation is handled by the user_id foreign key.
    domain_name = Column(String(255), nullable=False, index=True) 
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True) 
    
    
    security_score = Column(Integer, default=0)
    last_scanned = Column(DateTime, default=datetime.utcnow)
    
    # JSON strings for storing scan results
    ssl_data = Column(String(2000), default='{}')
    whois_data = Column(String(2000), default='{}')
    dns_data = Column(String(2000), default='{}')
    manual_data = Column(String(2000), default='{}')

    # Relationship
    owner = relationship("User", back_populates="domains")

class Monitor(Base):
    __tablename__ = "monitors"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_url = Column(String(500), nullable=False)
    friendly_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="monitors")
    logs = relationship("MonitorLog", back_populates="monitor", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="monitor", cascade="all, delete-orphan")


class MonitorLog(Base):
    __tablename__ = "monitor_logs"
    id = Column(Integer, primary_key=True, index=True)
    monitor_id = Column(Integer, ForeignKey("monitors.id"), nullable=False)
    
    # ADDED: Domain column
    domain = Column(String(255), nullable=True, index=True)
    
    status_code = Column(Integer, nullable=True)
    response_time = Column(Float, nullable=True)
    is_up = Column(Boolean, default=False)
    checked_at = Column(DateTime, default=datetime.utcnow, index=True)
    monitor = relationship("Monitor", back_populates="logs")


# models.py - Update the Incident class

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    
    # CHANGED: nullable=False → nullable=True
    monitor_id = Column(Integer, ForeignKey("monitors.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    
    domain = Column(String(255), nullable=True, index=True)
    status = Column(String(50), default="Ongoing")
    error_type = Column(String(100), nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    ended_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    
    # CHANGED: Remove back_populates or make it optional
    monitor = relationship("Monitor", back_populates="incidents")

# ================= NEW ALERT MODEL =================
class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Config
    name = Column(String(100), nullable=False)
    type = Column(String(50), nullable=False) # 'service' or 'domain'
    target_id = Column(Integer, nullable=True) # ID of monitor or domain
    target_url = Column(String(500), nullable=True) # ADDED: To store root domain patterns (e.g., example.com)
    condition = Column(String(100), nullable=False) # e.g. 'status_down', 'response_time_high'
    threshold = Column(String(50), nullable=True) # Optional value for threshold
    
    # Settings
    severity = Column(String(20), default="warning") # critical, high, warning, info
    channel = Column(String(20), default="email") # email
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    owner = relationship("User", back_populates="alert_rules")

class AlertHistory(Base):
    __tablename__ = "alert_history"
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, ForeignKey("alert_rules.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    message = Column(Text, nullable=True)
    severity = Column(String(20))
    channel = Column(String(20))
    status = Column(String(20), default="sent") # sent, failed, pending
    triggered_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Optional: Link to what caused it
    source_type = Column(String(50)) # 'monitor' or 'domain'
    source_id = Column(Integer)


class DetectionScan(Base):
    __tablename__ = "detection_scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target_url = Column(String(500), nullable=False)
    status = Column(String(50), default="completed")
    risk_score = Column(Integer, default=0)
    summary_json = Column(Text, nullable=True)
    metrics_json = Column(Text, nullable=True)
    step_trace_json = Column(Text, nullable=True)
    entry_points_json = Column(Text, nullable=True)
    additional_findings_json = Column(Text, nullable=True)
    tls_json = Column(Text, nullable=True)
    crawl_errors_json = Column(Text, nullable=True)
    owasp_catalog_json = Column(Text, nullable=True)
    policy_note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    findings = relationship("DetectionFinding", back_populates="scan", cascade="all, delete-orphan")


class DetectionFinding(Base):
    __tablename__ = "detection_findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("detection_scans.id"), nullable=False, index=True)
    owasp = Column(String(120), nullable=False)
    severity = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    location = Column(String(2000), nullable=True)
    remediation = Column(Text, nullable=True)
    confidence = Column(Integer, default=0)

    scan = relationship("DetectionScan", back_populates="findings")

# ================= NEW MODEL STATE MODEL =================
class MonitorModelState(Base):
    __tablename__ = "monitor_model_states"

    # FIX: Added composite unique constraint so one URL can have multiple model types
    __table_args__ = (
        UniqueConstraint('target_url', 'model_type', name='_url_model_type_uc'),
    )

    id = Column(Integer, primary_key=True, index=True)
    
    # FIX: Removed unique=True from this line (it was blocking IsolationForest and LSTM from saving)
    target_url = Column(String(500), index=True, nullable=False)
    
    # Type of model being stored (e.g., 'smart_detector', 'isolation_forest')
    model_type = Column(String(50), nullable=False)
    
    # JSON data for simple parameters (EMA, EMSD, Thresholds)
    parameters_json = Column(Text, nullable=True)
    
    # Binary data for complex objects (Sklearn models pickled)
    model_blob = Column(LargeBinary, nullable=True) 
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
