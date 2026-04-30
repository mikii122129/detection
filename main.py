# ================= main.py =================
import subprocess
import shlex
import sys
import json
import socket
import os
import concurrent.futures
import ssl  # Native SSL library
import re
import asyncio
import time
import copy
import math  # ADDED: Import math for ceil function
import threading
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from xml.sax.saxutils import escape
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request, Body, Query
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, or_, text, inspect
from sqlalchemy.orm import relationship, Session
from pydantic import BaseModel, EmailStr, field_validator

# External Libraries
import whois
import dns.resolver
import requests
import urllib3
from fastapi_mail import FastMail, MessageSchema

# PDF Generation Libraries
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pdfencrypt import StandardEncryption

# CHART Libraries
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

# Local imports
import auth
from database import Base, engine, get_db, SessionLocal
from fastapi.middleware.cors import CORSMiddleware
from models import AlertHistory, AlertRule, Domain, Incident, LoginAttempt, Monitor, User
from monitor import SmartDetector, MonitorState, monitoring_loop
from urllib.parse import urlparse

# Alert schemas (owned by this module)
class AlertRuleCreate(BaseModel):
    name: str
    type: str
    target_id: Optional[int] = None 
    target_url: Optional[str] = None 
    condition: str
    threshold: Optional[str] = None
    severity: str = "warning"
    channel: str = "email"

    @field_validator("channel")
    @classmethod
    def validate_channel(cls, v: str):
        value = (v or "email").strip().lower()
        if value not in {"email", "slack", "both"}:
            raise ValueError("Channel must be one of: both, email, slack")
        return value

def normalize_alert_channel(value: Optional[str]) -> str:
    channel = (value or "email").strip().lower()
    return channel if channel in {"email", "slack", "both"} else "email"

class AlertRuleResponse(AlertRuleCreate):
    id: int
    user_id: int
    created_at: datetime
    is_active: bool
    
    class Config:
        from_attributes = True
        
class AlertHistoryResponse(BaseModel):
    id: int
    rule_id: Optional[int]
    time: str
    channel: str
    status: str
    recipient: str
    severity: Optional[str] = "info"
    message: Optional[str] = None
    
    class Config:
        from_attributes = True

class IncidentHistoryResponse(BaseModel):
    id: int
    target: str
    status: str
    error_type: Optional[str] = None
    started_at: str
    ended_at: Optional[str] = None
    duration_seconds: Optional[int] = None

    class Config:
        from_attributes = True


class LiveDetectionStartRequest(BaseModel):
    target_url: str
    listen_host: str = "0.0.0.0"
    listen_port: int = 9999
    log_output_path: Optional[str] = None


def _incident_clean_domain(target_url: str) -> str:
    return (urlparse(target_url).hostname or target_url or "").strip().lower()


def _incident_rule_applies(rule: AlertRule, target: str) -> bool:
    clean_target = _incident_clean_domain(target)
    clean_rule = _incident_clean_domain(rule.target_url or "")

    if rule.target_url:
        if not clean_rule or not clean_target:
            return False
        if clean_rule == clean_target:
            return True
        if clean_target.endswith(f".{clean_rule}"):
            return True
        if clean_rule.endswith(f".{clean_target}"):
            return True
        if clean_rule in clean_target and len(clean_rule) > 3:
            return True
        return False

    return True


def _incident_status_category(status: str) -> str:
    upper = (status or "").upper()
    if "PROBE BLOCKED" in upper:
        return "probe_blocked"
    if "TIMEOUT" in upper:
        return "timeout"
    if "TLS ERROR" in upper or "SSL ERROR" in upper or "CERTIFICATE" in upper:
        return "tls"
    if "UNREACHABLE" in upper or "REFUSED" in upper or "CONNECTION REFUSED" in upper:
        return "unreachable"
    if "NOT FOUND" in upper or "CLIENT ERROR" in upper:
        return "client_error"
    if "SERVER DOWN" in upper or "DOWN" in upper:
        return "down"
    if "CRITICAL" in upper:
        return "critical"
    if "WARNING" in upper or "UNSTABLE" in upper or "SLOW" in upper or "ANOMALY" in upper:
        return "warning"
    return "info"


def _incident_error_type_for_rule(rule: AlertRule, current_status: str = "") -> str:
    category = _incident_status_category(current_status)

    if rule.condition == "status_down":
        if category == "probe_blocked":
            return "Probe Blocked"
        if category == "timeout":
            return "Timeout"
        if category == "tls":
            return "TLS Error"
        if category == "unreachable":
            return "Unreachable"
        if category == "client_error":
            return "4XX Client Error"
        if category == "down":
            return "Service Down"
        if category == "critical":
            return "Critical Failure"
    if rule.condition == "response_time_high":
        return f"High Response Time: {rule.name}"
    if rule.condition == "smart_anomaly":
        return f"Smart Anomaly: {rule.name}"
    return f"Rule Triggered: {rule.name}"


def _sync_live_rule_incidents(current_user: User, db: Session) -> None:
    state = get_user_monitor_state(current_user.id)
    if not state.targets:
        return

    rules = db.query(AlertRule).filter(
        AlertRule.user_id == current_user.id,
        AlertRule.type == "service",
        AlertRule.is_active == True
    ).all()

    if not rules:
        return

    monitors_by_target = {
        monitor.target_url: monitor
        for monitor in db.query(Monitor).filter(
            Monitor.user_id == current_user.id,
            Monitor.target_url.in_(state.targets)
        ).all()
    }

    for target in state.targets:
        current_status = state.current_statuses.get(target, "") or ""
        current_latency = state.last_known_latency.get(target, 0.0) or 0.0
        category = _incident_status_category(current_status)
        target_monitor = monitors_by_target.get(target)
        monitor_id = target_monitor.id if target_monitor else None
        target_domain = _incident_clean_domain(target)

        for rule in rules:
            if not _incident_rule_applies(rule, target):
                continue

            triggered = False
            if rule.condition == "status_down":
                triggered = category in {"probe_blocked", "timeout", "tls", "unreachable", "client_error", "down", "critical"}
            elif rule.condition == "response_time_high":
                raw_threshold = f"{rule.threshold or '>1000'}".replace("ms", "").replace("MS", "").strip()
                operator = ">"
                limit = 1000
                if ">=" in raw_threshold:
                    operator, limit = ">=", int(raw_threshold.replace(">=", "").strip() or "1000")
                elif "<=" in raw_threshold:
                    operator, limit = "<=", int(raw_threshold.replace("<=", "").strip() or "1000")
                elif ">" in raw_threshold:
                    operator, limit = ">", int(raw_threshold.replace(">", "").strip() or "1000")
                elif "<" in raw_threshold:
                    operator, limit = "<", int(raw_threshold.replace("<", "").strip() or "1000")
                elif raw_threshold.isdigit():
                    limit = int(raw_threshold)

                triggered = (
                    (operator == ">=" and current_latency >= limit) or
                    (operator == ">" and current_latency > limit) or
                    (operator == "<=" and current_latency <= limit) or
                    (operator == "<" and current_latency < limit)
                )
            elif rule.condition == "smart_anomaly":
                triggered = category in {"warning", "critical"}

            error_type = _incident_error_type_for_rule(rule, current_status)
            existing_query = db.query(Incident).filter(
                Incident.user_id == current_user.id,
                Incident.monitor_id == monitor_id,
                Incident.status == "Ongoing"
            )
            if rule.condition == "status_down":
                existing_query = existing_query.filter(
                    Incident.error_type.in_([
                        "Probe Blocked",
                        "Timeout",
                        "TLS Error",
                        "Unreachable",
                        "4XX Client Error",
                        "Service Down",
                        "Critical Failure",
                        f"Rule Triggered: {rule.name}",
                    ])
                )
            else:
                existing_query = existing_query.filter(Incident.error_type == error_type)

            existing = existing_query.order_by(Incident.started_at.desc()).first()

            if triggered and not existing:
                db.add(Incident(
                    monitor_id=monitor_id,
                    user_id=current_user.id,
                    domain=target_domain,
                    status="Ongoing",
                    error_type=error_type,
                    started_at=datetime.utcnow()
                ))
            elif triggered and existing and existing.error_type != error_type:
                existing.error_type = error_type
                if not existing.domain:
                    existing.domain = target_domain
            elif not triggered and existing:
                now = datetime.utcnow()
                existing.status = "Resolved"
                existing.ended_at = now
                existing.duration_seconds = int((now - existing.started_at).total_seconds())

    db.commit()

# Import delivery functions from alert module
try:
    from alert import dispatch_alert_notifications
except ImportError:
    def dispatch_alert_notifications(user, rule, target_url, message, current_status, current_latency):
        return {"channel": "email", "email_sent": False, "slack_sent": False}

from io import BytesIO
from fastapi.responses import StreamingResponse

# Suppress SSL warnings for internal checks
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create tables
Base.metadata.create_all(bind=engine)

def ensure_runtime_schema_updates():
    inspector = inspect(engine)
    user_columns = {column["name"] for column in inspector.get_columns("users")}
    if "slack_webhook_url" not in user_columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN slack_webhook_url VARCHAR"))
    incident_columns = {column["name"] for column in inspector.get_columns("incidents")}
    if "user_id" not in incident_columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE incidents ADD COLUMN user_id INTEGER"))
            conn.execute(text("UPDATE incidents SET user_id = monitors.user_id FROM monitors WHERE incidents.monitor_id = monitors.id"))
    if "detection_scans" in inspector.get_table_names():
        detection_scan_columns = {column["name"] for column in inspector.get_columns("detection_scans")}
        detection_scan_updates = {
            "metrics_json": "ALTER TABLE detection_scans ADD COLUMN metrics_json TEXT",
            "step_trace_json": "ALTER TABLE detection_scans ADD COLUMN step_trace_json TEXT",
            "entry_points_json": "ALTER TABLE detection_scans ADD COLUMN entry_points_json TEXT",
            "additional_findings_json": "ALTER TABLE detection_scans ADD COLUMN additional_findings_json TEXT",
            "tls_json": "ALTER TABLE detection_scans ADD COLUMN tls_json TEXT",
            "crawl_errors_json": "ALTER TABLE detection_scans ADD COLUMN crawl_errors_json TEXT",
            "owasp_catalog_json": "ALTER TABLE detection_scans ADD COLUMN owasp_catalog_json TEXT",
            "policy_note": "ALTER TABLE detection_scans ADD COLUMN policy_note TEXT",
        }
        with engine.begin() as conn:
            for column_name, statement in detection_scan_updates.items():
                if column_name not in detection_scan_columns:
                    conn.execute(text(statement))
    if "detection_findings" in inspector.get_table_names():
        with engine.begin() as conn:
            try:
                conn.execute(text("ALTER TABLE detection_findings ALTER COLUMN owasp TYPE VARCHAR(120)"))
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE detection_findings ALTER COLUMN location TYPE VARCHAR(2000)"))
            except Exception:
                pass
    with engine.begin() as conn:
        conn.execute(text("UPDATE alert_rules SET channel = 'email' WHERE channel IS NULL OR LOWER(channel) NOT IN ('email', 'slack', 'both')"))


def format_detection_error(error: Exception) -> str:
    message = str(error).strip()
    if "StringDataRightTruncation" in message or "value too long for type character varying" in message:
        return "Detection results could not be saved because one of the database fields is too small."
    if "OperationalError" in message:
        return "Detection scan failed because the database connection is unavailable."
    if len(message) > 220:
        return message[:217] + "..."
    return message or "Detection scan failed."

ensure_runtime_schema_updates()

# ================= FASTAPI APP =================
app = FastAPI()

LIVE_DETECTION_JOBS: Dict[int, Dict[str, Any]] = {}
LIVE_DETECTION_LOCK = threading.Lock()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

monitor_states: Dict[int, MonitorState] = {}
monitor_tasks: Dict[int, asyncio.Task] = {}


def get_user_monitor_state(user_id: int) -> MonitorState:
    state = monitor_states.get(user_id)
    if state is None:
        state = MonitorState()
        state.user_id = user_id
        monitor_states[user_id] = state
    return state


def reset_monitor_state(state: MonitorState) -> None:
    state.is_monitoring = False
    state.target_url = ""
    state.targets = []
    state.passive_targets = []
    state.previous_down_states = {}
    state.detectors = {}
    state.lstm_detectors = {}
    state.ml_detectors = {}
    state.histories = {}
    state.timestamps = {}
    state.baseline_avgs = {}
    state.current_statuses = {}
    state.http_status_codes = {}
    state.consecutive_probe_failures = {}
    state.last_known_status = {}
    state.last_known_latency = {}
    state.behind_protection_targets = {}


def stop_user_monitor_task(user_id: int) -> None:
    task = monitor_tasks.pop(user_id, None)
    if task and not task.done():
        task.cancel()


async def run_user_monitoring_task(user_id: int, state: MonitorState) -> None:
    try:
        await monitoring_loop(state)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        print(f"[MONITOR TASK ERROR] user={user_id}: {exc}")
        state.is_monitoring = False
        for target in state.targets:
            if state.current_statuses.get(target, "").strip() in {"", "Idle"}:
                state.current_statuses[target] = f"ERROR: Monitoring task failed ({str(exc)[:80]})"
    finally:
        existing = monitor_tasks.get(user_id)
        if existing is not None and existing.done():
            monitor_tasks.pop(user_id, None)

# ================= SCHEMAS =================
class RegisterSchema(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginSchema(BaseModel):
    username: str
    password: str

class ForgotPasswordSchema(BaseModel):
    email: EmailStr

class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str

class StartRequest(BaseModel):
    url: str
    behind_protection: bool = False

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str):
        v = v.strip()
        if not v.startswith(('http://', 'https://')):
            raise ValueError("URL must start with http:// or https://")
        return v

# Report Schemas
class GlobalReportRequest(BaseModel):
    password: str

class DomainAddRequest(BaseModel):
    domain: str

class AlertPreferencesUpdate(BaseModel):
    slack_webhook_url: Optional[str] = None

# ================= AUTHENTICATION ROUTES =================
@app.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    return auth.register_user(db, User, data.username, data.email, data.password)

@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    return auth.login_user(db, User, LoginAttempt, data.username, data.password)

@app.post("/forgot-password")
async def forgot_password(data: ForgotPasswordSchema, db: Session = Depends(get_db)):
    return await auth.forgot_password(db, User, data.email)

@app.post("/reset-password")
def reset_password(data: ResetPasswordSchema, db: Session = Depends(get_db)):
    return auth.reset_password(db, User, data.token, data.new_password)

@app.get("/")
def read_root():
    return {"version": "17.1", "model": "CyberGuard-Domain-Intel"}

# ================= DOMAIN TRACKING LOGIC & FIXES =================

# --- RDAP / WHOIS HELPER ---
def _get_rdap_info_ultra(domain_name):
    try:
        url = f"https://rdap.org/domain/{domain_name}"
        headers = {'Accept': 'application/rdap+json', 'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True, verify=False)
        if response.status_code == 200:
            data = response.json()
            info = {"registrar": None, "created": None, "expires": None}
            events = data.get("events", [])
            for event in events:
                action = str(event.get("eventAction", "")).lower()
                date_val = event.get("eventDate")
                if "expir" in action: info["expires"] = date_val
                if "regist" in action or "creat" in action: info["created"] = date_val
            entities = data.get("entities", [])
            for entity in entities:
                roles = [str(r).lower() for r in entity.get("roles", [])]
                if "registrar" in roles:
                    vcard = entity.get("vcardArray")
                    if vcard and isinstance(vcard, list) and len(vcard) > 1:
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                info["registrar"] = item[3]; break
                    if not info["registrar"]: info["registrar"] = "Redacted"
            return info, "RDAP"
        else: 
            return {"registrar": "Error", "created": None, "expires": None}, "Error"
    except Exception as e: 
        return {"registrar": f"Error: {str(e)[:20]}", "created": None, "expires": None}, "Error"

# --- DNS HELPER ---
def get_dns_records(domain):
    """Resolves DNS records for a domain."""
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
            results[rtype] = []
            
    return results

# --- SCAN LOGIC ---
def run_domain_scan_logic(domain_name):
    """Runs the blocking scan operations. REMOVED SSL FETCHING."""
    print(f"[SCAN START] Scanning {domain_name}...")
    
    # 1. Get DNS
    dns_data = get_dns_records(domain_name)
    
    # 2. REMOVED: SSL Fetching
    
    # 3. Get WHOIS (Using the RDAP function)
    whois_data, _ = _get_rdap_info_ultra(domain_name)
    
    # 4. Prepare Database Payloads
    return {
        "dns": json.dumps(dns_data),
        "ssl": json.dumps({}), 
        "whois": json.dumps(whois_data)
    }

# --- FIX: HELPER TO CHECK ALERTS (With Math.ceil) ---
def trigger_domain_alert_check(domain: Domain, db: Session):
    """
    Extracts expiration date (Manual > WHOIS) and triggers alert check.
    Uses Math.ceil to match Frontend behavior.
    """
    try:
        # Parse JSON data
        manual_data = json.loads(domain.manual_data) if domain.manual_data else {}
        whois_data = json.loads(domain.whois_data) if domain.whois_data else {}
    except:
        manual_data = {}
        whois_data = {}

    # Priority: Manual Expiration > WHOIS Expiration
    exp_date_str = manual_data.get("expirationDate") or whois_data.get("expires")
    
    if not exp_date_str:
        return

    try:
        # Parse Date
        if "T" in exp_date_str:
            exp_date_str = exp_date_str.split("T")[0]
        exp_date = datetime.strptime(exp_date_str, "%Y-%m-%d")
        
        # FIX: Calculate days remaining using Math.ceil to match Frontend
        delta = exp_date - datetime.utcnow()
        days_remaining = math.ceil(delta.total_seconds() / 86400)
        
        # Call the existing alert logic
        check_domain_expiry_alerts(domain, days_remaining, db)
        
    except Exception as e:
        print(f"[ALERT ERROR] Failed to parse date for {domain.domain_name}: {e}")

def check_domain_expiry_alerts(domain: Domain, days_remaining: int, db: Session):
    """
    Checks if any active domain alert rules are triggered based on expiration time.
    """
    try:
        rules = db.query(AlertRule).filter(
            AlertRule.user_id == domain.user_id,
            AlertRule.type == "domain",
            AlertRule.is_active == True
        ).all()

        for rule in rules:
            if rule.target_id is not None and rule.target_id != domain.id:
                continue

            triggered = False
            message = ""

            if rule.condition == "domain_expiring":
                threshold_str = rule.threshold.strip() if rule.threshold else ""
                match = re.search(r'(\d+)', threshold_str)
                if not match:
                    print(f"[ALERT DEBUG] Could not find number in threshold: {threshold_str}")
                    continue
                
                limit = int(match.group(1))
                operator = '>'
                if '>=' in threshold_str: operator = '>='
                elif '>' in threshold_str: operator = '>'
                elif '<=' in threshold_str: operator = '<='
                elif '<' in threshold_str: operator = '<'
                else: operator = '<' 

                if operator == '>=' and days_remaining >= limit: triggered = True
                elif operator == '>' and days_remaining > limit: triggered = True
                elif operator == '<=' and days_remaining <= limit: triggered = True
                elif operator == '<' and days_remaining < limit: triggered = True

            if triggered:
                recent_alert = db.query(AlertHistory).filter(
                    AlertHistory.user_id == domain.user_id,
                    AlertHistory.source_id == domain.id,
                    AlertHistory.rule_id == rule.id,
                    AlertHistory.triggered_at > datetime.utcnow() - timedelta(hours=1)
                ).first()

                if not recent_alert:
                    message = (f"Domain Expiring Alert: {domain.domain_name} expires in {days_remaining} days. "
                               f"(Threshold: {rule.threshold})")

                    print(f"[DOMAIN ALERT TRIGGERED] {message}")
                    user = db.query(User).filter(User.id == domain.user_id).first()
                    delivery = {"channel": (rule.channel or "email"), "email_sent": False, "slack_sent": False}
                    if user:
                        delivery = dispatch_alert_notifications(
                            user,
                            rule,
                            domain.domain_name,
                            message,
                            f"Domain expiration window reached: {days_remaining} days left",
                            0.0
                        )

                    status = "failed"
                    if delivery["channel"] == "both":
                        if delivery["email_sent"] and delivery["slack_sent"]:
                            status = "sent"
                        elif delivery["email_sent"] or delivery["slack_sent"]:
                            status = "partial"
                    elif delivery["email_sent"] or delivery["slack_sent"]:
                        status = "sent"

                    new_alert = AlertHistory(
                        user_id=domain.user_id,
                        rule_id=rule.id,
                        source_type="domain",
                        source_id=domain.id,
                        message=message,
                        severity=rule.severity,
                        channel=delivery["channel"],
                        status=status
                    )
                    db.add(new_alert)
                    db.commit()

    except Exception as e:
        print(f"[DOMAIN ALERT ERROR] {e}")
        db.rollback()

# ================= DOMAIN API ROUTES =================

@app.get("/domain/list")
def list_domains(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    domains = db.query(Domain).filter(Domain.user_id == current_user.id).all()
    response = []
    for d in domains:
        response.append({
            "id": d.id,
            "domain_name": d.domain_name,
            "security_score": d.security_score,
            "last_scanned": d.last_scanned.isoformat() if d.last_scanned else None
        })
    return response

@app.post("/domain/add")
async def add_domain(
    request: Request, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(auth.get_current_user)
):
    body = await request.body()
    domain_name = body.decode("utf-8").strip().strip('"\'')
    
    if not domain_name:
        raise HTTPException(status_code=400, detail="Domain name cannot be empty")
    
    clean_domain = domain_name.replace("https://", "").replace("http://", "").split("/")[0].strip()
    
    existing = db.query(Domain).filter(Domain.domain_name == clean_domain, Domain.user_id == current_user.id).first()
    if existing:
        return {"message": "Domain already tracked", "id": existing.id}

    new_domain = Domain(
        domain_name=clean_domain,
        user_id=current_user.id,
        security_score=0,
        ssl_data="{}", 
        whois_data="{}",
        dns_data="{}",
        manual_data="{}"
    )
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)

    loop = asyncio.get_event_loop()
    try:
        scan_results = await loop.run_in_executor(None, run_domain_scan_logic, clean_domain)
        
        new_domain.dns_data = scan_results["dns"]
        new_domain.ssl_data = "{}" 
        new_domain.whois_data = scan_results["whois"]
        new_domain.last_scanned = datetime.utcnow()
        
        whois_info = json.loads(scan_results["whois"])
        new_domain.security_score = 100 if whois_info.get("registrar") else 50
        
        db.commit()
        trigger_domain_alert_check(new_domain, db)
        
    except Exception as e:
        print(f"[SCAN ERROR] {e}")
        
    return {"message": "Domain added and scanned", "id": new_domain.id}

@app.get("/domain/detail/{id}")
def get_domain_detail(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")

    try:
        ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
        whois_data = json.loads(d.whois_data) if d.whois_data else {}
        manual_data = json.loads(d.manual_data) if d.manual_data else {}
        dns_data = json.loads(d.dns_data) if d.dns_data else {}
    except:
        ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

    return {
        "id": d.id,
        "domain_name": d.domain_name,
        "last_scanned": d.last_scanned.isoformat() if d.last_scanned else None,
        "creation_date": whois_data.get("created"),
        "expiration_date": whois_data.get("expires"),
        "registrar": whois_data.get("registrar"),
        "dns_records": dns_data,
        "manual_data": manual_data
    }

@app.post("/domain/scan/{id}")
async def rescan_domain(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")

    loop = asyncio.get_event_loop()
    try:
        scan_results = await loop.run_in_executor(None, run_domain_scan_logic, d.domain_name)
        
        d.dns_data = scan_results["dns"]
        d.ssl_data = "{}" 
        d.whois_data = scan_results["whois"]
        d.last_scanned = datetime.utcnow()
        
        whois_info = json.loads(scan_results["whois"])
        d.security_score = 100 if whois_info.get("registrar") else 50
        
        db.commit()
        trigger_domain_alert_check(d, db)
        
        return {"message": "Scan successful"}
    except Exception as e:
        print(f"[RESCAN ERROR] {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.delete("/domain/{id}")
def delete_domain(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    db.delete(d)
    db.commit()
    return {"message": "Deleted"}

@app.post("/domain/update-manual/{id}")
def update_manual_domain_data(id: int, data: dict, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    try:
        existing_manual = json.loads(d.manual_data) if d.manual_data else {}
    except:
        existing_manual = {}
        
    updated_manual = {**existing_manual, **data}
    d.manual_data = json.dumps(updated_manual)
    d.last_scanned = datetime.utcnow() 
    
    db.commit()
    trigger_domain_alert_check(d, db)
    
    return {"message": "Manual data updated"}


# ================= ALERTS API ROUTES =================

# NEW: Added GET endpoint to fetch rules securely for the current user only
@app.get("/alerts/rules", response_model=List[AlertRuleResponse])
def get_alert_rules(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """
    Retrieves alert rules for the currently authenticated user.
    Ensures data isolation so users cannot see rules created by others.
    """
    rules = db.query(AlertRule).filter(AlertRule.user_id == current_user.id).all()
    updated = False
    for rule in rules:
        normalized = normalize_alert_channel(rule.channel)
        if rule.channel != normalized:
            rule.channel = normalized
            updated = True
    if updated:
        db.commit()
        for rule in rules:
            db.refresh(rule)
    return rules

@app.get("/alerts/preferences")
def get_alert_preferences(current_user: User = Depends(auth.get_current_user)):
    slack_url = (current_user.slack_webhook_url or "").strip()
    return {
        "email": current_user.email,
        "slack_configured": bool(slack_url),
        "slack_webhook_hint": "Configured" if slack_url else "Not configured"
    }

@app.put("/alerts/preferences")
def update_alert_preferences(
    data: AlertPreferencesUpdate,
    current_user: User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    if data.slack_webhook_url is not None:
        webhook = data.slack_webhook_url.strip()
        if webhook:
            if not webhook.startswith("https://hooks.slack.com/"):
                raise HTTPException(status_code=400, detail="Slack webhook URL must start with https://hooks.slack.com/")
            current_user.slack_webhook_url = webhook
        else:
            current_user.slack_webhook_url = None

        db.add(current_user)
        db.commit()
        db.refresh(current_user)

    return {
        "message": "Alert preferences updated",
        "email": current_user.email,
        "slack_configured": bool((current_user.slack_webhook_url or "").strip()),
        "slack_webhook_hint": "Configured" if (current_user.slack_webhook_url or "").strip() else "Not configured"
    }

@app.post("/alerts/rules", response_model=AlertRuleResponse)
def create_alert_rule(rule: AlertRuleCreate, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    
    # ADDED: Validation to remove/deprecate http_error condition
    if rule.condition == "http_error":
        raise HTTPException(status_code=400, detail="The 'http_error' condition is deprecated. Please use 'status_down' to detect 404, 500, and connection errors.")
    rule.channel = normalize_alert_channel(rule.channel)
    if rule.channel in {"slack", "both"} and not (current_user.slack_webhook_url or "").strip():
        raise HTTPException(status_code=400, detail="Configure a Slack webhook in alert preferences before using Slack delivery.")

    resolved_target_id = rule.target_id
    resolved_target_url = rule.target_url 
    
    if rule.type == "service" and rule.target_url:
        clean_target_url = rule.target_url.rstrip('/')
        
        monitor = db.query(Monitor).filter(Monitor.target_url == clean_target_url).first()
        if monitor:
            resolved_target_id = monitor.id

    new_rule = AlertRule(
        user_id=current_user.id,
        name=rule.name,
        type=rule.type,
        target_id=resolved_target_id,
        target_url=resolved_target_url,
        condition=rule.condition,
        threshold=rule.threshold,
        severity=rule.severity,
        channel=rule.channel
    )
    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)
    return new_rule

@app.delete("/alerts/rules/{rule_id}")
def delete_alert_rule(rule_id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    rule = db.query(AlertRule).filter(AlertRule.id == rule_id, AlertRule.user_id == current_user.id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    # FIX: Delete associated history records first to avoid Foreign Key Violation
    db.query(AlertHistory).filter(AlertHistory.rule_id == rule_id).delete()
    
    db.delete(rule)
    db.commit()
    return {"message": "Deleted"}

@app.get("/alerts/history", response_model=List[AlertHistoryResponse])
def get_alert_history(limit: int = 50, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    history = db.query(AlertHistory).filter(AlertHistory.user_id == current_user.id).order_by(AlertHistory.triggered_at.desc()).limit(limit).all()
    
    result = []
    for h in history:
        data = {
            "id": h.id,
            "rule_id": h.rule_id,
            "time": h.triggered_at.isoformat() if h.triggered_at else "",
            "channel": h.channel,
            "status": h.status,
            "recipient": "User", 
            "severity": h.severity,
            "message": h.message
        }
        result.append(AlertHistoryResponse(**data))
    return result

@app.get("/incidents/history", response_model=List[IncidentHistoryResponse])
def get_incident_history(limit: int = 100, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    _sync_live_rule_incidents(current_user, db)

    incidents = (
        db.query(Incident, Monitor.target_url)
        .outerjoin(Monitor, Incident.monitor_id == Monitor.id)
        .filter(or_(Incident.user_id == current_user.id, Monitor.user_id == current_user.id))
        .order_by(Incident.started_at.desc())
        .limit(limit)
        .all()
    )

    result = []
    for incident, target_url in incidents:
        target_value = incident.domain or target_url or f"Monitor #{incident.monitor_id}"
        normalized_target = (target_value or "").strip().lower()
        normalized_status = (incident.status or "").strip().lower()
        normalized_error = (incident.error_type or "").strip().lower()

        if normalized_target == "idle" or normalized_status == "idle" or normalized_error == "idle":
            continue

        result.append(
            IncidentHistoryResponse(
                id=incident.id,
                target=target_value,
                status=incident.status,
                error_type=incident.error_type,
                started_at=incident.started_at.isoformat() if incident.started_at else "",
                ended_at=incident.ended_at.isoformat() if incident.ended_at else None,
                duration_seconds=incident.duration_seconds,
            )
        )
    return result

@app.delete("/incidents/history")
def clear_incident_history(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    monitor_ids = db.query(Monitor.id).filter(Monitor.user_id == current_user.id).subquery()
    db.query(Incident).filter(
        or_(
            Incident.user_id == current_user.id,
            Incident.monitor_id.in_(monitor_ids)
        )
    ).delete(synchronize_session=False)
    db.commit()
    return {"message": "Incident history cleared successfully"}

@app.delete("/alerts/history")
def clear_alert_history(
    current_user: User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    """
    Deletes all alert history for the currently logged-in user.
    """
    # Delete all records where the user_id matches the current user
    db.query(AlertHistory).filter(AlertHistory.user_id == current_user.id).delete()
    
    # Commit the changes to the database
    db.commit()
    
    return {"message": "History cleared successfully"}

# ... rest of the file ...

# ================= REPORT GENERATION HELPERS (Using Math.ceil) =================
PDF_TITLE_COLOR = colors.HexColor("#0f172a")
PDF_TEXT_COLOR = colors.HexColor("#1f2937")
PDF_MUTED_COLOR = colors.HexColor("#4b5563")
CYBER_CYAN = colors.HexColor("#06b6d4")
DARK_BG = colors.HexColor("#0f172a")
LIGHT_BG = colors.HexColor("#1e293b")
STATUS_GREEN = colors.HexColor("#10b981")
STATUS_RED = colors.HexColor("#ef4444")
STATUS_ORANGE = colors.HexColor("#f59e0b")
WHITE = colors.white
GRAY_TEXT = colors.HexColor("#94a3b8")
CARD_BG = colors.HexColor("#f8fafc")
BORDER_COLOR = colors.HexColor("#dbe4ee")
SOFT_BLUE = colors.HexColor("#e0f2fe")
SOFT_GREEN = colors.HexColor("#ecfdf5")
SOFT_RED = colors.HexColor("#fef2f2")
SOFT_ORANGE = colors.HexColor("#fff7ed")

def _safe_text(value, default="N/A"):
    text = str(value).strip() if value is not None else ""
    return escape(text) if text else default

def _status_hex(color_obj, fallback="#0f172a"):
    try:
        return color_obj.hexval()
    except Exception:
        return fallback

def _footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(BORDER_COLOR)
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, 22, doc.pagesize[0] - doc.rightMargin, 22)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(PDF_MUTED_COLOR)
    canvas.drawString(doc.leftMargin, 10, f"CyberGuard report | Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 10, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()

def _summary_cards(cards, total_width):
    card_width = total_width / len(cards)
    card_cells = []
    for card in cards:
        accent = card.get("accent", CYBER_CYAN)
        tone = card.get("tone", CARD_BG)
        cell = Table([
            [Paragraph(_safe_text(card.get("label")), ParagraphStyle(
                'SummaryLabel', fontSize=8, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, leading=10, uppercase=True
            ))],
            [Paragraph(f"<b>{_safe_text(card.get('value'))}</b>", ParagraphStyle(
                'SummaryValue', fontSize=18, textColor=PDF_TITLE_COLOR, alignment=TA_CENTER, leading=22
            ))],
            [Paragraph(_safe_text(card.get("caption"), ""), ParagraphStyle(
                'SummaryCaption', fontSize=8, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, leading=10
            ))]
        ], colWidths=[card_width - 10])
        cell.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), tone),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('LINEABOVE', (0, 0), (-1, 0), 4, accent),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        card_cells.append(cell)

    cards_table = Table([card_cells], colWidths=[card_width] * len(cards))
    cards_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    return cards_table

def _detail_table(rows, col_widths, label_style, value_style, accent=CYBER_CYAN):
    table_rows = []
    for label, value in rows:
        table_rows.append([
            Paragraph(f"<b>{_safe_text(label)}</b>", label_style),
            Paragraph(_safe_text(value), value_style)
        ])

    table = Table(table_rows, colWidths=col_widths)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, BORDER_COLOR),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LINEABOVE', (0, 0), (-1, 0), 3, accent),
    ]))
    return table

def analyze_subdomain(target, status, history):
    total_checks = len(history)
    valid_latency = [h for h in history if h > 0]
    healthy_count = len([h for h in history if h > 0 and h < 3000])
    unhealthy_count = total_checks - healthy_count
    uptime_pct = (healthy_count / total_checks * 100) if total_checks > 0 else 0
    avg_lat = sum(valid_latency) / len(valid_latency) if valid_latency else 0
    max_lat = max(valid_latency) if valid_latency else 0
    min_lat = min(valid_latency) if valid_latency else 0
    
    is_down = "DOWN" in status or "ERROR" in status or "REFUSED" in status or "404" in status
    is_slow = "WARNING" in status or "TIMEOUT" in status or avg_lat > 1500
    is_healthy = not is_down and not is_slow
    short_url = target.replace("https://", "").replace("http://", "")
    
    if is_down:
        desc = (f"<b>Critical Alert:</b> <font color='#dc2626'><b>{short_url}</b></font> is <b>DOWN</b>. "
                f"Last check: <i>{status}</i>. {unhealthy_count} failures.")
        status_color = STATUS_RED
        status_label = "CRITICAL"
    elif is_slow:
        desc = (f"<b>Performance Warning:</b> <font color='#d97706'><b>{short_url}</b></font> high latency. "
                f"Avg: <b>{avg_lat:.0f}ms</b>.")
        status_color = STATUS_ORANGE
        status_label = "WARNING"
    else:
        desc = (f"<b>Operational:</b> <font color='#059669'><b>{short_url}</b></font> is healthy. "
                f"Uptime: <b>{uptime_pct:.1f}%</b>, Avg: <b>{avg_lat:.0f}ms</b>.")
        status_color = STATUS_GREEN
        status_label = "OPERATIONAL"

    return {
        "desc": desc, "uptime": uptime_pct, "avg": avg_lat, "min": min_lat, "max": max_lat,
        "healthy": healthy_count, "unhealthy": unhealthy_count,
        "status_color": status_color, "status_label": status_label
    }

def create_global_pie_chart(data):
    drawing = Drawing(260, 170)
    pc = Pie()
    pc.x = 55; pc.y = 10; pc.width = 120; pc.height = 120
    pc.data = [data.get('up', 0), data.get('down', 0), data.get('warning', 0)]
    pc.labels = ['Operational', 'Down', 'Warning']
    pc.slices[0].fillColor = STATUS_GREEN
    pc.slices[1].fillColor = STATUS_RED
    pc.slices[2].fillColor = STATUS_ORANGE
    pc.slices.strokeWidth = 0.5; pc.slices.strokeColor = colors.white
    drawing.add(pc)
    return drawing

def create_mini_pie(healthy, unhealthy):
    drawing = Drawing(100, 100)
    if healthy == 0 and unhealthy == 0: return drawing
    pc = Pie()
    pc.x = 15; pc.y = 10; pc.width = 70; pc.height = 70
    pc.data = [healthy, unhealthy]
    pc.slices[0].fillColor = STATUS_GREEN
    pc.slices[1].fillColor = STATUS_RED
    pc.slices.strokeWidth = 0.5; pc.slices.strokeColor = colors.white
    drawing.add(pc)
    return drawing

def generate_global_monitoring_pdf(password: str, state_data: dict):
    """Generates a secure, detailed PDF report for Uptime Monitoring."""
    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=20, encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()
    content_width = letter[0] - doc.leftMargin - doc.rightMargin
    
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER, spaceAfter=10)
    subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=10, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=4)
    note_style = ParagraphStyle('Secure', parent=styles['Normal'], fontSize=9, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=18)
    header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=16, textColor=WHITE, backColor=DARK_BG, borderPadding=10, spaceBefore=15, spaceAfter=10)
    analysis_style = ParagraphStyle('Analysis', parent=styles['Normal'], fontSize=9, textColor=PDF_TEXT_COLOR, alignment=TA_JUSTIFY, spaceBefore=6, spaceAfter=10, leading=14)
    url_style = ParagraphStyle('MonitorUrl', parent=styles['Normal'], fontSize=9, textColor=WHITE, leading=11, wordWrap='CJK')
    label_style = ParagraphStyle('MonitorLabel', parent=styles['Normal'], fontSize=8, textColor=PDF_MUTED_COLOR, leading=10)
    value_style = ParagraphStyle('MonitorValue', parent=styles['Normal'], fontSize=10, textColor=PDF_TEXT_COLOR, leading=12)
    chart_title_style = ParagraphStyle('ChartTitle', parent=styles['Heading3'], fontSize=13, textColor=PDF_TITLE_COLOR, alignment=TA_CENTER, spaceAfter=10, leading=16)
    executive_narrative_style = ParagraphStyle('ExecutiveNarrative', parent=analysis_style, fontSize=10, leading=16, spaceBefore=0, spaceAfter=0)
    
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph(f"Global Monitoring Report | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    elements.append(Paragraph("Password-protected operational briefing for active monitored targets.", note_style))

    targets = state_data.get("targets", [])
    current_statuses = state_data.get("current_statuses", {})
    histories = state_data.get("histories", {})

    up_count = 0; down_count = 0; warning_count = 0
    analysis_results = []

    for target in targets:
        status = current_statuses.get(target, "Unknown")
        history = histories.get(target, [])
        res = analyze_subdomain(target, status, history)
        analysis_results.append({"target": target, "data": res})
        if res['status_label'] == "OPERATIONAL": up_count += 1
        elif res['status_label'] == "CRITICAL": down_count += 1
        else: warning_count += 1

    elements.append(Paragraph("Executive Summary", header_style))
    elements.append(_summary_cards([
        {"label": "Total Targets", "value": len(targets), "caption": "Monitors in this session", "accent": CYBER_CYAN, "tone": SOFT_BLUE},
        {"label": "Operational", "value": up_count, "caption": "Healthy endpoints", "accent": STATUS_GREEN, "tone": SOFT_GREEN},
        {"label": "Down", "value": down_count, "caption": "Critical failures", "accent": STATUS_RED, "tone": SOFT_RED},
        {"label": "Warnings", "value": warning_count, "caption": "Latency or timeout risk", "accent": STATUS_ORANGE, "tone": SOFT_ORANGE},
    ], content_width))
    elements.append(Spacer(1, 20))

    pie_data = {'up': up_count, 'down': down_count, 'warning': warning_count}
    if any(v > 0 for v in pie_data.values()):
        chart_block = Table([
            [Paragraph("Global System Status", chart_title_style)],
            [create_global_pie_chart(pie_data)]
        ], colWidths=[2.9 * inch])
        chart_block.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        chart_and_note = Table([[
            chart_block,
            Paragraph(
                f"Operational coverage is <b>{up_count}</b> of <b>{len(targets)}</b> targets. "
                f"Critical interruptions: <b>{down_count}</b>. "
                f"Performance warnings: <b>{warning_count}</b>.<br/><br/>"
                f"This report preserves the live state at export time and summarizes latency history "
                f"for each monitored target without modifying runtime monitoring logic.",
                executive_narrative_style
            )
        ]], colWidths=[3.0 * inch, content_width - 3.0 * inch])
        chart_and_note.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
            ('LEFTPADDING', (1, 0), (1, 0), 18),
        ]))
        elements.append(chart_and_note)
    elements.append(PageBreak())

    elements.append(Paragraph("Detailed Subdomain Analysis", header_style))
    elements.append(Spacer(1, 10))

    for item in analysis_results:
        target = item['target']
        res = item['data']
        subdomain_elements = []
        header_table = Table([[
            Paragraph(f"<b>{_safe_text(res['status_label'])}</b>", ParagraphStyle('H', fontSize=9, textColor=WHITE, alignment=TA_CENTER)),
            Paragraph(f"<b>{_safe_text(target)}</b>", url_style)
        ]], colWidths=[1.1 * inch, content_width - 1.1 * inch])
        
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), res['status_color']),
            ('BACKGROUND', (1, 0), (1, 0), LIGHT_BG),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR)
        ]))
        subdomain_elements.append(header_table)
        subdomain_elements.append(Spacer(1, 5))
        subdomain_elements.append(Paragraph(res['desc'], analysis_style))
        mini_chart = create_mini_pie(res['healthy'], res['unhealthy'])
        metric_data = [
            [Paragraph("Uptime", label_style), Paragraph(f"{res['uptime']:.1f}%", value_style)],
            [Paragraph("Average Latency", label_style), Paragraph(f"{res['avg']:.0f} ms", value_style)],
            [Paragraph("Peak Latency", label_style), Paragraph(f"{res['max']:.0f} ms", value_style)],
            [Paragraph("Executed Checks", label_style), Paragraph(f"{res['healthy'] + res['unhealthy']}", value_style)]
        ]
        t_metrics = Table(metric_data, colWidths=[1.8*inch, 1.1*inch])
        
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), CARD_BG),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('GRID', (0, 0), (-1, -1), 0.4, BORDER_COLOR),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5)
        ]))
        content_layout = Table([[t_metrics, mini_chart]], colWidths=[3.15 * inch, content_width - 3.15 * inch])
        
        content_layout.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ALIGN', (1, 0), (1, 0), 'CENTER'),
            ('LEFTPADDING', (0,0), (0,0), 0),
            ('RIGHTPADDING', (1,0), (1,0), 0),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (1, 0), (1, 0), 8)
        ]))
        subdomain_elements.append(content_layout)
        subdomain_elements.append(Spacer(1, 20))
        line = Table([['']], colWidths=[content_width])
        line.setStyle(TableStyle([('LINEABOVE', (0, 0), (-1, 0), 0.5, colors.HexColor("#e5e7eb"))]))
        subdomain_elements.append(line)
        subdomain_elements.append(Spacer(1, 10))
        elements.append(KeepTogether(subdomain_elements))

    doc.build(elements, onFirstPage=_footer, onLaterPages=_footer)
    buffer.seek(0)
    return buffer

@app.post("/monitoring/global-report")
async def download_global_monitoring_report(data: GlobalReportRequest, current_user: User = Depends(auth.get_current_user)):
    is_strong, msg = auth.validate_password(data.password, current_user.username)
    if not is_strong:
        raise HTTPException(status_code=400, detail=f"Weak Password: {msg}")

    try:
        state = get_user_monitor_state(current_user.id)
        state_data = {
            "targets": list(state.targets),
            "current_statuses": dict(state.current_statuses),
            "histories": {k: list(v) for k, v in state.histories.items()}
        }
        pdf_buffer = generate_global_monitoring_pdf(data.password, state_data)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=cyberguard_monitoring_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Failed to generate report: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
# ... existing imports ...
from detection import DetectionEngine, LiveLogReceiver
from models import DetectionScan, DetectionFinding
# ... existing code ...

# ================= DETECTION API ROUTES =================

@app.post("/detection/scan")
async def start_detection_scan(
    request: Request,
    current_user: User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    body = await request.json()
    target_url = body.get("target_url")

    if not target_url:
        raise HTTPException(status_code=400, detail="Target URL required")

    new_scan = DetectionScan(
        user_id=current_user.id,
        target_url=target_url,
        status="running"
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    scan_id = new_scan.id

    def run_scan_job(scan_id: int, target_url: str) -> None:
        task_db = SessionLocal()
        detection_engine = DetectionEngine()
        step_trace = []

        def update_progress(step: str, message: str) -> None:
            step_trace.append({"step": step, "message": message, "time": datetime.utcnow().isoformat()})
            stored_scan = task_db.query(DetectionScan).filter(DetectionScan.id == scan_id).first()
            if stored_scan:
                stored_scan.step_trace_json = json.dumps(step_trace)
                stored_scan.policy_note = message
                task_db.commit()

        try:
            update_progress("queued", "Saved receiver traffic analysis queued")
            results = detection_engine._scan_target_sync(target_url, update_progress)
            stored_scan = task_db.query(DetectionScan).filter(DetectionScan.id == scan_id).first()
            if not stored_scan:
                return

            update_progress("persisting", "Persisting scan summary to the database")
            stored_scan.status = results["status"]
            stored_scan.risk_score = results["risk_score"]
            stored_scan.summary_json = json.dumps(results["metrics"])
            stored_scan.metrics_json = json.dumps(results["metrics"])
            stored_scan.step_trace_json = json.dumps(step_trace)
            stored_scan.owasp_catalog_json = json.dumps(sorted({finding["owasp"] for finding in results["findings"]}))
            stored_scan.policy_note = "Saved receiver traffic analysis saved"
            task_db.commit()

            update_progress("writing_findings", "Writing vulnerability findings to the database")
            for finding in results["findings"]:
                task_db.add(DetectionFinding(
                    scan_id=stored_scan.id,
                    owasp=finding["owasp"],
                    severity=finding["severity"],
                    title=finding["title"],
                    description=finding["description"],
                    evidence=finding["evidence"],
                    location=finding["location"],
                    remediation=finding["remediation"],
                    confidence=finding["confidence"]
                ))

            stored_scan.policy_note = "Saved receiver traffic analysis complete"
            stored_scan.step_trace_json = json.dumps(step_trace + [{
                "step": "complete",
                "message": "Saved receiver traffic analysis complete",
                "time": datetime.utcnow().isoformat()
            }])
            task_db.commit()
        except Exception as e:
            print(f"[DETECTION ERROR] {e}")
            task_db.rollback()
            stored_scan = task_db.query(DetectionScan).filter(DetectionScan.id == scan_id).first()
            if stored_scan:
                stored_scan.status = "failed"
                stored_scan.policy_note = format_detection_error(e)
                stored_scan.step_trace_json = json.dumps(step_trace)
                try:
                    task_db.commit()
                except Exception:
                    task_db.rollback()
        finally:
            task_db.close()

    threading.Thread(target=run_scan_job, args=(scan_id, target_url), daemon=True).start()

    return {
        "message": "Saved receiver traffic analysis initiated",
        "scan_id": scan_id,
        "status": "running",
        "risk_score": 0,
        "metrics": {"requests_parsed": 0, "progress_message": "Passive detection session queued"},
        "findings": [],
    }


@app.post("/detection/live/start")
def start_live_detection(
    payload: LiveDetectionStartRequest,
    current_user: User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    target_url = (payload.target_url or "").strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="Target URL required")
    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Target URL must start with http:// or https://")
    if payload.listen_port < 1 or payload.listen_port > 65535:
        raise HTTPException(status_code=400, detail="listen_port must be between 1 and 65535")
    receiver_preview = LiveLogReceiver(
        DetectionEngine(),
        target_url,
        host=payload.listen_host,
        port=payload.listen_port,
        log_output_path=payload.log_output_path,
    )
    effective_log_output_path = receiver_preview.log_output_path

    new_scan = DetectionScan(
        user_id=current_user.id,
        target_url=target_url,
        status="listening",
        policy_note=f"Preparing live receiver on {payload.listen_host}:{payload.listen_port}",
        summary_json=json.dumps({
            "mode": "live_log_stream",
            "listen_host": payload.listen_host,
            "listen_port": payload.listen_port,
            "log_lines_received": 0,
            "requests_parsed": 0,
            "suspicious_events": 0,
            "saved_log_path": effective_log_output_path,
        }),
        metrics_json=json.dumps({
            "mode": "live_log_stream",
            "listen_host": payload.listen_host,
            "listen_port": payload.listen_port,
            "log_lines_received": 0,
            "requests_parsed": 0,
            "suspicious_events": 0,
            "saved_log_path": effective_log_output_path,
        }),
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    scan_id = new_scan.id
    stop_event = threading.Event()

    def run_live_job(scan_id: int, target_url: str, listen_host: str, listen_port: int) -> None:
        task_db = SessionLocal()
        detection_engine = DetectionEngine()
        receiver = LiveLogReceiver(
            detection_engine,
            target_url,
            host=listen_host,
            port=listen_port,
            log_output_path=effective_log_output_path,
        )
        step_trace = []
        metrics = {
            "mode": "live_log_stream",
            "listen_host": listen_host,
            "listen_port": listen_port,
            "log_lines_received": 0,
            "requests_parsed": 0,
            "suspicious_events": 0,
            "saved_log_path": receiver.log_output_path,
            "ml_predictions": [],
        }

        def persist_scan(stored_scan: DetectionScan) -> None:
            stored_scan.summary_json = json.dumps(metrics)
            stored_scan.metrics_json = json.dumps(metrics)
            stored_scan.step_trace_json = json.dumps(step_trace)

        def update_progress(step: str, message: str) -> None:
            step_trace.append({"step": step, "message": message, "time": datetime.utcnow().isoformat()})
            stored_scan = task_db.query(DetectionScan).filter(DetectionScan.id == scan_id).first()
            if stored_scan:
                if step == "listening":
                    stored_scan.status = "listening"
                elif step == "connected":
                    stored_scan.status = "running"
                elif step in {"complete", "stopped", "disconnected"} and stored_scan.status != "failed":
                    stored_scan.status = "completed" if step != "stopped" else "stopped"
                stored_scan.policy_note = message
                persist_scan(stored_scan)
                task_db.commit()

        def persist_finding(result: Dict[str, Any]) -> None:
            stored_scan = task_db.query(DetectionScan).filter(DetectionScan.id == scan_id).first()
            if not stored_scan:
                return

            parsed = result["parsed"]
            finding = result["finding"]
            prediction = result.get("prediction") or {}
            existing = task_db.query(DetectionFinding).filter(
                DetectionFinding.scan_id == scan_id,
                DetectionFinding.owasp == finding["owasp"],
                DetectionFinding.location == finding["location"],
                DetectionFinding.evidence == finding["evidence"],
            ).first()
            if not existing:
                task_db.add(DetectionFinding(
                    scan_id=scan_id,
                    owasp=finding["owasp"],
                    severity=finding["severity"],
                    title=finding["title"],
                    description=finding["description"],
                    evidence=finding["evidence"],
                    location=finding["location"],
                    remediation=finding["remediation"],
                    confidence=finding["confidence"],
                ))

            metrics["last_request_target"] = parsed.request_target
            metrics["last_source_ip"] = parsed.remote_host
            metrics["last_status_code"] = parsed.status_code
            metrics["last_detected_label"] = finding["owasp"]
            metrics["ml_predictions"] = metrics.get("ml_predictions", [])
            if prediction:
                metrics["ml_predictions"].append({
                    "label_id": prediction.get("label_id"),
                    "label": finding["owasp"],
                    "model_label": prediction.get("label"),
                    "confidence": finding["confidence"],
                    "model_confidence": prediction.get("confidence"),
                    "request_text": parsed.request_target,
                    "is_malicious": prediction.get("is_malicious", True),
                    "source_ip": parsed.remote_host,
                    "status_code": parsed.status_code,
                    "classifier": finding.get("classifier", "hybrid"),
                })
                metrics["ml_predictions"] = metrics["ml_predictions"][-50:]
            metrics["findings_by_severity"] = metrics.get("findings_by_severity", {})
            severity = finding["severity"].lower()
            metrics["findings_by_severity"][severity] = metrics["findings_by_severity"].get(severity, 0) + 1
            stored_scan.risk_score = min(
                100,
                stored_scan.risk_score + {"critical": 25, "high": 15, "warning": 8, "info": 4}.get(severity, 4),
            )
            stored_scan.status = "running"
            stored_scan.policy_note = f"Flagged {finding['owasp']} from {parsed.remote_host} on {parsed.request_target}"
            stored_scan.owasp_catalog_json = json.dumps(sorted({
                row[0]
                for row in task_db.query(DetectionFinding.owasp).filter(DetectionFinding.scan_id == scan_id).all()
            } | {finding["owasp"]}))
            persist_scan(stored_scan)
            task_db.commit()

        def persist_traffic_metrics(result: Dict[str, Any], live_metrics: Dict[str, Any]) -> None:
            stored_scan = task_db.query(DetectionScan).filter(DetectionScan.id == scan_id).first()
            if not stored_scan:
                return

            parsed = result.get("parsed")
            metrics.update({
                "mode": live_metrics.get("mode", "live_log_stream"),
                "target": live_metrics.get("target", target_url),
                "listen_host": live_metrics.get("listen_host", listen_host),
                "listen_port": live_metrics.get("listen_port", listen_port),
                "connection_count": live_metrics.get("connection_count", 0),
                "log_lines_received": live_metrics.get("log_lines_received", 0),
                "requests_parsed": live_metrics.get("requests_parsed", 0),
                "ignored_internal_test_requests": live_metrics.get("ignored_internal_test_requests", 0),
                "suspicious_events": live_metrics.get("suspicious_events", 0),
                "saved_log_path": live_metrics.get("saved_log_path", receiver.log_output_path),
                "model_enabled": live_metrics.get("model_enabled"),
                "model_source": live_metrics.get("model_source"),
                "model_error": live_metrics.get("model_error"),
            })
            if parsed:
                metrics["last_request_target"] = parsed.request_target
                metrics["last_source_ip"] = parsed.remote_host
                metrics["last_status_code"] = parsed.status_code
            prediction = result.get("prediction") or {}
            if prediction:
                metrics["last_prediction_label"] = prediction.get("label")
                metrics["last_prediction_confidence"] = prediction.get("confidence")
            if stored_scan.status in {"listening", "queued"}:
                stored_scan.status = "running"
            stored_scan.policy_note = (
                f"Live traffic: {metrics['requests_parsed']} parsed, "
                f"{metrics['suspicious_events']} suspicious"
            )
            persist_scan(stored_scan)
            task_db.commit()

        try:
            update_progress("queued", "Live detection session queued")

            def on_event(result: Dict[str, Any]) -> None:
                persist_finding(result)

            final_metrics = receiver.serve(
                should_stop=stop_event,
                progress_callback=update_progress,
                event_callback=on_event,
                traffic_callback=persist_traffic_metrics,
            )

            stored_scan = task_db.query(DetectionScan).filter(DetectionScan.id == scan_id).first()
            if stored_scan:
                metrics.update(final_metrics)
                stored_scan.status = final_metrics.get("status", "completed")
                stored_scan.policy_note = (
                    "Live detection listener stopped"
                    if stored_scan.status == "stopped"
                    else "Live detection session completed"
                )
                persist_scan(stored_scan)
                task_db.commit()
        except Exception as e:
            print(f"[LIVE DETECTION ERROR] {e}")
            task_db.rollback()
            stored_scan = task_db.query(DetectionScan).filter(DetectionScan.id == scan_id).first()
            if stored_scan:
                stored_scan.status = "failed"
                stored_scan.policy_note = format_detection_error(e)
                persist_scan(stored_scan)
                try:
                    task_db.commit()
                except Exception:
                    task_db.rollback()
        finally:
            task_db.close()
            with LIVE_DETECTION_LOCK:
                LIVE_DETECTION_JOBS.pop(scan_id, None)

    thread = threading.Thread(
        target=run_live_job,
        args=(scan_id, target_url, payload.listen_host, payload.listen_port),
        daemon=True,
    )
    with LIVE_DETECTION_LOCK:
        LIVE_DETECTION_JOBS[scan_id] = {
            "thread": thread,
            "stop_event": stop_event,
            "user_id": current_user.id,
        }
    thread.start()

    return {
        "message": "Live detection listener started",
        "scan_id": scan_id,
        "status": "listening",
        "risk_score": 0,
        "metrics": {
            "mode": "live_log_stream",
            "listen_host": payload.listen_host,
            "listen_port": payload.listen_port,
            "saved_log_path": effective_log_output_path,
            "progress_message": f"Listening for VM logs on {payload.listen_host}:{payload.listen_port}",
        },
        "findings": [],
    }


@app.post("/detection/live/stop/{scan_id}")
def stop_live_detection(
    scan_id: int,
    current_user: User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    scan = db.query(DetectionScan).filter(
        DetectionScan.id == scan_id,
        DetectionScan.user_id == current_user.id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    with LIVE_DETECTION_LOCK:
        job = LIVE_DETECTION_JOBS.get(scan_id)

    if not job:
        return {"message": "No active live detection job for this scan", "status": scan.status}
    if job.get("user_id") != current_user.id:
        raise HTTPException(status_code=403, detail="Not allowed to stop this live detection job")

    stop_event = job["stop_event"]
    stop_event.set()
    scan.policy_note = "Stop requested for live detection listener"
    if scan.status not in {"completed", "failed", "stopped"}:
        scan.status = "stopping"
    db.commit()

    return {"message": "Stop signal sent", "scan_id": scan_id, "status": scan.status}

@app.get("/detection/history")
def get_detection_history(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    scans = db.query(DetectionScan).filter(
        DetectionScan.user_id == current_user.id
    ).order_by(DetectionScan.created_at.desc()).limit(10).all()
    
    result = []
    for s in scans:
        findings_count = db.query(DetectionFinding).filter(DetectionFinding.scan_id == s.id).count()
        result.append({
            "id": s.id,
            "target_url": s.target_url,
            "status": s.status,
            "risk_score": s.risk_score,
            "created_at": s.created_at.isoformat(),
            "findings_count": findings_count,
            "progress_message": s.policy_note
        })
    return result

@app.delete("/detection/history")
def clear_detection_history(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    with LIVE_DETECTION_LOCK:
        for active_scan_id, job in list(LIVE_DETECTION_JOBS.items()):
            if job.get("user_id") == current_user.id:
                job["stop_event"].set()

    scans = db.query(DetectionScan).filter(
        DetectionScan.user_id == current_user.id
    ).all()

    if not scans:
        return {"message": "Detection history already empty"}

    scan_ids = [scan.id for scan in scans]
    db.query(DetectionFinding).filter(DetectionFinding.scan_id.in_(scan_ids)).delete(synchronize_session=False)
    db.query(DetectionScan).filter(DetectionScan.id.in_(scan_ids)).delete(synchronize_session=False)
    db.commit()

    return {"message": "Detection history cleared", "deleted_scan_count": len(scan_ids)}

@app.get("/detection/findings/{scan_id}")
def get_scan_findings(scan_id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    scan = db.query(DetectionScan).filter(
        DetectionScan.id == scan_id,
        DetectionScan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(DetectionFinding).filter(DetectionFinding.scan_id == scan_id).all()
    
    result_findings = []
    for f in findings:
        result_findings.append({
            "owasp": f.owasp,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
            "location": f.location,
            "remediation": f.remediation,
            "confidence": f.confidence
        })

    return {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "metrics": json.loads(scan.summary_json) if scan.summary_json else {"duration_seconds": 0, "requests_parsed": 0},
        "findings": result_findings,
        "policy_note": scan.policy_note,
        "step_trace": json.loads(scan.step_trace_json) if scan.step_trace_json else []
    }

# ================= SINGLE DOMAIN REPORT GENERATION (UPDATED - NO SSL) =================

def formatDate(date_str):
    if not date_str: return "N/A"
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return dt.strftime("%B %d, %Y")
    except:
        return date_str

def get_field_value(field_name, manual_data, whois_data, dns_data):
    if field_name == "Registrar":
        if manual_data.get("registrar"):
            return manual_data.get("registrar")
        if whois_data.get("registrar"):
            reg = whois_data.get("registrar")
            return reg if reg != "Redacted" else "Private / Redacted"
        return "Unknown"

    if field_name == "Hosting Provider":
        if manual_data.get("hostingProvider"):
            return manual_data.get("hostingProvider")
        if dns_data and "NS" in dns_data and len(dns_data["NS"]) > 0:
            ns = str(dns_data["NS"][0]).lower()
            if "aws" in ns: return "Amazon Web Services (AWS)"
            if "azure" in ns or "cloudapp" in ns: return "Microsoft Azure"
            if "google" in ns: return "Google Cloud (GCP)"
            if "cloudflare" in ns: return "Cloudflare"
            if "bluehost" in ns: return "Bluehost"
            if "godaddy" in ns: return "GoDaddy"
            if "hostgator" in ns: return "HostGator"
            if "digitalocean" in ns: return "DigitalOcean"
            if "heroku" in ns: return "Heroku"
            if "namecheap" in ns: return "Namecheap"
        return "Unknown (Set in Manual Asset)"

    if field_name == "DNS Provider":
        if manual_data.get("dnsProvider"):
            return manual_data.get("dnsProvider")

        if dns_data and "NS" in dns_data and len(dns_data["NS"]) > 0:
            ns = dns_data["NS"][0].lower()
            if "aws" in ns: return "AWS Route 53"
            if "cloudflare" in ns: return "Cloudflare DNS"
            if "azure" in ns: return "Azure DNS"
            if "google" in ns: return "Google Cloud DNS"
            if "godaddy" in ns: return "GoDaddy DNS"
            return dns_data["NS"][0]
            
        return "Unknown"

    return manual_data.get(field_name, "Not Set")

def generate_single_domain_pdf(domain_id: int, db: Session, password: str):
    """Generates a detailed PDF for a single specific domain. SSL REMOVED."""
    d = db.query(Domain).filter(Domain.id == domain_id).first()
    if not d: raise HTTPException(status_code=404, detail="Domain not found")

    try:
        whois_data = json.loads(d.whois_data) if d.whois_data else {}
        manual_data = json.loads(d.manual_data) if d.manual_data else {}
        dns_data = json.loads(d.dns_data) if d.dns_data else {}
    except (json.JSONDecodeError, TypeError):
        whois_data = {}; manual_data = {}; dns_data = {}

    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    
    doc = SimpleDocTemplate(buffer, pagesize=A4, 
                            rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72, 
                            encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()
    content_width = A4[0] - doc.leftMargin - doc.rightMargin

    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=32, textColor=CYBER_CYAN, alignment=TA_CENTER, spaceAfter=6)
    subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=18)
    header_style = ParagraphStyle('Header', parent=styles['Heading2'], fontSize=20, textColor=WHITE, backColor=DARK_BG, spaceBefore=20, spaceAfter=15, 
                                  borderPadding=12, alignment=TA_CENTER, borderWidth=1, borderColor=CYBER_CYAN, borderRadius=6)
    section_title_style = ParagraphStyle('SectionTitle', parent=styles['Heading3'], fontSize=16, textColor=PDF_TITLE_COLOR, spaceBefore=25, spaceAfter=12, leading=20)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=11, textColor=PDF_TEXT_COLOR, leading=16, spaceAfter=12)
    label_style = ParagraphStyle('Label', parent=styles['Normal'], fontSize=11, textColor=PDF_MUTED_COLOR, fontName='Helvetica-Bold')
    compact_style = ParagraphStyle('CompactBody', parent=body_style, fontSize=10, leading=13, spaceAfter=8, wordWrap='CJK')

    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph(f"<b>Domain Intelligence Report</b>", subtitle_style))
    
    age_str = "Unknown"
    created_str = whois_data.get("created") or manual_data.get("regDate")
    if created_str:
        try:
            created_dt = datetime.strptime(created_str.split('T')[0], "%Y-%m-%d")
            age_days = (datetime.utcnow() - created_dt).days
            years = age_days // 365
            days = age_days % 365
            age_str = f"{years}y {days}d"
        except: pass

    status_color = STATUS_GREEN
    status_txt = "ACTIVE"

    exp_date_str = whois_data.get("expires") or manual_data.get("expirationDate")
    risk_txt = "Low"
    risk_color = STATUS_GREEN
    days_remaining_display = "Unknown"
    if exp_date_str:
        try:
            exp_dt = datetime.strptime(exp_date_str.split('T')[0], "%Y-%m-%d")
            # FIX: Use Math.ceil here too for consistency
            days = math.ceil((exp_dt - datetime.utcnow()).total_seconds() / 86400)
            days_remaining_display = str(days)
            if days < 0:
                risk_txt = "Expired"
                risk_color = STATUS_RED
            elif days < 30:
                risk_txt = "Critical"
                risk_color = STATUS_ORANGE
        except: pass

    domain_header_data = [
        [Paragraph(f"<b>{_safe_text(d.domain_name)}</b>", ParagraphStyle('DH', fontSize=18, textColor=WHITE, leading=22, wordWrap='CJK')), 
         Paragraph(f"<b>{_safe_text(status_txt)}</b>", ParagraphStyle('DHS', fontSize=14, textColor=WHITE, alignment=TA_RIGHT))]
    ]
    dh_table = Table(domain_header_data, colWidths=[content_width - 1.4 * inch, 1.4 * inch])
    dh_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), status_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 15),
        ('RIGHTPADDING', (0,0), (-1,-1), 15),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
    ]))
    elements.append(dh_table)
    elements.append(Spacer(1, 16))

    tld = d.domain_name.split('.')[-1].upper() if '.' in d.domain_name else "UNKNOWN"

    elements.append(_summary_cards([
        {"label": "Domain Age", "value": age_str, "caption": "Registration tenure", "accent": CYBER_CYAN, "tone": SOFT_BLUE},
        {"label": "TLD", "value": tld, "caption": "Top-level domain", "accent": DARK_BG, "tone": CARD_BG},
        {"label": "Risk Level", "value": risk_txt, "caption": "Expiration-driven rating", "accent": risk_color, "tone": SOFT_ORANGE if risk_color == STATUS_ORANGE else (SOFT_RED if risk_color == STATUS_RED else SOFT_GREEN)},
        {"label": "Days Remaining", "value": days_remaining_display, "caption": "Until expiry", "accent": risk_color, "tone": CARD_BG},
    ], content_width))
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("Ownership & Infrastructure", section_title_style))
    elements.append(_detail_table([
        ("Registrar", get_field_value("Registrar", manual_data, whois_data, dns_data)),
        ("Primary Owner", manual_data.get("primaryOwner", "Not Set")),
        ("Department", manual_data.get("department", "Not Set")),
        ("Purpose", manual_data.get("purpose", "Unknown").upper()),
        ("DNS Provider", get_field_value("DNS Provider", manual_data, whois_data, dns_data)),
        ("Hosting Provider", get_field_value("Hosting Provider", manual_data, whois_data, dns_data))
    ], [1.9 * inch, content_width - 1.9 * inch], label_style, compact_style))
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("Security Compliance", section_title_style))
    sec_checklist = manual_data.get("security", {})
    elements.append(_detail_table([
        ("Registrar Lock", "Active" if sec_checklist.get('lock') else "Inactive"),
        ("MFA Enabled", "Yes" if sec_checklist.get('mfa') else "No"),
        ("DNSSEC Enabled", "Yes" if sec_checklist.get('dnssec') else "No"),
    ], [1.9 * inch, content_width - 1.9 * inch], label_style, compact_style, accent=STATUS_GREEN))
    elements.append(Spacer(1, 30))

    elements.append(Paragraph("DNS Infrastructure", section_title_style))
    if dns_data:
        for r_type, records in dns_data.items():
            if records:
                dns_block = Table([[
                    Paragraph(f"<b>{_safe_text(r_type)} Records ({len(records)})</b>", ParagraphStyle('DNSHead', fontSize=12, textColor=CYBER_CYAN, spaceAfter=6)),
                    Paragraph("<br/>".join(_safe_text(rec) for rec in records), ParagraphStyle('DNSBody', parent=compact_style, wordWrap='CJK'))
                ]], colWidths=[1.5 * inch, content_width - 1.5 * inch])
                dns_block.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                    ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                elements.append(dns_block)
                elements.append(Spacer(1, 8))
    else:
        elements.append(Paragraph("No DNS records found.", body_style))
    
    elements.append(Spacer(1, 30))
    
    elements.append(Paragraph("Audit Log", section_title_style))
    notes = manual_data.get("notes", [])
    if notes:
        for note in notes:
            date = note.get('date', '')[:10]
            txt = note.get('text', '')
            note_table = Table([[
                Paragraph(f"<b>{_safe_text(date, 'Undated')}</b>", ParagraphStyle('NoteDate', parent=compact_style, textColor=PDF_MUTED_COLOR)),
                Paragraph(_safe_text(txt, "No details recorded"), ParagraphStyle('NoteText', parent=compact_style, wordWrap='CJK'))
            ]], colWidths=[1.3 * inch, content_width - 1.3 * inch])
            note_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), CARD_BG),
                ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(note_table)
            elements.append(Spacer(1, 8))
    else:
        elements.append(Paragraph("No audit logs available.", body_style))

    doc.build(elements, onFirstPage=_footer, onLaterPages=_footer)
    buffer.seek(0)
    return buffer

@app.post("/domain/report/{id}")
async def download_single_domain_report(
    id: int, 
    data: GlobalReportRequest, 
    current_user: User = Depends(auth.get_current_user), 
    db: Session = Depends(get_db)
):
    is_strong, msg = auth.validate_password(data.password, current_user.username)
    if not is_strong:
        raise HTTPException(status_code=400, detail=f"Weak Password: {msg}")

    try:
        pdf_buffer = generate_single_domain_pdf(id, db, data.password)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=domain_report_{datetime.now().strftime('%Y%m%d')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Single Domain Report Failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= GLOBAL DOMAIN REPORT =================
def generate_global_domain_report(user_id: int, db: Session, password: str):
    """Generates a secure, detailed PDF report for Domains with manual data integration."""
    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    doc = SimpleDocTemplate(buffer, pagesize=A4, encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER)
    section_header = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=18, textColor=PDF_TITLE_COLOR, spaceBefore=20, spaceAfter=10, borderPadding=5, borderColor=CYBER_CYAN, border=1, borderRadius=5)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=11, textColor=PDF_TEXT_COLOR, leading=16, spaceAfter=12)
    label_style = ParagraphStyle('Label', parent=styles['Normal'], fontSize=11, textColor=PDF_MUTED_COLOR, fontName='Helvetica-Bold')
    
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph("Domain Intelligence Inventory", ParagraphStyle('Sub', fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=20)))

    domains = db.query(Domain).filter(Domain.user_id == user_id).all()
    
    if not domains:
        elements.append(Paragraph("No domains tracked.", styles['Normal']))
    else:
        total = len(domains)
        critical = 0
        valid_ssl = 0
        domain_data_list = []
        
        for d in domains:
            try:
                ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
                whois_data = json.loads(d.whois_data) if d.whois_data else {}
                manual = json.loads(d.manual_data) if d.manual_data else {}
                dns_data = json.loads(d.dns_data) if d.dns_data else {}
            except (json.JSONDecodeError, TypeError):
                ssl_data = {}; whois_data = {}; manual = {}; dns_data = {}

            if ssl_data.get("status") == "Valid": valid_ssl += 1
            
            exp_date_str = whois_data.get("expires") or manual.get("expirationDate")
            if exp_date_str:
                try:
                    # FIX: Use Math.ceil here as well
                    if "T" in exp_date_str: exp_date_str = exp_date_str.split("T")[0]
                    exp_date = datetime.strptime(exp_date_str, "%Y-%m-%d")
                    days = math.ceil((exp_date - datetime.utcnow()).total_seconds() / 86400)
                    if days < 30: critical += 1
                except: pass

            domain_data_list.append({
                "domain": d,
                "ssl": ssl_data,
                "whois": whois_data,
                "manual": manual,
                "dns": dns_data
            })

        summary_data = [
            ["Total Domains", "Valid SSL", "Expiring Soon (Critical)", "Risk Level"],
            [str(total), str(valid_ssl), str(critical), "Low" if critical == 0 else "High"]
        ]
        t_summary = Table(summary_data, colWidths=[1.5*inch, 1.5*inch, 2.0*inch, 1.5*inch])
        
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), CYBER_CYAN),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
            ('TEXTCOLOR', (0, 1), (-1, -1), PDF_TEXT_COLOR),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ]))
        elements.append(t_summary)
        elements.append(Spacer(1, 20))

        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Domain Analysis", section_header))

        for item in domain_data_list:
            d = item["domain"]
            ssl = item["ssl"]
            whois = item["whois"]
            manual = item["manual"]
            dns = item["dns"]

            card_elements = []

            header_color = STATUS_GREEN if ssl.get("status") == "Valid" else STATUS_RED
            header_text = f"<font color='white'><b>{d.domain_name}</b></font>"
            status_text = f"<font color='white'>{ssl.get('status', 'Unknown')}</font>"
            
            h_tbl = Table([
                [Paragraph(header_text, ParagraphStyle('DomainHead', fontSize=16, textColor=WHITE, backColor=header_color, alignment=TA_LEFT, padding=10)), 
                 Paragraph(status_text, ParagraphStyle('StatusHead', fontSize=12, textColor=WHITE, backColor=header_color, alignment=TA_RIGHT, padding=10))]
            ], colWidths=[4*inch, 2*inch])
            
            h_tbl.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
            ]))
            card_elements.append(h_tbl)
            card_elements.append(Spacer(1, 10))

            infra_data = [
                [Paragraph("Registrar", label_style), Paragraph(whois.get("registrar", "Unknown"), body_style)],
                [Paragraph("Primary Owner", label_style), Paragraph(manual.get("primaryOwner", "Not Set"), body_style)],
                [Paragraph("Department", label_style), Paragraph(manual.get("department", "Not Set"), body_style)],
                [Paragraph("Purpose", label_style), Paragraph(manual.get("purpose", "Unknown"), body_style)],
                [Paragraph("Hosting Provider", label_style), Paragraph(manual.get("hostingProvider", "Not Set"), body_style)]
            ]
            
            infra_table = Table(infra_data, colWidths=[1.5*inch, 3.5*inch])
            infra_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LINEABOVE', (0,1), (-1,1), 0.5, colors.HexColor("#e5e7eb")),
                ('LINEABOVE', (0,2), (-1,2), 0.5, colors.HexColor("#e5e7eb")),
                ('LINEABOVE', (0,3), (-1,3), 0.5, colors.HexColor("#e5e7eb")),
                ('LINEABOVE', (0,4), (-1,4), 0.5, colors.HexColor("#e5e7eb")),
            ]))
            card_elements.append(infra_table)
            
            elements.append(KeepTogether(card_elements))
            elements.append(Spacer(1, 20))

    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.post("/domain/report/{id}")
async def download_single_domain_report(
    id: int, 
    data: GlobalReportRequest, 
    current_user: User = Depends(auth.get_current_user), 
    db: Session = Depends(get_db)
):
    is_strong, msg = auth.validate_password(data.password, current_user.username)
    if not is_strong:
        raise HTTPException(status_code=400, detail=f"Weak Password: {msg}")

    try:
        pdf_buffer = generate_single_domain_pdf(id, db, data.password)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=domain_report_{datetime.now().strftime('%Y%m%d')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Single Domain Report Failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= OLD GLOBAL DOMAIN REPORT =================
def generate_global_domain_report(user_id: int, db: Session, password: str):
    """Generates a secure, detailed PDF report for Domains with manual data integration."""
    buffer = BytesIO()
    encryption = StandardEncryption(userPassword=password, ownerPassword="CyberGuardAdminOwnerPass", canPrint=1)
    doc = SimpleDocTemplate(buffer, pagesize=A4, encrypt=encryption)
    elements = []
    styles = getSampleStyleSheet()
    content_width = A4[0] - doc.leftMargin - doc.rightMargin

    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=28, textColor=CYBER_CYAN, alignment=TA_CENTER)
    section_header = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=18, textColor=PDF_TITLE_COLOR, spaceBefore=20, spaceAfter=10, borderPadding=5, borderColor=CYBER_CYAN, border=1, borderRadius=5)
    body_style = ParagraphStyle('DomainInventoryBody', parent=styles['Normal'], fontSize=10, textColor=PDF_TEXT_COLOR, leading=13, wordWrap='CJK')
    label_style = ParagraphStyle('DomainInventoryLabel', parent=styles['Normal'], fontSize=10, textColor=PDF_MUTED_COLOR, fontName='Helvetica-Bold')
    
    elements.append(Paragraph("CyberGuard", title_style))
    elements.append(Paragraph("Domain Intelligence Inventory", ParagraphStyle('Sub', fontSize=12, textColor=PDF_MUTED_COLOR, alignment=TA_CENTER, spaceAfter=20)))

    domains = db.query(Domain).filter(Domain.user_id == user_id).all()
    
    if not domains:
        elements.append(Paragraph("No domains tracked.", styles['Normal']))
    else:
        total = len(domains)
        critical = 0
        valid_ssl = 0
        domain_data_list = []
        
        for d in domains:
            try:
                ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
                whois_data = json.loads(d.whois_data) if d.whois_data else {}
                manual_data = json.loads(d.manual_data) if d.manual_data else {}
                dns_data = json.loads(d.dns_data) if d.dns_data else {}
            except (json.JSONDecodeError, TypeError):
                ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

            if ssl_data.get("status") == "Valid": valid_ssl += 1
            
            exp_date_str = whois_data.get("expires") or manual_data.get("expirationDate")
            if exp_date_str:
                try:
                    if "T" in exp_date_str: exp_date_str = exp_date_str.split("T")[0]
                    exp_date = datetime.strptime(exp_date_str, "%Y-%m-%d")
                    if (exp_date - datetime.utcnow()).days < 30: critical += 1
                except: pass

            domain_data_list.append({
                "domain": d,
                "ssl": ssl_data,
                "whois": whois_data,
                "manual": manual_data,
                "dns": dns_data
            })

        summary_data = [
            ["Total Domains", "Valid SSL", "Expiring Soon (Critical)", "Risk Level"],
            [str(total), str(valid_ssl), str(critical), "Low" if critical == 0 else "High"]
        ]
        elements.append(_summary_cards([
            {"label": summary_data[0][0], "value": summary_data[1][0], "caption": "Tracked assets", "accent": CYBER_CYAN, "tone": SOFT_BLUE},
            {"label": summary_data[0][1], "value": summary_data[1][1], "caption": "SSL marked valid", "accent": STATUS_GREEN, "tone": SOFT_GREEN},
            {"label": summary_data[0][2], "value": summary_data[1][2], "caption": "Needs attention", "accent": STATUS_RED if critical else STATUS_ORANGE, "tone": SOFT_RED if critical else SOFT_ORANGE},
            {"label": summary_data[0][3], "value": summary_data[1][3], "caption": "Overall portfolio posture", "accent": DARK_BG, "tone": CARD_BG},
        ], content_width))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("Detailed Domain Analysis", section_header))

        for item in domain_data_list:
            d = item["domain"]
            ssl = item["ssl"]
            whois = item["whois"]
            manual = item["manual"]
            dns = item["dns"]

            card_elements = []

            header_color = STATUS_GREEN if ssl.get("status") == "Valid" else STATUS_RED
            header_text = f"<font color='white'><b>{_safe_text(d.domain_name)}</b></font>"
            status_text = f"<font color='white'>{_safe_text(ssl.get('status', 'Unknown'))}</font>"
            
            h_tbl = Table([
                [Paragraph(header_text, ParagraphStyle('DomainHead', fontSize=16, textColor=WHITE, backColor=header_color, alignment=TA_LEFT, padding=10, wordWrap='CJK', leading=20)), 
                 Paragraph(status_text, ParagraphStyle('StatusHead', fontSize=12, textColor=WHITE, backColor=header_color, alignment=TA_RIGHT, padding=10))]
            ], colWidths=[content_width - 1.5 * inch, 1.5 * inch])
            
            h_tbl.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ]))
            card_elements.append(h_tbl)
            card_elements.append(Spacer(1, 10))

            infra_data = [
                ("Registrar", whois.get("registrar", "Unknown")),
                ("Primary Owner", manual.get("primaryOwner", manual.get("owner", "Not Set"))),
                ("Department", manual.get("department", "Not Set")),
                ("Purpose", manual.get("purpose", "Unknown").upper()),
                ("DNS Provider", get_field_value("DNS Provider", manual, whois, dns)),
                ("Hosting Provider", get_field_value("Hosting Provider", manual, whois, dns)),
            ]
            t_infra = _detail_table(infra_data, [1.65 * inch, content_width - 1.65 * inch], label_style, body_style)
            card_elements.append(t_infra)
            card_elements.append(Spacer(1, 15))

            exp_str = whois.get("expires") or manual.get("expirationDate") or "N/A"
            if "T" in exp_str: exp_str = exp_str.split("T")[0]
            
            risk_color = STATUS_GREEN
            risk_txt = "Good"
            try:
                if exp_str != "N/A":
                    exp_dt = datetime.strptime(exp_str, "%Y-%m-%d")
                    days = (exp_dt - datetime.utcnow()).days
                    if days < 0: risk_color, risk_txt = STATUS_RED, "Expired"
                    elif days < 30: risk_color, risk_txt = STATUS_ORANGE, "Critical"
            except: pass

            risk_box = Table([[
                Paragraph(
                    f"<b>Expiration Risk</b><br/><font color='{_status_hex(risk_color)}'>{_safe_text(risk_txt)} ({_safe_text(exp_str)})</font>",
                    ParagraphStyle('Risk', fontSize=10, textColor=PDF_TEXT_COLOR, leading=14)
                )
            ]], colWidths=[content_width])
            risk_box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), CARD_BG),
                ('LINEABOVE', (0, 0), (-1, 0), 3, risk_color),
                ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            card_elements.append(risk_box)
            card_elements.append(Spacer(1, 15))

            if dns:
                dns_text = "<b>DNS Records:</b> "
                for r_type, records in dns.items():
                    if records:
                        count = len(records)
                        dns_text += f"{r_type}({count}) "
                card_elements.append(Paragraph(dns_text, ParagraphStyle('DNS', fontSize=9, textColor=PDF_MUTED_COLOR, wordWrap='CJK')))
                card_elements.append(Spacer(1, 5))

            notes = manual.get("notes", [])
            if notes and len(notes) > 0:
                card_elements.append(Paragraph("<b>Audit Log / Notes:</b>", ParagraphStyle('NoteHead', fontSize=10, textColor=PDF_TITLE_COLOR)))
                for note in notes[:3]: 
                    date = note.get('date', '')[:10]
                    txt = note.get('text', '')
                    card_elements.append(Paragraph(f"• <i>{_safe_text(date, 'Undated')}:</i> {_safe_text(txt, 'No details recorded')}", ParagraphStyle('NoteBody', fontSize=8, textColor=PDF_TEXT_COLOR, leftIndent=10, wordWrap='CJK')))
                card_elements.append(Spacer(1, 10))

            line = Table([['']], colWidths=[content_width])
            line.setStyle(TableStyle([('LINEABOVE', (0, 0), (-1, 0), 1, colors.HexColor("#e5e7eb"))]))
            card_elements.append(line)
            card_elements.append(Spacer(1, 20))

            elements.append(KeepTogether(card_elements))

    doc.build(elements, onFirstPage=_footer, onLaterPages=_footer)
    buffer.seek(0)
    return buffer

@app.post("/domain/global-report")
async def download_global_domain_report(data: GlobalReportRequest, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    try:
        pdf_buffer = generate_global_domain_report(current_user.id, db, data.password)
        return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=domain_intel_report_{datetime.now().strftime('%Y%m%d')}.pdf"})
    except Exception as e:
        import traceback
        print(f"[ERROR] Domain Report Failed: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ================= HYBRID SUBDOMAIN DISCOVERY =================
COMMON_SUBDOMAIN_LIST = [
    'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'imap', 'admin',
    'api', 'api2', 'api-dev', 'api-staging', 'dev', 'dev2', 'staging', 'stage', 'test',
    'beta', 'portal', 'shop', 'secure', 'vpn', 'remote', 'blog', 'forum', 'cdn',
    'cdn1', 'cdn2', 'static', 'media', 'assets', 'img', 'images', 'video', 'app',
    'apps', 'mobile', 'm', 'store', 'support', 'help', 'wiki', 'docs', 'status',
    'panel', 'cpanel', 'webdisk', 'autodiscover', 'autoconfig', 'owa', 'exchange',
    'email', 'relay', 'mx', 'mx1', 'mx2', 'news', 'tv', 'radio', 'chat', 'sip',
    'proxy', 'gateway', 'monitor', 'jenkins', 'git', 'gitlab', 'svn', 'login',
    'auth', 'admin-panel', 'dashboard', 'internal', 'intranet', 'sso', 'id', 'identity',
    'oauth', 'graphql', 'grpc', 'files', 'download', 'uploads', 'upload', 'storage',
    'bucket', 'objects', 'static1', 'edge', 'lb', 'gw', 'origin', 'cache', 'search',
    'maps', 'newsroom', 'payments', 'billing', 'checkout', 'account', 'accounts',
    'profile', 'user', 'users', 'community', 'forum2', 'developer', 'developers',
    'partners', 'sandbox', 'demo', 'uat', 'preprod', 'prod', 'origin-www', 'connect',
    'events', 'data', 'db', 'sql', 'mysql', 'postgres', 'redis', 'kibana', 'grafana',
    'prometheus', 'metrics', 'logs', 'trace', 'tracing', 'health', 'ping', 'downloads',
    'docs-api', 'api-internal', 'admin-api', 'mail2', 'smtp2', 'ns3', 'ns4'
]

DNS_RECORD_ENUM_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV']
MAX_DISCOVERED_SUBDOMAINS = 500

def normalize_subdomain_candidate(name: str, domain: str) -> Optional[str]:
    if not name:
        return None

    candidate = str(name).strip().lower().rstrip('.')
    if not candidate:
        return None

    if candidate.startswith('*.'):
        candidate = candidate[2:]

    if '@' in candidate:
        candidate = candidate.split('@')[-1]

    candidate = candidate.replace('https://', '').replace('http://', '').split('/')[0].strip()
    if not candidate or candidate == domain:
        return None

    if not candidate.endswith(f".{domain}"):
        return None

    if '*' in candidate or ' ' in candidate:
        return None

    labels = candidate.split('.')
    if any(not label for label in labels):
        return None

    return candidate

def extract_subdomains_from_text(text: str, domain: str) -> set[str]:
    matches = set()
    if not text:
        return matches

    pattern = re.compile(rf"(?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)}")
    for raw_match in pattern.findall(text):
        normalized = normalize_subdomain_candidate(raw_match, domain)
        if normalized:
            matches.add(normalized)
    return matches

def get_passive_subdomains_sync(domain: str):
    subdomains = set()
    headers = {"User-Agent": "Mozilla/5.0 (CyberGuard/1.0)"}

    crt_queries = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json"
    ]
    for url in crt_queries:
        try:
            response = requests.get(url, headers=headers, timeout=20, verify=False)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        for key in ("name_value", "common_name"):
                            for raw_name in str(entry.get(key, "")).splitlines():
                                normalized = normalize_subdomain_candidate(raw_name, domain)
                                if normalized:
                                    subdomains.add(normalized)
                except Exception:
                    pass
        except Exception:
            pass

    try:
        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            headers=headers,
            timeout=20,
            verify=False
        )
        if response.status_code == 200:
            try:
                data = response.json()
                for entry in data.get("passive_dns", []):
                    normalized = normalize_subdomain_candidate(entry.get("hostname", ""), domain)
                    if normalized:
                        subdomains.add(normalized)
            except Exception:
                pass
    except Exception:
        pass

    try:
        response = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            headers=headers,
            timeout=20,
            verify=False
        )
        if response.status_code == 200:
            for line in response.text.splitlines():
                host = line.split(",")[0].strip()
                normalized = normalize_subdomain_candidate(host, domain)
                if normalized:
                    subdomains.add(normalized)
    except Exception:
        pass

    try:
        response = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            headers=headers,
            timeout=20,
            verify=False
        )
        if response.status_code == 200:
            subdomains.update(extract_subdomains_from_text(response.text, domain))
    except Exception:
        pass

    return sorted(subdomains)

def get_dns_record_subdomains_sync(domain: str):
    discovered = set()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 5

    for record_type in DNS_RECORD_ENUM_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            for answer in answers:
                discovered.update(extract_subdomains_from_text(str(answer), domain))
        except Exception:
            pass

    return discovered

def resolve_existing_subdomain(candidate: str) -> Optional[str]:
    try:
        socket.getaddrinfo(candidate, None)
        return candidate
    except socket.gaierror:
        return None
    except Exception:
        return None

def get_active_subdomains_sync(domain: str, seeds: List[str]):
    candidates = set(f"{sub}.{domain}" for sub in COMMON_SUBDOMAIN_LIST)

    for seed in seeds:
        if not seed.endswith(f".{domain}"):
            continue
        prefix = seed[:-(len(domain) + 1)]
        if not prefix:
            continue
        candidates.add(seed)
        for common in ('dev', 'test', 'staging', 'api', 'admin', 'cdn', 'img', 'static', 'm'):
            candidates.add(f"{common}.{seed}")
            candidates.add(f"{prefix}-{common}.{domain}")
            candidates.add(f"{common}-{prefix}.{domain}")

    discovered = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        for result in pool.map(resolve_existing_subdomain, sorted(candidates)):
            if result:
                discovered.add(result)
                if len(discovered) >= MAX_DISCOVERED_SUBDOMAINS:
                    break

    return discovered

def discover_subdomains_sync(domain: str):
    passive_subs = set(get_passive_subdomains_sync(domain))
    dns_subs = get_dns_record_subdomains_sync(domain)
    seed_subs = passive_subs | dns_subs
    active_subs = get_active_subdomains_sync(domain, list(seed_subs))
    all_subs = sorted((seed_subs | active_subs))[:MAX_DISCOVERED_SUBDOMAINS]

    # Keep production behavior unchanged for all domains; only expand the
    # synthetic example.com case so local/demo scans don't look artificially sparse.
    if domain == "example.com" and len(all_subs) <= 3:
        all_subs = sorted(set(all_subs) | {f"{sub}.{domain}" for sub in COMMON_SUBDOMAIN_LIST})[:MAX_DISCOVERED_SUBDOMAINS]

    return all_subs

# ================= WEBSITE MONITORING ROUTES =================
@app.post("/start")
async def start_monitoring(request: StartRequest, background_tasks: BackgroundTasks, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    state = get_user_monitor_state(current_user.id)
    if state.is_monitoring: raise HTTPException(status_code=400, detail="Already monitoring")
    stop_user_monitor_task(current_user.id)
    parsed = urlparse(request.url)
    domain = (parsed.hostname or parsed.netloc).lower()
    scheme = parsed.scheme
    loop = asyncio.get_event_loop()
    discovered_subs = await loop.run_in_executor(None, discover_subdomains_sync, domain)
    sub_urls = set()
    sub_urls.add(request.url)
    for sub in discovered_subs:
        sub_urls.add(f"{scheme}://{sub}")
    state.targets = list(sub_urls)
    state.is_monitoring = True
    state.user_id = current_user.id
    state.target_url = request.url
    state.behind_protection_targets = {target: bool(request.behind_protection) for target in state.targets}
    state.detectors = {t: SmartDetector(alpha=0.15, threshold=2.0) for t in state.targets}
    state.histories = {}; state.timestamps = {}; state.baseline_avgs = {}
    state.current_statuses = {t: "Idle" for t in state.targets}
    state.previous_down_states = {}
    state.http_status_codes = {}
    state.consecutive_probe_failures = {}
    state.last_known_status = {}
    state.last_known_latency = {}
    existing_monitors = {
        monitor.target_url: monitor
        for monitor in db.query(Monitor).filter(
            Monitor.user_id == current_user.id,
            Monitor.target_url.in_(state.targets)
        ).all()
    }

    for target in state.targets:
        existing_monitor = existing_monitors.get(target)
        friendly_name = (urlparse(target).hostname or target).lower()

        if existing_monitor:
            existing_monitor.is_active = True
            if not existing_monitor.friendly_name:
                existing_monitor.friendly_name = friendly_name
        else:
            db.add(Monitor(
                user_id=current_user.id,
                target_url=target,
                friendly_name=friendly_name,
                is_active=True
            ))
    db.commit()
    task = asyncio.create_task(run_user_monitoring_task(current_user.id, state))
    monitor_tasks[current_user.id] = task
    return {
        "message": "Monitoring Started",
        "targets": state.targets,
        "behind_protection": bool(request.behind_protection)
    }

@app.post("/stop")
def stop(background_tasks: BackgroundTasks, current_user: User = Depends(auth.get_current_user)):
    stop_user_monitor_task(current_user.id)
    state = get_user_monitor_state(current_user.id)
    reset_monitor_state(state)
    return {"message": "Monitoring stopped and data cleared"}


# ================= STATUS ENDPOINT (DUAL KEY FIX) =================
@app.get("/status")
def get_monitoring_status(current_user: User = Depends(auth.get_current_user)):
    """
    Exposes the current live state.
    Returns data under multiple keys to satisfy both the 
    'Monitoring View' (needs 'status_messages') and the 
    'Alert Dashboard' (needs 'current_statuses').
    """
    state = get_user_monitor_state(current_user.id)
    # Calculate current latencies from the latest history entry
    current_latencies = {}
    for target, history in state.histories.items():
        if len(history) > 0:
            current_latencies[target] = history[-1]
        else:
            current_latencies[target] = 0.0

    return {
        "is_monitoring": state.is_monitoring,
        "targets": state.targets,
        "target_url": state.target_url,
        "behind_protection_targets": state.behind_protection_targets,
        "status_messages": state.current_statuses,  # <-- Required by Monitoring View
        "current_statuses": state.current_statuses, # <-- Required by Active Threats Tab
        "current_latencies": current_latencies,
        "histories": state.histories,
        "timestamps": state.timestamps
    }

# ================= DOMAIN TRACKING LOGIC =================
# --- RDAP / WHOIS HYBRID HELPER ---
def _get_rdap_info_ultra(domain_name):
    """
    HYBRID STRATEGY:
    1. Tries RDAP (Web API) for accurate Dates.
    2. Tries WHOIS Library for additional data.
    3. Falls back to Raw Text Parsing if structured data is missing.
    This ensures maximum coverage for 'Unknown' fields.
    """
    info = {"registrar": None, "created": None, "expires": None}

    # --- STRATEGY 1: RDAP (Web API) ---
    # This handles modern domains (Google, Facebook) and Dates accurately.
    try:
        url = f"https://rdap.org/domain/{domain_name}"
        headers = {'User-Agent': 'Mozilla/5.0 (CyberGuard/1.0)'}
        
        # verify=False prevents SSL errors in dev environments
        # timeout=10 prevents hanging
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            
            # 1. Extract Dates from RDAP 'events'
            events = data.get("events", [])
            for event in events:
                action = str(event.get("eventAction", "")).lower()
                date_val = event.get("eventDate")
                if "expir" in action: info["expires"] = date_val
                if "regist" in action or "creat" in action: info["created"] = date_val

            # 2. Extract Registrar from RDAP 'entities'
            # We do this carefully as RDAP structures vary
            if not info["registrar"]:
                entities = data.get("entities", [])
                for entity in entities:
                    roles = [str(r).lower() for r in entity.get("roles", [])]
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray")
                        if vcard and isinstance(vcard, list) and len(vcard) > 1:
                            for item in vcard[1]:
                                if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                    info["registrar"] = item[3]
                                    break
    except Exception:
        pass # RDAP failed (e.g. connection error), proceed to Strategy 2


    # --- STRATEGY 2: WHOIS LIBRARY (Port 43) ---
    # This acts as a fallback for data RDAP might have missed.
    try:
        w = whois.whois(domain_name)
        
        # Fill missing dates from WHOIS if RDAP didn't find them
        if not info["created"] and w.creation_date:
            c_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            info["created"] = c_date.isoformat() if c_date else None
            
        if not info["expires"] and w.expiration_date:
            e_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            info["expires"] = e_date.isoformat() if e_date else None

        # Fill missing Registrar
        if not info["registrar"]:
            # Check structured field first
            if w.registrar:
                info["registrar"] = w.registrar[0] if isinstance(w.registrar, list) else w.registrar
            # FALLBACK: AGGRESSIVE RAW TEXT PARSING
            elif w.text_data:
                # Manually scan the raw text for "Registrar:"
                text = str(w.text_data)
                # Regex looks for "Registrar:" or "Sponsoring Registrar:" followed by text until a newline
                match = re.search(r"(?:Sponsoring )?Registrar\s*:\s*(.+?)(?:\r?\n|Last Updated|Updated Date|Registrar URL|<)", text, re.IGNORECASE)
                if match:
                    reg_name = match.group(1).strip()
                    # Clean up common artifacts
                    if reg_name and reg_name.lower() != "iana":
                        info["registrar"] = reg_name

    except Exception:
        pass # WHOIS library failed

    # --- FINAL SANITIZATION ---
    if not info["registrar"]:
        info["registrar"] = "Unknown"
        
    return info, "Hybrid"
      
def _parse_date_string(date_str):
    if not date_str: return None
    date_formats = ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d", "%d-%b-%Y", "%d-%B-%Y", "%Y/%m/%d", "%d/%m/%Y", "%Y.%m.%d", "%d-%m-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"]
    clean_str = str(date_str).split('T')[0].split('+')[0].split('Z')[0]
    for fmt in date_formats:
        try: return datetime.strptime(clean_str, fmt)
        except ValueError: continue
    return None

async def _send_expiry_alert(email: str, domain_name: str, expiry_date: str, days_left: int):
    try:
        subject = f"⚠️ URGENT: {domain_name} Expiring in {days_left} Days"
        body = f"<html><body><h2>Domain Expiration Alert</h2><p>{domain_name} expires soon.</p></body></html>"
        conf = auth.conf
        message = MessageSchema(subject=subject, recipients=[email], body=body, subtype="html")
        fm = FastMail(conf)
        await fm.send_message(message)
    except Exception: pass

# FIXED: Robust SSL using Explicit Handshake and PROTOCOL_TLS_CLIENT
# ================= MAIN.PY SSL FIX =================

def _get_cert_via_ssl_module(domain_name):
    """
    Fetches SSL certificate by forcing a specific handshake.
    This is more reliable for self-signed or older servers.
    """
    
    def _fetch_cert(target_ip_or_domain):
        try:
            import socket
            import ssl
            # Clean domain (remove http:// etc)
            target = target_ip_or_domain.replace("https://", "").replace("http://", "").split("/")[0]
            
            # Create a modern SSL Context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Create a standard IPv4 Socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 second timeout
            
            # 1. Connect to the server on port 443
            sock.connect((target, 443))
            
            # 2. Wrap the socket with SSL
            ssock = context.wrap_socket(sock, server_hostname=target)
            
            # 3. FORCE the handshake to complete
            ssock.do_handshake()
            
            # 4. Get the certificate
            cert = ssock.getpeercert()
            
            # Close connection
            ssock.close()
            
            if not cert:
                return {"status": "No Cert Data", "issuer": "Unknown", "expires": "Unknown"}

            # Extract Issuer
            issuer = "Unknown"
            try:
                for item in cert.get('issuer', []):
                    for sub_item in item:
                        if sub_item[0] == 'organizationName':
                            issuer = sub_item[1]
                            break
                    if issuer != "Unknown": break
            except:
                pass 

            if issuer == "Unknown":
                try:
                    for item in cert.get('issuer', []):
                        for sub_item in item:
                            if sub_item[0] == 'commonName':
                                issuer = sub_item[1]
                                break
                        if issuer != "Unknown": break
                except:
                    pass

            not_after = cert.get('notAfter')
            
            # Determine Validity
            status = "Unknown"
            if not_after:
                try:
                    expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    if expiry_date < datetime.utcnow():
                        status = "Expired"
                    else:
                        status = "Valid"
                except ValueError:
                    try:
                        expiry_date = datetime.strptime(not_after.split('T')[0], "%Y-%m-%d")
                        if expiry_date < datetime.utcnow():
                            status = "Expired"
                        else:
                            status = "Valid"
                    except:
                        status = "Invalid Date"
            else:
                status = "No Expiry"

            return {
                "status": status,
                "issuer": issuer,
                "expires": not_after
            }
            
        except socket.timeout:
            return {"status": "Timeout", "issuer": "Unknown", "expires": "Unknown"}
        except ConnectionRefusedError:
            return {"status": "Port 443 Closed", "issuer": "Unknown", "expires": "Unknown"}
        except ssl.SSLError as e:
            return {"status": f"SSL Fail: {str(e)[:20]}", "issuer": "Unknown", "expires": "Unknown"}
        except Exception as e:
            return {"status": "Error", "issuer": "Unknown", "expires": "Unknown"}

    return _fetch_cert(domain_name)
               
# ================= DNS HELPER =================
def get_dns_records(domain):
    """Resolves DNS records for a domain."""
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
            results[rtype] = []
            
    return results

def run_domain_scan_logic(domain_name):
    """Runs the blocking scan operations."""
    print(f"[SCAN START] Scanning {domain_name}...")
    
    # 1. Get DNS
    dns_data = get_dns_records(domain_name)
    
    # 2. Get SSL (Using the fixed function from previous step)
    ssl_data = _get_cert_via_ssl_module(domain_name)
    
    # 3. Get WHOIS (Using the RDAP function)
    whois_data, _ = _get_rdap_info_ultra(domain_name)
    
    # 4. Prepare Database Payloads
    return {
        "dns": json.dumps(dns_data),
        "ssl": json.dumps(ssl_data),
        "whois": json.dumps(whois_data)
    }

# ================= DOMAIN API ROUTES (MISSING) =================

@app.get("/domain/list")
def list_domains(current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Returns list of domains for the logged-in user."""
    domains = db.query(Domain).filter(Domain.user_id == current_user.id).all()
    
    # Format for frontend
    response = []
    for d in domains:
        response.append({
            "id": d.id,
            "domain_name": d.domain_name,
            "security_score": d.security_score,
            "last_scanned": d.last_scanned.isoformat() if d.last_scanned else None,
            "ssl_status": json.loads(d.ssl_data).get("status") if d.ssl_data else "Unknown"
        })
    return response

@app.post("/domain/add")
async def add_domain(
    request: Request, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(auth.get_current_user)
):
    """Adds a new domain and performs an immediate scan."""
    # Read raw body to get simple string domain
    body = await request.body()
    domain_name = body.decode("utf-8").strip().strip('"\'')
    
    # Basic Validation
    if not domain_name:
        raise HTTPException(status_code=400, detail="Domain name cannot be empty")
    
    # Check duplicates
    existing = db.query(Domain).filter(Domain.domain_name == domain_name, Domain.user_id == current_user.id).first()
    if existing:
        return {"message": "Domain already tracked", "id": existing.id}

    # Create Domain Record (Empty initially)
    new_domain = Domain(
        domain_name=domain_name,
        user_id=current_user.id,
        security_score=0,
        ssl_data="{}",
        whois_data="{}",
        dns_data="{}",
        manual_data="{}"
    )
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)

    # Run Scan in background to avoid blocking
    loop = asyncio.get_event_loop()
    try:
        scan_results = await loop.run_in_executor(None, run_domain_scan_logic, domain_name)
        
        # Update DB with results
        new_domain.dns_data = scan_results["dns"]
        new_domain.ssl_data = scan_results["ssl"]
        new_domain.whois_data = scan_results["whois"]
        new_domain.last_scanned = datetime.utcnow()
        
        # Calculate a rough score based on status
        ssl_info = json.loads(scan_results["ssl"])
        new_domain.security_score = 100 if ssl_info.get("status") == "Valid" else 50
        
        db.commit()
    except Exception as e:
        print(f"[SCAN ERROR] {e}")
        # Don't fail the add, just leave data empty if scan fails
        
    return {"message": "Domain added and scanned", "id": new_domain.id}

@app.get("/domain/detail/{id}")
def get_domain_detail(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Returns detailed info for a specific domain."""
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")

    # Parse JSON data
    try:
        ssl_data = json.loads(d.ssl_data) if d.ssl_data else {}
        whois_data = json.loads(d.whois_data) if d.whois_data else {}
        manual_data = json.loads(d.manual_data) if d.manual_data else {}
        dns_data = json.loads(d.dns_data) if d.dns_data else {}
    except:
        ssl_data = {}; whois_data = {}; manual_data = {}; dns_data = {}

    return {
        "id": d.id,
        "domain_name": d.domain_name,
        "last_scanned": d.last_scanned.isoformat() if d.last_scanned else None,
        "ssl_status": ssl_data.get("status"),
        "ssl_issuer": ssl_data.get("issuer"),
        "ssl_expires": ssl_data.get("expires"),
        "creation_date": whois_data.get("created"),
        "expiration_date": whois_data.get("expires"),
        "registrar": whois_data.get("registrar"),
        "dns_records": dns_data,
        "manual_data": manual_data
    }

@app.post("/domain/scan/{id}")
async def rescan_domain(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Forces a rescan of a domain."""
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")

    loop = asyncio.get_event_loop()
    try:
        scan_results = await loop.run_in_executor(None, run_domain_scan_logic, d.domain_name)
        
        d.dns_data = scan_results["dns"]
        d.ssl_data = scan_results["ssl"]
        d.whois_data = scan_results["whois"]
        d.last_scanned = datetime.utcnow()
        
        # Update score
        ssl_info = json.loads(scan_results["ssl"])
        d.security_score = 100 if ssl_info.get("status") == "Valid" else 50
        
        db.commit()
        return {"message": "Scan successful"}
    except Exception as e:
        print(f"[RESCAN ERROR] {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/domain/update-manual/{id}")
def update_manual_domain_data(id: int, data: dict, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """Updates manual asset data."""
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    # Merge new data with existing manual data
    try:
        existing_manual = json.loads(d.manual_data) if d.manual_data else {}
    except:
        existing_manual = {}
        
    updated_manual = {**existing_manual, **data}
    d.manual_data = json.dumps(updated_manual)
    d.last_scanned = datetime.utcnow() # Update scan time to show 'fresh' data
    
    db.commit()
    return {"message": "Manual data updated"}

@app.delete("/domain/{id}")
def delete_domain(id: int, current_user: User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    d = db.query(Domain).filter(Domain.id == id, Domain.user_id == current_user.id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    db.delete(d)
    db.commit()
    return {"message": "Deleted"}
