# alert.py
import logging
import asyncio
import threading
from datetime import datetime, timedelta
import requests
from sqlalchemy import or_
from fastapi_mail import FastMail, MessageSchema
from database import SessionLocal
from models import AlertRule, AlertHistory, Incident, Monitor, Domain, User
from auth import conf
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _get_clean_domain(target_url: str) -> str:
    host = urlparse(target_url).hostname or ""
    return (host or target_url).strip().lower()


def _incident_error_type_for_rule(rule: AlertRule) -> str:
    if rule.condition == "response_time_high":
        return f"High Response Time: {rule.name}"
    if rule.condition == "smart_anomaly":
        return f"Smart Anomaly: {rule.name}"
    return f"Rule Triggered: {rule.name}"


def _classify_service_status(status: str) -> str:
    upper = (status or "").upper()
    if "PROBE BLOCKED" in upper or "BEHIND WAF / FIREWALL / VPN" in upper:
        return "protected"
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


def _sync_rule_incident(
    db,
    rule: AlertRule,
    target_url: str,
    monitor_id: int | None,
    user_id: int,
    triggered: bool,
):
    # Status-down incidents are already tracked by monitor.py on service transitions.
    if rule.condition == "status_down":
        return

    error_type = _incident_error_type_for_rule(rule)
    clean_domain = _get_clean_domain(target_url)
    ongoing_incident = (
        db.query(Incident)
        .filter(
            Incident.user_id == user_id,
            Incident.monitor_id == monitor_id,
            Incident.status == "Ongoing",
            Incident.error_type == error_type,
        )
        .order_by(Incident.started_at.desc())
        .first()
    )

    if triggered:
        if ongoing_incident:
            if not ongoing_incident.domain:
                ongoing_incident.domain = clean_domain
            return

        db.add(
            Incident(
                monitor_id=monitor_id,
                user_id=user_id,
                domain=clean_domain,
                status="Ongoing",
                error_type=error_type,
                started_at=datetime.utcnow(),
            )
        )
        return

    if ongoing_incident:
        now = datetime.utcnow()
        ongoing_incident.status = "Resolved"
        ongoing_incident.ended_at = now
        ongoing_incident.duration_seconds = int((now - ongoing_incident.started_at).total_seconds())

def _normalize_channel(channel: str) -> str:
    value = (channel or "email").strip().lower()
    return value if value in {"email", "slack", "both"} else "email"

def _send_email_in_background(recipient: str, subject: str, body: str):
    async def _send():
        message = MessageSchema(subject=subject, recipients=[recipient], body=body, subtype="html")
        fm = FastMail(conf)
        await fm.send_message(message)

    def _runner():
        try:
            asyncio.run(_send())
        except Exception as e:
            logger.error(f"Email notification failed: {e}")

    threading.Thread(target=_runner, daemon=True).start()

def _send_slack_message(webhook_url: str, text: str, severity: str, rule_name: str, target_url: str, current_status: str, current_latency: float):
    color_map = {
        "critical": "#dc2626",
        "high": "#ef4444",
        "warning": "#f59e0b",
        "info": "#06b6d4",
    }
    payload = {
        "text": f"CyberGuard alert: {rule_name}",
        "attachments": [
            {
                "color": color_map.get(severity, "#06b6d4"),
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": "CyberGuard Alert", "emoji": True},
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Rule:*\n{rule_name}"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                            {"type": "mrkdwn", "text": f"*Target:*\n{target_url}"},
                            {"type": "mrkdwn", "text": f"*Status:*\n{current_status}"},
                            {"type": "mrkdwn", "text": f"*Latency:*\n{current_latency:.2f} ms"},
                            {"type": "mrkdwn", "text": f"*Triggered At:*\n{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": text},
                    },
                ],
            }
        ],
    }
    response = requests.post(webhook_url, json=payload, timeout=10)
    response.raise_for_status()

def dispatch_alert_notifications(user: User, rule: AlertRule, target_url: str, message: str, current_status: str, current_latency: float):
    severity = (rule.severity or "warning").lower()
    if severity == "medium":
        severity = "warning"
    channel = _normalize_channel(rule.channel)
    subject = f"[{severity.upper()}] CyberGuard Alert: {rule.name}"
    detailed_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #111827; line-height: 1.6;">
        <h2 style="margin-bottom: 8px;">CyberGuard Alert Notification</h2>
        <p>A rule has been triggered and needs your attention.</p>
        <table style="border-collapse: collapse; width: 100%; margin-top: 16px;">
          <tr><td style="padding: 8px; font-weight: bold;">Rule</td><td style="padding: 8px;">{rule.name}</td></tr>
          <tr><td style="padding: 8px; font-weight: bold;">Severity</td><td style="padding: 8px;">{severity.upper()}</td></tr>
          <tr><td style="padding: 8px; font-weight: bold;">Target</td><td style="padding: 8px;">{target_url}</td></tr>
          <tr><td style="padding: 8px; font-weight: bold;">Current Status</td><td style="padding: 8px;">{current_status}</td></tr>
          <tr><td style="padding: 8px; font-weight: bold;">Latency</td><td style="padding: 8px;">{current_latency:.2f} ms</td></tr>
          <tr><td style="padding: 8px; font-weight: bold;">Delivery Path</td><td style="padding: 8px;">{channel.title()}</td></tr>
          <tr><td style="padding: 8px; font-weight: bold;">Triggered At</td><td style="padding: 8px;">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
        </table>
        <div style="margin-top: 18px; padding: 12px; background: #f3f4f6; border-left: 4px solid #dc2626;">
          {message}
        </div>
        <p style="margin-top: 16px;">Recommended action: review the target immediately and inspect the monitoring dashboard for live diagnostics.</p>
      </body>
    </html>
    """
    email_sent = False
    slack_sent = False

    if channel in {"email", "both"} and user.email:
        _send_email_in_background(user.email, subject, detailed_body)
        email_sent = True

    if channel in {"slack", "both"} and (user.slack_webhook_url or "").strip():
        try:
            _send_slack_message(
                user.slack_webhook_url.strip(),
                message,
                severity,
                rule.name,
                target_url,
                current_status,
                current_latency,
            )
            slack_sent = True
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")

    return {
        "channel": channel,
        "email_sent": email_sent,
        "slack_sent": slack_sent,
    }

# Replace the existing get_domain_suffixes function with this:
def get_domain_suffixes(url):
    """
    Generates a list of domain suffixes to search for potential parent monitors.
    e.g. 'lms.courses.bdu.edu.et' -> ['lms.courses.bdu.edu.et', 'courses.bdu.edu.et', 'bdu.edu.et', 'edu.et', 'et']
    e.g. 'user@example.com' -> ['example.com', 'com'] (Handles username/host format)
    """
    try:
        # Remove protocol and path
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        
        # FIX: Handle username/host format (e.g., user@example.com)
        # If '@' exists, we only care about the host part after it.
        if '@' in domain:
            domain = domain.split('@')[-1]

        parts = domain.split(".")
        suffixes = []
        for i in range(len(parts)):
            suffixes.append(".".join(parts[i:]))
        return suffixes
    except:
        return [url]

# Replace the existing get_root_domain helper inside check_service_alerts (or at the top level) with this:
# If it is defined locally inside the function, update it there.
def get_root_domain(u):
    try:
        d = u.replace("https://", "").replace("http://", "").split("/")[0]
        
        # FIX: Handle username/host format
        if '@' in d:
            d = d.split('@')[-1]
            
        p = d.split(".")
        return ".".join(p[-2:]) if len(p) > 2 else d
    except: 
        return u
def check_service_alerts(target_url, current_status, current_latency, user_id=None):
    """
    Evaluates the current monitoring state against user-defined AlertRules.
    Includes Fuzzy Matching for subdomains with typos or Certificate Intermediate strings.
    """
    db = SessionLocal()
    try:
        target_monitor_ids = set()
        user_id_to_check = user_id
        monitor_id_to_use = None 

        # 1. EXACT MATCH: Try to find an exact monitor entry first
        monitor_query = db.query(Monitor).filter(Monitor.target_url == target_url)
        if user_id_to_check is not None:
            monitor_query = monitor_query.filter(Monitor.user_id == user_id_to_check)
        monitor = monitor_query.order_by(Monitor.id.desc()).first()
        if monitor:
            target_monitor_ids.add(monitor.id)
            user_id_to_check = monitor.user_id
            monitor_id_to_use = monitor.id

        # 2. SUFFIX SEARCH: If no exact match, try to find a parent monitor
        if not user_id_to_check:
            possible_domains = get_domain_suffixes(target_url)
            
            # Iterate from most specific to least specific
            for domain_candidate in reversed(possible_domains):
                parent_monitor_query = db.query(Monitor).filter(
                    or_(
                        Monitor.target_url == f"http://{domain_candidate}",
                        Monitor.target_url == f"https://{domain_candidate}",
                        Monitor.target_url == domain_candidate
                    )
                )
                if user_id_to_check is not None:
                    parent_monitor_query = parent_monitor_query.filter(Monitor.user_id == user_id_to_check)
                parent_monitor = parent_monitor_query.order_by(Monitor.id.desc()).first()

                if parent_monitor:
                    target_monitor_ids.add(parent_monitor.id)
                    user_id_to_check = parent_monitor.user_id
                    monitor_id_to_use = parent_monitor.id
                    break 

        # 3. DOMAIN TABLE FALLBACK
        if not user_id_to_check:
            for domain_candidate in reversed(possible_domains):
                domain_query = db.query(Domain).filter(Domain.domain_name == domain_candidate)
                if user_id_to_check is not None:
                    domain_query = domain_query.filter(Domain.user_id == user_id_to_check)
                domain_entry = domain_query.order_by(Domain.id.desc()).first()
                if domain_entry:
                    user_id_to_check = domain_entry.user_id
                    break

        # 4. RULE TABLE FALLBACK (If no Monitor/Domain entry exists)
        if not user_id_to_check:
            norm_url = target_url.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
            matching_rule_query = db.query(AlertRule).filter(
                AlertRule.target_url == norm_url,
                AlertRule.type == "service",
                AlertRule.is_active == True
            )
            if user_id_to_check is not None:
                matching_rule_query = matching_rule_query.filter(AlertRule.user_id == user_id_to_check)
            matching_rule_for_user = matching_rule_query.order_by(AlertRule.id.desc()).first()

            if matching_rule_for_user:
                user_id_to_check = matching_rule_for_user.user_id

        # If we still can't identify the user, we can't proceed
        if not user_id_to_check:
            return

        # 5. FETCH RULES
        rules = db.query(AlertRule).filter(
            AlertRule.user_id == user_id_to_check,
            AlertRule.type == "service",
            AlertRule.is_active == True
        ).all()
        user = db.query(User).filter(User.id == user_id_to_check).first()

        # --- HELPER: Get Root Domain ---
        def get_root_domain(u):
            try:
                d = u.replace("https://", "").replace("http://", "").split("/")[0]
                if '@' in d: d = d.split('@')[-1]
                p = d.split(".")
                return ".".join(p[-2:]) if len(p) > 2 else d
            except: return u

        current_root_domain = get_root_domain(target_url)

        for rule in rules:
            # --- SMART MATCHING LOGIC ---
            rule_applies = False
            
            # Case A: Exact ID match
            if rule.target_id and rule.target_id in target_monitor_ids:
                rule_applies = True
            
            # Case B: Rule has a specific URL string
            elif rule.target_url:
                clean_rule_url = rule.target_url.replace("https://", "").replace("http://", "").strip().lower().rstrip("/")
                clean_current_url = target_url.replace("https://", "").replace("http://", "").strip().lower().rstrip("/")
                
                # Check if current URL ends with the rule URL (Standard Subdomain)
                if clean_current_url.endswith("." + clean_rule_url) or clean_current_url == clean_rule_url:
                    rule_applies = True
                
                # --- NEW: FUZZY MATCH (CONTAINS) ---
                # Handles "m.testexample.com" matching "example.com" 
                # and "AS207960 Test Intermediate - example.com" matching "example.com"
                elif clean_rule_url in clean_current_url and len(clean_rule_url) > 3:
                    rule_applies = True

                # Fallback: Root domain check
                elif get_root_domain(clean_current_url) == get_root_domain(clean_rule_url):
                    rule_applies = True
            
            # Case C: Global Rule
            elif rule.target_id is None and not rule.target_url:
                rule_applies = True
            
            if not rule_applies:
                continue

            triggered = False
            message = ""

            # --- LOGIC: STATUS DOWN ---
            if rule.condition == "status_down":
                category = _classify_service_status(current_status)
                if category in {"timeout", "tls", "unreachable", "client_error", "down", "critical"}:
                    triggered = True
                    message = f"CRITICAL: {target_url} reported status '{current_status}'. (Rule: {rule.name})"

            # --- LOGIC: HIGH LATENCY ---
            elif rule.condition == "response_time_high":
                thresh_str = rule.threshold if rule.threshold else ">1000"
                
                if thresh_str.strip().isdigit():
                    thresh_str = ">" + thresh_str

                operator = ">"
                limit = 1000

                if ">=" in thresh_str:
                    operator = ">="; limit = int(thresh_str.replace(">=", ""))
                elif ">" in thresh_str:
                    operator = ">"; limit = int(thresh_str.replace(">", ""))
                elif "<=" in thresh_str:
                    operator = "<="; limit = int(thresh_str.replace("<=", ""))
                elif "<" in thresh_str:
                    operator = "<"; limit = int(thresh_str.replace("<", ""))

                is_breached = False
                if operator == ">=" and current_latency >= limit: is_breached = True
                elif operator == ">" and current_latency > limit: is_breached = True
                elif operator == "<=" and current_latency <= limit: is_breached = True
                elif operator == "<" and current_latency < limit: is_breached = True

                if is_breached:
                    triggered = True
                    message = f"WARNING: {target_url} latency {current_latency:.2f}ms > {limit}ms (Rule: {rule.name})"
            elif rule.condition == "smart_anomaly":
                upper_status = (current_status or "").upper()
                anomaly_keywords = [
                    "UNSTABLE",
                    "WARNING: HIGH LATENCY",
                    "CRITICAL: PATTERN BREAKDOWN",
                    "WARNING: DRIFTING",
                    "WARNING: TREND ANOMALY",
                    "WARNING: COMPLEX ANOMALY",
                ]
                if any(kw in upper_status for kw in anomaly_keywords):
                    triggered = True
                    message = (
                        f"SMART ANOMALY DETECTED: {target_url} behavior deviates significantly from baseline. "
                        f"System Status: '{current_status}'. (Rule: {rule.name})"
                    )

            _sync_rule_incident(
                db=db,
                rule=rule,
                target_url=target_url,
                monitor_id=monitor_id_to_use,
                user_id=user_id_to_check,
                triggered=triggered,
            )

            # --- DEBOUNCE & SAVE ---
            if triggered:
                # Check for recent alerts. 
                recent_alert = db.query(AlertHistory).filter(
                    AlertHistory.rule_id == rule.id,
                    AlertHistory.source_id == monitor_id_to_use,
                    AlertHistory.triggered_at > datetime.utcnow() - timedelta(minutes=30),
                    AlertHistory.message.like(f"%{target_url}%")
                ).first()

                if not recent_alert:
                    delivery = {"channel": _normalize_channel(rule.channel), "email_sent": False, "slack_sent": False}
                    if user:
                        delivery = dispatch_alert_notifications(user, rule, target_url, message, current_status, current_latency)

                    status = "failed"
                    if delivery["channel"] == "both":
                        if delivery["email_sent"] and delivery["slack_sent"]:
                            status = "sent"
                        elif delivery["email_sent"] or delivery["slack_sent"]:
                            status = "partial"
                    elif delivery["email_sent"] or delivery["slack_sent"]:
                        status = "sent"

                    new_alert = AlertHistory(
                        user_id=user_id_to_check,
                        rule_id=rule.id,
                        source_type="monitor",
                        source_id=monitor_id_to_use,
                        message=message,
                        severity=rule.severity,
                        channel=delivery["channel"],
                        status=status
                    )
                    db.add(new_alert)
                    db.commit()
                    logger.info(f"ALERT TRIGGERED: {message}")
                else:
                    logger.debug(f"ALERT DEBOUNCED: Rule {rule.id} for {target_url}")

        db.commit()

    except Exception as e:
        logger.error(f"Alert Logic Error: {e}")
        db.rollback()
    finally:
        db.close()
