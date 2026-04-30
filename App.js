import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import "./App.css";

const API_BASE_URL = (() => {
  if (process.env.REACT_APP_API_BASE_URL) {
    return process.env.REACT_APP_API_BASE_URL.replace(/\/$/, "");
  }
  if (typeof window !== "undefined") {
    const { protocol, hostname } = window.location;
    return `${protocol}//${hostname}:8000`;
  }
  return "http://localhost:8000";
})();

// ================= HELPER FUNCTIONS =================
const formatDate = (dateStr) => {
  if (!dateStr) return "Unknown";
  try {
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return "Invalid Date";
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  } catch (e) {
    return "Unknown";
  }
};

// PASSWORD VALIDATION HELPER (Mirrors Backend)
const validateReportPassword = (password, username) => {
  if (!password) return { valid: false, msg: "Password cannot be empty." };
  if (password.length < 8) return { valid: false, msg: "Password too short (min 8 chars)." };
  if (username && password.toLowerCase().includes(username.toLowerCase())) {
    return { valid: false, msg: "Password too similar to username." };
  }
  if (!/[A-Z]/.test(password)) return { valid: false, msg: "Password must contain uppercase." };
  if (!/[a-z]/.test(password)) return { valid: false, msg: "Password must contain lowercase." };
  if (!/\d/.test(password)) return { valid: false, msg: "Password must contain a number." };
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return { valid: false, msg: "Password must contain a special character." };
  return { valid: true, msg: "" };
};

// ================= RISK SCORING ALGORITHM (UPDATED - NO SSL) =================
// ================= RISK SCORING ALGORITHM (UPDATED - NEW CHECKLISTS) =================
const calculateRisk = (manualData) => {
  let score = 0;
  let riskLevel = "Low";
  let color = "var(--status-green)";

  // --- 1. EXISTING LOGIC: Expiration & Lifecycle ---
  const expDate = new Date(manualData.expirationDate || manualData.apiExpiration);
  const now = new Date();
  
  // Handle invalid dates gracefully
  if (isNaN(expDate.getTime())) {
      // If date is invalid, assume high risk
      score += 40;
  } else {
      const daysLeft = Math.ceil((expDate - now) / (1000 * 60 * 60 * 24));

      if (daysLeft < 0) {
        score += 80;
      } else if (daysLeft < 30) {
        score += 50;
      } else if (daysLeft < 90) {
        score += 20;
      }
  }

  if (!manualData.autoRenew) {
    score += 30; 
  }

  if (manualData.purpose === "production") {
    score += 10;
  }

  // --- 2. NEW LOGIC: Security Checklists Integration ---
  const s = manualData.security || {};

  // We REDUCE the score (Lower Risk) when these security measures are active (Checked).
  
  // 🔐 Registrar Security (Weight: -5 each)
  if (s.mfa) score -= 5;
  if (s.lock) score -= 5;
  if (s.registrarLock) score -= 5;
  if (s.registryLock) score -= 5;

  // 🌐 DNS Security (Weight: -5 each)
  if (s.dnssec) score -= 5;
  if (s.secureNameservers) score -= 5;
  if (s.noDanglingRecords) score -= 5;

  // 🔑 Web Security (Weight: -5 each)
  if (s.tlsVersion) score -= 5;
  if (s.sslExpiry) score -= 5;
  if (s.hsts) score -= 5;

  // 📧 Email Security (Weight: -5 each)
  if (s.spf) score -= 5;
  if (s.dkim) score -= 5;
  if (s.dmarc) score -= 5;

  // 🛡️ Threat Monitoring (Weight: -10 each, High Value)
  if (s.blacklistCheck) score -= 10;
  if (s.phishingDetection) score -= 10;
  if (s.typosquatting) score -= 10;

  // --- 3. FINAL CALCULATION ---
  // Ensure score stays between 0 and 100
  score = Math.max(0, Math.min(100, score));

  if (score >= 60) {
    riskLevel = "Critical";
    color = "var(--status-red)";
  } else if (score >= 30) {
    riskLevel = "Medium";
    color = "var(--status-orange)";
  } else {
    riskLevel = "Low";
    color = "var(--status-green)";
  }

  return { score, riskLevel, color };
};

// ================= DOMAIN ADD MODAL (NEW) =================
const DomainAddModal = ({ isOpen, onClose, onAdd, isLoading }) => {
  const [domain, setDomain] = useState("");

  useEffect(() => {
    if (isOpen) {
      setDomain(""); // Reset input when modal opens
    }
  }, [isOpen]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (domain.trim()) {
      onAdd(domain.trim());
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h3>Track New Domain</h3>
        <p style={{color: 'var(--text-muted)', marginBottom: '20px', fontSize: '0.9rem'}}>
          Enter the domain name you wish to monitor for DNS, WHOIS, and Expiration changes.
        </p>
        
        <form onSubmit={handleSubmit} style={{display: 'flex', flexDirection: 'column', gap: '15px'}}>
          <div>
            <label className="form-label">DOMAIN NAME</label>
            <input 
              type="text" 
              className="cyber-input" 
              placeholder="e.g. mycompany.com" 
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              autoFocus
              disabled={isLoading}
              autoComplete="off"
            />
          </div>

          <div className="modal-actions">
            <button type="button" onClick={onClose} className="btn-cancel" disabled={isLoading}>
              Cancel
            </button>
            <button type="submit" className="btn-submit" disabled={isLoading || !domain.trim()}>
              {isLoading ? "Tracking..." : "Track Domain"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// ================= CONFIRM MODAL COMPONENT =================
const ConfirmModal = ({ isOpen, onClose, onConfirm, title, message }) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h3>{title || "Confirm Action"}</h3>
        <p style={{color: 'var(--text-muted)', marginBottom: '20px', fontSize: '0.9rem', lineHeight: '1.5'}}>
          {message || "Are you sure you want to proceed?"}
        </p>
        <div className="modal-actions">
          <button onClick={onClose} className="btn-cancel">Cancel</button>
          <button onClick={onConfirm} className="btn-modal-danger">Confirm</button>
        </div>
      </div>
    </div>
  );
};

// ================= PASSWORD MODAL COMPONENT =================
const PasswordModal = ({ isOpen, onClose, onSubmit, title, username }) => {
  const [pwd, setPwd] = useState("");
  const [confirm, setConfirm] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    if (errorMsg) setErrorMsg("");
  }, [pwd, confirm, errorMsg]);

  if (!isOpen) return null;

  const handleSubmit = () => {
    if (pwd !== confirm) {
      setErrorMsg("Passwords do not match!");
      return;
    }

    const strengthCheck = validateReportPassword(pwd, username);
    if (!strengthCheck.valid) {
      setErrorMsg(strengthCheck.msg);
      return;
    }

    onSubmit(pwd);
    setPwd("");
    setConfirm("");
    setErrorMsg("");
    onClose();
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h3>{title || "Secure PDF Report"}</h3>
        <p style={{fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "15px"}}>
          Enter a strong password to encrypt the PDF.
        </p>
        
        {errorMsg && (
          <div className="modal-error">
            ⚠️ {errorMsg}
          </div>
        )}

        <div className="modal-input-group">
          <input 
            type="password" 
            placeholder="Enter Password" 
            value={pwd} 
            onChange={(e) => setPwd(e.target.value)} 
            autoFocus
            className={errorMsg ? "input-error" : ""}
          />
          <input 
            type="password" 
            placeholder="Confirm Password" 
            value={confirm} 
            onChange={(e) => setConfirm(e.target.value)} 
            className={errorMsg ? "input-error" : ""}
          />
        </div>
        <div className="modal-actions">
          <button onClick={onClose} className="btn-cancel">Cancel</button>
          <button onClick={handleSubmit} className="btn-submit">Generate PDF</button>
        </div>
      </div>
    </div>
  );
};

// ================= SPARKLINE COMPONENT =================
const Sparkline = ({ history, width = 200, height = 40, isDegraded }) => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    const w = width;
    const h = height;
    
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, w, h);
    
    if (!history || history.length < 2) return;

    const minVal = Math.min(...history);
    const maxVal = Math.max(...history, minVal + 50);
    const range = maxVal - minVal;
    const stepX = w / (history.length - 1);

    const currentVal = history[history.length - 1];
    const isBad = currentVal > 3000 || currentVal === 0 || isDegraded;
    
    const lineColor = isBad ? "#ef4444" : (currentVal > 1000 ? "#f59e0b" : "#00eaff");

    const gradient = ctx.createLinearGradient(0, 0, 0, h);
    if (isBad) {
      gradient.addColorStop(0, "rgba(239, 68, 68, 0.5)");
      gradient.addColorStop(1, "rgba(239, 68, 68, 0)");
    } else {
      gradient.addColorStop(0, "rgba(0, 234, 255, 0.4)");
      gradient.addColorStop(1, "rgba(0, 234, 255, 0)");
    }

    ctx.beginPath();
    history.forEach((val, i) => {
      const x = i * stepX;
      const normalizedY = (val - minVal) / (range || 1); 
      const y = h - (normalizedY * h);
      if (i === 0) ctx.moveTo(x, y);
      else {
        const prevX = (i - 1) * stepX;
        const prevVal = history[i - 1];
        const prevNormalizedY = (prevVal - minVal) / (range || 1);
        const prevY = h - (prevNormalizedY * h);
        const cp1x = prevX + (x - prevX) / 2;
        const cp1y = prevY;
        const cp2x = prevX + (x - prevX) / 2;
        const cp2y = y;
        ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, x, y);
      }
    });

    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    ctx.shadowBlur = 10;
    ctx.shadowColor = lineColor;
    ctx.stroke();
    ctx.shadowBlur = 0;

  }, [history, width, height, isDegraded]);

  return (
    <div className="chart-container">
      <canvas 
        ref={canvasRef} 
        width={width} 
        height={height} 
        style={{ width: "100%", height: "100%", display: "block" }} 
      />
    </div>);
};
// ================= ADVANCED PROFESSIONAL ALERT DASHBOARD COMPONENT =================
const AlertDashboardComponent = ({ onBack, token }) => {
    const [view, setView] = useState('rule-config');
    const [loading, setLoading] = useState(true);
    const [historyFilter, setHistoryFilter] = useState('all');
    const [rules, setRules] = useState([]);
    const [history, setHistory] = useState([]);
    const [incidentHistory, setIncidentHistory] = useState([]);
    const [domains, setDomains] = useState([]);
    const [preferences, setPreferences] = useState({
        email: "",
        slack_configured: false,
        slack_webhook_hint: "Not configured"
    });
    const [slackWebhookInput, setSlackWebhookInput] = useState("");
    const [monitors, setMonitors] = useState({
        targets: [],
        current_statuses: {},
        current_latencies: {}
    });
    const [formData, setFormData] = useState({
        name: "",
        type: "service",
        target_id: "",
        condition: "status_down",
        threshold: "",
        severity: "critical",
        channel: "email"
    });
    const [showClearIncidentConfirm, setShowClearIncidentConfirm] = useState(false);
    const [deleteRuleModal, setDeleteRuleModal] = useState({ isOpen: false, id: null });
    const ignoredHistoryIdsRef = useRef(new Set());
    const threatCounterRef = useRef({});
    const CONSECUTIVE_FAILURES_THRESHOLD = 2;

    const getCleanDomain = (url) => {
        if (!url) return "";
        return url.replace(/.*:\/\//, "").split("/")[0].split("@").pop().trim().toLowerCase();
    };

    const getSeverityColor = (sev) => {
        switch ((sev || "").toLowerCase()) {
            case "critical": return "#8B0000";
            case "high": return "#FF0000";
            case "warning": return "#F59E0B";
            case "info": return "#17A2B8";
            default: return "var(--text-muted)";
        }
    };

    const normalizeSeverity = (sev) => {
        const value = (sev || "info").toLowerCase();
        return value === "medium" ? "warning" : value;
    };

    const getSeverityClass = (sev) => {
        switch (normalizeSeverity(sev)) {
            case "critical": return "sev-critical";
            case "high": return "sev-high";
            case "warning": return "sev-warning";
            case "info": return "sev-info";
            default: return "sev-info";
        }
    };

    const getChannelLabel = (channel) => {
        switch ((channel || "").toLowerCase()) {
            case "email":
                return "Email";
            case "slack":
                return "Slack";
            case "both":
                return "Email + Slack";
            default:
                return channel || "Unspecified";
        }
    };

    const deliveryModeLabel = preferences.slack_configured ? "Email + Slack Ready" : "Email Only";

    const getConditionDescription = (rule) => {
        if (rule.type === "service") {
            if (rule.condition === "status_down") return "Any outage, timeout, or hard error";
            if (rule.condition === "response_time_high") return `Latency breach at ${rule.threshold || "1000"}ms`;
            if (rule.condition === "smart_anomaly") return "Behavior drift detected by smart anomaly engine";
        }
        if (rule.type === "domain") {
            if (rule.condition === "domain_expiring") return `Expiry window under ${rule.threshold || "30"} days`;
            if (rule.condition === "dns_changed") return "DNS record integrity changed";
            if (rule.condition === "whois_changed") return "WHOIS ownership data changed";
        }
        return rule.condition;
    };

    const getTargetName = (rule) => {
        if (rule.target_url) return rule.target_url;
        if (rule.target_id) {
            const domain = domains.find((d) => d.id === rule.target_id);
            return domain ? domain.domain_name : `ID: ${rule.target_id}`;
        }
        return "Global Scope";
    };

    const classifyAlertStatus = (status) => {
        const upper = (status || "").toUpperCase();
        if (upper.includes("PROBE BLOCKED")) return "probe_blocked";
        if (upper.includes("TIMEOUT")) return "timeout";
        if (upper.includes("TLS ERROR") || upper.includes("SSL ERROR") || upper.includes("CERTIFICATE")) return "tls";
        if (upper.includes("UNREACHABLE") || upper.includes("REFUSED") || upper.includes("CONNECTION REFUSED")) return "unreachable";
        if (upper.includes("NOT FOUND") || upper.includes("CLIENT ERROR")) return "client_error";
        if (upper.includes("SERVER DOWN") || upper.includes("DOWN")) return "down";
        if (upper.includes("CRITICAL")) return "critical";
        if (upper.includes("WARNING") || upper.includes("UNSTABLE") || upper.includes("SLOW")) return "warning";
        return "info";
    };

    const buildThreatSummary = (target, status, latency) => {
        const category = classifyAlertStatus(status);
        switch (category) {
            case "probe_blocked":
                return {
                    severity: "high",
                    message: `[HIGH] ${target} probe blocked. Status: ${status}`,
                    guidance: "The target is responding with a protection or challenge page. Review CDN/WAF rules, allowlists, or bot-defense settings."
                };
            case "timeout":
                return {
                    severity: "critical",
                    message: `[CRITICAL] ${target} timed out. Status: ${status}`,
                    guidance: "The request exceeded the probe deadline. Check network reachability, upstream saturation, or origin health."
                };
            case "tls":
                return {
                    severity: "high",
                    message: `[HIGH] ${target} has a TLS failure. Status: ${status}`,
                    guidance: "Inspect certificate validity, chain trust, SNI configuration, and TLS termination."
                };
            case "unreachable":
                return {
                    severity: "critical",
                    message: `[CRITICAL] ${target} is unreachable. Status: ${status}`,
                    guidance: "The target could not be reached. Check DNS, routing, firewall rules, and service availability."
                };
            case "client_error":
                return {
                    severity: "warning",
                    message: `[WARNING] ${target} returned a client error. Status: ${status}`,
                    guidance: "Verify the monitored URL path and access expectations. This may be a bad route or an authorization issue."
                };
            case "down":
            case "critical":
                return {
                    severity: "critical",
                    message: `[CRITICAL] ${target} is down. Status: ${status}`,
                    guidance: "Review the target immediately and inspect the monitor timeline for the first failing transition."
                };
            case "warning":
                return {
                    severity: "warning",
                    message: `[WARNING] ${target} is degraded. Status: ${status}${latency ? ` (${latency.toFixed(0)}ms)` : ""}`,
                    guidance: "Review performance telemetry and confirm whether this is transient or developing into an outage."
                };
            default:
                return null;
        }
    };

    const ruleAppliesToTarget = (rule, target) => {
        const cleanRule = getCleanDomain(rule.target_url);
        const cleanTarget = getCleanDomain(target);

        if (!cleanRule || !cleanTarget) return false;
        if (cleanRule === cleanTarget) return true;
        if (cleanTarget.endsWith(`.${cleanRule}`)) return true;
        if (cleanRule.endsWith(`.${cleanTarget}`)) return true;
        if (cleanTarget.includes(cleanRule) && cleanRule.length > 3) return true;
        return false;
    };

    const getLiveViolations = () => {
        const violations = [];
        const targetsToCheck = monitors.targets || [];

        targetsToCheck.forEach((target) => {
            const currentStatus = monitors.current_statuses?.[target] || "Unknown";
            const currentLatency = monitors.current_latencies?.[target] || 0;
            const currentStatusUpper = currentStatus.toUpperCase();

            let isThreat = false;
            let threatSeverity = "info";
            let threatMessage = "";
            let matchingRuleId = "SYSTEM";
            let escalationChannel = "Email";
            let guidance = "Review live diagnostics and confirm whether the degradation is transient.";

            const matchedRules = rules.filter(
                (rule) => rule.type === "service" && rule.is_active && ruleAppliesToTarget(rule, target)
            );

            if (matchedRules.length > 0) {
                for (const rule of matchedRules) {
                    if (rule.condition === "status_down") {
                        const category = classifyAlertStatus(currentStatus);
                        const isDown = ["probe_blocked", "timeout", "tls", "unreachable", "client_error", "down", "critical"].includes(category);

                        if (isDown) {
                            const summary = buildThreatSummary(target, currentStatus, currentLatency);
                            isThreat = true;
                            threatSeverity = normalizeSeverity(rule.severity || summary?.severity || "critical");
                            threatMessage = summary?.message || `[${threatSeverity.toUpperCase()}] ${target} status issue. Status: ${currentStatus}`;
                            matchingRuleId = rule.id;
                            escalationChannel = getChannelLabel(rule.channel);
                            guidance = summary?.guidance || "Use the selected delivery path to start response, then review the full incident context.";
                            break;
                        }
                    } else if (rule.condition === "response_time_high") {
                        const rawThreshold = `${rule.threshold || ">1000"}`;
                        const normalized = rawThreshold.replace(/ms/gi, "").trim();
                        let operator = ">";
                        let limit = 1000;

                        if (normalized.includes(">=")) { operator = ">="; limit = parseInt(normalized.replace(">=", ""), 10); }
                        else if (normalized.includes(">")) { operator = ">"; limit = parseInt(normalized.replace(">", ""), 10); }
                        else if (normalized.includes("<=")) { operator = "<="; limit = parseInt(normalized.replace("<=", ""), 10); }
                        else if (normalized.includes("<")) { operator = "<"; limit = parseInt(normalized.replace("<", ""), 10); }
                        else { limit = parseInt(normalized, 10); }

                        if (isNaN(limit)) limit = 1000;

                        const isBreached =
                            (operator === ">=" && currentLatency >= limit) ||
                            (operator === ">" && currentLatency > limit) ||
                            (operator === "<=" && currentLatency <= limit) ||
                            (operator === "<" && currentLatency < limit);

                        if (isBreached) {
                            isThreat = true;
                            threatSeverity = normalizeSeverity(rule.severity || "warning");
                            threatMessage = `[${threatSeverity.toUpperCase()}] ${target} latency ${currentLatency.toFixed(0)}ms (Threshold: ${rawThreshold})`;
                            matchingRuleId = rule.id;
                            escalationChannel = getChannelLabel(rule.channel);
                            guidance = "Investigate response saturation, upstream dependency delay, or regional degradation.";
                            break;
                        }
                    } else if (rule.condition === "smart_anomaly") {
                        const anomalyFound = ["UNSTABLE", "WARNING: HIGH LATENCY", "CRITICAL: PATTERN BREAKDOWN", "WARNING: DRIFTING"]
                            .some((kw) => currentStatusUpper.includes(kw));

                        if (anomalyFound) {
                            isThreat = true;
                            threatSeverity = rule.severity || "high";
                            threatMessage = `[${threatSeverity.toUpperCase()}] ${target} shows anomaly drift. Status: ${currentStatus}`;
                            matchingRuleId = rule.id;
                            escalationChannel = getChannelLabel(rule.channel);
                            guidance = "Baseline drift detected. Review telemetry before the issue graduates into downtime.";
                            break;
                        }
                    }
                }
            } else {
                const summary = buildThreatSummary(target, currentStatus, currentLatency);
                const isDown = summary && ["critical", "high"].includes(normalizeSeverity(summary.severity));
                const isWarning = ["WARNING", "SLOW", "UNSTABLE"].some((kw) => currentStatusUpper.includes(kw));

                if (isDown) {
                    isThreat = true;
                    threatSeverity = normalizeSeverity(summary?.severity || "critical");
                    threatMessage = summary?.message || `[SYSTEM CRITICAL] ${target} issue detected. Status: ${currentStatus}`;
                    matchingRuleId = "SYSTEM-AUTO";
                    guidance = summary?.guidance || "No custom rule matched. Add a dedicated escalation path for this service.";
                } else if (isWarning) {
                    isThreat = true;
                    threatSeverity = "warning";
                    threatMessage = `[SYSTEM WARNING] ${target} is experiencing instability. Status: ${currentStatus}`;
                    matchingRuleId = "SYSTEM-AUTO";
                    guidance = "System fallback detected a degradation signal. Consider formalizing a threshold rule.";
                }
            }

            if (isThreat) {
                threatCounterRef.current[target] = (threatCounterRef.current[target] || 0) + 1;
            } else {
                threatCounterRef.current[target] = Math.max(0, (threatCounterRef.current[target] || 0) - 1);
            }

            const count = threatCounterRef.current[target] || 0;
            if (count >= CONSECUTIVE_FAILURES_THRESHOLD && !violations.find((item) => item.id === target)) {
                violations.push({
                    id: target,
                    time: new Date().toISOString(),
                    rule_id: matchingRuleId,
                    channel: escalationChannel,
                    message: threatMessage,
                    severity: normalizeSeverity(threatSeverity),
                    target,
                    latency: currentLatency,
                    status: currentStatus,
                    guidance,
                    source: "live"
                });
            }
        });

        return violations.sort((a, b) => new Date(b.time) - new Date(a.time));
    };

    const activeThreats = getLiveViolations();

    const operationsSnapshot = useMemo(() => {
        const counts = {
            critical: 0,
            high: 0,
            warning: 0,
            info: 0
        };

        history.forEach((item) => {
            const severity = normalizeSeverity(item.severity);
            if (counts[severity] !== undefined) counts[severity] += 1;
        });

        const channelCounts = history.reduce((acc, item) => {
            const label = getChannelLabel(item.channel);
            acc[label] = (acc[label] || 0) + 1;
            return acc;
        }, {});

        const strongestChannel = Object.entries(channelCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || "Email";
        const criticalCoverage = rules.filter((rule) => rule.severity === "critical").length;

        return {
            counts,
            strongestChannel,
            criticalCoverage,
            monitoredTargets: monitors.targets?.length || 0,
            activeThreatCount: activeThreats.length
        };
    }, [history, rules, monitors, activeThreats]);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const headers = { Authorization: `Bearer ${token}` };
                const [rulesRes, historyRes, incidentsRes, domainsRes, statusRes, prefsRes] = await Promise.all([
                    fetch("http://localhost:8000/alerts/rules", { headers }),
                    fetch("http://localhost:8000/alerts/history?limit=1000", { headers }),
                    fetch("http://localhost:8000/incidents/history?limit=1000", { headers }),
                    fetch("http://localhost:8000/domain/list", { headers }),
                    fetch("http://localhost:8000/status", { headers }),
                    fetch("http://localhost:8000/alerts/preferences", { headers })
                ]);

                if (rulesRes.ok) setRules(await rulesRes.json());
                if (historyRes.ok) {
                    const payload = await historyRes.json();
                    setHistory(payload.filter((h) => !ignoredHistoryIdsRef.current.has(h.id)));
                }
                if (incidentsRes.ok) setIncidentHistory(await incidentsRes.json());
                if (domainsRes.ok) setDomains(await domainsRes.json());
                if (statusRes.ok) setMonitors(await statusRes.json());
                if (prefsRes.ok) {
                    const prefs = await prefsRes.json();
                    setPreferences((prev) => ({
                        ...prev,
                        ...prefs
                    }));
                }
            } catch (e) {
                console.error("Failed to load alert data", e);
                if (window.showToast) window.showToast("Failed to load alert data", "error");
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, [token]);

    const resetForm = () => {
        setFormData({
            name: "",
            type: "service",
            target_id: "",
            condition: "status_down",
            threshold: "",
            severity: "critical",
            channel: "email"
        });
    };

    const handleOpenCreateRule = (type) => {
        resetForm();
        setFormData((prev) => ({
            ...prev,
            type,
            condition: type === "domain" ? "domain_expiring" : "status_down",
            threshold: type === "domain" ? "30" : "1000"
        }));
        setView("create-rule");
    };

    const handleDeleteRule = (ruleId) => {
        setDeleteRuleModal({ isOpen: true, id: ruleId });
    };

    const handleConfirmDeleteRule = async () => {
        const { id } = deleteRuleModal;
        if (!id) return;

        try {
            const res = await fetch(`http://localhost:8000/alerts/rules/${id}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` }
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "Failed to delete rule");
            }

            setRules((prev) => prev.filter((rule) => rule.id !== id));
            if (window.showToast) window.showToast("Rule deleted", "success");
        } catch (e) {
            console.error(e);
            if (window.showToast) window.showToast(e.message || "Network error", "error");
        } finally {
            setDeleteRuleModal({ isOpen: false, id: null });
        }
    };

    const handleConfirmClearIncidents = async () => {
        try {
            const res = await fetch("http://localhost:8000/incidents/history", {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` }
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "Failed to clear incident history from server.");
            }

            setIncidentHistory([]);
            setShowClearIncidentConfirm(false);
            if (window.showToast) window.showToast("Incident history cleared", "success");
        } catch (e) {
            console.error(e);
            if (window.showToast) window.showToast(e.message || "Failed to clear incident history", "error");
        }
    };

    const handleSavePreferences = async (e) => {
        e.preventDefault();

        try {
            const res = await fetch("http://localhost:8000/alerts/preferences", {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    slack_webhook_url: slackWebhookInput
                })
            });

            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.detail || "Failed to update preferences");

            setPreferences((prev) => ({
                ...prev,
                ...data
            }));
            setSlackWebhookInput("");
            if (window.showToast) window.showToast("Notification preferences updated", "success");
        } catch (e) {
            console.error(e);
            if (window.showToast) window.showToast(e.message || "Failed to update preferences", "error");
        }
    };

    const handleSubmitRule = async (e) => {
        e.preventDefault();

        const payload = { ...formData };

        if (payload.type === "service") {
            payload.target_url = formData.target_id;
            payload.target_id = null;
            if (payload.condition === "status_down") payload.threshold = null;
            else if (!payload.threshold || `${payload.threshold}`.trim() === "") payload.threshold = null;
            else payload.threshold = `${payload.threshold}`.trim();
        } else {
            const parsedId = parseInt(payload.target_id, 10);
            payload.target_id = isNaN(parsedId) ? null : parsedId;
            payload.target_url = null;

            if (payload.condition === "domain_expiring") {
                const days = `${payload.threshold || "30"}`.replace(/[^\d]/g, "") || "30";
                payload.threshold = days;
            } else if (!payload.threshold || `${payload.threshold}`.trim() === "") {
                payload.threshold = "Any Change";
            }
        }

        try {
            const res = await fetch("http://localhost:8000/alerts/rules", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(payload)
            });

            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.detail || "Failed to create rule");

            setRules((prev) => [...prev, data]);
            resetForm();
            setView("rule-config");
            if (window.showToast) window.showToast("Advanced alert rule deployed", "success");
        } catch (e) {
            console.error(e);
            if (window.showToast) window.showToast(e.message || "Network error while creating rule", "error");
        }
    };

    const renderSidebar = () => (
        <aside className="alert-sidebar-pro">
            <div className="alert-sidebar-logo">
                <span className="logo-icon">🛡️</span>
                <div>
                    <h2>SECURITY CENTER</h2>
                    <div className="status-badge pulse">SYSTEM ONLINE</div>
                </div>
            </div>
            <nav className="alert-nav-pro">
                <div className={`alert-nav-item ${view === "rule-config" ? "active" : ""}`} onClick={() => setView("rule-config")}>
                    <span className="nav-icon">⚙️</span>
                    <span className="nav-text">Command</span>
                </div>
                <div className={`alert-nav-item ${view === "active-alerts" ? "active" : ""}`} onClick={() => setView("active-alerts")}>
                    <span className="nav-icon">🚨</span>
                    <span className="nav-text">Live Threats</span>
                    {activeThreats.length > 0 && <span className="nav-dot"></span>}
                </div>
                <div className={`alert-nav-item ${view === "history" ? "active" : ""}`} onClick={() => setView("history")}>
                    <span className="nav-icon">📜</span>
                    <span className="nav-text">Incident Log</span>
                </div>
            </nav>
            <div className="alert-footer-pro">
                    <div className="alert-footer-mini">
                        <div className="footer-mini-label">Escalation Readiness</div>
                    <div className="footer-mini-value">{deliveryModeLabel}</div>
                </div>
                <button onClick={onBack} className="btn-back-alert">← Exit Dashboard</button>
            </div>
        </aside>
    );

    const renderRuleConfigView = () => (
        <main className="alert-main-pro">
            <header className="alert-header-pro">
                <div>
                    <h3>Alert Command Center</h3>
                    <p className="subtext">Advanced rule design, escalation routing, and operator readiness.</p>
                </div>
            </header>

            <div className="alert-hero-grid">
                <div className="alert-hero-card">
                    <div className="hero-kicker">Current Posture</div>
                    <h4>{operationsSnapshot.activeThreatCount > 0 ? "Incident Handling Required" : "Quiet Monitoring Window"}</h4>
                    <p>
                        {operationsSnapshot.activeThreatCount > 0
                            ? `${operationsSnapshot.activeThreatCount} live threat${operationsSnapshot.activeThreatCount > 1 ? "s are" : " is"} waiting for action.`
                            : "No active failures are holding the line right now."}
                    </p>
                    <div className="hero-pill-row">
                        <span className="hero-pill critical">{operationsSnapshot.counts.critical} critical logged</span>
                        <span className="hero-pill blue">{operationsSnapshot.monitoredTargets} targets observed</span>
                    </div>
                </div>

                <div className="alert-stat-strip">
                    <div className="alert-stat-card">
                        <span>Active Rules</span>
                        <strong>{rules.length}</strong>
                    </div>
                    <div className="alert-stat-card">
                        <span>Critical Coverage</span>
                        <strong>{operationsSnapshot.criticalCoverage}</strong>
                    </div>
                    <div className="alert-stat-card">
                        <span>Main Channel</span>
                        <strong>{operationsSnapshot.strongestChannel}</strong>
                    </div>
                </div>
            </div>

            <div className="alert-config-layout advanced">
                <div className="config-left-stack">
                    <section className="control-panel-card">
                        <div className="section-heading">
                            <div>
                                <h4>Escalation Studio</h4>
                                <p>Shape how CyberGuard reaches you when a rule crosses into risk.</p>
                            </div>
                        </div>
                        <div className="protocol-cards-grid">
                            <div className="protocol-card-pro" onClick={() => handleOpenCreateRule("service")}>
                                <div className="card-glow blue"></div>
                                <div className="card-content">
                                    <div className="icon-box blue">📡</div>
                                    <h5>Service Guard</h5>
                                    <p>Outage, latency, and anomaly rules for uptime monitoring.</p>
                                </div>
                                <div className="action-arrow">→</div>
                            </div>
                            <div className="protocol-card-pro" onClick={() => handleOpenCreateRule("domain")}>
                                <div className="card-glow green"></div>
                                <div className="card-content">
                                    <div className="icon-box green">🌐</div>
                                    <h5>Domain Watch</h5>
                                    <p>Expiry, DNS, and ownership change intelligence for tracked assets.</p>
                                </div>
                                <div className="action-arrow">→</div>
                            </div>
                            <div className="protocol-card-pro disabled">
                                <div className="card-glow orange"></div>
                                <div className="card-content">
                                    <div className="icon-box orange">🔎</div>
                                    <h5>Threat Detection</h5>
                                    <p>.</p>
                                </div>
                                <div className="lock-icon">ACTIVE</div>
                            </div>
                        </div>
                    </section>

                    <section className="control-panel-card">
                        <div className="section-heading">
                            <div>
                                <h4>Operator Preferences</h4>
                                <p>Configure delivery destinations for email-only or Slack-backed incident routing.</p>
                            </div>
                        </div>
                        <form className="prefs-grid" onSubmit={handleSavePreferences}>
                            <div className="pref-readout">
                                <span className="pref-label">EMAIL DESTINATION</span>
                                <strong>{preferences.email || "Not available"}</strong>
                            </div>
                            <div className="pref-readout">
                                <span className="pref-label">DELIVERY MODE</span>
                                <strong>{preferences.slack_configured ? "Email + Slack available" : "Email only"}</strong>
                            </div>
                            <div className="pref-readout">
                                <span className="pref-label">SLACK STATUS</span>
                                <strong>{preferences.slack_webhook_hint || "Not configured"}</strong>
                            </div>
                            <div className="pref-readout">
                                <span className="pref-label">SLACK WEBHOOK</span>
                                <input
                                    type="url"
                                    className="input-pro"
                                    placeholder="https://hooks.slack.com/services/..."
                                    value={slackWebhookInput}
                                    onChange={(e) => setSlackWebhookInput(e.target.value)}
                                />
                            </div>
                            <div className="prefs-actions">
                                <div className="prefs-note">
                                    Email keeps the detailed incident packet. Slack adds a fast operational summary for team response. Clear the Slack field and save to disable Slack delivery.
                                </div>
                                <button type="submit" className="btn-secondary-alert">
                                    Save Preferences
                                </button>
                            </div>
                        </form>
                    </section>
                </div>

                <div className="config-right-stack">
                    <section className="control-panel-card">
                        <div className="section-heading">
                            <div>
                                <h4>Response Runbook</h4>
                                <p>Recommended workflow for critical incidents.</p>
                            </div>
                        </div>
                        <div className="runbook-list">
                            <div className="runbook-step">
                                <span>1</span>
                                <div>
                                    <strong>Immediate route</strong>
                                    <p>The rule sends to email, Slack, or both based on the selected delivery path.</p>
                                </div>
                            </div>
                            <div className="runbook-step">
                                <span>2</span>
                                <div>
                                    <strong>Slack summary</strong>
                                    <p>Slack carries the short operational alert with severity, target, status, latency, and trigger time.</p>
                                </div>
                            </div>
                            <div className="runbook-step">
                                <span>3</span>
                                <div>
                                    <strong>Email packet</strong>
                                    <p>Email remains the detailed incident record with the full alert context.</p>
                                </div>
                            </div>
                        </div>
                    </section>

                    <section className="control-panel-card">
                        <div className="section-heading">
                            <div>
                                <h4>Active Rules ({rules.length})</h4>
                                <p>Each rule now carries severity and delivery intent.</p>
                            </div>
                        </div>
                        {rules.length === 0 ? (
                            <div className="empty-state-pro">No active rules found. Build your first escalation path.</div>
                        ) : (
                            <div className="rules-grid-pro">
                                {rules.map((rule) => (
                                    <div key={rule.id} className="rule-card-pro advanced">
                                        <div className={`rule-status-bar ${getSeverityClass(rule.severity)}`}></div>
                                        <div className="rule-header-row">
                                            <h5>{rule.name}</h5>
                                            <span className={`rule-tag ${getSeverityClass(rule.severity)}`}>{rule.severity}</span>
                                        </div>
                                        <div className="rule-target-banner">{getTargetName(rule)}</div>
                                        <div className="rule-info-grid advanced">
                                            <div className="rule-info-item">
                                                <span className="rule-info-label">TYPE</span>
                                                <span className="rule-info-value">{rule.type === "service" ? "Service" : "Domain"}</span>
                                            </div>
                                            <div className="rule-info-item">
                                                <span className="rule-info-label">TRIGGER</span>
                                                <span className="rule-info-value val-condition">{getConditionDescription(rule)}</span>
                                            </div>
                                            <div className="rule-info-item">
                                                <span className="rule-info-label">CHANNEL</span>
                                                <span className="rule-info-value">{getChannelLabel(rule.channel)}</span>
                                            </div>
                                        </div>
                                        <div className="rule-footer">
                                            <span className="rule-id-label">ID #{rule.id}</span>
                                            <button onClick={() => handleDeleteRule(rule.id)} className="btn-rule-delete">
                                                Delete
                                            </button>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </section>
                </div>
            </div>
        </main>
    );

    const renderCreateRuleView = () => {
        const isService = formData.type === "service";
        const channelOptions = [
            {
                id: "email",
                label: "Email Detail",
                note: "Full incident details delivered by email."
            },
            {
                id: "slack",
                label: "Slack Summary",
                note: "Fast operational delivery into the configured Slack channel."
            },
            {
                id: "both",
                label: "Email + Slack",
                note: "Send the detailed email and the Slack escalation summary together."
            }
        ];

        return (
            <main className="alert-main-pro">
                <header className="alert-header-pro">
                    <div>
                        <h3>{isService ? "New Service Response Rule" : "New Domain Response Rule"}</h3>
                        <p className="subtext">Create a sharper escalation workflow with severity and delivery path.</p>
                    </div>
                    <button onClick={() => setView("rule-config")} className="btn-secondary-alert">Cancel</button>
                </header>

                <div className="creation-form-wrapper advanced">
                    <form onSubmit={handleSubmitRule}>
                        <div className="form-two-col">
                            <div className="form-group">
                                <label>Rule Name</label>
                                <input
                                    required
                                    className="input-pro"
                                    placeholder={isService ? "API Gateway Failure Escalation" : "Domain Renewal Protection"}
                                    value={formData.name}
                                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                />
                            </div>

                            <div className="form-group">
                                <label>{isService ? "Target URL" : "Domain Asset"}</label>
                                {isService ? (
                                    <input
                                        required
                                        className="input-pro"
                                        placeholder="https://api.example.com"
                                        value={formData.target_id}
                                        onChange={(e) => setFormData({ ...formData, target_id: e.target.value })}
                                    />
                                ) : (
                                    <select
                                        required
                                        className="input-pro"
                                        value={formData.target_id}
                                        onChange={(e) => setFormData({ ...formData, target_id: e.target.value })}
                                    >
                                        <option value="">-- Select Domain --</option>
                                        {domains.map((d) => (
                                            <option key={d.id} value={d.id}>{d.domain_name}</option>
                                        ))}
                                    </select>
                                )}
                            </div>
                        </div>

                        <div className="form-two-col">
                            <div className="form-group">
                                <label>Condition</label>
                                <select
                                    required
                                    className="input-pro"
                                    value={formData.condition}
                                    onChange={(e) => setFormData({ ...formData, condition: e.target.value, threshold: "" })}
                                >
                                    {isService ? (
                                        <>
                                            <option value="status_down">Service Down</option>
                                            <option value="response_time_high">High Response Time</option>
                                            <option value="smart_anomaly">Smart Anomaly Detected</option>
                                        </>
                                    ) : (
                                        <>
                                            <option value="domain_expiring">Domain Expiring Soon</option>
                                            <option value="dns_changed">DNS Records Changed</option>
                                            <option value="whois_changed">WHOIS Data Changed</option>
                                        </>
                                    )}
                                </select>
                            </div>

                            <div className="form-group">
                                <label>{isService ? "Threshold" : "Expiry Window (Days)"}</label>
                                <input
                                    className="input-pro"
                                    type="number"
                                    placeholder={isService ? "1000" : "30"}
                                    disabled={(isService && formData.condition === "status_down") || (!isService && formData.condition !== "domain_expiring")}
                                    value={formData.threshold}
                                    onChange={(e) => setFormData({ ...formData, threshold: e.target.value })}
                                />
                            </div>
                        </div>

                        <div className="form-group">
                            <label>Severity</label>
                            <div className="severity-selector">
                                {["critical", "high", "warning", "info"].map((lvl) => (
                                    <div
                                        key={lvl}
                                        className={`severity-opt ${formData.severity === lvl ? "active" : ""}`}
                                        onClick={() => setFormData({ ...formData, severity: lvl })}
                                        style={{ borderColor: formData.severity === lvl ? getSeverityColor(lvl) : "transparent" }}
                                    >
                                        {lvl}
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="form-group">
                            <label>Delivery Path</label>
                            <div className="channel-option-grid">
                                {channelOptions.map((option) => (
                                    <button
                                        key={option.id}
                                        type="button"
                                        className={`channel-option-card ${formData.channel === option.id ? "active" : ""}`}
                                        onClick={() => setFormData({ ...formData, channel: option.id })}
                                    >
                                        <strong>{option.label}</strong>
                                        <span>{option.note}</span>
                                    </button>
                                ))}
                            </div>
                        </div>

                        <div className="alert-design-note">
                            Slack delivery requires a configured webhook in Operator Preferences. Email remains the detailed incident packet when included in the route.
                        </div>

                        <div className="form-actions">
                            <button type="button" onClick={() => setView("rule-config")} className="btn-cancel-alert-red">
                                Discard
                            </button>
                            <button type="submit" className="btn-deploy-alert">
                                Deploy Advanced Rule
                            </button>
                        </div>
                    </form>
                </div>
            </main>
        );
    };

    const renderActiveAlertsView = () => (
        <main className="alert-main-pro">
            <header className="alert-header-pro">
                <div>
                    <h3>Live Threat Matrix</h3>
                    <p className="subtext">Current failures, their severity, and recommended operator response.</p>
                </div>
            </header>

            <div className="live-summary-grid">
                <div className="live-summary-card">
                    <span>Open Threats</span>
                    <strong>{activeThreats.length}</strong>
                </div>
                <div className="live-summary-card">
                    <span>Critical Now</span>
                    <strong>{activeThreats.filter((item) => item.severity === "critical").length}</strong>
                </div>
                <div className="live-summary-card">
                    <span>Email Path Ready</span>
                    <strong>{preferences.email ? "Yes" : "No"}</strong>
                </div>
            </div>

            {activeThreats.length === 0 ? (
                <div className="empty-state-pro secure">
                    <div className="secure-icon">🛡️</div>
                    <h4>System Secure</h4>
                    <p>No active violations detected across all monitored targets.</p>
                </div>
            ) : (
                <div className="threat-feed advanced">
                    {activeThreats.map((item) => (
                        <div key={item.id || item.message} className={`threat-card advanced ${getSeverityClass(item.severity)}`}>
                            <div className={`threat-indicator ${getSeverityClass(item.severity)}`}></div>
                            <div className="threat-content">
                                <div className="threat-meta">
                                    <span className="time-stamp">{new Date(item.time).toLocaleString()}</span>
                                    <span className={`threat-sev ${getSeverityClass(item.severity)}`}>{item.severity.toUpperCase()}</span>
                                </div>
                                <div className="threat-message">{item.message}</div>
                                <div className="threat-intel-grid">
                                    <div>
                                        <span className="threat-intel-label">Target</span>
                                        <strong>{item.target}</strong>
                                    </div>
                                    <div>
                                        <span className="threat-intel-label">Status</span>
                                        <strong>{item.status}</strong>
                                    </div>
                                    <div>
                                        <span className="threat-intel-label">Latency</span>
                                        <strong>{item.latency ? `${item.latency.toFixed(0)} ms` : "N/A"}</strong>
                                    </div>
                                    <div>
                                        <span className="threat-intel-label">Delivery</span>
                                        <strong>{item.channel}</strong>
                                    </div>
                                </div>
                                <div className={`threat-guidance ${getSeverityClass(item.severity)}`}>{item.guidance}</div>
                                <div className="threat-details">
                                    <span>Rule ID: #{item.rule_id}</span>
                                    <span>Source: Live Monitor</span>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </main>
    );

    const renderHistoryView = () => {
        const getLiveThreatErrorType = (item) => {
            const category = classifyAlertStatus(item.status || "");
            if (category === "probe_blocked") return "Probe Blocked";
            if (category === "timeout") return "Timeout";
            if (category === "tls") return "TLS Error";
            if (category === "unreachable") return "Unreachable";
            if (category === "client_error") return "4XX Client Error";
            if (category === "down") return "Service Down";
            if (category === "critical") return "Critical Failure";
            if ((item.status || "").toUpperCase().includes("ANOMALY")) return "Smart Anomaly";
            if ((item.status || "").toUpperCase().includes("SLOW") || (item.status || "").toUpperCase().includes("LATENCY")) {
                return "High Response Time";
            }
            return item.severity === "warning" ? "Warning" : "Info";
        };

        const getIncidentSeverity = (item) => {
            const status = (item.status || "").toUpperCase();
            const errorType = (item.error_type || "").toLowerCase();

            if (
                errorType.includes("timeout") ||
                errorType.includes("unreachable") ||
                errorType.includes("down") ||
                errorType.includes("critical")
            ) {
                return "critical";
            }
            if (
                errorType.includes("probe blocked") ||
                errorType.includes("tls") ||
                errorType.includes("certificate") ||
                errorType.includes("smart anomaly")
            ) {
                return "high";
            }
            if (
                errorType.includes("high response time") ||
                errorType.includes("warning") ||
                errorType.includes("client error")
            ) {
                return "warning";
            }
            if (status === "ONGOING") {
                return "info";
            }
            return "info";
        };

        const getIncidentSeverityClass = (severity) => {
            if (severity === "critical") return "sev-critical";
            if (severity === "high") return "sev-high";
            if (severity === "warning") return "sev-warning";
            return "sev-info";
        };

        const getIncidentDescription = (item) => {
            const errorType = (item.error_type || "").toLowerCase();
            const status = (item.status || "").toLowerCase();
            const combined = `${errorType} ${(item.target || "").toLowerCase()}`;

            if (errorType.includes("timeout")) return "The monitor could not get a response before the request deadline.";
            if (errorType.includes("unreachable")) return "The target could not be reached from the monitoring probe.";
            if (errorType.includes("probe blocked")) return "The probe was blocked by a protection layer such as WAF, CDN, or challenge page.";
            if (errorType.includes("tls") || errorType.includes("certificate")) return "A TLS or certificate problem prevented a trusted connection.";
            if (errorType.includes("high response time")) return "The service responded, but latency crossed the configured threshold.";
            if (errorType.includes("smart anomaly")) return "Behavior drift was detected against the learned performance baseline.";
            if (errorType.includes("client error")) return "The target responded with a client-side error condition such as a 4xx response.";
            if (errorType.includes("down") || errorType.includes("critical")) return "The service entered a critical failure state and needs investigation.";
            if (combined.includes("4xx") || combined.includes("404") || combined.includes("not found")) {
                return "The monitor received a 4XX client error response from the target.";
            }
            if (combined.includes("refused") || combined.includes("connection refused")) {
                return "The connection was actively refused by the target service or upstream host.";
            }
            if (combined.includes("server error") || combined.includes("5xx") || combined.includes("500")) {
                return "The target responded with a server-side failure condition.";
            }
            if (combined.includes("blocked")) {
                return "The request was blocked before the monitor could complete a normal health check.";
            }
            if (combined.includes("anomaly")) {
                return "The monitor detected behavior that deviates from the expected service pattern.";
            }
            if (combined.includes("latency") || combined.includes("slow")) {
                return "The service stayed reachable, but response performance degraded beyond the expected level.";
            }
            if (status === "resolved") return "The original alert condition cleared after the detected failure reason stopped occurring.";
            return "A monitored rule was triggered and recorded in the incident log.";
        };

        const persistentIncidents = [...incidentHistory]
            .filter((item) => {
                const target = (item.target || "").trim().toLowerCase();
                const status = (item.status || "").trim().toLowerCase();
                const errorType = (item.error_type || "").trim().toLowerCase();
                return target !== "idle" && status !== "idle" && errorType !== "idle";
            })
            .concat(
                activeThreats
                    .filter((threat) => {
                        const liveErrorType = getLiveThreatErrorType(threat);
                        return !incidentHistory.some((item) => {
                            const sameTarget = (item.target || "").trim().toLowerCase() === (threat.target || "").trim().toLowerCase();
                            const sameError = (item.error_type || "").trim().toLowerCase() === liveErrorType.toLowerCase();
                            const stillOpen = (item.status || "").trim().toLowerCase() === "ongoing";
                            return sameTarget && sameError && stillOpen;
                        });
                    })
                    .map((threat) => ({
                        id: `live-${threat.id || threat.target}`,
                        target: threat.target,
                        status: "Ongoing",
                        error_type: getLiveThreatErrorType(threat),
                        started_at: threat.time,
                        ended_at: null,
                        duration_seconds: null,
                    }))
            )
            .map((item) => ({
                ...item,
                severity: getIncidentSeverity(item)
            }))
            .sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
        const filteredIncidents = persistentIncidents.filter((item) => {
            if (historyFilter === "all") return true;
            if (historyFilter === "critical") return item.severity === "critical";
            if (historyFilter === "high") return item.severity === "high";
            if (historyFilter === "warning") return item.severity === "warning";
            if (historyFilter === "info") return item.severity === "info";
            return true;
        });
        const cardData = [
            { id: "all", label: "All Incidents", count: persistentIncidents.length, color: "var(--text-muted)" },
            { id: "critical", label: "Critical", count: persistentIncidents.filter((i) => i.severity === "critical").length, color: "#8B0000" },
            { id: "high", label: "High", count: persistentIncidents.filter((i) => i.severity === "high").length, color: "#FF0000" },
            { id: "warning", label: "Warning", count: persistentIncidents.filter((i) => i.severity === "warning").length, color: "#F59E0B" },
            { id: "info", label: "Info", count: persistentIncidents.filter((i) => i.severity === "info").length, color: "#06b6d4" }
        ];

        return (
            <main className="alert-main-pro">
                <header className="alert-header-pro">
                    <div>
                        <h3>Incident Log</h3>
                        <p className="subtext">Persistent incident records with the exact detected problem.</p>
                    </div>
                    {persistentIncidents.length > 0 && (
                        <button onClick={() => setShowClearIncidentConfirm(true)} className="btn-clear-alert">
                            Clear Log
                        </button>
                    )}
                </header>

                <div className="history-stats-grid">
                    {cardData.map((card) => (
                        <div
                            key={card.id}
                            className={`h-stat-card-pro ${historyFilter === card.id ? "active" : ""}`}
                            onClick={() => setHistoryFilter(card.id)}
                            style={{ borderColor: historyFilter === card.id ? card.color : "rgba(255,255,255,0.05)" }}
                        >
                            <div className="h-stat-count" style={{ color: card.color }}>{card.count}</div>
                            <div className="h-stat-label">{card.label}</div>
                        </div>
                    ))}
                </div>

                <div className="audit-list-pro" style={{ marginBottom: "24px" }}>
                    {filteredIncidents.length === 0 ? (
                        <div className="empty-state-pro">
                            <div className="empty-icon">🛰️</div>
                            <p>No incidents match this filter.</p>
                        </div>
                    ) : (
                        filteredIncidents.map((item) => (
                            <div key={`incident-${item.id}`} className="audit-row-pro advanced">
                                <div className="audit-time-pro">
                                    <div className="date-text">{new Date(item.started_at).toLocaleDateString()}</div>
                                    <div className="time-text">{new Date(item.started_at).toLocaleTimeString()}</div>
                                </div>
                                <div className="audit-body-pro">
                                    <div className="audit-header-pro">
                                        <span className={`audit-sev-tag ${getIncidentSeverityClass(item.severity)}`}>{item.severity.toUpperCase()}</span>
                                        <span className="audit-id">{item.error_type || "Status Recorded"}</span>
                                    </div>
                                    <div className="audit-msg-pro">{item.target}</div>
                                    <div className="time-text" style={{ marginTop: "8px", lineHeight: 1.5 }}>
                                        {getIncidentDescription(item)}
                                    </div>
                                    <div className="time-text" style={{ marginTop: "6px" }}>
                                        {item.error_type || item.status}
                                    </div>
                                </div>
                                <div className="audit-channel-pro">
                                    <span className="channel-badge">
                                        {item.duration_seconds ? `${item.duration_seconds}s` : item.status}
                                    </span>
                                </div>
                            </div>
                        ))
                    )}
                </div>
                <ConfirmModal
                    isOpen={showClearIncidentConfirm}
                    onClose={() => setShowClearIncidentConfirm(false)}
                    onConfirm={handleConfirmClearIncidents}
                    title="Clear Incident Log"
                    message="Are you sure you want to permanently clear the saved incident log? This action will delete incident records from the database."
                />
            </main>
        );
    };

    if (loading) return <div className="loading-overlay">INITIALIZING SECURITY RULES...</div>;

    return (
        <div className="alert-dashboard-pro-layout">
            {renderSidebar()}
            {view === "rule-config" && renderRuleConfigView()}
            {view === "create-rule" && renderCreateRuleView()}
            {view === "active-alerts" && renderActiveAlertsView()}
            {view === "history" && renderHistoryView()}

            <ConfirmModal
                isOpen={deleteRuleModal.isOpen}
                onClose={() => setDeleteRuleModal({ isOpen: false, id: null })}
                onConfirm={handleConfirmDeleteRule}
                title="Delete Alert Rule"
                message="Are you sure you want to permanently remove this alert rule? This action cannot be undone."
            />
        </div>
    );
};
    

// ================= UPGRADED DOMAIN TRACKING COMPONENT =================

const ExpiryCountdown = ({ label, dateStr }) => {
  if (!dateStr) return <div className="expiry-badge">N/A</div>;

  const targetDate = new Date(dateStr);
  const now = new Date();
  const diffTime = targetDate - now;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

  let statusClass = "status-green"; 
  if (diffDays <= 7) statusClass = "status-red";
  else if (diffDays <= 30) statusClass = "status-yellow";

  return (
    <div className={`expiry-info ${statusClass}`}>
      <span className="expiry-label">{label}</span>
      <span className="expiry-days">
        {diffDays < 0 ? "Expired" : `${diffDays} Days`}
      </span>
      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px' }}>
        ({formatDate(dateStr)})
      </span>
    </div>
  );
};

// ... existing code ...

const DEFAULT_MANUAL_DATA = {
  registrar: "",
  regDate: "",
  expirationDate: "",
  autoRenew: false,
  dnsProvider: "",
  hostingProvider: "",
  sslProvider: "",
  purpose: "production",
  riskLevel: "Medium",
  primaryOwner: "",
  backupOwner: "",
  team: "",
  department: "",
  security: {
    // --- Existing ---
    mfa: false,
    lock: false,
    dnssec: false,
    backupContact: false,
    
    // --- NEW: Registrar Security ---
    registrarLock: false,
    registryLock: false,
    
    // --- NEW: DNS Security ---
    secureNameservers: false,
    noDanglingRecords: false,
    
    // --- NEW: Web Security ---
    tlsVersion: false,
    sslExpiry: false,
    hsts: false,
    
    // --- NEW: Email Security ---
    spf: false,
    dkim: false,
    dmarc: false,
    
    // --- NEW: Threat Monitoring ---
    blacklistCheck: false,
    phishingDetection: false,
    typosquatting: false
  },
  notes: []
};

// ... existing code ...

const DomainTrackingComponent = ({ onBack, token, username }) => {
  const [domains, setDomains] = useState([]);
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [detailData, setDetailData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAdding, setIsAdding] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  
  // UI States
  const [activeDetailTab, setActiveDetailTab] = useState("overview"); 
  const [isEditMode, setIsEditMode] = useState(false);
  const [expandedDns, setExpandedDns] = useState({});
  const [isPwdModalOpen, setIsPwdModalOpen] = useState(false);
  
  // NEW: State for Domain Add Modal
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  // NEW: State for Delete Confirmation Modal
  const [deleteModal, setDeleteModal] = useState({ isOpen: false, id: null });

  const [domainManualDataMap, setDomainManualDataMap] = useState({});

  const currentManualData = useMemo(() => {
    if (!selectedDomain) return DEFAULT_MANUAL_DATA;
    return domainManualDataMap[selectedDomain.domain_name] || DEFAULT_MANUAL_DATA;
  }, [selectedDomain, domainManualDataMap]);

  const fetchDomains = useCallback(async () => {
    try {
      const res = await fetch("http://localhost:8000/domain/list", {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) {
        if (res.status === 401) {
            alert("Session expired. Please login again.");
            window.location.reload();
        }
        setDomains([]);
        setLoading(false);
        return;
      }
      const data = await res.json();
      setDomains(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Failed to fetch domains", err);
      setDomains([]);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchDomains();
    const interval = setInterval(fetchDomains, 60000);
    return () => clearInterval(interval);
  }, [token, fetchDomains]);

  const handleGlobalDomainReport = () => {
    if (!selectedDomain) {
      alert("Please select a domain from the sidebar first to generate a report.");
      return;
    }
    setIsPwdModalOpen(true);
  };

  const downloadReportWithPassword = async (password) => {
    try {
        const res = await fetch(`http://localhost:8000/domain/report/${selectedDomain.id}`, {
            method: "POST",
            headers: { "Content-Type": "application/json", 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ password: password })
        });

        if (!res.ok) {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.detail || "Failed to generate report");
        }

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${selectedDomain.domain_name}_report.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (err) {
        console.error(err);
        alert("Error generating report: " + err.message);
    }
  };

  // UPDATED: handleAdd now accepts domain from modal
  const handleAdd = async (domainName) => {
    if (!domainName) return;
    setIsAdding(true);
    try {
      const res = await fetch("http://localhost:8000/domain/add", {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(domainName),
      });
      if (res.ok) {
        const data = await res.json();
        setIsAddModalOpen(false); // Close modal on success
        if(window.showToast) window.showToast(`${data.message}`, "success");
        await fetchDomains();
      } else {
        const errorData = await res.json().catch(() => ({}));
        setIsAddModalOpen(false);
        if(window.showToast) window.showToast(`Failed to add domain: ${errorData.detail || "Unknown error"}`, "error");
      }
    } catch (err) {
      setIsAdding(false);
      setIsAddModalOpen(false);
      if(window.showToast) window.showToast("Network error adding domain", "error");
    } finally {
      setIsAdding(false);
    }
  };

  // UPDATED: Opens the professional modal instead of window.confirm
  const handleDelete = (e, id) => {
    e.stopPropagation();
    // Set the state to open the modal with the specific ID
    setDeleteModal({ isOpen: true, id: id });
  };

  // NEW: Handles the actual deletion after confirmation
  const handleConfirmDelete = async () => {
    const { id } = deleteModal;
    if (!id) return;

    try {
      const res = await fetch(`http://localhost:8000/domain/${id}`, {
        method: "DELETE",
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (res.ok || res.status === 204) {
        // If the deleted domain was currently selected, clear selection
        if (selectedDomain?.id === id) {
          setSelectedDomain(null);
          setDetailData(null);
        }
        if(window.showToast) window.showToast("Domain deleted successfully", "success");
        await fetchDomains();
      } else {
        let errorText = "Failed to delete domain.";
        try {
            const errData = await res.json();
            if (errData.detail) errorText += ` Server says: ${errData.detail}`;
        } catch (e) {
            errorText += ` Server status: ${res.status} ${res.statusText}`;
        }
        if(window.showToast) window.showToast(errorText, "error");
      }
    } catch (err) {
      console.error(err);
      if(window.showToast) window.showToast("Network error while deleting. Please check console.", "error");
    } finally {
      // Always close the modal and clear the ID
      setDeleteModal({ isOpen: false, id: null });
    }
  };

  const handleSelect = async (domainId) => {
    const domain = domains.find((d) => d.id === domainId);
    setSelectedDomain(domain);
    setExpandedDns({});
    setDetailData(null); 

    try {
      const res = await fetch(`http://localhost:8000/domain/detail/${domainId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error("Failed to fetch details");
      const data = await res.json();
      
      if (data.manual_data && Object.keys(data.manual_data).length > 0) {
          setDomainManualDataMap(prev => ({
              ...prev,
              [domain.domain_name]: {
                  ...DEFAULT_MANUAL_DATA, 
                  ...data.manual_data     
              }
          }));
      } else {
          setDomainManualDataMap(prev => ({
              ...prev,
              [domain.domain_name]: {
                  ...DEFAULT_MANUAL_DATA,
                  registrar: data.registrar || "",
                  regDate: data.creation_date || "",
                  expirationDate: "", 
                  apiExpiration: data.expiration_date 
              }
          }));
      }

      setTimeout(() => setDetailData(data), 100);
    } catch (err) {
      console.error(err);
      if(window.showToast) window.showToast("Could not load details.", "error");
      setDetailData(null);
    }
  };

  const handleRescan = async () => {
    if (!selectedDomain) return;
    setIsScanning(true);
    try {
      const res = await fetch(`http://localhost:8000/domain/scan/${selectedDomain.id}`, {
        method: "POST",
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        await handleSelect(selectedDomain.id);
        await fetchDomains();
      } else {
        throw new Error("Scan failed");
      }
    } catch (err) {
      console.error(err);
      if(window.showToast) window.showToast("❌ Scan failed.", "error");
    } finally {
      setTimeout(() => setIsScanning(false), 1500);
    }
  };

  const toggleDns = (type) => {
    setExpandedDns(prev => ({ ...prev, [type]: !prev[type] }));
  };

  const updateManualField = (key, value) => {
    if (!selectedDomain) return;
    setDomainManualDataMap(prev => ({
      ...prev,
      [selectedDomain.domain_name]: {
        ...(prev[selectedDomain.domain_name] || DEFAULT_MANUAL_DATA),
        [key]: value
      }
    }));
  };

  const updateSecurityField = (key, value) => {
    if (!selectedDomain) return;
    const domainName = selectedDomain.domain_name;
    const prevData = domainManualDataMap[domainName] || DEFAULT_MANUAL_DATA;
    
    const newSecurity = {
        ...(prevData.security || DEFAULT_MANUAL_DATA.security),
        [key]: value
    };

    const newManualData = {
        ...prevData,
        security: newSecurity
    };

    setDomainManualDataMap(prev => ({
      ...prev,
      [domainName]: newManualData
    }));

    saveManualData(true, newManualData);
  };

    const saveManualData = async (isSilent = false, manualPayload = null) => {
    if (!selectedDomain) return;

    // Get the data we intend to save
    let payload = manualPayload || domainManualDataMap[selectedDomain.domain_name] || DEFAULT_MANUAL_DATA;
    
    // --- NEW: Automatic Audit Logging for Asset Tab Saves ---
    // If the user clicked "Save Changes" (Not silent like a checkbox toggle), we add a log entry.
    if (!isSilent) {
        const newNote = {
            date: new Date().toISOString(),
            text: "Asset Profile Updated: Ownership, Infrastructure, or Lifecycle changes saved."
        };

        // Ensure notes array exists and prepend the new note
        const currentNotes = payload.notes || [];
        payload = {
            ...payload,
            notes: [newNote, ...currentNotes] 
        };
    }

    try {
        const res = await fetch(`http://localhost:8000/domain/update-manual/${selectedDomain.id}`, {
            method: "POST",
            headers: { 
                "Content-Type": "application/json", 
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || "Failed to save");
        }
        
        // NEW: Update Local State immediately with the new note
        // This ensures the Security tab refreshes instantly with the new audit entry
        setDomainManualDataMap(prev => ({
            ...prev,
            [selectedDomain.domain_name]: payload
        }));
        
        if (!isSilent) {
            setIsEditMode(false);
            if(window.showToast) window.showToast("Asset Profile Updated & Saved", "success");
        }
    } catch (err) {
        console.error(err);
        if (!isSilent) {
            alert("Error saving data: " + err.message);
        } else {
            console.warn("Silent auto-save failed:", err.message);
        }
    }
  };

  const addNote = () => {
    const text = prompt("Enter note or audit log entry:");
    if (text) {
        const domainName = selectedDomain.domain_name;
        const prevData = domainManualDataMap[domainName] || DEFAULT_MANUAL_DATA;
        const newNotes = [
            ...(prevData.notes || []),
            { date: new Date().toISOString(), text }
        ];
        
        const newManualData = {
            ...prevData,
            notes: newNotes
        };

        setDomainManualDataMap(prev => ({
            ...prev,
            [domainName]: newManualData
        }));

        saveManualData(true, newManualData);
    }
  };

  const riskScoreObj = detailData ? calculateRisk(currentManualData) : { score: 0, riskLevel: "Unknown", color: "gray" };
  
  // Helper: Calculate Domain Age
  const getDomainAge = (dateStr) => {
      if (!dateStr) return "Unknown";
      try {
          const created = new Date(dateStr);
          const now = new Date();
          const diff = now - created;
          const days = Math.floor(diff / (1000 * 60 * 60 * 24));
          const years = Math.floor(days / 365);
          const remainingDays = days % 365;
          if (years > 0) return `${years}y ${remainingDays}d`;
          return `${days}d`;
      } catch(e) { return "Invalid"; }
  };

  // Helper: Extract TLD
  const getTLD = (domain) => {
      if (!domain) return "??";
      const parts = domain.split('.');
      return parts.length > 1 ? parts[parts.length - 1].toUpperCase() : "??";
  };

  return (
    <div className="up-dashboard dashboard-atmosphere" style={{ gridTemplateColumns: "350px 1fr" }}>
      <div className="glow-orb orb-dashboard-1"></div>
      <div className="glow-orb orb-dashboard-2"></div>

      <aside className="up-sidebar">
        <div className="up-sidebar-header" style={{ flexDirection: "column", alignItems: "flex-start", gap: "10px" }}>
            <div style={{ display: "flex", width: "100%", justifyContent: "space-between", alignItems: "center" }}>
                <h2 style={{margin: 0}}>Domain Assets</h2>
                <div className="up-status-badge live">Live Tracking</div>
            </div>
        </div>

        <div style={{ marginTop: "20px" }}>
          <button 
            onClick={() => setIsAddModalOpen(true)}
            className="up-btn-blue"
            style={{ width: "100%", fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "10px" }}
          >
            <span>+</span> Add New Domain
          </button>
        </div>

        <div className="up-nav" style={{ marginTop: "20px", padding: 0 }}>
          {domains.map((d) => (
            <div
              key={d.id}
              className={`nav-item domain-card-item interactive-card ${
                selectedDomain?.id === d.id ? "active-glow" : ""
              }`}
              onClick={() => handleSelect(d.id)}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "12px", width: "100%" }}>
                
                <div className="health-ring-container" title={`Score: ${d.security_score}`}>
                  <div 
                    className="health-ring"
                    style={{
                      background: `conic-gradient(var(--status-blue) ${d.security_score}%, rgba(255,255,255,0.1) 0)`,
                      borderColor: d.security_score > 50 ? "rgba(255,255,255,0.1)" : "var(--status-red)"
                    }}
                  ></div>
                  <div className="health-dot"></div>
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: "bold", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {d.domain_name}
                  </div>
                </div>

                <button
                  onClick={(e) => handleDelete(e, d.id)}
                  className="icon-btn-delete"
                  title="Delete"
                >
                  ✕
                </button>
              </div>
            </div>
          ))}
          {domains.length === 0 && !loading && (
            <div className="up-empty-state" style={{border: "none", background: "transparent"}}>
              <p>No domains tracked yet.</p>
            </div>
          )}
        </div>

        <div className="up-footer-nav">
          <button onClick={onBack} className="back-btn">← Back to Dashboard</button>
        </div>
      </aside>

      <main className="up-main">
        {detailData ? (
          <div className="fade-in-content">
            <header className="up-header">
              <div>
                  <div style={{display: "flex", alignItems: "center", gap: "15px"}}>
                    <h3 style={{ margin: 0 }}>{detailData.domain_name}</h3>
                    <div style={{
                        padding: "4px 8px", 
                        background: "rgba(0,0,0,0.3)", 
                        border: "1px solid", 
                        borderColor: riskScoreObj.color,
                        borderRadius: "4px",
                        color: riskScoreObj.color,
                        fontSize: "0.7rem",
                        fontWeight: "bold",
                        textTransform: "uppercase"
                    }}>
                        Risk: {riskScoreObj.riskLevel}
                    </div>
                  </div>
                <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
                  Last Scanned: {new Date(detailData.last_scanned).toLocaleString()}
                </span>
              </div>
              
              <div style={{ display: "flex", gap: "10px" }}>
                <button 
                    onClick={handleGlobalDomainReport} 
                    className="up-btn-gray" 
                    style={{ fontSize: "0.8rem" }}
                    title="Generate PDF for this domain only"
                >
                    📄 Domain Report
                </button>
                <button 
                    onClick={handleRescan} 
                    className={`up-btn-blue ${isScanning ? 'scanning-btn' : ''}`} 
                    disabled={isScanning}
                >
                    {isScanning ? "Scanning..." : "🔄 Re-Scan Auto"}
                </button>
              </div>
            </header>

            {isScanning && <div className="scan-overlay"><div className="scan-line"></div></div>}

            {/* TABS */}
            <div style={{ display: "flex", gap: "20px", marginBottom: "20px", borderBottom: "1px solid var(--border-color)" }}>
                {['overview', 'asset', 'security'].map(tab => (
                    <div 
                        key={tab}
                        onClick={() => setActiveDetailTab(tab)}
                        style={{
                            padding: "10px 20px",
                            cursor: "pointer",
                            textTransform: "uppercase",
                            fontSize: "0.8rem",
                            fontWeight: "bold",
                            color: activeDetailTab === tab ? "var(--status-blue)" : "var(--text-muted)",
                            borderBottom: activeDetailTab === tab ? "2px solid var(--status-blue)" : "2px solid transparent",
                            transition: "0.3s"
                        }}
                    >
                        {tab}
                    </div>
                ))}
            </div>

            {/* TAB CONTENT */}
            {activeDetailTab === "overview" && (
                <div className="fade-in-content">
                    <div className="analytics-grid">
                        
                        {/* 1. Ownership Card (Manual) */}
                        {(currentManualData.primaryOwner || currentManualData.department) && (
                            <div className="analytics-card glass-card-hover" style={{borderTop: "3px solid var(--status-blue)"}}>
                                <div className="card-header">
                                    <span className="card-icon">👥</span>
                                    <h4>Ownership (Manual)</h4>
                                </div>
                                <div className="card-body">
                                    <div className="status-row">
                                        <span>Primary Owner:</span>
                                        <span style={{fontWeight:"bold", color:"white"}}>{currentManualData.primaryOwner || "---"}</span>
                                    </div>
                                    <div className="status-row">
                                        <span>Backup Owner:</span>
                                        <span>{currentManualData.backupOwner || "---"}</span>
                                    </div>
                                    <div className="status-row">
                                        <span>Department:</span>
                                        <span className="text-glow">{currentManualData.department || "---"}</span>
                                    </div>
                                    <div style={{marginTop: "10px", fontSize: "0.7rem", color: "var(--text-muted)"}}>
                                        * Edit in Asset Profile tab
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* 2. NEW: Domain Vitality Card (Replaces SSL) */}
                        <div className="analytics-card glass-card-hover">
                            <div className="card-header">
                                <span className="card-icon">📅</span>
                                <h4>Domain Vitality</h4>
                            </div>
                            <div className="card-body">
                                <div className="status-row">
                                    <span>Age:</span>
                                    <span style={{fontWeight:"bold", color:"var(--status-blue)"}}>{getDomainAge(currentManualData.regDate || detailData.creation_date)}</span>
                                </div>
                                <div className="status-row">
                                    <span>TLD:</span>
                                    <span style={{fontWeight:"bold", color:"var(--status-green)"}}>{getTLD(detailData.domain_name)}</span>
                                </div>
                                <div className="status-row">
                                    <span>Registrar:</span>
                                    <span className="text-glow">
                                        {currentManualData.registrar || detailData.registrar || "Unknown"}
                                    </span>
                                </div>
                                <div style={{marginTop: "15px"}}>
                                    <ExpiryCountdown label="Renewal In" dateStr={currentManualData.expirationDate || detailData.expiration_date} />
                                </div>
                            </div>
                        </div>

                         {/* 3. Infrastructure Providers (Manual) */}
                         {(currentManualData.hostingProvider || currentManualData.dnsProvider) && (
                            <div className="analytics-card glass-card-hover" style={{borderTop: "3px solid var(--status-blue)"}}>
                                <div className="card-header">
                                    <span className="card-icon">🏢</span>
                                    <h4>Providers (Manual)</h4>
                                </div>
                                <div className="card-body">
                                    <div className="status-row">
                                        <span>DNS:</span>
                                        <span style={{fontWeight:"bold"}}>{currentManualData.dnsProvider || "---"}</span>
                                    </div>
                                    <div className="status-row">
                                        <span>Hosting:</span>
                                        <span style={{fontWeight:"bold"}}>{currentManualData.hostingProvider || "---"}</span>
                                    </div>
                                    <div style={{marginTop: "10px", fontSize: "0.7rem", color: "var(--text-muted)"}}>
                                        * Edit in Asset Profile tab
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* 4. Lifecycle & Purpose (Manual) */}
                        <div className="analytics-card glass-card-hover">
                            <div className="card-header">
                                <span className="card-icon">⚙️</span>
                                <h4>Purpose & Lifecycle</h4>
                            </div>
                            <div className="card-body">
                                <div className="status-row">
                                    <span>Purpose:</span>
                                    <span style={{
                                        background: "rgba(6, 182, 212, 0.1)", 
                                        padding: "2px 8px", 
                                        borderRadius: "4px",
                                        textTransform: "uppercase",
                                        fontSize: "0.75rem",
                                        fontWeight: "bold"
                                    }}>
                                        {currentManualData.purpose}
                                    </span>
                                </div>
                                <div className="status-row">
                                    <span>Auto-Renew:</span>
                                    <span style={{color: currentManualData.autoRenew ? "var(--status-green)" : "var(--status-red)"}}>
                                        {currentManualData.autoRenew ? "Enabled" : "Disabled"}
                                    </span>
                                </div>
                            </div>
                        </div>

                        {/* 5. Quick Health (DNS Only) */}
                        <div className="analytics-card glass-card-hover">
                             <div className="card-header">
                                <span className="card-icon">🩺</span>
                                <h4>Quick Health</h4>
                            </div>
                            <div className="card-body" style={{flexDirection: "column", gap: "12px"}}>
                                <div className="health-item interactive-item">
                                    <span className="health-icon">{detailData.dns_records?.A?.length ? '✅' : '⚠️'}</span>
                                    <div className="health-text"><strong>DNS Resolution</strong></div>
                                </div>
                                <div className="health-item interactive-item">
                                    <span className="health-icon">{detailData.registrar ? '✅' : '⚠️'}</span>
                                    <div className="health-text"><strong>WHOIS Data</strong></div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="up-widget glass-widget" style={{marginTop: "20px"}}>
                      <h4>DNS Infrastructure (Auto)</h4>
                      {detailData.dns_records && Object.keys(detailData.dns_records).length > 0 ? (
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: "15px" }}>
                          {Object.entries(detailData.dns_records).map(([type, records]) => (
                            records.length > 0 && (
                              <div key={type} className="dns-box interactive-dns-box">
                                <div className="dns-type">{type} Records ({records.length})</div>
                                <div className="dns-list">
                                    {records.slice(0, expandedDns[type] ? records.length : 3).map((rec, i) => (
                                        <div key={i} className="dns-item interactive-dns-item">{rec}</div>
                                    ))}
                                    {records.length > 3 && (
                                        <div className="dns-more-btn" onClick={() => toggleDns(type)}>
                                            {expandedDns[type] ? `Show less` : `+ ${records.length - 3} more`}
                                        </div>
                                    )}
                                </div>
                              </div>
                            )
                          ))}
                        </div>
                      ) : (
                        <div className="up-empty-state">No DNS records detected.</div>
                      )}
                    </div>
                </div>
            )}

                       {activeDetailTab === "asset" && (
                <div className="fade-in-content">
                    <div className="asset-tab-container">
                        <div className="up-widget glass-widget">
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px", borderBottom: "1px solid var(--border-color)", paddingBottom: "15px" }}>
                                <div>
                                    <h3 style={{ margin: 0, color: "white", fontSize: "1.5rem", textTransform: "uppercase" }}>Manual Asset Profile</h3>
                                    <p style={{ margin: "5px 0 0", color: "var(--text-muted)", fontSize: "0.85rem" }}>Manage ownership, infrastructure, and lifecycle metadata.</p>
                                </div>
                                <button 
                                    onClick={() => setIsEditMode(!isEditMode)} 
                                    className={`up-btn-blue ${isEditMode ? 'btn-active-edit' : ''}`} 
                                    style={{ fontSize: "0.8rem", padding: "10px 25px", textTransform: "uppercase", letterSpacing: "1px" }}
                                >
                                    {isEditMode ? "Cancel Edit" : "✎ Edit Profile"}
                                </button>
                            </div>

                            <div className="asset-modules-grid">
                                
                                {/* MODULE 1: IDENTITY & OWNERSHIP */}
                                <div className="asset-module">
                                    <div className="module-header">
                                        <span className="module-icon">👤</span>
                                        <h4>Identity & Ownership</h4>
                                    </div>
                                    <div className="module-content">
                                        <div className="data-field-row">
                                            <label>Primary Owner</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.primaryOwner} 
                                                onChange={(e) => updateManualField('primaryOwner', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Not Assigned"
                                            />
                                        </div>
                                        <div className="data-field-row">
                                            <label>Backup Owner</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.backupOwner} 
                                                onChange={(e) => updateManualField('backupOwner', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Not Assigned"
                                            />
                                        </div>
                                        <div className="data-field-row">
                                            <label>Department</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.department} 
                                                onChange={(e) => updateManualField('department', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Not Assigned"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* MODULE 2: INFRASTRUCTURE STACK */}
                                <div className="asset-module">
                                    <div className="module-header">
                                        <span className="module-icon">🏢</span>
                                        <h4>Infrastructure Stack</h4>
                                    </div>
                                    <div className="module-content">
                                        <div className="data-field-row">
                                            <label>Registrar</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.registrar} 
                                                onChange={(e) => updateManualField('registrar', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Unknown"
                                            />
                                        </div>
                                        <div className="data-field-row">
                                            <label>DNS Provider</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.dnsProvider} 
                                                onChange={(e) => updateManualField('dnsProvider', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Unknown"
                                            />
                                        </div>
                                        <div className="data-field-row">
                                            <label>Hosting Provider</label>
                                            <input 
                                                type="text" 
                                                value={currentManualData.hostingProvider} 
                                                onChange={(e) => updateManualField('hostingProvider', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                                placeholder="Unknown"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* MODULE 3: LIFECYCLE & PURPOSE */}
                                <div className="asset-module full-width">
                                    <div className="module-header">
                                        <span className="module-icon">⚙️</span>
                                        <h4>Lifecycle & Operations</h4>
                                    </div>
                                    <div className="module-content">
                                        <div className="data-field-row">
                                            <label>Purpose</label>
                                            <select 
                                                value={currentManualData.purpose} 
                                                onChange={(e) => updateManualField('purpose', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-select-field" : "cyber-input-readonly"}
                                                style={isEditMode ? {} : {textAlign: 'right', cursor: 'default'}}
                                            >
                                                <option value="production">Production</option>
                                                <option value="staging">Staging</option>
                                                <option value="test">Test</option>
                                                <option value="internal">Internal</option>
                                            </select>
                                        </div>
                                        <div className="data-field-row">
                                            <label>Manual Expiration</label>
                                            <input 
                                                type="date" 
                                                value={currentManualData.expirationDate} 
                                                onChange={(e) => updateManualField('expirationDate', e.target.value)}
                                                disabled={!isEditMode}
                                                className={isEditMode ? "cyber-input-field" : "cyber-input-readonly"}
                                            />
                                        </div>
                                        <div className="data-field-row" style={{ alignItems: 'center' }}>
                                            <label style={{ marginBottom: 0 }}>Auto-Renew Status</label>
                                            <label className={`toggle-switch ${currentManualData.autoRenew ? 'active' : ''}`} onClick={() => isEditMode && updateManualField('autoRenew', !currentManualData.autoRenew)}>
                                                <div className="toggle-slider"></div>
                                                <span className="toggle-text">{currentManualData.autoRenew ? "ENABLED" : "DISABLED"}</span>
                                            </label>
                                        </div>
                                    </div>
                                </div>

                            </div>
                            
                            {/* SAVE BUTTON AREA */}
                            {isEditMode && (
                                <div style={{ marginTop: "30px", textAlign: "right", borderTop: "1px dashed var(--border-color)", paddingTop: "20px" }}>
                                    <button onClick={() => saveManualData(false)} className="up-btn-green" style={{fontSize: "0.9rem", padding: "12px 35px"}}>
                                        💾 Save Changes
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

                        {activeDetailTab === "security" && (
                <div className="fade-in-content">
                    <div className="analytics-grid" style={{gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))'}}>
                        
                        {/* 1. RISK SCORE CARD */}
                        <div className="analytics-card glass-card-hover" style={{ gridRow: "span 1" }}>
                             <div className="card-header">
                                <span className="card-icon">📊</span>
                                <h4>Calculated Risk Score</h4>
                            </div>
                            <div style={{ textAlign: "center", padding: "10px 0" }}>
                                <div style={{ 
                                    width: "100px", 
                                    height: "100px", 
                                    borderRadius: "50%", 
                                    border: `8px solid ${riskScoreObj.color}`, 
                                    display: "flex", 
                                    alignItems: "center", 
                                    justifyContent: "center", 
                                    margin: "0 auto 10px",
                                    position: "relative",
                                    boxShadow: `0 0 30px ${riskScoreObj.color}40`
                                }}>
                                    <div>
                                        <div style={{ fontSize: "2rem", fontWeight: "bold", color: "white" }}>{riskScoreObj.score}</div>
                                        <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>/ 100</div>
                                    </div>
                                </div>
                                <div style={{ fontSize: "1rem", color: riskScoreObj.color, fontWeight: "bold", textTransform: "uppercase" }}>
                                    {riskScoreObj.riskLevel} RISK
                                </div>
                            </div>
                        </div>

                        {/* 2. COMPREHENSIVE SECURITY CHECKLIST */}
                        <div className="analytics-card glass-card-hover" style={{ gridColumn: "span 2" }}>
                             <div className="card-header">
                                <span className="card-icon">🔐</span>
                                <h4>Compliance & Security Checklist</h4>
                            </div>
                            
                            <div className="security-grid-layout">
                                {/* Group 1: Registrar Security */}
                                <div className="security-group">
                                    <h5>🔐 Registrar Security</h5>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.mfa} onChange={(e) => updateSecurityField('mfa', e.target.checked)} />
                                        <span>MFA Enabled</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.lock} onChange={(e) => updateSecurityField('lock', e.target.checked)} />
                                        <span>Registrar Lock</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.registrarLock} onChange={(e) => updateSecurityField('registrarLock', e.target.checked)} />
                                        <span>Registry Lock</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.autoRenew} onChange={(e) => updateManualField('autoRenew', e.target.checked)} />
                                        <span>Auto Renew</span>
                                    </label>
                                </div>

                                {/* Group 2: DNS Security */}
                                <div className="security-group">
                                    <h5>🌐 DNS Security</h5>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.dnssec} onChange={(e) => updateSecurityField('dnssec', e.target.checked)} />
                                        <span>DNSSEC</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.secureNameservers} onChange={(e) => updateSecurityField('secureNameservers', e.target.checked)} />
                                        <span>Secure Nameservers</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.noDanglingRecords} onChange={(e) => updateSecurityField('noDanglingRecords', e.target.checked)} />
                                        <span>No Dangling Records</span>
                                    </label>
                                </div>

                                {/* Group 3: Web Security */}
                                <div className="security-group">
                                    <h5>🔑 Web Security</h5>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.tlsVersion} onChange={(e) => updateSecurityField('tlsVersion', e.target.checked)} />
                                        <span>TLS Version (v1.2+)</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.sslExpiry} onChange={(e) => updateSecurityField('sslExpiry', e.target.checked)} />
                                        <span>Valid SSL Expiry</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.hsts} onChange={(e) => updateSecurityField('hsts', e.target.checked)} />
                                        <span>HSTS Enabled</span>
                                    </label>
                                </div>

                                {/* Group 4: Email Security */}
                                <div className="security-group">
                                    <h5>📧 Email Security</h5>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.spf} onChange={(e) => updateSecurityField('spf', e.target.checked)} />
                                        <span>SPF Record</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.dkim} onChange={(e) => updateSecurityField('dkim', e.target.checked)} />
                                        <span>DKIM Record</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.dmarc} onChange={(e) => updateSecurityField('dmarc', e.target.checked)} />
                                        <span>DMARC Record</span>
                                    </label>
                                </div>

                                {/* Group 5: Threat Monitoring */}
                                <div className="security-group">
                                    <h5>🛡️ Threat Monitoring</h5>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.blacklistCheck} onChange={(e) => updateSecurityField('blacklistCheck', e.target.checked)} />
                                        <span>Blacklist Clear</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.phishingDetection} onChange={(e) => updateSecurityField('phishingDetection', e.target.checked)} />
                                        <span>Phishing Detected</span>
                                    </label>
                                    <label className="security-checkbox">
                                        <input type="checkbox" checked={currentManualData.security.typosquatting} onChange={(e) => updateSecurityField('typosquatting', e.target.checked)} />
                                        <span>No Typosquatting</span>
                                    </label>
                                </div>
                            </div>
                        </div>

                        {/* 3. AUDIT LOG */}
                        <div className="analytics-card glass-card-hover">
                             <div className="card-header">
                                <span className="card-icon">📝</span>
                                <h4>Audit & Workflow Log</h4>
                            </div>
                            <div style={{ maxHeight: "150px", overflowY: "auto", marginBottom: "10px" }}>
                                {currentManualData.notes.length > 0 ? currentManualData.notes.map((note, i) => (
                                    <div key={i} style={{ fontSize: "0.75rem", marginBottom: "8px", borderBottom: "1px dashed var(--border-color)", paddingBottom: "5px" }}>
                                        <div style={{ color: "var(--status-blue)", fontSize: "0.7rem" }}>{formatDate(note.date)}</div>
                                        <div>{note.text}</div>
                                    </div>
                                )) : <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>No notes yet.</div>}
                            </div>
                            <button onClick={addNote} className="up-btn-gray" style={{ fontSize: "0.7rem", width: "100%" }}>+ Add Note / Action</button>
                        </div>
                    </div>
                </div>
            )}

          </div>
        ) : (
          <div className="up-empty-state fade-in-content">
            <div style={{fontSize: "3rem", marginBottom: "20px"}}>🔍</div>
            <h3>Select a domain</h3>
            <p>Choose a domain from sidebar to view detailed analytics, asset management, and risk scoring.</p>
          </div>
        )}
      </main>
      
      {/* MODALS */}
      <DomainAddModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onAdd={handleAdd}
        isLoading={isAdding}
      />

      <PasswordModal 
        isOpen={isPwdModalOpen} 
        onClose={() => setIsPwdModalOpen(false)} 
        onSubmit={downloadReportWithPassword}
        title="Secure Domain Report"
        username={username}
      />
      
      {/* NEW: PROFESSIONAL DELETE CONFIRMATION MODAL */}
      <ConfirmModal
        isOpen={deleteModal.isOpen}
        onClose={() => setDeleteModal({ isOpen: false, id: null })}
        onConfirm={handleConfirmDelete}
        title="Delete Domain Asset"
        message="Are you sure you want to stop tracking this domain? This action cannot be undone and all historical data will be lost."
      />
    </div>
  );
};

// ================= MONITORING COMPONENT =================
const MonitoringComponent = ({ onBack, token, username }) => {
  // LocalStorage Keys
  const storageScope = username || "anonymous";
  const STORAGE_KEY_DATA = `cyberguard_monitor_data_${storageScope}`;
  const STORAGE_KEY_URL = `cyberguard_monitor_url_${storageScope}`;
  const STORAGE_KEY_STATE = `cyberguard_monitor_state_${storageScope}`;
  const STORAGE_KEY_PROTECTION = `cyberguard_monitor_protection_${storageScope}`;

  // Initialize state from localStorage if available
  const [url, setUrl] = useState(() => {
    return localStorage.getItem(STORAGE_KEY_URL) || "";
  });
  
  const [, setLastStartedUrl] = useState("");
  const [behindProtection, setBehindProtection] = useState(() => {
    const stored = localStorage.getItem(STORAGE_KEY_PROTECTION);
    return stored ? JSON.parse(stored) : false;
  });
  
  const [isMonitoring, setIsMonitoring] = useState(() => {
    const stored = localStorage.getItem(STORAGE_KEY_STATE);
    return stored ? JSON.parse(stored) : false;
  });

  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("monitoring");
  const [searchTerm, setSearchTerm] = useState("");
  const [incidentSearchTerm, setIncidentSearchTerm] = useState("");
  const [incidentTypeFilter, setIncidentTypeFilter] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  
  const [selectedMonitor, setSelectedMonitor] = useState(null);
  const [isPwdModalOpen, setIsPwdModalOpen] = useState(false);

  // --- NEW: Success Modal State ---
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [newlyAddedUrl, setNewlyAddedUrl] = useState("");

  // Load data from localStorage on mount
  const [data, setData] = useState(() => {
    try {
      const storedData = localStorage.getItem(STORAGE_KEY_DATA);
      return storedData ? JSON.parse(storedData) : {
        targets: [],
        current_latencies: {},
        baseline_avgs: {},
        status_messages: {},
        histories: {},
        timestamps: {},
        behind_protection_targets: {},
      };
    } catch (e) {
      return {
    targets: [],
    current_latencies: {},
    baseline_avgs: {},
        current_statuses: {},
        histories: {},
        timestamps: {},
        behind_protection_targets: {},
};
    }
  });

  // Persist data to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY_DATA, JSON.stringify(data));
    localStorage.setItem(STORAGE_KEY_URL, url);
    localStorage.setItem(STORAGE_KEY_STATE, JSON.stringify(isMonitoring));
    localStorage.setItem(STORAGE_KEY_PROTECTION, JSON.stringify(behindProtection));
  }, [
    data,
    url,
    isMonitoring,
    behindProtection,
    STORAGE_KEY_DATA,
    STORAGE_KEY_URL,
    STORAGE_KEY_STATE,
    STORAGE_KEY_PROTECTION,
  ]);

     const isProbeBlockedStatus = (status) => {
    if (!status) return false;
    const upperStatus = status.toUpperCase();
    if (
      upperStatus.includes("TLS ERROR") ||
      upperStatus.includes("SSL ERROR") ||
      upperStatus.includes("CERTIFICATE")
    ) {
      return false;
    }
    return upperStatus.includes("PROBE BLOCKED");
  };

     const isTargetDown = (status, latency) => {
    if (!status) return false;
    const upperStatus = status.toUpperCase();
    if (isProbeBlockedStatus(status)) {
      return false;
    }
    const backendDown = 
           upperStatus.includes("CRITICAL") || 
           upperStatus.includes("ERROR") || 
           upperStatus.includes("SERVER DOWN") ||
           upperStatus.includes("CONNECTION REFUSED") ||
           upperStatus.includes("NOT FOUND") || 
           upperStatus.includes("TIMEOUT") ||
           upperStatus.includes("UNREACHABLE") ||
           latency === 0;           
    return backendDown;
  };

  useEffect(() => {
      const syncBackendState = async () => {
          try {
              const response = await fetch("http://localhost:8000/status", {
                  headers: { 'Authorization': `Bearer ${token}` }
              });
              if (response.ok) {
                  const backendData = await response.json();
                  
                  // Only overwrite local state if backend has active targets or we are actively monitoring
                  if (backendData.is_monitoring || (backendData.targets && backendData.targets.length > 0)) {
                      setIsMonitoring(backendData.is_monitoring);
                      setData(backendData); 
                      if (backendData.is_monitoring) {
                          const activeUrl = backendData.target_url || (backendData.targets.length > 0 ? backendData.targets[0] : "");
                          setUrl(activeUrl);
                          setLastStartedUrl(activeUrl);
                          const protectedMap = backendData.behind_protection_targets || {};
                          setBehindProtection(Object.values(protectedMap).some(Boolean));
                      }
                  }
              }
          } catch (error) {
              console.error("Failed to sync with backend:", error);
          }
      };
      syncBackendState();
  }, [token]);

  useEffect(() => {
    let interval;
    if (isMonitoring) {
      interval = setInterval(async () => {
        try {
          const response = await fetch("http://localhost:8000/status", {
              headers: { 'Authorization': `Bearer ${token}` }
          });
          if (response.status === 401) {
              clearInterval(interval);
              alert("Session expired");
              window.location.reload();
              return;
          }
          const jsonData = await response.json();
          
          if (!jsonData.is_monitoring && isMonitoring) {
              setIsMonitoring(false);
          } else {
              setData(jsonData);
              const protectedMap = jsonData.behind_protection_targets || {};
              setBehindProtection(Object.values(protectedMap).some(Boolean));
          }
        } catch (error) {
          console.error("Backend connection lost", error);
        }
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isMonitoring, token]);

  const handleGlobalMonitoringReport = () => {
    setIsPwdModalOpen(true);
  };

  const downloadReportWithPassword = async (password) => {
    try {
        const res = await fetch("http://localhost:8000/monitoring/global-report", {
            method: "POST",
            headers: { "Content-Type": "application/json", 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ password: password })
        });

        if (!res.ok) {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.detail || "Failed to generate report");
        }

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `global_session_report.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (err) {
        console.error(err);
        alert("Error generating report: " + err.message);
    }
  };

  const handleStart = async () => {
    if (isMonitoring) return;
    if (!url || !url.startsWith("http")) {
      alert("Please enter a valid URL starting with http/https");
      return;
    }
    setIsLoading(true); 
    const payload = { url: url.trim(), behind_protection: behindProtection };
    try {
      const response = await fetch("http://localhost:8000/start", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json", 
          Accept: "application/json",
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
          if (response.status === 401) {
              alert("Unauthorized");
              return;
          }
          const errorBody = await response.json().catch(() => ({ detail: "No details" }));
          throw new Error(`Backend rejected request (${response.status}): ${errorBody.detail || "Validation error"}`);
      }
      const startData = await response.json();
      const startedTargets = Array.isArray(startData?.targets) ? startData.targets : [payload.url];
      const optimisticStatuses = Object.fromEntries(startedTargets.map((t) => [t, "Idle"]));
      const optimisticHistories = Object.fromEntries(startedTargets.map((t) => [t, []]));
      const optimisticLatencies = Object.fromEntries(startedTargets.map((t) => [t, 0]));

      // Show monitors immediately instead of waiting for the polling loop.
      setData((prev) => ({
        ...prev,
        targets: startedTargets,
        status_messages: optimisticStatuses,
        current_statuses: optimisticStatuses,
        histories: optimisticHistories,
        current_latencies: optimisticLatencies,
        behind_protection_targets: Object.fromEntries(
          startedTargets.map((t) => [t, !!payload.behind_protection])
        ),
      }));
      
      // --- NEW: Trigger Success Modal ---
      setNewlyAddedUrl(payload.url);
      setShowSuccessModal(true);
      // -----------------------------------

      setIsMonitoring(true);
      setLastStartedUrl(url.trim()); 

      // Pull fresh backend state immediately (do not wait for next interval tick).
      fetch("http://localhost:8000/status", {
        headers: { 'Authorization': `Bearer ${token}` }
      })
        .then((res) => (res.ok ? res.json() : null))
        .then((jsonData) => {
          if (!jsonData) return;
          setData(jsonData);
          const protectedMap = jsonData.behind_protection_targets || {};
          setBehindProtection(Object.values(protectedMap).some(Boolean));
        })
        .catch((error) => {
          console.error("Immediate status refresh failed", error);
        });
    } catch (err) {
      console.error(err);
      alert("Start failed:\n" + (err.message || "Unknown error"));
    } finally {
      setIsLoading(false); 
    }
  };

  const handleResume = () => {
      if (!url || !url.startsWith("http")) {
          alert("Could not determine the target URL to resume. Please enter it manually.");
          return;
      }
      handleStart();           
  };

  const handleStop = async () => {
    try {
      const res = await fetch("http://localhost:8000/stop", { 
          method: "POST",
          headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error(res.statusText);
      setIsMonitoring(false);
    } catch (error) {
      console.error(error);
      alert("Failed to stop: " + error.message);
    }
  };

  // --- MODIFIED: Clear Logic to remove localStorage ---
  const handleClear = async () => {
    // 1. Call the backend to stop the monitoring loop
    await handleStop(); 

    // 2. Clear the local state
    setData({
      targets: [],
      current_latencies: {},
      baseline_avgs: {},
      status_messages: {},
      histories: {},
      timestamps: {},
      behind_protection_targets: {},
    });
    setIsMonitoring(false);
    setSelectedMonitor(null);
    setLastStartedUrl(""); 
    setBehindProtection(false);
    
    // 3. Clear Persistence
    localStorage.removeItem(STORAGE_KEY_DATA);
    localStorage.removeItem(STORAGE_KEY_URL);
    localStorage.removeItem(STORAGE_KEY_STATE);
    localStorage.removeItem(STORAGE_KEY_PROTECTION);
  };

  const getFilteredTargets = () => {
    return data.targets.filter((target) => {
      const matchesSearch = target.toLowerCase().includes(searchTerm.toLowerCase());
      const latency = data.current_latencies[target] || 0;
      const status = data.status_messages[target] || "";
      const down = isTargetDown(status, latency);
      
      let matchesFilter = true;
      if (filterStatus === "up") matchesFilter = !down;
      if (filterStatus === "down") matchesFilter = down;

      return matchesSearch && matchesFilter;
    });
  };

  const getIncidentTargets = () => {
    return data.targets.filter((target) => {
      const latency = data.current_latencies[target] || 0;
      const status = data.status_messages[target] || data.current_statuses?.[target] || "";
      return isTargetDown(status, latency) || isProbeBlockedStatus(status) || isTlsIssueStatus(status);
    });
  };

  const isTlsIssueStatus = (status) => {
    if (!status) return false;
    const upperStatus = status.toUpperCase();
    return upperStatus.includes("TLS ERROR") || upperStatus.includes("SSL ERROR") || upperStatus.includes("CERTIFICATE");
  };

  const isUnreachableStatus = (status) => {
    if (!status) return false;
    return status.toUpperCase().includes("UNREACHABLE");
  };

  const isTimeoutStatus = (status) => {
    if (!status) return false;
    return status.toUpperCase().includes("TIMEOUT");
  };

  const isOther4xxStatus = (status) => {
    if (!status) return false;
    const upperStatus = status.toUpperCase();
    const match = upperStatus.match(/\b(4\d\d)\b/);
    if (!match) return false;
    const code = Number(match[1]);
    return code >= 400 && code < 500 && code !== 404;
  };

  // --- NEW: Success Modal Component ---
  const SuccessModal = ({ isOpen, onClose, targetUrl }) => {
      if (!isOpen) return null;
      
      return (
          <div className="modal-overlay" onClick={onClose}>
              <div className="success-modal-content" onClick={(e) => e.stopPropagation()}>
                  <div className="success-icon-circle">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="20 6 9 17 4 12"></polyline>
                      </svg>
                  </div>
                  <h3 className="success-title">Monitor Active</h3>
                  <p style={{color: "var(--text-muted)", marginBottom: "20px"}}>
                      The system is now tracking the health and latency of this endpoint in real-time.
                  </p>
                  
                  <div className="success-url">
                      {targetUrl}
                  </div>
                  
                  <button onClick={onClose} className="btn-success-close">
                      Got it
                  </button>
              </div>
          </div>
      );
  };

  const MonitorDetailView = ({ target }) => {
      const history = data.histories[target] || [];
      const status = data.current_statuses[target] || "Idle";
      
      const SLOW_THRESHOLD = 2000;
      const validHistory = history.filter(h => h > 0);
      const totalCount = history.length;
      const healthyCount = history.filter(h => h > 0 && h < SLOW_THRESHOLD).length;
      
      const uptimePercent = totalCount > 0 ? ((healthyCount / totalCount) * 100).toFixed(2) : "0.00";
      const avg = validHistory.length ? (validHistory.reduce((a, b) => a + b, 0) / validHistory.length).toFixed(0) : 0;
      const min = validHistory.length ? Math.min(...validHistory).toFixed(0) : 0;
      const max = validHistory.length ? Math.max(...validHistory).toFixed(0) : 0;
      
          const is404 = status.includes("NOT FOUND");
          const isProtected = isProbeBlockedStatus(status);
          const isTlsIssue = isTlsIssueStatus(status);
          const down = isTargetDown(status, history[history.length - 1]);
          const isSlow = !down && (status.includes("WARNING") || (history.length > 0 && history[history.length-1] > 2000));
          const lastCheck = new Date().toLocaleTimeString();

          const getDetailStatusLabel = () => {
            if (is404) return "404 Not Found";
            if (isTlsIssue) return "TLS ERROR";
            if (isProtected) return "PROBE BLOCKED";
            if (!down) return isSlow ? "SLOW RESPONSE" : "UP";
            const upperStatus = status.toUpperCase();
            if (upperStatus.includes("TIMEOUT")) return "TIMEOUT";
            if (upperStatus.includes("CRITICAL") || upperStatus.includes("PATTERN")) return "CRITICAL";
            if (upperStatus.includes("REFUSED")) return "UNREACHABLE";
            return "DOWN";
          };

          return (
              <div className="monitor-detail-container fade-in-content">
                  <button onClick={() => setSelectedMonitor(null)} className="back-btn" style={{marginBottom: "20px"}}>
                  ← Back to Dashboard
              </button>

              <div className="up-widget" style={{borderLeft: "5px solid", borderLeftColor: isTlsIssue ? "var(--status-tls)" : (isProtected ? "var(--status-blue)" : (down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")))}}>
                  <div style={{display: "flex", justifyContent: "space-between", alignItems: "center"}}>
                      <div>
                          <h1 style={{fontSize: "2rem", margin: "0 0 10px 0"}}>{target.replace(/^https?:\/\//, '')}</h1>
                          <div style={{display: "flex", alignItems: "center", gap: "20px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: isTlsIssue ? "var(--status-tls)" : (isProtected ? "var(--status-blue)" : (down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")))}}>
                                  {getDetailStatusLabel()}
                              </div>
                              <div style={{color: "var(--text-muted)", fontSize: "0.9rem"}}>
                                  HTTP/S monitor for {target}
                              </div>
                          </div>
                      </div>
                  </div>
                  <div style={{textAlign: "right", color: "var(--text-muted)", marginTop: "10px"}}>
                      <div>Last check: {lastCheck}</div>
                      <div>Checked every 1.5s</div>
                  </div>
              </div>

              <div className="analytics-grid" style={{marginTop: "20px"}}>
                  <div className="analytics-card glass-card-hover" style={{gridColumn: "span 3"}}>
                      <div className="card-header">
                          <span className="card-icon">⚡</span>
                          <h4>Response Time (Last Session)</h4>
                      </div>
                      <div style={{display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "20px", marginTop: "10px"}}>
                          <div style={{textAlign: "center", padding: "15px", background: "rgba(0,0,0,0.2)", borderRadius: "4px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: "var(--status-blue)"}}>{avg} ms</div>
                              <div style={{color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem"}}>Average</div>
                          </div>
                          <div style={{textAlign: "center", padding: "15px", background: "rgba(0,0,0,0.2)", borderRadius: "4px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: "var(--status-green)"}}>{min} ms</div>
                              <div style={{color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem"}}>Minimum</div>
                          </div>
                          <div style={{textAlign: "center", padding: "15px", background: "rgba(0,0,0,0.2)", borderRadius: "4px"}}>
                              <div style={{fontSize: "2rem", fontWeight: "bold", color: "var(--status-red)"}}>{max} ms</div>
                              <div style={{color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.75rem"}}>Maximum</div>
                          </div>
                      </div>
                  </div>
              </div>

              <div className="analytics-grid" style={{marginTop: "20px", gridTemplateColumns: "repeat(4, 1fr)"}}>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Current Session</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Last 24h (Est.)</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Last 30 Days (Est.)</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
                  <div className="analytics-card glass-card-hover">
                      <h4 style={{margin: "0 0 10px 0", fontSize: "0.9rem", color: "var(--text-muted)"}}>Last 365 Days (Est.)</h4>
                      <div style={{fontSize: "1.8rem", fontWeight: "bold"}}>{uptimePercent}%</div>
                      <div style={{fontSize: "0.75rem", color: down ? "var(--status-red)" : (isSlow ? "var(--status-orange)" : "var(--status-green)")}}>
                          {down ? "Ongoing Incident" : (isSlow ? "Performance Issue" : "0 Incidents")}
                      </div>
                  </div>
              </div>

              <div className="up-widget glass-widget" style={{marginTop: "20px"}}>
                  <div className="card-header">
                      <h4>Response Time History</h4>
                      <span className="text-muted" style={{fontSize: "0.8rem"}}>Last {history.length} checks</span>
                  </div>
                  <div style={{padding: "20px", display: "flex", justifyContent: "center"}}>
                       <Sparkline history={history} width={800} height={200} isDegraded={down} />
                  </div>
              </div>

              <div className="up-widget glass-widget" style={{marginTop: "20px"}}>
                  <h4>Latest Incidents</h4>
                  {down ? (
                      <table style={{width: "100%", textAlign: "left", borderCollapse: "collapse", marginTop: "10px"}}>
                          <thead>
                              <tr style={{borderBottom: "1px solid rgba(255,255,255,0.1)"}}>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: 'uppercase'}}>Status</th>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: 'uppercase'}}>Root Cause</th>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: 'uppercase'}}>Started</th>
                                  <th style={{padding: "10px", color: "var(--text-muted)", fontSize: "0.8rem", textTransform: 'uppercase'}}>Duration</th>
                              </tr>
                          </thead>
                          <tbody>
                              <tr>
                                  <td style={{padding: "10px", color: down ? (is404 ? "var(--status-red)" : "var(--status-red)") : "var(--status-green)", fontWeight: "bold"}}>
                                      {is404 ? "404 Error" : "Down"}
                                  </td>
                                  <td style={{padding: "10px"}}>{status}</td>
                                  <td style={{padding: "10px"}}>{lastCheck}</td>
                                  <td style={{padding: "10px", color: "var(--status-red)"}}>Ongoing...</td>
                              </tr>
                          </tbody>
                      </table>
                  ) : isSlow ? (
                      <div className="up-empty-state" style={{border: "none", background: "transparent", padding: "20px"}}>
                          <p style={{color: "var(--status-orange)"}}>⚠️ High latency detected. Site is responding but slowly.</p>
                      </div>
                  ) : (
                      <div className="up-empty-state" style={{border: "none", background: "transparent", padding: "20px"}}>
                          <p style={{color: "var(--status-green)"}}>✅ No active incidents in the current session.</p>
                      </div>
                  )}
              </div>
          </div>
      );
  };

  const renderContent = () => {
    if (selectedMonitor) {
        return <MonitorDetailView target={selectedMonitor} />;
    }

    if (activeTab === "monitoring") {
      const displayTargets = getFilteredTargets();
      return (
        <div className="analytics-grid" style={{marginTop: "20px"}}>
          {displayTargets.length === 0 ? (
            <div className="up-empty-state" style={{gridColumn: "1 / -1"}}>
              <p>No monitors found matching your criteria.</p>
            </div>
          ) : (
            displayTargets.map((target) => {
              const history = data.histories[target] || [];
              let latency = data.current_latencies[target] || 0;
              if (latency === 0 && history.length > 0) {
                  latency = history[history.length - 1];
              }

              const status = data.status_messages[target] || "Idle";
              const down = isTargetDown(status, latency);
              
              const is404 = status.includes("NOT FOUND");
              const isProtected = isProbeBlockedStatus(status);
              const isTlsIssue = isTlsIssueStatus(status);
              const isSlow = !down && (status.includes("WARNING") || latency > 2000);

              let statusLabel = "Operational";
              let statusBadgeColor = "var(--status-green)";
              let statusBgColor = "rgba(16, 185, 129, 0.15)";

              if (is404) {
                  statusLabel = "404 Not Found";
                  statusBadgeColor = "var(--status-red)";
                  statusBgColor = "rgba(239, 68, 68, 0.15)";
             } else if (isTlsIssue) {
              statusLabel = "TLS ERROR";
              statusBadgeColor = "var(--status-tls)";
              statusBgColor = "rgba(244, 63, 94, 0.15)";
             } else if (isProtected) {
              statusLabel = "PROBE BLOCKED";
              statusBadgeColor = "var(--status-blue)";
              statusBgColor = "rgba(6, 182, 212, 0.15)";
             } else if (down) {
              const upperStatus = status.toUpperCase();
              if (upperStatus.includes("TIMEOUT")) {
                statusLabel = "TIMEOUT";
              } else if (upperStatus.includes("CRITICAL") || upperStatus.includes("PATTERN")) {
                statusLabel = "CRITICAL";
              } else if (upperStatus.includes("REFUSED")) {
                statusLabel = "UNREACHABLE";
              } else {
                statusLabel = "DOWN";
              }
              statusBadgeColor = "var(--status-red)";
              statusBgColor = "rgba(239, 68, 68, 0.15)";
              } else {
                  if (isSlow) {
                      statusLabel = "SLOW RESPONSE";
                      statusBadgeColor = "var(--status-orange)";
                      statusBgColor = "rgba(245, 158, 11, 0.15)";
                  } else if (status.includes("Learning")) {
                      statusLabel = "Learning Baseline";
                      statusBadgeColor = "var(--status-blue)";
                      statusBgColor = "rgba(6, 182, 212, 0.15)";
                  } else if (status.includes("Unstable")) {
                      statusLabel = "Unstable";
                      statusBadgeColor = "var(--status-orange)";
                      statusBgColor = "rgba(245, 158, 11, 0.15)";
                  }
              }

              return (
                <div 
                  key={target} 
                  className="analytics-card glass-card-hover" 
                  onClick={() => setSelectedMonitor(target)} 
                  style={{cursor: "pointer", position: "relative", overflow: "hidden"}}
                >
                    <div style={{
                        position: "absolute", top: 0, left: 0, bottom: 0, width: "4px", 
                        background: statusBadgeColor
                    }}></div>

                    <div className="monitor-card-header" style={{paddingLeft: "12px"}}>
                        <div className="monitor-card-title">
                            <span style={{fontSize: "0.7rem", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px"}}>Endpoint</span>
                            <span className="monitor-card-url" title={target}>
                                {target.replace(/^https?:\/\//, '')}
                            </span>
                        </div>
                        
                        <div className="up-status-badge" style={{
                            background: statusBgColor,
                            borderColor: statusBadgeColor,
                            color: statusBadgeColor,
                            fontSize: "0.65rem",
                            padding: "4px 8px",
                            whiteSpace: "nowrap"
                        }}>
                            {statusLabel}
                        </div>
                    </div>

                    <div className="monitor-chart-wrapper">
                        <Sparkline history={history} width={400} height={70} isDegraded={down} />
                    </div>

                    <div className="card-body" style={{paddingTop: "5px", paddingLeft: "12px", paddingRight: "12px", paddingBottom: "15px"}}>
                        <div className="monitor-card-metrics">
                            <div className="metric-box">
                                <span className="metric-label">Latency</span>
                                <span className="metric-value" style={{color: latency > 1000 ? "var(--status-orange)" : "white"}}>
                                    {latency.toFixed(0)} <span style={{fontSize: "0.8rem", color: "var(--text-muted)"}}>ms</span>
                                </span>
                            </div>
                            <div className="metric-box" style={{textAlign: "right"}}>
                                <span className="metric-label">Last Check</span>
                                <span style={{fontSize: "0.9rem", color: "var(--text-main)", fontWeight: "600"}}>
                                    {new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'})}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
              );
            })
          )}
        </div>
      );
    } else if (activeTab === "incidents") {
      const incidents = getIncidentTargets();
      const filteredIncidents = incidents.filter((target) => {
        const status = data.status_messages[target] || data.current_statuses?.[target] || "";
        const matchesSearch = target.toLowerCase().includes(incidentSearchTerm.toLowerCase().trim());
        const matchesType =
          incidentTypeFilter === "all" ||
          (incidentTypeFilter === "down" && isUnreachableStatus(status)) ||
          (incidentTypeFilter === "timeout" && isTimeoutStatus(status)) ||
          (incidentTypeFilter === "other-4xx" && isOther4xxStatus(status)) ||
          (incidentTypeFilter === "probe-blocked" && isProbeBlockedStatus(status)) ||
          (incidentTypeFilter === "tls-error" && isTlsIssueStatus(status));
        return matchesSearch && matchesType;
      });
      const probeBlockedCount = incidents.filter((target) => {
        const status = data.status_messages[target] || data.current_statuses?.[target] || "";
        return isProbeBlockedStatus(status);
      }).length;
      const tlsIssueCount = incidents.filter((target) => {
        const status = data.status_messages[target] || data.current_statuses?.[target] || "";
        return isTlsIssueStatus(status);
      }).length;
      const downIncidentCount = incidents.filter((target) => {
        const status = data.status_messages[target] || data.current_statuses?.[target] || "";
        return isUnreachableStatus(status);
      }).length;
      const timeoutIncidentCount = incidents.filter((target) => {
        const status = data.status_messages[target] || data.current_statuses?.[target] || "";
        return isTimeoutStatus(status);
      }).length;
      const other4xxIncidentCount = incidents.filter((target) => {
        const status = data.status_messages[target] || data.current_statuses?.[target] || "";
        return isOther4xxStatus(status);
      }).length;

      return (
        <div className="up-monitors-list">
          {incidents.length === 0 ? (
            <div className="up-empty-state" style={{borderColor: "var(--status-blue)"}}>
              <p>Great! No incidents detected.</p>
            </div>
          ) : (
            <>
              <div className="up-widget" style={{marginBottom: "20px", borderLeft: "4px solid var(--status-red)"}}>
                <h4 style={{color: "white", marginBottom: "5px"}}>Active Incidents</h4>
                <p style={{fontSize: "0.9rem", color: "var(--text-muted)"}}>
                  {filteredIncidents.length} of {incidents.length} monitor(s) currently reporting issues.
                </p>
                <div className="incident-filter-row">
                  <button
                    className={`incident-filter-chip ${incidentTypeFilter === "all" ? "active" : ""}`}
                    onClick={() => setIncidentTypeFilter("all")}
                  >
                    All ({incidents.length})
                  </button>
                  <button
                    className={`incident-filter-chip ${incidentTypeFilter === "down" ? "active" : ""}`}
                    onClick={() => setIncidentTypeFilter("down")}
                  >
                    Unreachable ({downIncidentCount})
                  </button>
                  <button
                    className={`incident-filter-chip ${incidentTypeFilter === "timeout" ? "active" : ""}`}
                    onClick={() => setIncidentTypeFilter("timeout")}
                  >
                    Timeout ({timeoutIncidentCount})
                  </button>
                  <button
                    className={`incident-filter-chip ${incidentTypeFilter === "other-4xx" ? "active" : ""}`}
                    onClick={() => setIncidentTypeFilter("other-4xx")}
                  >
                    Other 4XX ({other4xxIncidentCount})
                  </button>
                  <button
                    className={`incident-filter-chip probe ${incidentTypeFilter === "probe-blocked" ? "active" : ""}`}
                    onClick={() => setIncidentTypeFilter("probe-blocked")}
                  >
                    Probe Blocked ({probeBlockedCount})
                  </button>
                  <button
                    className={`incident-filter-chip tls ${incidentTypeFilter === "tls-error" ? "active" : ""}`}
                    onClick={() => setIncidentTypeFilter("tls-error")}
                  >
                    TLS Error ({tlsIssueCount})
                  </button>
                </div>
              </div>
              {filteredIncidents.length === 0 ? (
                <div className="up-empty-state up-empty-state-compact" style={{borderColor: "rgba(239, 68, 68, 0.35)"}}>
                  <p>No active incidents match this search or filter.</p>
                </div>
              ) : filteredIncidents.map((target) => {
                const status = data.status_messages[target] || data.current_statuses?.[target] || "";
                const latency = data.current_latencies[target] || 0;
                const is404 = status && status.includes("NOT FOUND");
                const isProbeBlocked = isProbeBlockedStatus(status);
                const isTlsIssue = isTlsIssueStatus(status);
                
                return (
                  <div
                    key={target}
                    className={`up-monitor-row down ${is404 ? 'row-404' : ''}`}
                    style={{ borderLeft: `4px solid ${isProbeBlocked ? "var(--status-blue)" : (isTlsIssue ? "var(--status-tls)" : "var(--status-red)")}` }}
                  >
                    <div className="up-status-icon">
                      <div className={`indicator ${isProbeBlocked ? "blue" : (isTlsIssue ? "tls" : "red")}`}></div>
                    </div>
                    <div className="up-monitor-info">
                      <div className="up-url">{target}</div>
                      <div className="up-type" style={{color: isProbeBlocked ? "var(--status-blue)" : (isTlsIssue ? "var(--status-tls)" : "var(--status-red)")}}>
                          {isProbeBlocked ? "PROBE BLOCKED" : (isTlsIssue ? "CERTIFICATE ISSUE" : (is404 ? "404 Page Not Found" : (latency > 3000 ? `CRITICAL LAG (${latency.toFixed(0)}ms)` : status)))}
                      </div>
                    </div>
                    <div className="up-monitor-uptime">
                      <span className="time-ago">{isProbeBlocked ? "Protected Edge" : (isTlsIssue ? "Certificate Issue" : "Ongoing")}</span>
                    </div>
                  </div>
                );
              })}
            </>
          )}
        </div>
      );
    }
  };

  const getOverallUptime = () => {
      let totalChecks = 0;
      let upChecks = 0;

      Object.values(data.histories).forEach(history => {
          totalChecks += history.length;
          upChecks += history.filter(h => h > 0).length;
      });

      if (totalChecks === 0) return "N/A";
      return ((upChecks / totalChecks) * 100).toFixed(2) + "%";
  };

  return (
    <div className="up-dashboard">
      <aside className="up-sidebar">
        <div className="up-sidebar-header">
          <h2>CyberGuard</h2>
          <div className={`up-status-badge ${isMonitoring ? "live" : "idle"}`}>
            {isMonitoring ? "● System Active" : "○ System Idle"}
          </div>
        </div>

        <nav className="up-nav">
          <div 
            className={`nav-item ${activeTab === "monitoring" ? "active" : ""}`}
            onClick={() => { setActiveTab("monitoring"); setSelectedMonitor(null); }}
          >
            Monitoring
          </div>
          <div 
            className={`nav-item ${activeTab === "incidents" ? "acti ve" : ""}`}
            onClick={() => { setActiveTab("incidents"); setSelectedMonitor(null); }}
          >
            Incidents
          </div>
        </nav>

     <div className="up-add-monitor">
        <div className="up-add-monitor-heading">Add New Monitor</div>
        <div className="up-input-group">
          <input 
              type="text" 
              value={url} 
              onChange={(e) => setUrl(e.target.value)} 
              disabled={isMonitoring || isLoading} 
              placeholder="https://example.com"
              autoComplete="off"
            />
        </div>

        <label className={`up-protection-card ${behindProtection ? "active" : ""} ${(isMonitoring || isLoading) ? "disabled" : ""}`}>
          <input
            type="checkbox"
            checked={behindProtection}
            onChange={(e) => setBehindProtection(e.target.checked)}
            disabled={isMonitoring || isLoading}
          />
          <span className="up-protection-switch" aria-hidden="true">
            <span className="up-protection-knob"></span>
          </span>
          <span className="up-protection-copy">
            <span className="up-protection-kicker">Traffic Profile</span>
            <span className="up-protection-title">Behind CDN / VPN / WAF</span>
            <span className="up-protection-desc">Enable this for Cloudflare, reverse proxies, challenge pages, or other protected edges.</span>
          </span>
        </label>

        <div className="up-monitor-actions">
          {!isMonitoring ? (
            <>
                {data.targets.length > 0 ? (
                     <button className="up-btn-resume" onClick={handleResume} disabled={isLoading}>Resume Monitoring</button>
                ) : (
                    <button className="up-btn-green" onClick={handleStart} disabled={isLoading || !url}>
                        {isLoading ? "Starting..." : "Start Monitoring"}
                    </button>
                )}
                <button className="up-btn-gray" onClick={handleClear}>Clear</button>
            </>
          ) : (
              <button className="up-btn-red" onClick={handleStop}>Stop</button>
          )}
        </div>
    </div>
      </aside>

      <main className="up-main">
        <header className="up-header">
          <div style={{ display: "flex", alignItems: "center", gap: "15px" }}>
              <h3 style={{textTransform: "capitalize", margin: 0}}>{selectedMonitor ? "Monitor Details" : activeTab.replace("_", " ")}</h3>
              {!selectedMonitor && activeTab === "monitoring" && (
                  <span style={{fontSize: "0.8rem", color: "var(--text-muted)"}}>({data.targets.length})</span>
              )}
          </div>
          
          <div className="up-actions">
            {!selectedMonitor && activeTab === "monitoring" && data.targets.length > 0 && (
                <button onClick={handleGlobalMonitoringReport} className="up-btn-blue" style={{marginRight: "10px"}}>
                    📊 Global Report
                </button>
            )}

            {activeTab === "monitoring" && !selectedMonitor && (
              <>
                <input 
                  type="text" 
                  placeholder="Search monitors..." 
                  className="up-search" 
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  autoComplete="off"
                />
                <div style={{ position: "relative" }}>
                  <button 
                    className="up-filter-btn" 
                    onClick={() => setShowFilterDropdown(!showFilterDropdown)}
                  >
                    {filterStatus === "all" ? "Filter" : filterStatus} ▼
                  </button>
                  {showFilterDropdown && (
                    <div style={{
                      position: "absolute", top: "100%", right: 0, marginTop: "5px", 
                      background: "var(--bg-panel)", border: "1px solid var(--border-color)", 
                      borderRadius: "6px", width: "120px", boxShadow: "0 4px 12px rgba(0,0,0,0.8)",
                      zIndex: 9999, color: "var(--text-main)"
                    }}>
                      <div onClick={() => { setFilterStatus("all"); setShowFilterDropdown(false); }} style={{padding: "8px 12px", cursor: "pointer", color: filterStatus === "all" ? "var(--status-blue)" : "var(--text-main)", fontSize: "0.9rem"}}>All</div>
                      <div onClick={() => { setFilterStatus("up"); setShowFilterDropdown(false); }} style={{padding: "8px 12px", cursor: "pointer", color: filterStatus === "up" ? "var(--status-blue)" : "var(--text-main)", fontSize: "0.9rem"}}>Up</div>
                      <div onClick={() => { setFilterStatus("down"); setShowFilterDropdown(false); }} style={{padding: "8px 12px", cursor: "pointer", color: filterStatus === "down" ? "var(--status-blue)" : "var(--text-main)", fontSize: "0.9rem"}}>Down</div>
                    </div>
                  )}
                </div>
              </>
            )}
            {activeTab === "incidents" && !selectedMonitor && (
              <div className="up-search-group">
                <input
                  type="text"
                  placeholder="Search incident subdomain..."
                  className="up-search up-search-incidents"
                  value={incidentSearchTerm}
                  onChange={(e) => setIncidentSearchTerm(e.target.value)}
                  autoComplete="off"
                />
              </div>
            )}
          </div>
        </header>

        {renderContent()}
      </main>

      {activeTab === "monitoring" && !selectedMonitor && (
        <aside className="up-right-panel">
          <div className="up-widget current-status">
            <h4>Current status</h4>
            <div className="status-grid">
              {(() => {
                  let down = 0;
                  let up = 0;
                  data.targets.forEach(t => {
    if(isTargetDown(data.current_statuses[t], data.current_latencies[t])) down++;
    else up++;
});
                  return (
                      <>
                          <div className="status-item">
                              <span className="label">Down</span>
                              <span className="val red">{down}</span>
                          </div>
                          <div className="status-item">
                              <span className="label">Up</span>
                              <span className="val green">{up}</span>
                          </div>
                          <div className="status-item">
                              <span className="label">Paused</span>
                              <span className="val gray">{0}</span>
                          </div>
                      </>
                  )
              })()}
            </div>
          </div>

          <div className="up-widget last-hours">
            <h4>Last 24 hours</h4>
            <div className="stat-row">
              <span className="lbl">Overall uptime</span>
              <span className="val">{getOverallUptime()}</span>
            </div>
            <div className="stat-row">
              <span className="lbl">Incidents</span>
              <span className="val">{getIncidentTargets().length}</span>
            </div>
            <div className="stat-row">
              <span className="lbl">Without incid.</span>
              <span className="val">{Math.max(0, data.targets.length - getIncidentTargets().length)}</span>
            </div>
            <div className="stat-row">
              <span className="lbl">Affected mon.</span>
              <span className="val">{getIncidentTargets().length}</span>
            </div>
          </div>
          
          <div className="up-footer-nav">
            <button onClick={onBack} className="back-btn">← Back to Dashboard</button>
          </div>
        </aside>
      )}

      {/* PASSWORD MODAL */}
      <PasswordModal 
        isOpen={isPwdModalOpen} 
        onClose={() => setIsPwdModalOpen(false)} 
        onSubmit={downloadReportWithPassword}
        title="Secure Monitoring Report"
        username={username}
      />

      {/* SUCCESS MODAL */}
      <SuccessModal 
        isOpen={showSuccessModal} 
        onClose={() => setShowSuccessModal(false)}
        targetUrl={newlyAddedUrl}
      />
    </div>
  );
};

// ================= LANDING PAGE COMPONENT =================
const LandingPage = ({ onLogin, onRegister }) => {
  const scrollToSection = (id) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="landing-page">
      <div className="glow-orb orb-1"></div>
      <div className="glow-orb orb-2"></div>

      <nav className="landing-nav">
        <div className="brand">
          Cyber<span>Guard</span>
        </div>
        <div className="nav-actions">
          <a 
            href="#contact" 
            onClick={(e) => { e.preventDefault(); scrollToSection('contact'); }} 
            className="btn-nav contact"
          >
            Contact Us
          </a>
          <button onClick={onLogin} className="btn-nav login">
            Login
          </button>
          <button onClick={onRegister} className="btn-nav register">
            Register
          </button>
        </div>
      </nav>

      <header className="hero-section">
        <h1 className="hero-title">
          Next-Generation Domain
          <br /> Monitoring & Detection
        </h1>
        <p className="hero-subtitle">
          Unify automated domain intelligence with manual asset governance. Secure your infrastructure with  
          real-time anomaly detection and comprehensive risk reporting.
        </p>
        <div className="cta-group">
            <button 
                onClick={() => scrollToSection('features')} 
                className="btn-large btn-secondary-large" 
                style={{ 
                    background: 'transparent', 
                    border: '1px solid var(--status-blue)',
                    color: 'var(--status-blue)',
                    padding: '16px 48px',
                    fontSize: '1.1rem',
                    fontWeight: '700',
                    cursor: 'pointer',
                    textTransform: 'uppercase',
                    letterSpacing: '1px',
                    borderRadius: '2px',
                    transition: '0.2s'
                }}
                onMouseEnter={(e) => {
                    e.target.style.background = 'rgba(6, 182, 212, 0.1)';
                    e.target.style.color = 'white';
                }}
                onMouseLeave={(e) => {
                    e.target.style.background = 'transparent';
                    e.target.style.color = 'var(--status-blue)';
                }}
            >
                Learn More
            </button>
        </div>
      </header>

      <section id="features" className="features-section">
        <div className="section-header">
          <h2>System Capabilities</h2>
          <p>Everything you need to manage your digital presence.</p>
        </div>
        <div className="cards-grid">
          <div className="feature-card">
            <div className="card-icon">📡</div>
            <h3>Auto-Tracking</h3>
            <p>
              Automatically tracks your domain's status, DNS records, and registration information.
            </p>
          </div>
          <div className="feature-card">
            <div className="card-icon">📝</div>
            <h3>Manual Asset Mgmt</h3>
            <p>
              Allows you to manually enter ownership details and infrastructure information.
            </p>
          </div>
          <div className="feature-card">
            <div className="card-icon">📊</div>
            <h3>Risk Intelligence</h3>
            <p>
              Calculates a risk score based on expiration dates and security checklist status.
            </p>
          </div>
          
          <div className="feature-card">
            <div className="card-icon">⚡</div>
            <h3>Real-Time Monitoring</h3>
            <p>
              Continuously checks if your website is online and measures its response speed.
            </p>
          </div>
          <div className="feature-card">
            <div className="card-icon">🔒</div>
            <h3>Secure Reports</h3>
            <p>
              Generates password-protected PDF reports for your records and compliance needs.
            </p>
          </div>
          <div className="feature-card">
            <div className="card-icon">🚨</div>
            <h3>Incident Response</h3>
            <p>
              Logs downtime incidents and sends alerts when services go down.
            </p>
          </div>
        </div>
      </section>

      <section id="contact" className="contact-section">
        <div className="section-header">
          <h2>Contact Our Developers</h2>
          <p>Connect with the architects behind your digital defense.</p>
        </div>
        <div className="team-grid">
          <div className="team-card">
            <div className="avatar">HC</div>
            <div className="dev-name">Henon Chare</div>
           
            <a href="mailto:henonchare21@gmail.com" className="contact-link email-link">📧 henonchare21@gmail.com</a>
            <a href="tel:+251982049520" className="contact-link phone-link">📞 +251 98 204 9520</a>
            <a href="https://github.com/henon-chare" target="_blank" rel="noopener noreferrer" className="contact-link github-link">💻 henon-chare</a>
          </div>
          <div className="team-card">
            <div className="avatar">BT</div>
            <div className="dev-name">Biniyam Temesgen</div>
            
            <a href="mailto:biniyamtemesgen40@gmail.com" className="contact-link email-link">📧 biniyamtemesgen40@gmail.com</a>
            <a href="tel:+251985957185" className="contact-link phone-link">📞 +251 98 595 7185</a>
            <a href="https://github.com/Bi-ni-yam" target="_blank" rel="noopener noreferrer" className="contact-link github-link">💻 Bi-ni-yam</a>
          </div>
          <div className="team-card">
            <div className="avatar">MK</div>
            <div className="dev-name">Mikiyas Kindie</div>
            
            <a href="mailto:mikiyaskindie6@gmail.com" className="contact-link email-link">📧 mikiyaskindie6@gmail.com</a>
            <a href="tel:+251948010770" className="contact-link phone-link">📞 +251 94 801 0770</a>
            <a href="https://github.com/mikii122129" target="_blank" rel="noopener noreferrer" className="contact-link github-link">💻 mikii122129</a>
          </div>
          <div className="team-card">
            <div className="avatar">AM</div>
            <div className="dev-name">Abinet Melkamu</div>
           
            <a href="mailto:instaman2124@gmail.com" className="contact-link email-link">📧 instaman2124@gmail.com</a>
            <a href="tel:+251923248825" className="contact-link phone-link">📞 +251 92 324 8825</a>
            <a href="https://github.com/abinetbdu" target="_blank" rel="noopener noreferrer" className="contact-link github-link">💻 abinetbdu</a>
          </div>
        </div>
      </section>

      <footer className="landing-footer">
        &copy; 2026 Domain Monitoring and Detecting System. All rights reserved.
      </footer>
    </div>
  );
};

// ================= DETECTION DASHBOARD COMPONENT =================
const DetectionDashboard = ({ onBack, token }) => {
  const [targetUrl, setTargetUrl] = useState("");
  const [history, setHistory] = useState([]);
  const [scanResults, setScanResults] = useState(null);
  const [currentView, setCurrentView] = useState("scanner");
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanProgress, setScanProgress] = useState("Ready to start live detection.");
  const [showClearHistoryConfirm, setShowClearHistoryConfirm] = useState(false);
  const [listenHost, setListenHost] = useState("0.0.0.0");
  const [listenPort, setListenPort] = useState("9999");
  const [activeLiveScanId, setActiveLiveScanId] = useState(null);

  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/detection/history`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) {
        setHistory(Array.isArray(data) ? data : []);
      }
    } catch (error) {
      console.error(error);
      setScanError(`Cannot reach ${API_BASE_URL}. Check that the backend is running and reachable from this browser.`);
    }
  }, [token]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const pollScanResults = useCallback(async (scanId, { live = false } = {}) => {
    const deadline = Date.now() + 300000;

    while (Date.now() < deadline) {
      const res = await fetch(`${API_BASE_URL}/detection/findings/${scanId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Failed to load scan results");
      }

      setScanProgress(data.policy_note || "Processing scan");
      setScanResults(data);

      if (live && ["listening", "running", "stopping"].includes(data.status)) {
        return data;
      }

      if (data.status === "completed" || data.status === "failed") {
        return data;
      }

      await new Promise((resolve) => setTimeout(resolve, 1500));
    }

    throw new Error("Scan is still running. Check History in a moment.");
  }, [token]);

  const refreshActiveScan = useCallback(async () => {
    if (!scanResults?.scan_id) {
      return;
    }
    setIsScanning(true);
    setScanError("");
    try {
      const res = await fetch(`${API_BASE_URL}/detection/findings/${scanResults.scan_id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to refresh scan");
      }
      setScanResults(data);
      setScanProgress(data.policy_note || "Scan status refreshed");
      await fetchHistory();
      if (data.status === "completed" && window.showToast) {
        window.showToast("Detection scan complete", "success");
      }
    } catch (error) {
      console.error(error);
      setScanError(error.message || "Failed to refresh scan");
    } finally {
      setIsScanning(false);
    }
  }, [fetchHistory, scanResults?.scan_id, token]);

  const handleStartScan = async () => {
    const cleanTarget = targetUrl.trim();
    if (!cleanTarget) {
      setScanError("Enter a target URL.");
      return;
    }
    if (!/^https?:\/\//i.test(cleanTarget)) {
      setScanError("Target URL must start with http:// or https://");
      return;
    }

    setIsScanning(true);
    setScanError("");
    setScanResults(null);
    setCurrentView("scanner");
    const portNumber = Number(listenPort);
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
      setScanError("Listen port must be between 1 and 65535.");
      setIsScanning(false);
      return;
    }

    setScanProgress("Starting live receiver...");

    try {
      const res = await fetch(`${API_BASE_URL}/detection/live/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          target_url: cleanTarget,
          listen_host: listenHost.trim() || "0.0.0.0",
          listen_port: portNumber,
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Failed to start scan");
      }

      setScanResults(data);
      setActiveLiveScanId(data.scan_id);
      setScanProgress(data.metrics?.progress_message || "Live detection listener started");
      const liveResults = await pollScanResults(data.scan_id, { live: true });
      setScanResults(liveResults);
      setScanProgress(liveResults.policy_note || "Live detection is listening for VM traffic");
      await fetchHistory();
      if (window.showToast) window.showToast("Live detection started", "success");
    } catch (error) {
      console.error(error);
      const message = error?.message === "Failed to fetch"
        ? `Cannot reach ${API_BASE_URL}. Start the FastAPI backend or set REACT_APP_API_BASE_URL.`
        : (error.message || "Scan failed");
      setScanError(message);
      setScanProgress(message);
      if (window.showToast) window.showToast(message, "error");
    } finally {
      setIsScanning(false);
    }
  };

  const handleAnalyzeSavedTraffic = async () => {
    const cleanTarget = targetUrl.trim();
    if (!cleanTarget) {
      setScanError("Enter the same target URL used by receiver.py.");
      return;
    }
    if (!/^https?:\/\//i.test(cleanTarget)) {
      setScanError("Target URL must start with http:// or https://");
      return;
    }

    setIsScanning(true);
    setScanError("");
    setScanResults(null);
    setCurrentView("scanner");
    setScanProgress("Analyzing saved receiver traffic...");

    try {
      const res = await fetch(`${API_BASE_URL}/detection/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ target_url: cleanTarget }),
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Failed to analyze saved traffic");
      }

      setScanResults(data);
      setScanProgress(data.metrics?.progress_message || "Saved traffic analysis started");
      const finalResults = await pollScanResults(data.scan_id);
      setScanResults(finalResults);
      setScanProgress(finalResults.policy_note || "Saved traffic analysis complete");
      setCurrentView("results");
      await fetchHistory();
      if (window.showToast) window.showToast("Saved receiver traffic analyzed", "success");
    } catch (error) {
      console.error(error);
      const message = error?.message === "Failed to fetch"
        ? `Cannot reach ${API_BASE_URL}. Start the FastAPI backend or set REACT_APP_API_BASE_URL.`
        : (error.message || "Saved traffic analysis failed");
      setScanError(message);
      setScanProgress(message);
      if (window.showToast) window.showToast(message, "error");
    } finally {
      setIsScanning(false);
    }
  };
  const analyzeSavedTrafficAction = handleAnalyzeSavedTraffic;

  const handleStopLiveDetection = async () => {
    const scanId = activeLiveScanId || scanResults?.scan_id;
    if (!scanId) {
      setScanError("No active live detection session to stop.");
      return;
    }
    setIsScanning(true);
    setScanError("");
    try {
      const res = await fetch(`${API_BASE_URL}/detection/live/stop/${scanId}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to stop live detection");
      }
      setScanProgress("Stop requested for live detection listener.");
      setActiveLiveScanId(null);
      await refreshActiveScan();
      await fetchHistory();
      if (window.showToast) window.showToast("Live detection stop requested", "success");
    } catch (error) {
      console.error(error);
      setScanError(error.message || "Failed to stop live detection");
    } finally {
      setIsScanning(false);
    }
  };

  const loadHistoricalScan = async (scanId) => {
    setIsScanning(true);
    setScanError("");
    try {
      const res = await fetch(`${API_BASE_URL}/detection/findings/${scanId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to load scan");
      }
      setScanResults(data);
      setScanProgress(data.policy_note || "Loaded historical scan");
      setCurrentView("results");
    } catch (error) {
      console.error(error);
      const message = error?.message === "Failed to fetch"
        ? `Cannot reach ${API_BASE_URL}. Start the FastAPI backend or set REACT_APP_API_BASE_URL.`
        : (error.message || "Failed to load historical scan");
      setScanError(message);
    } finally {
      setIsScanning(false);
    }
  };

  const handleClearHistory = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/detection/history`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to clear detection history");
      }
      setHistory([]);
      setScanResults(null);
      setCurrentView("history");
      setShowClearHistoryConfirm(false);
      setScanProgress("Detection history cleared.");
      if (window.showToast) window.showToast("Detection history cleared", "success");
    } catch (error) {
      console.error(error);
      if (window.showToast) window.showToast(error.message || "Failed to clear detection history", "error");
    }
  };

  const getSeverityColor = (severity = "info") => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "var(--status-red)";
      case "high":
        return "var(--status-orange)";
      case "warning":
        return "#facc15";
      default:
        return "var(--status-blue)";
    }
  };

  const resultHighlights = useMemo(() => {
    const findings = Array.isArray(scanResults?.findings) ? scanResults.findings : [];
    if (!scanResults) {
      return null;
    }

    const priority = { critical: 4, high: 3, warning: 2, info: 1 };
    const topFinding = findings.slice().sort((a, b) => {
      const severityGap = (priority[b.severity?.toLowerCase()] || 0) - (priority[a.severity?.toLowerCase()] || 0);
      if (severityGap !== 0) return severityGap;
      return (b.confidence || 0) - (a.confidence || 0);
    })[0] || null;

    const maliciousPredictions = Array.isArray(scanResults.metrics?.ml_predictions)
      ? scanResults.metrics.ml_predictions.filter((prediction) => prediction.is_malicious)
      : [];

    return {
      completionLabel: scanResults.status === "completed" ? "Detection Complete" : scanResults.status === "failed" ? "Detection Failed" : "Live Detection Active",
      completionColor: scanResults.status === "completed" ? "var(--status-green)" : scanResults.status === "failed" ? "var(--status-red)" : "var(--status-blue)",
      topFinding,
      maliciousPredictions,
      safeSummary: findings.length === 0 ? "No findings were recorded for this target." : `${findings.length} findings were recorded across the scan flow.`,
    };
  }, [scanResults]);

  return (
    <div className="up-main fade-in-content">
      <header className="up-header">
        <div>
          <h3>Live Threat Detection</h3>
          <p className="subtext">AI-assisted OWASP detection for Apache access-log traffic streamed from the VM.</p>
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button onClick={() => { setCurrentView("scanner"); setScanResults(null); }} className="btn-secondary-alert">
            Live Session
          </button>
          <button onClick={() => setCurrentView("history")} className="btn-secondary-alert">
            History
          </button>
          <button onClick={onBack} className="up-btn-gray">
            ← Back
          </button>
        </div>
      </header>

      {currentView === "scanner" && (
        <div className="up-widget">
          <h4>Live Receiver Configuration</h4>
          <div style={{ display: "flex", gap: "10px", marginTop: "10px", flexWrap: "wrap" }}>
            <input
              type="text"
              className="up-search"
              style={{ width: "100%", maxWidth: "560px" }}
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              disabled={isScanning}
            />
            <input
              type="text"
              className="up-search"
              style={{ width: "180px" }}
              value={listenHost}
              onChange={(e) => setListenHost(e.target.value)}
              placeholder="0.0.0.0"
              disabled={isScanning}
            />
            <input
              type="number"
              className="up-search"
              style={{ width: "130px" }}
              value={listenPort}
              onChange={(e) => setListenPort(e.target.value)}
              min="1"
              max="65535"
              disabled={isScanning}
            />
            <button onClick={handleStartScan} disabled={isScanning} className="up-btn-blue">
              {isScanning ? "Starting..." : "Start Live Detection"}
            </button>
            <button onClick={analyzeSavedTrafficAction} disabled={isScanning} className="btn-secondary-alert">
              Analyze Saved Traffic
            </button>
            {(activeLiveScanId || ["listening", "running"].includes(scanResults?.status)) && (
              <button onClick={handleStopLiveDetection} disabled={isScanning} className="btn-modal-danger">
                Stop Live Detection
              </button>
            )}
          </div>
          {scanError && (
            <div style={{ marginTop: "15px", color: "var(--status-red)", fontSize: "0.9rem" }}>
              {scanError}
            </div>
          )}
          {isScanning && (
            <div style={{ marginTop: "20px", color: "var(--status-blue)", display: "grid", gap: "8px" }}>
              <div style={{ color: "white", fontWeight: 700 }}>Live detection starting</div>
              <div>{scanProgress}</div>
              <div style={{ color: "var(--text-muted)", fontSize: "0.82rem" }}>
                The system is loading the trained model from `model.py` and classifying each Apache access-log line sent by the VM sender.
              </div>
              {Array.isArray(scanResults?.step_trace) && scanResults.step_trace.length > 0 && (
                <div style={{ display: "grid", gap: "6px", marginTop: "8px" }}>
                  {scanResults.step_trace.slice(-5).map((step, index) => (
                    <div key={`${step.step}-${index}`} style={{ color: "var(--text-muted)", fontSize: "0.82rem" }}>
                      {step.message}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {currentView === "history" && (
        <div className="up-widget">
          <div style={{ display: "flex", justifyContent: "space-between", gap: "12px", alignItems: "center", marginBottom: "15px", flexWrap: "wrap" }}>
            <h4 style={{ margin: 0 }}>Recent Scans</h4>
            <button onClick={() => setShowClearHistoryConfirm(true)} className="btn-secondary-alert" disabled={history.length === 0}>
              Clear History
            </button>
          </div>
          {history.length === 0 ? (
            <div style={{ color: "var(--text-muted)" }}>No scans yet.</div>
          ) : (
            <div style={{ display: "grid", gap: "12px" }}>
              {history.map((scan) => (
                <div
                  key={scan.id}
                  className="history-row-item interactive-item"
                  onClick={() => loadHistoricalScan(scan.id)}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: "16px",
                    padding: "14px",
                    border: "1px solid rgba(255,255,255,0.08)",
                    cursor: "pointer",
                    background: "rgba(255,255,255,0.02)",
                  }}
                >
                  <div>
                    <div style={{ color: "white", fontWeight: 700 }}>{scan.target_url}</div>
                    <div style={{ color: "var(--text-muted)", fontSize: "0.82rem" }}>
                      {new Date(scan.created_at).toLocaleString()} • {scan.findings_count} findings
                    </div>
                    {scan.progress_message && (
                      <div style={{ color: "var(--status-blue)", fontSize: "0.78rem", marginTop: "4px" }}>
                        {scan.progress_message}
                      </div>
                    )}
                  </div>
                  <div style={{ color: scan.risk_score > 0 ? "var(--status-red)" : "var(--status-green)", fontWeight: 700 }}>
                    {scan.status}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {currentView === "results" && scanResults && (
        <>
          <div className="up-widget" style={{ borderColor: "rgba(16, 185, 129, 0.25)", boxShadow: "0 0 20px rgba(16, 185, 129, 0.08)" }}>
            <h4>Detection Outcome</h4>
            <div style={{ display: "grid", gap: "8px" }}>
              <div style={{ color: resultHighlights?.completionColor || "white", fontSize: "1.35rem", fontWeight: 800 }}>
                {resultHighlights?.completionLabel || "Scan Complete"}
              </div>
              <div style={{ color: "white", fontWeight: 700 }}>
                {scanResults.policy_note || "The live detection session is ready."}
              </div>
              <div style={{ color: "var(--text-muted)" }}>
                {resultHighlights?.safeSummary}
              </div>
            </div>
            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginTop: "15px" }}>
                {["listening", "running"].includes(scanResults.status) && (
                <button onClick={refreshActiveScan} className="btn-secondary-alert" disabled={isScanning}>
                  {isScanning ? "Refreshing..." : "Refresh Status"}
                </button>
              )}
              {["listening", "running"].includes(scanResults.status) && (
                <button onClick={handleStopLiveDetection} className="btn-modal-danger" disabled={isScanning}>
                  Stop Live Detection
                </button>
              )}
              <button onClick={() => setCurrentView("history")} className="btn-secondary-alert">
                Open History
              </button>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "20px", marginBottom: "20px" }}>
            <div className="up-widget">
              <h4>Risk Score</h4>
              <div style={{ fontSize: "2.2rem", fontWeight: 800, color: scanResults.risk_score > 30 ? "var(--status-red)" : "var(--status-green)" }}>
                {scanResults.risk_score}
              </div>
            </div>
            <div className="up-widget">
              <h4>Total Findings</h4>
              <div style={{ fontSize: "2.2rem", fontWeight: 800, color: "white" }}>
                {Array.isArray(scanResults.findings) ? scanResults.findings.length : 0}
              </div>
            </div>
            <div className="up-widget">
              <h4>Status</h4>
              <div style={{ fontSize: "1.2rem", fontWeight: 800, color: resultHighlights?.completionColor || "white", textTransform: "uppercase" }}>
                {scanResults.status}
              </div>
            </div>
            <div className="up-widget">
              <h4>Model Source</h4>
              <div style={{ fontSize: "1rem", fontWeight: 700, color: "white", wordBreak: "break-word" }}>
                {scanResults.metrics?.model_source || "unknown"}
              </div>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "20px", marginBottom: "20px" }}>
            <div className="up-widget">
              <h4>Primary Highlight</h4>
              {resultHighlights?.topFinding ? (
                <>
                  <div style={{ color: "white", fontWeight: 700 }}>{resultHighlights.topFinding.title}</div>
                  <div style={{ color: getSeverityColor(resultHighlights.topFinding.severity), marginTop: "6px", fontWeight: 700 }}>
                    {resultHighlights.topFinding.severity} • {resultHighlights.topFinding.owasp}
                  </div>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.82rem", marginTop: "8px" }}>
                    Confidence {resultHighlights.topFinding.confidence}% at {resultHighlights.topFinding.location || "target surface"}
                  </div>
                </>
              ) : (
                <div style={{ color: "var(--status-green)", fontWeight: 700 }}>No highlighted vulnerability.</div>
              )}
            </div>
            <div className="up-widget">
              <h4>ML Signal</h4>
              {resultHighlights?.maliciousPredictions?.length ? (
                <>
                  <div style={{ color: "white", fontWeight: 700 }}>
                    {resultHighlights.maliciousPredictions.length} suspicious request pattern(s) flagged
                  </div>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.82rem", marginTop: "8px" }}>
                    Strongest label: {resultHighlights.maliciousPredictions[0].label} ({resultHighlights.maliciousPredictions[0].confidence}%)
                  </div>
                </>
              ) : (
                <div style={{ color: "var(--status-green)", fontWeight: 700 }}>No malicious ML signal recorded.</div>
              )}
            </div>
          </div>

          <div className="up-widget">
            <h4>Live Progress</h4>
            <div style={{ color: "white", fontWeight: 700 }}>{scanResults.policy_note || "Live detection ready"}</div>
            {Array.isArray(scanResults.step_trace) && scanResults.step_trace.length > 0 && (
              <div style={{ display: "grid", gap: "8px", marginTop: "12px" }}>
                {scanResults.step_trace.map((step, index) => (
                  <div key={`${step.step}-${index}`} style={{ color: "var(--text-muted)", fontSize: "0.82rem" }}>
                    {step.message}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="up-widget">
            <h4>ML Predictions</h4>
            {Array.isArray(scanResults.metrics?.ml_predictions) && scanResults.metrics.ml_predictions.length > 0 ? (
              <div style={{ display: "grid", gap: "10px" }}>
                {scanResults.metrics.ml_predictions.map((prediction, index) => (
                  <div key={`${prediction.request_text || prediction.label}-${index}`} style={{ padding: "12px", border: "1px solid rgba(255,255,255,0.08)", background: "rgba(255,255,255,0.02)" }}>
                    <div style={{ color: "white", fontWeight: 700 }}>
                      {prediction.label} ({prediction.confidence}%)
                    </div>
                    <div style={{ color: "var(--text-muted)", fontSize: "0.82rem", wordBreak: "break-all", marginTop: "4px" }}>
                      {prediction.request_text}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ color: "var(--text-muted)" }}>No ML predictions were returned for this scan.</div>
            )}
          </div>

          <div className="up-widget">
            <h4>Vulnerability Findings</h4>
            {!Array.isArray(scanResults.findings) || scanResults.findings.length === 0 ? (
              <div style={{ color: "var(--text-muted)" }}>No findings detected for this scan.</div>
            ) : (
              <div style={{ display: "grid", gap: "12px" }}>
                {scanResults.findings.map((finding, index) => (
                  <div key={`${finding.title}-${index}`} style={{ borderLeft: `4px solid ${getSeverityColor(finding.severity)}`, background: "rgba(255,255,255,0.02)", padding: "14px 16px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: "12px", flexWrap: "wrap" }}>
                      <strong style={{ color: "white" }}>{finding.title}</strong>
                      <span style={{ color: getSeverityColor(finding.severity), fontWeight: 700 }}>
                        {finding.severity}
                      </span>
                    </div>
                    <div style={{ color: "var(--text-muted)", fontSize: "0.82rem", marginTop: "6px" }}>
                      {finding.owasp} • Confidence {finding.confidence}%
                    </div>
                    <div style={{ color: "#dbe4f0", marginTop: "8px", lineHeight: 1.5 }}>
                      {finding.description}
                    </div>
                    {finding.location && (
                      <div style={{ color: "var(--status-blue)", fontSize: "0.82rem", marginTop: "8px", wordBreak: "break-all" }}>
                        {finding.location}
                      </div>
                    )}
                    {finding.evidence && (
                      <div style={{ color: "var(--text-muted)", fontSize: "0.8rem", marginTop: "8px", wordBreak: "break-word" }}>
                        Evidence: {finding.evidence}
                      </div>
                    )}
                    {finding.remediation && (
                      <div style={{ color: "white", fontSize: "0.82rem", marginTop: "8px" }}>
                        Remediation: {finding.remediation}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      <ConfirmModal
        isOpen={showClearHistoryConfirm}
        onClose={() => setShowClearHistoryConfirm(false)}
        onConfirm={handleClearHistory}
        title="Clear Detection History"
        message="Are you sure you want to permanently clear the saved detection scan history? This will delete stored scan results and findings until new scans are created."
      />
    </div>
  );
};

// ================= MAIN APP COMPONENT =================
function App() {
  
const ToastContainer = () => {
    const [toasts, setToasts] = useState([]);

    useEffect(() => {
        window.showToast = (message, type = "info") => {
            const id = Date.now();
            setToasts(prev => [...prev, { id, message, type }]);
            setTimeout(() => {
                setToasts(prev => prev.filter(t => t.id !== id));
            }, 4000);
        };
    }, []);

    return (
        <div className="toast-container">
            {toasts.map(toast => (
                <div key={toast.id} className={`toast ${toast.type}`}>
                    <div className="toast-icon">
                        {toast.type === 'success' ? '✅' : toast.type === 'error' ? '❌' : 'ℹ️'}
                    </div>
                    <div>{toast.message}</div>
                </div>
            ))}
        </div>
    );
};
  const [showLanding, setShowLanding] = useState(true);
  const [page, setPage] = useState("login");
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    token: "",
  });
 // ... existing code ...
  const [message, setMessage] = useState("");
  const [userLoggedIn, setUserLoggedIn] = useState(false);
  const [confirmPassword, setConfirmPassword] = useState(""); 

  const [authToken, setAuthToken] = useState(null); 
  const [selectedCard, setSelectedCard] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  
  // --- EXISTING STATE ---
  const [showPassword, setShowPassword] = useState(false);
  
  // --- NEW STATE: Independent visibility for Confirm Password ---
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const profileRef = useRef(null);
// ... existing code ...

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (profileRef.current && !profileRef.current.contains(event.target)) {
        setIsProfileOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    const path = window.location.pathname;
    if (path.startsWith("/reset-password/")) {
      const tokenFromUrl = path.split("/")[2];
      if (tokenFromUrl) {
        setFormData(prev => ({ ...prev, token: tokenFromUrl }));
        setPage("reset");
        setShowLanding(false);
      }
    }
  }, []);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("");
    if (page === "register" || page === "reset") {
      if (formData.password !== confirmPassword) {
        setMessage("Passwords do not match.");
        return;
      }
    }
    
    // SPECIFIC LOGIC FOR FORGOT PASSWORD BUTTON
    // Disable the button immediately when user clicks "Send Reset Email"
    if (page === "forgot") {
        setIsSubmitting(true);
    }

    let url = "";
    let body = {};
    if (page === "login") {
      url = "http://localhost:8000/login";
      body = { username: formData.username, password: formData.password };
    } else if (page === "register") {
      url = "http://localhost:8000/register";
      body = { username: formData.username, email: formData.email, password: formData.password };
    } else if (page === "forgot") {
      url = "http://localhost:8000/forgot-password";
      body = { email: formData.email };
    } else if (page === "reset") {
      url = "http://localhost:8000/reset-password";
      body = { token: formData.token, new_password: formData.password, username: formData.username };
    }
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.ok) {
        setMessage(data.message);
        if (page === "login") {
          if (data.access_token) {
            setAuthToken(data.access_token);
            localStorage.setItem('auth_token', data.access_token);
          }
          setUserLoggedIn(true);
          setSelectedCard(null);
          setShowLanding(false);
        } else if (page === "register") {
          setTimeout(() => { setPage("login"); setMessage("Registration successful! Please login."); }, 1500);
        } else if (page === "reset") {
          setTimeout(() => { setPage("login"); setMessage("Password reset successful! Please login."); }, 2000);
        }
        // NOTE: For "forgot" page, we leave isSubmitting as true.
        // The button stays disabled and displays "Sending..." while the success message is shown.
        // The user sees the success message and the flow effectively ends for that action.
      } else {
        // On error, we re-enable the button so the user can try again.
        setIsSubmitting(false);
        
        let errorMessage = "Error occurred";
        if (data.detail) {
          if (Array.isArray(data.detail)) {
            errorMessage = data.detail.map((err) => err.msg).join(", ");
          } else {
            errorMessage = data.detail;
          }
        } else {
          errorMessage = JSON.stringify(data);
        }
        setMessage(errorMessage);
      }
    } catch (err) {
      // On network error, re-enable the button.
      setIsSubmitting(false);
      setMessage("Server not reachable");
    }
  };

  // --- NEW LOGOUT HANDLER ---
  const handleLogout = () => {
     setUserLoggedIn(false); 
     setShowLanding(true);
     setAuthToken(null);
     localStorage.removeItem('auth_token');
     
     // Clear Monitoring Data on Logout
     const logoutScope = formData.username || "anonymous";
     localStorage.removeItem(`cyberguard_monitor_data_${logoutScope}`);
     localStorage.removeItem(`cyberguard_monitor_url_${logoutScope}`);
     localStorage.removeItem(`cyberguard_monitor_state_${logoutScope}`);
     localStorage.removeItem(`cyberguard_monitor_protection_${logoutScope}`);
     
     setIsProfileOpen(false);
  };

  const HomePage = () => {
    if (selectedCard === "monitoring") {
      return <MonitoringComponent onBack={() => setSelectedCard(null)} token={authToken} username={formData.username} />;
    }
    if (selectedCard === "domains") {
      return <DomainTrackingComponent onBack={() => setSelectedCard(null)} token={authToken} username={formData.username} />;
    }
    if (selectedCard === "detection") {
      return <DetectionDashboard onBack={() => setSelectedCard(null)} token={authToken} />;
    }
    if (selectedCard === "alerts") {
      return <AlertDashboardComponent onBack={() => setSelectedCard(null)} token={authToken} />;
    }
    return (
      <div className="dashboard">
        <header className="dashboard-header">
          <h1>CyberGuard</h1>
          
          <div className="profile-wrapper" ref={profileRef}>
            <div className="profile-trigger" onClick={() => setIsProfileOpen(!isProfileOpen)}>
                <div className="profile-icon-circle">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                        <circle cx="12" cy="7" r="4"></circle>
                    </svg>
                </div>
                <span className="profile-label">Profile</span>
                <span className="chevron">▼</span>
            </div>

            {isProfileOpen && (
                <div className="profile-dropdown">
                    <div className="profile-header">
                        <div className="avatar-large">
                           <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                                <circle cx="12" cy="7" r="4"></circle>
                            </svg>
                        </div>
                        <div className="user-info">
                            <h3>{formData.username || "User"}</h3>
                            <p>{formData.email || formData.username || "user@cyberguard.ai"}</p>
                        </div>
                    </div>
                    <div className="profile-divider"></div>
                    <div className="profile-stats">
                        <div className="stat-item">
                            <span className="stat-label">Status</span>
                            <span className="stat-value text-green">Active</span>
                        </div>
                        <div className="stat-item">
                            <span className="stat-label">Role</span>
                            <span className="stat-value">Admin</span>
                        </div>
                    </div>
                    <div className="profile-divider"></div>
                    {/* UPDATED: Use handleLogout */}
                    <button className="profile-logout-btn" onClick={handleLogout}>
                        Logout
                    </button>
                </div>
            )}
          </div>
        </header>
        <section className="hero">
          <h2>Security Operations Center</h2>
          <p>Monitor • Detect • Protect • Respond</p>
        </section>
        <section className="cards">
          <div className="card" onClick={() => setSelectedCard("monitoring")}>
            <span className="icon">🌐</span>
            <h3>Website Monitoring</h3>
            <p>Track uptime, response time, and anomalies in real time.</p>
          </div>
          <div className="card" onClick={() => setSelectedCard("domains")}>
            <span className="icon">🔍</span>
            <h3>Domain Tracking</h3>
            <p>Deep DNS inspection, WHOIS analysis, and domain reputation.</p>
          </div>
          <div className="card" onClick={() => setSelectedCard("detection")}>
            <span className="icon">🛡️</span>
            <h3>Threat Detection</h3>
            <p>Identify vulnerabilities and suspicious activities.</p>
          </div>
          <div className="card" onClick={() => setSelectedCard("alerts")}>
            <span className="icon">🚨</span>
            <h3>Alert Dashboard</h3>
            <p>Instant alerts for critical security events.</p>
          </div>
        </section>
      </div>
    );
  };

  if (showLanding) return <LandingPage 
    onLogin={() => { setShowLanding(false); setPage("login"); }} 
    onRegister={() => { setShowLanding(false); setPage("register"); }} 
  />;

  if (userLoggedIn) return (
      <>
        <HomePage />
        <ToastContainer />
      </>
  );

  return (
    <div className="app-auth">
      <div className="container">
        <h1>CyberGuard</h1>
        <div style={{ marginBottom: "20px", color: "#94a3b8", cursor: "pointer", textDecoration: "underline" }} onClick={() => setShowLanding(true)}>
          &larr; Back to Home
        </div>
        {message && <div className="message">{message}</div>}
        <form onSubmit={handleSubmit} className="form" autoComplete="off">
          {(page === "register" || page === "login") && (
            <input 
              type="text" 
              name="username" 
              placeholder="Username" 
              value={formData.username} 
              onChange={handleChange} 
              required 
              autoComplete="off" 
            />
          )}
          {(page === "register" || page === "forgot") && (
            <input 
              type="email" 
              name="email" 
              placeholder="Email" 
              value={formData.email} 
              onChange={handleChange} 
              required 
              autoComplete="off" 
            />
          )}
                    {/* ... Password Field (Leave this one as is) ... */}
          {(page === "login" || page === "register" || page === "reset") && (
            <div className="password-wrapper">
              <input 
                type={showPassword ? "text" : "password"} 
                name="password" 
                placeholder={page === "reset" ? "New Password" : "Password"} 
                value={formData.password} 
                onChange={handleChange} 
                required 
                autoComplete="new-password" 
              />
              <span className="eye-icon" onClick={() => setShowPassword(!showPassword)} role="button" tabIndex="0">{showPassword ? "🔐" : "🔓"}</span>
            </div>
          )}

          {/* ... Confirm Password Field (Updated below) ... */}
          {(page === "register" || page === "reset") && (
            <div className="password-wrapper">
              <input 
                // CHANGED: Use showConfirmPassword here
                type={showConfirmPassword ? "text" : "password"} 
                name="confirmPassword" 
                placeholder="Confirm Password" 
                value={confirmPassword} 
                onChange={(e) => setConfirmPassword(e.target.value)} 
                required 
                autoComplete="new-password" 
              />
              {/* CHANGED: Toggle showConfirmPassword here */}
              <span className="eye-icon" onClick={() => setShowConfirmPassword(!showConfirmPassword)} role="button" tabIndex="0">
                {showConfirmPassword ? "🔐" : "🔓"}
              </span>
            </div>
          )}
          {page === "reset" && (
            <>
              <input type="text" name="username" placeholder="Username" value={formData.username} onChange={handleChange} required autoComplete="off" />
              <input type="text" name="token" placeholder="Reset Token (Check Email)" value={formData.token} onChange={handleChange} required autoComplete="off" />
            </>
          )}
          <button 
              type="submit" 
              disabled={page === "forgot" && isSubmitting}
              style={{ opacity: (page === "forgot" && isSubmitting) ? 0.6 : 1, cursor: (page === "forgot" && isSubmitting) ? 'not-allowed' : 'pointer' }}
          >
            {page === "login" && "Login"}
            {page === "register" && "Register"}
            {page === "forgot" && (isSubmitting ? "Sending..." : "Send Reset Email")}
            {page === "reset" && "Reset Password"}
          </button>
        </form>
        <div className="links">
          {page !== "login" && <p onClick={() => { setPage("login"); setMessage(""); setConfirmPassword(""); }}>Login</p>}
          {page !== "register" && <p onClick={() => { setPage("register"); setMessage(""); setConfirmPassword(""); }}>Register</p>}
          {page !== "forgot" && <p onClick={() => { setPage("forgot"); setMessage(""); setConfirmPassword(""); }}>Forgot-Password</p>}
          {page !== "reset" && page === "forgot" && <p onClick={() => { setPage("reset"); setMessage(""); setConfirmPassword(""); }}>Reset-Password</p>}
        </div>
      </div>
    </div>
  );
}

export default App;
