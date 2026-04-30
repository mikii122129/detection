import asyncio
import os
import math
import re
import socket
import time
from contextlib import closing
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import unquote, urljoin, urlparse

import requests


@dataclass(frozen=True)
class ParsedAccessLog:
    raw_line: str
    remote_host: str
    method: str
    request_target: str
    protocol: str
    status_code: int
    bytes_sent: Optional[int]
    referer: Optional[str] = None
    user_agent: Optional[str] = None


class DetectionEngine:
    _shared_system = None
    _model_ready: Optional[bool] = None
    _model_error: Optional[str] = None
    _access_log_pattern = re.compile(
        r'(?P<remote_host>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]+)\s+(?P<request_target>[^"]*?)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    def __init__(self):
        self.scanner = WebsiteScanner()

    @staticmethod
    def safe_target_name(target_url: str) -> str:
        normalized = target_url if target_url.startswith(("http://", "https://")) else f"http://{target_url}"
        parsed = urlparse(normalized)
        raw_target = parsed.netloc or target_url or "target"
        return re.sub(r"[^a-zA-Z0-9._-]+", "_", raw_target).strip("_") or "target"

    @classmethod
    def default_live_log_path(cls, target_url: str) -> str:
        default_log_dir = os.path.join(os.path.dirname(__file__), "detection", "live_logs")
        os.makedirs(default_log_dir, exist_ok=True)
        return os.path.join(default_log_dir, f"{cls.safe_target_name(target_url)}.access.log")

    def _ensure_model_loaded(self) -> None:
        if DetectionEngine._model_ready is not None:
            return

        try:
            from model import OWASPSystem, Config

            config = Config(device="cpu")
            system = OWASPSystem(config)
            checkpoint_path = os.path.join(os.path.dirname(__file__), "owasp_trained_model.pth")
            DetectionEngine._model_ready = system.load_checkpoint(checkpoint_path)
            DetectionEngine._shared_system = system if DetectionEngine._model_ready else None
            DetectionEngine._model_error = None if DetectionEngine._model_ready else "Checkpoint unavailable or incompatible"
        except Exception as exc:
            DetectionEngine._shared_system = None
            DetectionEngine._model_ready = False
            DetectionEngine._model_error = str(exc)

    async def scan_target(self, target_url: str, progress_callback=None) -> Dict:
        return await asyncio.to_thread(self._scan_target_sync, target_url, progress_callback)

    def _scan_target_sync(self, target_url: str, progress_callback=None) -> Dict:
        started = time.time()
        normalized_target = self._normalize_target(target_url)
        log_file_path = self.default_live_log_path(normalized_target)
        self._progress(progress_callback, "initializing", "Loading saved receiver traffic")
        self._ensure_model_loaded()
        metrics = {
            "duration_seconds": 0.0,
            "mode": "saved_live_log_analysis",
            "saved_log_path": log_file_path,
            "log_lines_received": 0,
            "requests_parsed": 0,
            "ignored_internal_test_requests": 0,
            "suspicious_events": 0,
            "model_enabled": bool(DetectionEngine._model_ready),
            "model_source": "model.py" if DetectionEngine._model_ready else "heuristic-fallback",
            "model_error": DetectionEngine._model_error,
            "target": normalized_target,
            "ml_predictions": [],
        }

        if not os.path.exists(log_file_path):
            self._progress(progress_callback, "missing_log", f"No receiver log found for {normalized_target}: {log_file_path}")
            metrics["duration_seconds"] = round(time.time() - started, 2)
            metrics["findings_by_severity"] = self._findings_by_severity([])
            return {
                "status": "completed",
                "risk_score": 0,
                "metrics": metrics,
                "findings": [],
            }

        self._progress(progress_callback, "analyzing_log", f"Analyzing receiver log file {log_file_path}")
        findings: List[Dict] = []
        seen_findings = set()
        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                if not raw_line.strip():
                    continue
                metrics["log_lines_received"] += 1
                analyzed = self.analyze_log_line(normalized_target, raw_line.rstrip("\n"))
                if not analyzed or not analyzed.get("parsed"):
                    continue

                metrics["requests_parsed"] += 1
                parsed = analyzed["parsed"]
                metrics["last_request_target"] = parsed.request_target
                metrics["last_status_code"] = parsed.status_code
                metrics["last_source_ip"] = parsed.remote_host

                if analyzed.get("ignored"):
                    metrics["ignored_internal_test_requests"] += 1
                    continue

                finding = analyzed.get("finding")
                if not finding:
                    continue

                prediction = analyzed.get("prediction") or {}
                if prediction:
                    metrics["ml_predictions"].append({
                        "label_id": prediction.get("label_id"),
                        "label": finding["owasp"],
                        "model_label": prediction.get("label"),
                        "confidence": finding["confidence"],
                        "model_confidence": prediction.get("confidence"),
                        "request_text": parsed.request_target,
                        "is_malicious": True,
                        "source_ip": parsed.remote_host,
                        "status_code": parsed.status_code,
                        "classifier": finding.get("classifier", "hybrid"),
                    })
                    metrics["ml_predictions"] = metrics["ml_predictions"][-100:]

                metrics["suspicious_events"] += 1
                metrics["last_detected_label"] = prediction.get("label", finding["owasp"])
                dedupe_key = (finding["owasp"], finding["location"], finding["evidence"])
                if dedupe_key not in seen_findings:
                    seen_findings.add(dedupe_key)
                    findings.append(finding)

        self._progress(progress_callback, "finalizing", f"Classified {metrics['requests_parsed']} requests from saved traffic")
        metrics["duration_seconds"] = round(time.time() - started, 2)
        metrics["findings_by_severity"] = self._findings_by_severity(findings)
        risk_score = self._calculate_risk_score(findings)

        return {
            "status": "completed",
            "risk_score": risk_score,
            "metrics": metrics,
            "findings": findings,
        }

    def _progress(self, callback, step: str, message: str) -> None:
        if callback:
            callback(step, message)

    def _scan_headers(self, target_url: str) -> List[Dict]:
        findings = []
        for item in self.scanner.scan(target_url):
            owasp = "A05-SecurityMisconfiguration"
            severity = "warning"
            if item["cat"] == "A02":
                owasp = "A02-CryptographicFailures"
                severity = "high"
            elif item["cat"] == "A06":
                owasp = "A06-VulnerableOutdatedComponents"
                severity = "warning"
            elif item["cat"] == "A09":
                owasp = "A09-SecurityLoggingMonitoringFailures"
                severity = "warning"

            findings.append(
                {
                    "owasp": owasp,
                    "severity": severity,
                    "title": item["msg"],
                    "description": f"Passive security check flagged: {item['msg']}.",
                    "evidence": item["msg"],
                    "location": target_url,
                    "remediation": self._remediation_for_owasp(owasp),
                    "confidence": 65,
                }
            )
        return findings

    def _predict_request(self, base_url: str, request_target: str) -> Optional[Dict]:
        if DetectionEngine._model_ready is not True or not DetectionEngine._shared_system:
            return self._heuristic_prediction(request_target)
        prediction = DetectionEngine._shared_system.predict_request(base_url, request_target)
        return {
            "label_id": prediction["label_id"],
            "label": prediction["label"],
            "confidence": prediction["confidence"],
            "request_text": prediction["request_text"],
            "is_malicious": prediction["is_malicious"],
        }

    def parse_access_log_line(self, log_line: str) -> Optional[ParsedAccessLog]:
        text = (log_line or "").strip()
        if not text:
            return None

        match = self._access_log_pattern.match(text)
        if not match:
            return None

        request_target = (match.group("request_target") or "").strip()
        if request_target.startswith(("http://", "https://")):
            parsed_target = urlparse(request_target)
            request_target = parsed_target.path or "/"
            if parsed_target.query:
                request_target = f"{request_target}?{parsed_target.query}"

        size_value = match.group("size")
        bytes_sent = None if size_value in {None, "-", ""} else int(size_value)

        return ParsedAccessLog(
            raw_line=text,
            remote_host=match.group("remote_host"),
            method=match.group("method"),
            request_target=request_target or "/",
            protocol=match.group("protocol"),
            status_code=int(match.group("status")),
            bytes_sent=bytes_sent,
            referer=match.group("referer"),
            user_agent=match.group("user_agent"),
        )

    def analyze_log_line(self, base_url: str, log_line: str) -> Optional[Dict]:
        parsed = self.parse_access_log_line(log_line)
        if not parsed:
            return None

        normalized_target = self._normalize_target(base_url)
        self._ensure_model_loaded()

        if self._is_internal_test_traffic(parsed):
            return {
                "parsed": parsed,
                "prediction": None,
                "finding": None,
                "ignored": True,
                "ignored_reason": "internal_test_traffic",
            }

        ml = self._predict_request(normalized_target, parsed.request_target)

        if not self._is_suspicious_log_event(parsed, ml):
            return {
                "parsed": parsed,
                "prediction": ml,
                "finding": None,
                "ignored": False,
            }

        detected_owasp = self._owasp_from_log_event(parsed, ml)
        classifier = self._classifier_source(parsed, ml, detected_owasp)
        severity = self._severity_from_log_event(parsed, ml, classifier, detected_owasp)
        location = urljoin(normalized_target.rstrip("/") + "/", parsed.request_target.lstrip("/"))
        evidence = [
            f"Source={parsed.remote_host}",
            f"Method={parsed.method}",
            f"Status={parsed.status_code}",
        ]
        if classifier == "ml" and ml:
            evidence.append(f"ML={ml['label']} ({ml['confidence']}%)")
        elif ml:
            evidence.append(f"Rule={detected_owasp}")
            evidence.append(f"ModelSignal={ml['label']} ({ml['confidence']}%)")
        else:
            evidence.append(f"Rule={detected_owasp}")
        evidence.append(f"Raw={parsed.raw_line[:500]}")

        description = (
            f"Live Apache traffic matched the {detected_owasp} detection profile while streaming from the monitored VM. "
            f"The request `{parsed.request_target}` returned HTTP {parsed.status_code} and should be reviewed against the application logs."
        )

        title_suffix = detected_owasp.split("-", 1)[-1] if "-" in detected_owasp else detected_owasp
        confidence = 55
        if classifier == "rule":
            confidence = 88
        elif ml:
            confidence = max(confidence, int(ml.get("confidence", 55)))
        if parsed.status_code >= 500:
            confidence = max(confidence, 80)

        finding = {
            "owasp": detected_owasp,
            "severity": severity,
            "title": f"Live Traffic Flagged: {title_suffix}",
            "description": description,
            "evidence": " | ".join(evidence),
            "location": location,
            "remediation": self._remediation_for_owasp(detected_owasp),
            "confidence": min(confidence, 99),
            "classifier": classifier,
        }

        return {
            "parsed": parsed,
            "prediction": ml,
            "finding": finding,
            "ignored": False,
        }

    def analyze_saved_log_file(self, base_url: str, log_file_path: str, start_position: int = 0) -> Dict:
        results: List[Dict] = []
        if not os.path.exists(log_file_path):
            return {"results": results, "next_position": start_position}

        with open(log_file_path, "r", encoding="utf-8", errors="ignore") as handle:
            handle.seek(start_position)
            for raw_line in handle:
                analyzed = self.analyze_log_line(base_url, raw_line.rstrip("\n"))
                if analyzed:
                    results.append(analyzed)
            next_position = handle.tell()

        return {"results": results, "next_position": next_position}

    def _heuristic_prediction(self, request_target: str) -> Dict:
        text = unquote(request_target or "").lower()
        if any(token in text for token in [
            "union select", "<script", "alert(", " onerror", "' or '1'='1",
            "\" or \"1\"=\"1", "'1--", "'--", "\"--", "sleep(", "benchmark(", "information_schema",
            "cmd=", "exec=", ";cat ", "|id", "$(", "../", "..\\",
        ]) or self._has_sql_injection_marker(text):
            return {"label_id": 3, "label": "A03-Injection", "confidence": 84.0, "is_malicious": True}
        if any(token in text for token in ["/admin", "role=admin", "isadmin=true", "user_id=1", "uid=1"]):
            return {"label_id": 1, "label": "A01-BrokenAccessControl", "confidence": 68.0, "is_malicious": True}
        if any(token in text for token in ["url=http://127.0.0.1", "url=http://localhost", "169.254.169.254", "metadata.google", "/latest/meta-data"]):
            return {"label_id": 10, "label": "A10-ServerSideRequestForgery", "confidence": 86.0, "is_malicious": True}
        if any(token in text for token in [".env", "/debug", "config", "token", "swagger", "phpinfo", ".git/"]):
            return {"label_id": 5, "label": "A05-SecurityMisconfiguration", "confidence": 70.0, "is_malicious": True}
        if len(text) > 250 or calculate_entropy(text) > 4.8:
            return {"label_id": 9, "label": "A09-SecurityLoggingMonitoringFailures", "confidence": 61.0, "is_malicious": True}
        return {"label_id": 0, "label": "Benign", "confidence": 70.0, "is_malicious": False}

    def _is_internal_test_traffic(self, parsed: ParsedAccessLog) -> bool:
        user_agent = (parsed.user_agent or "").lower()
        request_target = (parsed.request_target or "").lower()
        decoded_target = unquote(request_target)

        if "python-requests" not in user_agent:
            return False

        # Ignore traffic generated by the old active scanner if an older process is still running.
        known_internal_targets = {
            "/search?q=' or '1'='1",
            "/search?q=<script>alert(1)</script>",
            "/proxy?url=http://127.0.0.1:80",
            "/.env",
            "/admin",
            "/debug?trace=true",
        }
        return any(
            request_target.endswith(target) or decoded_target.endswith(target)
            for target in known_internal_targets
        )

    def _is_suspicious_log_event(self, parsed: ParsedAccessLog, ml: Optional[Dict]) -> bool:
        if self._has_attack_marker(parsed.request_target):
            return True
        if self._looks_like_normal_browser_request(parsed):
            return False
        if self._is_low_signal_navigation(parsed):
            return False
        if parsed.status_code >= 500 and ml and ml.get("label") != "Benign":
            return self._ml_label_supported_by_request(ml.get("label"), parsed.request_target, allow_weak_signal=True)
        if ml and ml.get("label") != "Benign" and ml.get("confidence", 0) >= 65:
            return self._ml_label_supported_by_request(ml.get("label"), parsed.request_target)
        return False

    def _classifier_source(self, parsed: ParsedAccessLog, ml: Optional[Dict], detected_owasp: str) -> str:
        if self._has_attack_marker(parsed.request_target):
            if ml and ml.get("label") == detected_owasp:
                return "hybrid"
            return "rule"
        if ml and ml.get("label") == detected_owasp and ml.get("label") != "Benign":
            return "ml"
        return "rule"

    def _owasp_from_log_event(self, parsed: ParsedAccessLog, ml: Optional[Dict]) -> str:
        text = unquote(parsed.request_target or "").lower()
        if any(token in text for token in ["union select", "<script", "alert(", "onerror=", "' or '1'='1", "'1--", "'--", "\"--"]) or self._has_sql_injection_marker(text):
            return "A03-Injection"
        if any(token in text for token in ["url=http://127.0.0.1", "url=http://localhost", "169.254.169.254", "/latest/meta-data", "metadata"]):
            return "A10-ServerSideRequestForgery"
        if any(token in text for token in ["/admin", "role=admin"]):
            return "A01-BrokenAccessControl"
        if any(token in text for token in [".env", "/debug", "trace=true", "config", "phpinfo", ".git/", "swagger"]):
            return "A05-SecurityMisconfiguration"
        if ml and ml.get("label") and ml["label"] != "Benign":
            return ml["label"]
        return "A09-SecurityLoggingMonitoringFailures"

    def _has_attack_marker(self, request_target: str) -> bool:
        text = unquote(request_target or "").lower()
        attack_markers = [
            "union select", "<script", "alert(", "onerror=", "../", "..%2f",
            "%3cscript", "' or '1'='1", "\" or \"1\"=\"1", "'1--", "'--", "\"--", "/admin", "/debug",
            ".env", "trace=true", "cmd=", "exec=", "sleep(", "benchmark(",
            "information_schema", ";cat ", "|id", "$(", "url=http://127.0.0.1",
            "url=http://localhost", "169.254.169.254", "/latest/meta-data",
            "metadata", "phpinfo", ".git/", "swagger",
        ]
        return any(marker in text for marker in attack_markers) or self._has_sql_injection_marker(text)

    def _ml_label_supported_by_request(
        self,
        label: Optional[str],
        request_target: str,
        allow_weak_signal: bool = False,
    ) -> bool:
        if label == "A03-Injection":
            return self._has_injection_marker(request_target)
        if label == "A10-ServerSideRequestForgery":
            return self._has_ssrf_marker(request_target)
        if label == "A05-SecurityMisconfiguration":
            return self._has_misconfiguration_marker(request_target)
        if label == "A01-BrokenAccessControl":
            return self._has_access_control_marker(request_target)
        if label in {"A02-CryptographicFailures", "A06-VulnerableOutdatedComponents"}:
            return allow_weak_signal
        if label in {
            "A04-InsecureDesign",
            "A07-IdentificationAuthFailures",
            "A08-SoftwareDataIntegrityFailures",
            "A09-SecurityLoggingMonitoringFailures",
        }:
            return allow_weak_signal and not self._is_clean_path(request_target)
        return False

    def _has_injection_marker(self, request_target: str) -> bool:
        return (
            self._has_sql_injection_marker(request_target)
            or self._has_xss_marker(request_target)
            or self._has_command_injection_marker(request_target)
        )

    def _has_sql_injection_marker(self, text: str) -> bool:
        decoded = unquote(text or "").lower()
        sql_patterns = [
            r"['\"]\s*\d+\s*--",
            r"['\"]\s*--",
            r"['\"]\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"(\bor\b|\band\b)\s+\d+\s*=\s*\d+",
            r"union\s+(all\s+)?select",
            r"(sleep|benchmark)\s*\(",
        ]
        return any(re.search(pattern, decoded) for pattern in sql_patterns)

    def _has_xss_marker(self, request_target: str) -> bool:
        text = unquote(request_target or "").lower()
        return any(token in text for token in [
            "<script", "%3cscript", "alert(", "onerror=", "onload=", "javascript:",
            "document.cookie", "img src=", "svg/onload",
        ])

    def _has_command_injection_marker(self, request_target: str) -> bool:
        text = unquote(request_target or "").lower()
        return any(token in text for token in [
            "cmd=", "exec=", "command=", ";cat ", ";id", "|id", "|whoami", "$(",
            "`id`", "&&", "||",
        ])

    def _has_ssrf_marker(self, request_target: str) -> bool:
        text = unquote(request_target or "").lower()
        return any(token in text for token in [
            "url=http://127.0.0.1", "url=http://localhost", "url=https://127.0.0.1",
            "url=https://localhost", "169.254.169.254", "/latest/meta-data",
            "metadata.google", "metadata/compute", "file://", "gopher://",
        ])

    def _has_misconfiguration_marker(self, request_target: str) -> bool:
        text = unquote(request_target or "").lower()
        return any(token in text for token in [
            "/.env", "/debug", "trace=true", "config.php", "phpinfo", ".git/",
            "swagger", "openapi.json", "server-status", "backup", ".bak",
        ])

    def _has_access_control_marker(self, request_target: str) -> bool:
        text = unquote(request_target or "").lower()
        return any(token in text for token in [
            "/admin", "/administrator", "role=admin", "isadmin=true", "user_id=1",
            "uid=1", "debug_user=", "impersonate=", "access_token=",
        ])

    def _looks_like_normal_browser_request(self, parsed: ParsedAccessLog) -> bool:
        if parsed.method not in {"GET", "HEAD", "OPTIONS"} or parsed.status_code >= 400:
            return False
        target = unquote(parsed.request_target or "").lower()
        if "?" in target:
            return False
        return bool(re.search(r"(^/$|/[^/?#]+\.(html?|css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map)$)", target))

    def _is_low_signal_navigation(self, parsed: ParsedAccessLog) -> bool:
        if parsed.method not in {"GET", "HEAD", "OPTIONS"} or parsed.status_code >= 500:
            return False

        target = parsed.request_target or "/"
        decoded_target = unquote(target).lower()
        if self._has_attack_marker(target):
            return False
        if "?" in decoded_target or "=" in decoded_target:
            return False
        if any(char in decoded_target for char in ["'", "\"", "<", ">", ";", "|", "$", "\\"]):
            return False

        return bool(re.match(r"^/[a-z0-9._~!&()+,/:@%-]*$", decoded_target))

    def _is_clean_path(self, request_target: str) -> bool:
        decoded_target = unquote(request_target or "").lower()
        if "?" in decoded_target or "=" in decoded_target:
            return False
        if any(char in decoded_target for char in ["'", "\"", "<", ">", ";", "|", "$", "\\"]):
            return False
        return bool(re.match(r"^/[a-z0-9._~!&()+,/:@%-]*$", decoded_target))

    def _severity_from_log_event(
        self,
        parsed: ParsedAccessLog,
        ml: Optional[Dict],
        classifier: str = "rule",
        owasp: Optional[str] = None,
    ) -> str:
        if parsed.status_code >= 500:
            return "critical"

        if classifier in {"rule", "hybrid"}:
            if owasp in {"A03-Injection", "A10-ServerSideRequestForgery"}:
                return "high"
            if owasp in {"A01-BrokenAccessControl", "A05-SecurityMisconfiguration"}:
                return "warning"
            return "warning"

        confidence = ml.get("confidence", 0) if ml else 0
        if confidence >= 90:
            return "high"
        return "warning"

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []
        for finding in findings:
            key = (finding["owasp"], finding["title"], finding.get("location"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    def _calculate_risk_score(self, findings: List[Dict]) -> int:
        weights = {"critical": 30, "high": 20, "warning": 10, "info": 5}
        total = sum(weights.get(f["severity"].lower(), 5) for f in findings)
        return min(total, 100)

    def _findings_by_severity(self, findings: List[Dict]) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "warning": 0, "info": 0}
        for finding in findings:
            severity = finding["severity"].lower()
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _normalize_target(self, target_url: str) -> str:
        url = (target_url or "").strip()
        if not url:
            return url
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid target URL")
        return url

    def _remediation_for_owasp(self, owasp: str) -> str:
        mapping = {
            "A01-BrokenAccessControl": "Restrict privileged routes, require authentication, and validate authorization on every request.",
            "A02-CryptographicFailures": "Enforce HTTPS, HSTS, and modern TLS configuration across the target.",
            "A03-Injection": "Use parameterized queries, output encoding, and strict server-side validation for untrusted input.",
            "A05-SecurityMisconfiguration": "Harden the deployment, disable debug artifacts, and remove exposed internal files or endpoints.",
            "A06-VulnerableOutdatedComponents": "Patch or replace components that disclose versions or are past supported releases.",
            "A09-SecurityLoggingMonitoringFailures": "Improve monitoring, alerting, and failure visibility around rejected or malformed traffic.",
            "A10-ServerSideRequestForgery": "Block outbound requests to internal networks and validate destination allowlists on proxy-style features.",
        }
        return mapping.get(owasp, "Review the affected component and apply the relevant OWASP mitigation guidance.")


class LiveLogReceiver:
    def __init__(
        self,
        detection_engine: DetectionEngine,
        target_url: str,
        host: str = "0.0.0.0",
        port: int = 9999,
        log_output_path: Optional[str] = None,
    ):
        self.detection_engine = detection_engine
        self.target_url = target_url
        self.host = host
        self.port = port
        self.log_output_path = log_output_path or DetectionEngine.default_live_log_path(target_url)
        output_dir = os.path.dirname(self.log_output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

    def serve(
        self,
        should_stop=None,
        progress_callback: Optional[Callable[[str, str], None]] = None,
        event_callback: Optional[Callable[[Dict], None]] = None,
        traffic_callback: Optional[Callable[[Dict, Dict], None]] = None,
        line_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict:
        target_url = self.detection_engine._normalize_target(self.target_url)
        self.detection_engine._ensure_model_loaded()
        metrics = {
            "mode": "live_log_stream",
            "target": target_url,
            "listen_host": self.host,
            "listen_port": self.port,
            "connection_count": 0,
            "log_lines_received": 0,
            "requests_parsed": 0,
            "ignored_internal_test_requests": 0,
            "suspicious_events": 0,
            "saved_log_path": self.log_output_path,
            "file_read_position": 0,
            "model_enabled": bool(DetectionEngine._model_ready),
            "model_source": "model.py" if DetectionEngine._model_ready else "heuristic-fallback",
            "model_error": DetectionEngine._model_error,
            "started_at": time.time(),
        }

        def progress(step: str, message: str) -> None:
            if progress_callback:
                progress_callback(step, message)

        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(1)
            server.settimeout(1.0)
            progress("listening", f"Listening for VM log stream on {self.host}:{self.port} and saving to {self.log_output_path}")

            while not self._stop_requested(should_stop):
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue

                metrics["connection_count"] += 1
                progress("connected", f"Connected to VM sender at {addr[0]}:{addr[1]}")

                with closing(conn):
                    conn.settimeout(1.0)
                    buffer = ""
                    while not self._stop_requested(should_stop):
                        try:
                            payload = conn.recv(4096)
                        except socket.timeout:
                            continue

                        if not payload:
                            progress("disconnected", "VM sender disconnected")
                            break

                        buffer += payload.decode(errors="ignore")
                        while "\n" in buffer:
                            raw_line, buffer = buffer.split("\n", 1)
                            self._save_and_process_stream_line(
                                raw_line,
                                metrics,
                                event_callback,
                                traffic_callback,
                                line_callback,
                            )

                    if buffer.strip():
                        self._save_and_process_stream_line(
                            buffer.strip(),
                            metrics,
                            event_callback,
                            traffic_callback,
                            line_callback,
                        )
                        buffer = ""

        metrics["duration_seconds"] = round(time.time() - metrics["started_at"], 2)
        metrics.pop("started_at", None)
        if self._stop_requested(should_stop):
            progress("stopped", "Live detection listener stopped")
            metrics["status"] = "stopped"
        else:
            progress("complete", "Live detection listener finished")
            metrics["status"] = "completed"
        return metrics

    def _save_and_process_stream_line(
        self,
        raw_line: str,
        metrics: Dict,
        event_callback: Optional[Callable[[Dict], None]],
        traffic_callback: Optional[Callable[[Dict, Dict], None]],
        line_callback: Optional[Callable[[str], None]],
    ) -> None:
        if not raw_line.strip():
            return

        metrics["log_lines_received"] += 1
        output_dir = os.path.dirname(self.log_output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(self.log_output_path, "a", encoding="utf-8", errors="ignore") as handle:
            handle.write(raw_line.rstrip("\n") + "\n")

        if line_callback:
            line_callback(raw_line)

        analyzed = self.detection_engine.analyze_log_line(self.target_url, raw_line.rstrip("\n"))
        if analyzed:
            self._consume_processed_result(analyzed, metrics, event_callback, traffic_callback)

    def _consume_processed_result(
        self,
        result: Dict,
        metrics: Dict,
        event_callback: Optional[Callable[[Dict], None]],
        traffic_callback: Optional[Callable[[Dict, Dict], None]],
    ) -> None:
        if not result or not result.get("parsed"):
            return

        metrics["requests_parsed"] += 1
        parsed = result["parsed"]
        metrics["last_request_target"] = parsed.request_target
        metrics["last_status_code"] = parsed.status_code
        metrics["last_source_ip"] = parsed.remote_host

        if result.get("ignored"):
            metrics["ignored_internal_test_requests"] = metrics.get("ignored_internal_test_requests", 0) + 1
            if traffic_callback:
                traffic_callback(result, metrics)
            return

        if not result.get("finding"):
            if traffic_callback:
                traffic_callback(result, metrics)
            return

        metrics["suspicious_events"] += 1
        prediction = result.get("prediction") or {}
        metrics["last_detected_label"] = result["finding"]["owasp"]

        if traffic_callback:
            traffic_callback(result, metrics)
        if event_callback:
            event_callback(result)

    def _stop_requested(self, should_stop) -> bool:
        if should_stop is None:
            return False
        if callable(should_stop):
            return bool(should_stop())
        is_set = getattr(should_stop, "is_set", None)
        if callable(is_set):
            return bool(is_set())
        return bool(should_stop)


def calculate_entropy(value: str) -> float:
    if not value:
        return 0.0
    probabilities = [float(value.count(char)) / len(value) for char in dict.fromkeys(value)]
    return -sum(prob * math.log(prob) / math.log(2.0) for prob in probabilities)


class WebsiteScanner:
    def scan(self, domain: str) -> List[Dict]:
        findings = []
        url = domain if domain.startswith("http") else f"http://{domain}"
        try:
            response = requests.get(url, timeout=2.5, verify=False)
            headers = response.headers
            if not url.startswith("https"):
                findings.append({"cat": "A02", "msg": "No HTTPS"})
            if "Strict-Transport-Security" not in headers:
                findings.append({"cat": "A02", "msg": "Missing HSTS"})
            for header in ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"]:
                if header not in headers:
                    findings.append({"cat": "A05", "msg": f"Missing {header}"})
            server = headers.get("Server", "")
            if re.search(r"\d", server):
                findings.append({"cat": "A06", "msg": f"Version Exposed: {server}"})
        except Exception as exc:
            findings.append({"cat": "A09", "msg": f"Connection Failed: {exc}"})
        return findings
