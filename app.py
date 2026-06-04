import argparse
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import smtplib
import threading
from email.message import EmailMessage
from html import escape as html_escape
from http.cookies import SimpleCookie
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from cyberscan import CyberScan, ScanCancelled


ROOT = Path(__file__).resolve().parent
INDEX_PATH = ROOT / "prototype.html"
REPORTS_DIR = ROOT / "reports"
HISTORY_PATH = REPORTS_DIR / "history.json"
AUTOMATION_PATH = REPORTS_DIR / "automation.json"
TRIAGE_PATH = REPORTS_DIR / "triage.json"

REPORTS_DIR.mkdir(exist_ok=True)

STATE_LOCK = threading.Lock()
STATE = {
    "latest_scan": None,
    "history": [],
    "template_reports": [],
    "schedules": {},
    "triage": {},
}

TEMPLATE_CONFIG = {
    "Executive Summary": {
        "description": "High-level overview for stakeholders",
        "format": "HTML",
    },
    "Developer Handoff": {
        "description": "Technical details and remediation steps",
        "format": "HTML",
    },
    "Full Technical Report": {
        "description": "Comprehensive vulnerability documentation",
        "format": "HTML",
    },
    "Compliance Report": {
        "description": "OWASP Top 10 and compliance mapping",
        "format": "HTML",
    },
}

SESSION_COOKIE = "cyberscan_session"
SESSIONS = {}
PENDING_OTPS = {}
OTP_LOCK = threading.Lock()
ACTIVE_SCANS = {}
ACTIVE_SCANS_LOCK = threading.Lock()
SCAN_JOBS = {}
SCAN_JOBS_LOCK = threading.Lock()
OWNER_PASSWORD_HASH = os.environ.get("CYBERSCAN_OWNER_PASSWORD_HASH", "")
OWNER_PASSWORD = os.environ.get("CYBERSCAN_OWNER_PASSWORD", "password")
OTP_TTL_MINUTES = int(os.environ.get("CYBERSCAN_OTP_TTL_MINUTES", "10"))
SMTP_HOST = os.environ.get("CYBERSCAN_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("CYBERSCAN_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("CYBERSCAN_SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("CYBERSCAN_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("CYBERSCAN_SMTP_FROM", SMTP_USERNAME)
SMTP_USE_TLS = os.environ.get("CYBERSCAN_SMTP_USE_TLS", "true").strip().lower() not in {"0", "false", "no", "off"}
TRUSTED_ORIGINS = {
    "http://127.0.0.1",
    "http://127.0.0.1:8006",
    "http://localhost",
    "http://localhost:8006",
    "http://cyberscan.local",
    "http://cyberscan.local:8006",
}
TRUSTED_ORIGINS.update(
    origin.strip().rstrip("/")
    for origin in os.environ.get("CYBERSCAN_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
)

OWNER_PERMISSIONS = [
    "dashboard:view",
    "scan:start",
    "scan:configure",
    "finding:view",
    "finding:triage",
    "report:export",
    "settings:view",
    "settings:manage",
]

OWNER_PROFILE = {
    "email": "owner@company.com",
    "name": "Owner",
    "initials": "OW",
    "role": "Owner",
    "permissions": OWNER_PERMISSIONS,
}


def normalize_url(url):
    if not url:
        return ""
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url.rstrip("/")


def slugify(text):
    text = re.sub(r"[^A-Za-z0-9]+", "-", text.strip().lower())
    return text.strip("-") or "scan"


def load_state():
    if HISTORY_PATH.exists():
        try:
            with open(HISTORY_PATH, "r", encoding="utf-8") as file:
                history = json.load(file)
            if isinstance(history, list):
                STATE["history"] = history
                if history:
                    STATE["latest_scan"] = history[0].get("report")
        except Exception:
            STATE["history"] = []
            STATE["latest_scan"] = None
    if AUTOMATION_PATH.exists():
        try:
            with open(AUTOMATION_PATH, "r", encoding="utf-8") as file:
                automation = json.load(file)
            STATE["template_reports"] = automation.get("template_reports", [])
            STATE["schedules"] = automation.get("schedules", {})
        except Exception:
            STATE["template_reports"] = []
            STATE["schedules"] = {}
    if TRIAGE_PATH.exists():
        try:
            with open(TRIAGE_PATH, "r", encoding="utf-8") as file:
                triage = json.load(file)
            if isinstance(triage, dict):
                STATE["triage"] = triage
        except Exception:
            STATE["triage"] = {}
    for entry in STATE["history"]:
        annotate_report_findings(entry.get("report"))
    annotate_report_findings(STATE["latest_scan"])


def save_state():
    with open(HISTORY_PATH, "w", encoding="utf-8") as file:
        json.dump(STATE["history"], file, indent=2)


def save_automation_state():
    with open(AUTOMATION_PATH, "w", encoding="utf-8") as file:
        json.dump({
            "template_reports": STATE["template_reports"],
            "schedules": STATE["schedules"],
        }, file, indent=2)


def save_triage_state():
    with open(TRIAGE_PATH, "w", encoding="utf-8") as file:
        json.dump(STATE["triage"], file, indent=2)


def finding_fingerprint(finding):
    parts = [
        finding.get("title", ""),
        finding.get("severity", ""),
        finding.get("owasp_category", ""),
        finding.get("cwe", ""),
        finding.get("affected_url", ""),
    ]
    normalized = "|".join(str(part).strip().lower() for part in parts)
    return re.sub(r"\s+", " ", normalized)


def annotate_report_findings(report):
    if not report:
        return report
    triage = STATE.get("triage", {})
    visible_findings = []
    for finding in report.get("findings", []) or []:
        key = finding_fingerprint(finding)
        finding["fingerprint"] = key
        triage_entry = triage.get(key, {})
        if triage_entry.get("hidden"):
            continue
        if triage_entry.get("status"):
            finding["lifecycle_status"] = triage_entry["status"]
        if triage_entry.get("owner_review"):
            finding["owner_review"] = triage_entry["owner_review"]
        visible_findings.append(finding)
    report["findings"] = visible_findings
    return report


def compare_report_findings(report, previous_report=None):
    current_findings = report.get("findings", []) or []
    previous_findings = (previous_report or {}).get("findings", []) or []
    previous_by_key = {
        finding_fingerprint(finding): finding
        for finding in previous_findings
    }
    current_keys = set()
    new_count = 0
    existing_count = 0

    for finding in current_findings:
        key = finding_fingerprint(finding)
        current_keys.add(key)
        if key in previous_by_key:
            finding["lifecycle_status"] = "Existing"
            existing_count += 1
        else:
            finding["lifecycle_status"] = "New"
            new_count += 1
        finding["fingerprint"] = key

    fixed_findings = [
        {
            "title": finding.get("title", "Scanner Finding"),
            "severity": finding.get("severity", "Info"),
            "owasp_category": finding.get("owasp_category", "Security Finding"),
            "cwe": finding.get("cwe", "CWE-N/A"),
            "confidence": finding.get("confidence", "Medium"),
            "affected_url": finding.get("affected_url", ""),
            "evidence": finding.get("evidence", ""),
        }
        for key, finding in previous_by_key.items()
        if key not in current_keys
    ]

    comparison = {
        "new": new_count,
        "existing": existing_count,
        "fixed": len(fixed_findings),
        "fixed_findings": fixed_findings[:25],
    }
    report["comparison"] = comparison
    annotate_report_findings(report)
    return comparison


def parse_json_body(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def request_origin(handler):
    origin = handler.headers.get("Origin") or ""
    if origin:
        return origin.rstrip("/")
    referer = handler.headers.get("Referer") or ""
    if referer:
        parsed = urlparse(referer)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    return ""


def allowed_origin(handler):
    origin = request_origin(handler)
    if not origin:
        return None
    parsed = urlparse(origin)
    request_host = (handler.headers.get("X-Forwarded-Host") or handler.headers.get("Host") or "").split(",", 1)[0].strip()
    request_hostname = request_host.split(":", 1)[0].lower()
    if parsed.hostname and parsed.hostname.lower() == request_hostname:
        return origin
    if parsed.hostname in ("127.0.0.1", "localhost") or origin in TRUSTED_ORIGINS:
        return origin
    return None


def add_common_headers(handler, extra_headers=None):
    origin = allowed_origin(handler)
    if origin:
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Vary", "Origin")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("X-Frame-Options", "DENY")
    for key, value in (extra_headers or {}).items():
        handler.send_header(key, value)


def verify_post_origin(handler):
    origin = request_origin(handler)
    return not origin or allowed_origin(handler) is not None


def password_is_valid(password):
    if OWNER_PASSWORD_HASH:
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(digest, OWNER_PASSWORD_HASH)
    return hmac.compare_digest(password, OWNER_PASSWORD)


def send_json(handler, payload, status=200, extra_headers=None):
    body = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    add_common_headers(handler, extra_headers)
    handler.end_headers()
    handler.wfile.write(body)


def send_bytes(handler, payload, content_type, status=200, extra_headers=None):
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Cache-Control", "no-store")
    add_common_headers(handler, extra_headers)
    handler.end_headers()
    handler.wfile.write(payload)


def build_user(email=None):
    user = OWNER_PROFILE.copy()
    if email:
        user["email"] = email
    return user


def smtp_configured():
    return bool(SMTP_HOST and SMTP_PORT and SMTP_FROM and SMTP_USERNAME and SMTP_PASSWORD)


def send_otp_email(email, code):
    if not smtp_configured():
        return False

    message = EmailMessage()
    message["Subject"] = "Your CyberScan verification code"
    message["From"] = SMTP_FROM
    message["To"] = email
    message.set_content(
        "Your CyberScan verification code is:\n\n"
        f"{code}\n\n"
        f"This code expires in {OTP_TTL_MINUTES} minutes. If you did not request this, ignore this email."
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        if SMTP_USE_TLS:
            smtp.starttls()
        smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
        smtp.send_message(message)
    return True


def create_otp_challenge(email):
    code = f"{secrets.randbelow(1_000_000):06d}"
    challenge_id = secrets.token_urlsafe(24)
    expires_at = datetime.now() + timedelta(minutes=OTP_TTL_MINUTES)
    sent_email = send_otp_email(email, code)
    with OTP_LOCK:
        PENDING_OTPS[challenge_id] = {
            "email": email,
            "code_hash": hashlib.sha256(code.encode("utf-8")).hexdigest(),
            "expires_at": expires_at,
            "attempts": 0,
        }
    return challenge_id, expires_at, sent_email, (None if sent_email else code)


def verify_otp_challenge(challenge_id, code):
    now = datetime.now()
    with OTP_LOCK:
        challenge = PENDING_OTPS.get(challenge_id)
        if not challenge:
            raise ValueError("Verification session expired. Please sign in again.")
        if challenge["expires_at"] < now:
            PENDING_OTPS.pop(challenge_id, None)
            raise ValueError("Verification code expired. Please sign in again.")
        challenge["attempts"] += 1
        if challenge["attempts"] > 5:
            PENDING_OTPS.pop(challenge_id, None)
            raise ValueError("Too many verification attempts. Please sign in again.")

        digest = hashlib.sha256(str(code or "").strip().encode("utf-8")).hexdigest()
        if not hmac.compare_digest(digest, challenge["code_hash"]):
            raise ValueError("Invalid verification code.")

        PENDING_OTPS.pop(challenge_id, None)
        return challenge["email"]


def session_cookie_header(token):
    return f"{SESSION_COOKIE}={token}; Path=/; SameSite=Lax; HttpOnly"


def clear_session_cookie_header():
    return f"{SESSION_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly"


def cookie_token(handler):
    raw_cookie = handler.headers.get("Cookie", "")
    if not raw_cookie:
        return None
    cookie = SimpleCookie()
    cookie.load(raw_cookie)
    morsel = cookie.get(SESSION_COOKIE)
    return morsel.value if morsel else None


def current_user(handler):
    token = cookie_token(handler)
    if token and token in SESSIONS:
        return SESSIONS[token]
    return build_user()


def has_permission(user, permission):
    return bool(user and permission in user.get("permissions", []))


def role_payload():
    return {"Owner": OWNER_PERMISSIONS}


def iso_now():
    return datetime.now().isoformat(timespec="seconds")


def parse_iso(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def latest_report_data():
    if STATE["latest_scan"]:
        return STATE["latest_scan"]
    if STATE["history"]:
        return STATE["history"][0].get("report")
    return None


def template_report_html(template, report, generated_at, source):
    findings = report.get("findings", []) if report else []
    prevention_plan = report.get("prevention_plan", []) if report else []
    summary = report.get("summary", {}) if report else {}
    scan = report.get("scan", {}) if report else {}
    coverage = report.get("coverage", {}) if report else {}
    target = report.get("target") or "No scan target yet" if report else "No scan target yet"
    rows = []
    for finding in findings[:25]:
        rows.append(
            "<tr>"
            f"<td>{html_escape(str(finding.get('severity', 'Info')))}</td>"
            f"<td>{html_escape(str(finding.get('title', 'Scanner Finding')))}</td>"
            f"<td>{html_escape(str(finding.get('owasp_category', 'Security Finding')))}</td>"
            f"<td>{html_escape(str(finding.get('cwe', 'CWE-N/A')))}</td>"
            f"<td>{html_escape(str(finding.get('confidence', 'Medium')))}</td>"
            f"<td>{html_escape(str(finding.get('validation_status', 'Needs Manual Validation')))}</td>"
            f"<td>{html_escape(str(finding.get('affected_url', '')))}</td>"
            f"<td>{html_escape(str(finding.get('evidence', '')))}</td>"
            f"<td>{html_escape(str(finding.get('recommendation', 'Review and remediate the affected endpoint.')))}</td>"
            "</tr>"
        )
    if not rows:
        rows.append("<tr><td>Info</td><td>No findings</td><td>Baseline</td><td>CWE-N/A</td><td>High</td><td>Informational</td><td></td><td></td><td>No issues found in the latest scan data.</td></tr>")

    prevention_cards = []
    prevention_items = prevention_plan or [
        {
            "title": finding.get("title", "Scanner Finding"),
            "recommendation": finding.get("recommendation", "Review and remediate the affected endpoint."),
            "severity": finding.get("severity", "Info"),
            "count": 1,
        }
        for finding in findings[:6]
    ]
    for item in prevention_items[:6]:
        count = int(item.get("count") or 0)
        prevention_cards.append(
            "<article>"
            f"<strong>{html_escape(str(item.get('title', 'Security Finding')))}</strong>"
            f"<p>{html_escape(str(item.get('recommendation', 'Review and remediate the affected endpoint.')))}</p>"
            f"<small>{html_escape(str(item.get('severity', 'Info')))}"
            f"{' - ' + str(count) + ' related finding' + ('' if count == 1 else 's') if count else ''}</small>"
            "</article>"
        )
    if not prevention_cards:
        prevention_cards.append(
            "<article><strong>Maintain Secure Baseline</strong>"
            "<p>Keep security headers, dependency checks, and periodic authenticated scans in the release process.</p>"
            "<small>Info</small></article>"
        )

    summary_cards = "".join(
        f"<div><span>{html_escape(str(key))}</span><strong>{html_escape(str(value))}</strong></div>"
        for key, value in (summary or {"Findings": len(findings)}).items()
    )
    coverage_cards = "".join(
        f"<div><span>{html_escape(label)}</span><strong>{html_escape(str(value))}</strong></div>"
        for label, value in (
            ("URLs Scanned", coverage.get("urls_scanned", len(scan.get("settings", {}).get("crawled_urls", [])))),
            ("Max Pages", coverage.get("max_pages", scan.get("settings", {}).get("max_pages", 0))),
            ("Max Depth", coverage.get("max_depth", scan.get("settings", {}).get("max_depth", 0))),
            ("Safe Probes", f"{coverage.get('safe_probes_used', 0)} / {coverage.get('safe_probe_limit', 0)}"),
            ("Open Ports", coverage.get("open_ports_found", len(report.get("open_ports", [])) if report else 0)),
        )
    )
    coverage_notes = "".join(
        f"<li>{html_escape(str(note))}</li>"
        for note in coverage.get("notes", [])
    ) or "<li>No coverage limitations were recorded for this scan.</li>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html_escape(template)} - CyberScan Report</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; color: #172033; background: #f5f7fb; }}
    main {{ max-width: 1040px; margin: 0 auto; padding: 34px 24px; }}
    h1 {{ margin: 0 0 8px; }}
    .meta {{ color: #56657d; margin: 0 0 24px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 22px 0; }}
    .cards div, section {{ background: white; border: 1px solid #dbe3ef; border-radius: 8px; padding: 18px; }}
    .cards span {{ display: block; color: #66758d; font-size: 13px; }}
    .cards strong {{ font-size: 26px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; }}
    th, td {{ padding: 12px; border-bottom: 1px solid #e6ecf5; text-align: left; vertical-align: top; }}
    th {{ background: #edf3fb; }}
    .table-wrap {{ overflow-x: auto; }}
    .prevention-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; }}
    .prevention-grid article {{ border: 1px solid #dbe3ef; border-radius: 8px; padding: 16px; background: white; }}
    .prevention-grid p {{ color: #334155; }}
    .prevention-grid small {{ color: #66758d; }}
  </style>
</head>
<body>
  <main>
    <h1>{html_escape(template)}</h1>
    <p class="meta">Generated {html_escape(generated_at)} by {html_escape(source)} automation for {html_escape(str(target))}</p>
    <section>
      <h2>Scan Context</h2>
      <p><strong>{html_escape(str(scan.get("name", "Latest Scan")))}</strong></p>
      <p>{html_escape(TEMPLATE_CONFIG.get(template, {}).get("description", "Security report"))}</p>
    </section>
    <div class="cards">{summary_cards}</div>
    <section>
      <h2>Scan Coverage</h2>
      <div class="cards">{coverage_cards}</div>
      <ul>{coverage_notes}</ul>
    </section>
    <section>
      <h2>Findings and Remediation</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>CWE</th><th>Confidence</th><th>Validation</th><th>Affected URL</th><th>Evidence</th><th>Recommendation</th></tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
      </div>
    </section>
    <section>
      <h2>How to Prevent Recurrence</h2>
      <div class="prevention-grid">{''.join(prevention_cards)}</div>
    </section>
  </main>
</body>
</html>"""


def create_template_report(template, source="manual"):
    if template not in TEMPLATE_CONFIG:
        raise ValueError("Unknown report template.")

    report = latest_report_data()
    generated_at = iso_now()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{slugify(template)}_{source}_{stamp}"
    html_name = f"{base_name}.html"
    html_path = REPORTS_DIR / html_name
    content = template_report_html(template, report or {}, generated_at, source)
    html_path.write_text(content, encoding="utf-8")

    findings = report.get("findings", []) if report else []
    entry = {
        "name": f"{template} - CyberScan",
        "template": template,
        "generated": generated_at,
        "format": TEMPLATE_CONFIG[template]["format"],
        "size": f"{max(1, round(len(content.encode('utf-8')) / 1024))} KB",
        "source": source,
        "findings_count": len(findings),
        "report_files": {"html": f"/reports/{html_name}"},
    }
    STATE["template_reports"] = [entry] + STATE["template_reports"][:24]
    return entry


def schedule_payload():
    return {
        template: config
        for template, config in STATE["schedules"].items()
        if config.get("enabled")
    }


def start_scheduler(stop_event):
    def worker():
        while not stop_event.wait(30):
            now = datetime.now()
            generated = False
            with STATE_LOCK:
                schedules = list(STATE["schedules"].items())
                for template, config in schedules:
                    if not config.get("enabled"):
                        continue
                    next_run = parse_iso(config.get("next_run"))
                    if next_run and next_run > now:
                        continue
                    try:
                        create_template_report(template, source="scheduled")
                        config["last_run"] = iso_now()
                        config["next_run"] = (now + timedelta(days=7)).isoformat(timespec="seconds")
                        generated = True
                    except Exception as exc:
                        config["last_error"] = str(exc)
                if generated:
                    save_automation_state()

    thread = threading.Thread(target=worker, name="CyberScanScheduler", daemon=True)
    thread.start()
    return thread


def infer_hosts(targets, primary_target):
    hosts = []
    for target in targets or []:
        host = urlparse(target).netloc or target
        if host and host not in hosts:
            hosts.append(host)

    if not hosts:
        host = urlparse(primary_target).netloc or primary_target
        if host:
            hosts.append(host)

    if len(hosts) == 1 and not hosts[0].startswith("www."):
        hosts.insert(0, f"www.{hosts[0]}")

    return [
        {
            "host": host,
            "findings": max(1, len(hosts) * 2 - idx)
        }
        for idx, host in enumerate(hosts[:4])
    ]


def build_scanner_from_payload(payload):
    raw_targets = payload.get("targets") or []
    if isinstance(raw_targets, str):
        raw_targets = [line.strip() for line in re.split(r"[\n,]", raw_targets) if line.strip()]

    targets = [normalize_url(target) for target in raw_targets if normalize_url(target)]
    target = normalize_url(payload.get("target") or (targets[0] if targets else ""))
    if not target:
        raise ValueError("A target URL is required.")

    scan_name = (payload.get("scan_name") or "").strip() or f"CyberScan - {urlparse(target).netloc or 'target'}"
    scan_type = (payload.get("scan_type") or "Quick").strip().title() or "Quick"
    if scan_type == "Auth":
        scan_type = "Authenticated"
    if scan_type not in CyberScan.SCAN_PROFILES:
        scan_type = "Quick"
    scan_profile = CyberScan.SCAN_PROFILES[scan_type]
    tags = payload.get("tags") or []
    if isinstance(tags, str):
        tags = [tag.strip() for tag in tags.split(",") if tag.strip()]

    try:
        max_depth = max(1, min(5, int(payload.get("max_depth") or scan_profile["max_depth"])))
    except (TypeError, ValueError):
        max_depth = scan_profile["max_depth"]

    try:
        rate_limit = max(1, min(50, int(payload.get("rate_limit") or scan_profile["rate_limit"])))
    except (TypeError, ValueError):
        rate_limit = scan_profile["rate_limit"]

    try:
        max_pages = max(1, min(500, int(payload.get("max_pages") or scan_profile["max_pages"])))
    except (TypeError, ValueError):
        max_pages = scan_profile["max_pages"]

    cancel_event = threading.Event()
    scan_id = (payload.get("scan_id") or secrets.token_urlsafe(12)).strip()
    scanner = CyberScan(
        target,
        scan_name=scan_name,
        scan_type=scan_type,
        target_urls=targets or [target],
        tags=tags,
        max_depth=max_depth,
        include_paths=payload.get("include_paths") or [],
        exclude_paths=payload.get("exclude_paths") or [],
        rate_limit=rate_limit,
        max_pages=max_pages,
        auth_headers=payload.get("auth_headers") or [],
        session_cookies=payload.get("session_cookies") or [],
        port_scan=payload.get("port_scan") or False,
        ports=payload.get("ports") or "",
        cancel_event=cancel_event,
    )
    return scan_id, cancel_event, scanner


def execute_scan_payload(payload):
    scan_id, cancel_event, scanner = build_scanner_from_payload(payload)
    with ACTIVE_SCANS_LOCK:
        ACTIVE_SCANS[scan_id] = cancel_event

    try:
        scanner.scan()
        report = scanner.build_report_data()
        with STATE_LOCK:
            previous_report = STATE["history"][0].get("report") if STATE["history"] else None
        comparison = compare_report_findings(report, previous_report)
        scanner.comparison = comparison

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{slugify(scanner.scan_name)}_{stamp}"
        json_name = f"{base_name}.json"
        csv_name = f"{base_name}.csv"
        html_name = f"{base_name}.html"

        scanner.save_json_report(str(REPORTS_DIR / json_name))
        scanner.save_csv_report(str(REPORTS_DIR / csv_name))
        scanner.save_html_report(str(REPORTS_DIR / html_name))

        report_files = {
            "json": f"/reports/{json_name}",
            "csv": f"/reports/{csv_name}",
            "html": f"/reports/{html_name}",
        }

        report["report_files"] = report_files
        report["affected_hosts"] = infer_hosts(report["scan"]["targets"], report["target"])

        history_entry = {
            "scan_name": report["scan"]["name"],
            "target": report["target"],
            "type": report["scan"]["type"],
            "started": report["scan_date"],
            "duration_seconds": report["duration_seconds"],
            "status": "Complete",
            "summary": report["summary"],
            "findings_count": len(report["findings"]),
            "report_files": report_files,
            "affected_hosts": report["affected_hosts"],
            "report": report,
        }

        with STATE_LOCK:
            STATE["latest_scan"] = report
            STATE["history"] = [history_entry] + STATE["history"][:9]
            save_state()

        return report
    finally:
        with ACTIVE_SCANS_LOCK:
            ACTIVE_SCANS.pop(scan_id, None)


def start_scan_job(payload):
    scan_id = (payload.get("scan_id") or secrets.token_urlsafe(12)).strip()
    payload = {**payload, "scan_id": scan_id}
    job = {
        "scan_id": scan_id,
        "status": "queued",
        "created": iso_now(),
        "updated": iso_now(),
        "report": None,
        "error": None,
    }
    with SCAN_JOBS_LOCK:
        SCAN_JOBS[scan_id] = job

    def worker():
        with SCAN_JOBS_LOCK:
            job["status"] = "running"
            job["updated"] = iso_now()
        try:
            report = execute_scan_payload(payload)
            with SCAN_JOBS_LOCK:
                job["status"] = "complete"
                job["report"] = report
                job["updated"] = iso_now()
        except ScanCancelled as exc:
            with SCAN_JOBS_LOCK:
                job["status"] = "cancelled"
                job["error"] = str(exc)
                job["updated"] = iso_now()
        except Exception as exc:
            with SCAN_JOBS_LOCK:
                job["status"] = "failed"
                job["error"] = str(exc)
                job["updated"] = iso_now()

    thread = threading.Thread(target=worker, name=f"CyberScanJob-{scan_id}", daemon=True)
    thread.start()
    return job


class CyberScanHandler(BaseHTTPRequestHandler):
    server_version = "CyberScanWeb/1.0"

    def log_message(self, format, *args):
        return

    def do_OPTIONS(self):
        self.send_response(204)
        origin = allowed_origin(self)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def do_GET(self):
        path = unquote(urlparse(self.path).path)

        if path in ("/", "/index.html", "/prototype.html"):
            if not INDEX_PATH.exists():
                self.send_error(404, "prototype.html not found")
                return
            content = INDEX_PATH.read_bytes()
            send_bytes(self, content, "text/html; charset=utf-8")
            return

        if path == "/api/state":
            with STATE_LOCK:
                payload = {
                    "latest_scan": STATE["latest_scan"],
                    "history": STATE["history"],
                    "template_reports": STATE["template_reports"],
                    "schedules": schedule_payload(),
                    "triage": STATE["triage"],
                    "current_user": current_user(self),
                    "roles": role_payload(),
                }
            send_json(self, payload)
            return

        if path == "/api/session":
            send_json(self, {
                "current_user": current_user(self),
                "roles": role_payload(),
            })
            return

        if path == "/api/health":
            with STATE_LOCK:
                latest = STATE["history"][0] if STATE["history"] else None
                payload = {
                    "status": "ok",
                    "service": "CyberScan",
                    "reports_dir": str(REPORTS_DIR),
                    "saved_scans": len(STATE["history"]),
                    "saved_reports": len(STATE["template_reports"]),
                    "latest_scan": latest.get("started") if latest else None,
                    "schedules_enabled": sum(
                        1 for schedule in STATE["schedules"].values()
                        if schedule.get("enabled")
                    ),
                }
            send_json(self, payload)
            return

        if path.startswith("/api/scan/jobs/"):
            scan_id = Path(path).name
            with SCAN_JOBS_LOCK:
                job = SCAN_JOBS.get(scan_id)
                payload = dict(job) if job else None
            if not payload:
                send_json(self, {"error": "Scan job not found."}, status=404)
                return
            send_json(self, payload)
            return

        if path.startswith("/reports/"):
            filename = Path(path).name
            file_path = REPORTS_DIR / filename
            if not file_path.exists():
                self.send_error(404, "Report not found")
                return

            content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
            send_bytes(self, file_path.read_bytes(), content_type)
            return

        self.send_error(404, "Not found")

    def do_POST(self):
        path = unquote(urlparse(self.path).path)

        if not verify_post_origin(self):
            send_json(self, {"error": "Cross-origin POST requests are not allowed."}, status=403)
            return

        if path == "/api/login":
            try:
                payload = parse_json_body(self)
            except Exception as exc:
                send_json(self, {"error": f"Invalid JSON payload: {exc}"}, status=400)
                return

            email = (payload.get("email") or "").strip() or OWNER_PROFILE["email"]
            password = (payload.get("password") or "").strip()
            if not password or not password_is_valid(password):
                send_json(self, {"error": "Invalid owner credentials."}, status=401)
                return

            challenge_id, expires_at, sent_email, demo_code = create_otp_challenge(email)

            send_json(self, {
                "otp_required": True,
                "challenge_id": challenge_id,
                "email": email,
                "expires_at": expires_at.isoformat(timespec="seconds"),
                "delivery": "email" if sent_email else "temporary",
                "demo_otp": demo_code,
                "message": "Verification code sent to the owner email." if sent_email else "Temporary local email OTP generated for prototype sign-in.",
            })
            return

        if path == "/api/verify-otp":
            try:
                payload = parse_json_body(self)
            except Exception as exc:
                send_json(self, {"error": f"Invalid JSON payload: {exc}"}, status=400)
                return

            try:
                email = verify_otp_challenge(payload.get("challenge_id"), payload.get("code"))
            except ValueError as exc:
                send_json(self, {"error": str(exc)}, status=401)
                return

            user = build_user(email=email)
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = user
            send_json(self, {
                "current_user": user,
                "roles": role_payload(),
            }, extra_headers={"Set-Cookie": session_cookie_header(token)})
            return

        if path == "/api/logout":
            token = cookie_token(self)
            if token:
                SESSIONS.pop(token, None)
            send_json(self, {
                "current_user": None,
                "roles": role_payload(),
            }, extra_headers={"Set-Cookie": clear_session_cookie_header()})
            return

        if path == "/api/report/generate":
            try:
                payload = parse_json_body(self)
                template = (payload.get("template") or "").strip()
                with STATE_LOCK:
                    entry = create_template_report(template, source="manual")
                    save_automation_state()
                send_json(self, {
                    "report": entry,
                    "template_reports": STATE["template_reports"],
                    "schedules": schedule_payload(),
                })
            except Exception as exc:
                send_json(self, {"error": f"Report generation failed: {exc}"}, status=400)
            return

        if path == "/api/report/schedule":
            try:
                payload = parse_json_body(self)
                template = (payload.get("template") or "").strip()
                enabled = bool(payload.get("enabled", True))
                if template not in TEMPLATE_CONFIG:
                    raise ValueError("Unknown report template.")

                with STATE_LOCK:
                    if enabled:
                        now = datetime.now()
                        schedule = STATE["schedules"].get(template, {})
                        schedule.update({
                            "template": template,
                            "enabled": True,
                            "frequency": "weekly",
                            "updated": iso_now(),
                            "next_run": (now + timedelta(days=7)).isoformat(timespec="seconds"),
                        })
                        entry = create_template_report(template, source="scheduled")
                        schedule["last_run"] = entry["generated"]
                        STATE["schedules"][template] = schedule
                    else:
                        schedule = STATE["schedules"].get(template, {"template": template})
                        schedule.update({
                            "enabled": False,
                            "updated": iso_now(),
                        })
                        STATE["schedules"][template] = schedule
                    save_automation_state()

                send_json(self, {
                    "template": template,
                    "enabled": enabled,
                    "template_reports": STATE["template_reports"],
                    "schedules": schedule_payload(),
                })
            except Exception as exc:
                send_json(self, {"error": f"Report schedule failed: {exc}"}, status=400)
            return

        if path == "/api/findings/triage":
            user = current_user(self)
            if not has_permission(user, "finding:triage"):
                send_json(self, {
                    "error": "Finding triage access is not available.",
                    "required_permission": "finding:triage",
                }, status=403)
                return

            try:
                payload = parse_json_body(self)
                updates = payload.get("updates") or []
                if isinstance(updates, dict):
                    updates = [updates]
                with STATE_LOCK:
                    for update in updates:
                        key = str(update.get("fingerprint") or update.get("key") or "").strip()
                        if not key:
                            continue
                        entry = STATE["triage"].get(key, {})
                        if "status" in update:
                            entry["status"] = str(update.get("status") or "").strip()
                        if "owner_review" in update:
                            entry["owner_review"] = str(update.get("owner_review") or "").strip()
                        if "hidden" in update:
                            entry["hidden"] = bool(update.get("hidden"))
                        entry["updated"] = iso_now()
                        STATE["triage"][key] = entry
                    annotate_report_findings(STATE["latest_scan"])
                    for history_entry in STATE["history"]:
                        annotate_report_findings(history_entry.get("report"))
                    save_triage_state()
                    save_state()
                    response = {"triage": STATE["triage"], "latest_scan": STATE["latest_scan"]}
                send_json(self, response)
            except Exception as exc:
                send_json(self, {"error": f"Finding triage failed: {exc}"}, status=400)
            return

        if path == "/api/scan/cancel":
            try:
                payload = parse_json_body(self)
            except Exception as exc:
                send_json(self, {"error": f"Invalid JSON payload: {exc}"}, status=400)
                return

            scan_id = (payload.get("scan_id") or "").strip()
            if not scan_id:
                send_json(self, {"error": "A scan_id is required."}, status=400)
                return

            with ACTIVE_SCANS_LOCK:
                cancel_event = ACTIVE_SCANS.get(scan_id)

            if not cancel_event:
                send_json(self, {"status": "not_found", "message": "No active scan found for that ID."}, status=404)
                return

            cancel_event.set()
            send_json(self, {"status": "cancelling", "scan_id": scan_id})
            return

        if path != "/api/scan":
            self.send_error(404, "Not found")
            return

        user = current_user(self)
        if not has_permission(user, "scan:start"):
            send_json(self, {
                "error": "Scan access is not available.",
                "required_permission": "scan:start",
            }, status=403)
            return

        try:
            payload = parse_json_body(self)
        except Exception as exc:
            send_json(self, {"error": f"Invalid JSON payload: {exc}"}, status=400)
            return

        if not payload.get("authorized"):
            send_json(self, {
                "error": "Confirm that you own the target or have explicit permission to scan it before starting.",
                "required_confirmation": "authorized",
            }, status=400)
            return

        try:
            if payload.get("background"):
                job = start_scan_job(payload)
                send_json(self, job, status=202)
                return
            report = execute_scan_payload(payload)
            send_json(self, report)
        except ScanCancelled as exc:
            send_json(self, {"error": str(exc), "cancelled": True, "scan_id": payload.get("scan_id")}, status=499)
        except ValueError as exc:
            send_json(self, {"error": str(exc)}, status=400)
        except Exception as exc:
            send_json(self, {"error": f"Scan failed: {exc}"}, status=500)


def main():
    parser = argparse.ArgumentParser(description="CyberScan local web app")
    parser.add_argument("--host", default=os.environ.get("HOST", os.environ.get("CYBERSCAN_HOST", "127.0.0.1")), help="Bind host")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", os.environ.get("CYBERSCAN_PORT", "8006"))), help="Bind port")
    args = parser.parse_args()

    load_state()
    scheduler_stop = threading.Event()
    start_scheduler(scheduler_stop)
    server = ThreadingHTTPServer((args.host, args.port), CyberScanHandler)
    print(f"CyberScan web app running at http://{args.host}:{args.port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down CyberScan web app...")
    finally:
        scheduler_stop.set()
        server.server_close()


if __name__ == "__main__":
    main()
