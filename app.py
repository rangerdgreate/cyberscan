import argparse
import csv
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import smtplib
import threading
import time
from email.message import EmailMessage
from functools import wraps
from html import escape as html_escape
from http.cookies import SimpleCookie
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse
from dotenv import load_dotenv

load_dotenv()

import requests
from cyberscan import (
    CyberScan,
    ScanCancelled,
    api_scanner as tool_api_scanner,
    authorized_password_security_audit as tool_password_audit,
    cloud_configuration_check as tool_cloud_check,
    cookie_security_check as tool_cookie_security,
    domain_finder as tool_domain_finder,
    drupal_scanner as tool_drupal_scanner,
    exposed_path_check as tool_exposed_path,
    form_inspector as tool_form_inspector,
    joomla_scanner as tool_joomla_scanner,
    kubernetes_configuration_check as tool_kubernetes_check,
    mixed_content_check as tool_mixed_content,
    network_scanner as tool_network_scanner,
    port_scanner as tool_port_scanner,
    reflected_xss_safe_marker_checker as tool_xss_checker,
    report_generator as tool_report_generator,
    request_logger as tool_request_logger,
    security_header_check as tool_security_headers,
    sql_error_pattern_checker as tool_sql_checker,
    ssl_tls_check as tool_ssl_scanner,
    subdomain_finder as tool_subdomain_finder,
    url_fuzzer as tool_url_fuzzer,
    virtual_host_finder as tool_virtual_host_finder,
    waf_detector as tool_waf_detector,
    website_recon as tool_website_recon,
    website_scanner as tool_website_scanner,
    wordpress_scanner as tool_wordpress_scanner,
)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

try:
    from flask_mail import Mail, Message as FlaskMailMessage
except ImportError:
    Mail = None
    FlaskMailMessage = None

try:
    from pymongo import MongoClient, DESCENDING
except ImportError:
    MongoClient = None
    DESCENDING = -1

try:
    from bson import ObjectId
except ImportError:
    ObjectId = None


ROOT = Path(__file__).resolve().parent
if load_dotenv:
    load_dotenv()
INDEX_PATH = ROOT / "prototype.html"
REPORTS_DIR = ROOT / "reports"
DATA_DIR = ROOT / "data"
HISTORY_PATH = REPORTS_DIR / "history.json"
AUTOMATION_PATH = REPORTS_DIR / "automation.json"
TRIAGE_PATH = REPORTS_DIR / "triage.json"
AUDIT_LOG_PATH = DATA_DIR / "audit_log.jsonl"
REPORT_SHARES_PATH = DATA_DIR / "report_shares.json"
SECURITY_PATH = DATA_DIR / "security.json"
USERS_PATH = DATA_DIR / "users.json"
EMAIL_VERIFICATIONS_PATH = DATA_DIR / "email_verifications.json"
MONGO_URI = os.environ.get("MONGO_URI", os.environ.get("CYBERSCAN_MONGO_URI", "")).strip()
MONGO_URI_DB = (urlparse(MONGO_URI).path or "").lstrip("/") if MONGO_URI else ""
MONGO_DB_NAME = os.environ.get("CYBERSCAN_MONGO_DB", os.environ.get("MONGO_DB", MONGO_URI_DB or "cyberscan_db")).strip() or "cyberscan_db"
MONGO_TIMEOUT_MS = int(os.environ.get("CYBERSCAN_MONGO_TIMEOUT_MS", "2000"))

REPORTS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

STATE_LOCK = threading.Lock()
STATE = {
    "latest_scan": None,
    "history": [],
    "template_reports": [],
    "schedules": {},
    "triage": {},
}
SECURITY_STATE = {
    "owner_password_hash": "",
    "owner_email": "",
    "owner_name": "",
    "updated": None,
}
MONGO_CLIENT = None
MONGO_DB = None

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
OWNER_EMAIL = os.environ.get("CYBERSCAN_OWNER_EMAIL", os.environ.get("MAIL_DEFAULT_SENDER", os.environ.get("MAIL_USERNAME", "owner@localhost"))).strip() or "owner@localhost"
OWNER_NAME = os.environ.get("CYBERSCAN_OWNER_NAME", "Owner").strip() or "Owner"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@cyberscan.local").strip()
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
OTP_TTL_MINUTES = int(os.environ.get("CYBERSCAN_OTP_TTL_MINUTES", "10"))
SMTP_HOST = os.environ.get("MAIL_SERVER", os.environ.get("CYBERSCAN_SMTP_HOST", ""))
SMTP_PORT = int(os.environ.get("MAIL_PORT", os.environ.get("CYBERSCAN_SMTP_PORT", "587")))
SMTP_USERNAME = os.environ.get("MAIL_USERNAME", os.environ.get("CYBERSCAN_SMTP_USERNAME", ""))
# Gmail SMTP does not accept your normal Gmail password.
# Use a Google App Password, which requires 2-Step Verification.
# MAIL_PASSWORD should be the 16-character app password with spaces removed.
SMTP_PASSWORD = os.environ.get("MAIL_PASSWORD", os.environ.get("CYBERSCAN_SMTP_PASSWORD", "")).replace(" ", "")
SMTP_FROM = os.environ.get("MAIL_DEFAULT_SENDER", os.environ.get("CYBERSCAN_SMTP_FROM", SMTP_USERNAME))
SMTP_USE_TLS = os.environ.get("MAIL_USE_TLS", os.environ.get("CYBERSCAN_SMTP_USE_TLS", "true")).strip().lower() not in {"0", "false", "no", "off"}
SMTP_USE_SSL = os.environ.get("MAIL_USE_SSL", os.environ.get("CYBERSCAN_SMTP_USE_SSL", "false")).strip().lower() in {"1", "true", "yes", "on"}
DEV_MODE = os.environ.get("DEV_MODE", os.environ.get("CYBERSCAN_DEV_MODE", "false")).strip().lower() in {"1", "true", "yes", "on"}
BASE_URL = os.environ.get("BASE_URL", os.environ.get("CYBERSCAN_BASE_URL", "http://127.0.0.1:8006")).strip().rstrip("/") or "http://127.0.0.1:8006"
EMAIL_SETTINGS = {
    "smtp_host": SMTP_HOST,
    "smtp_port": SMTP_PORT,
    "smtp_username": SMTP_USERNAME,
    "smtp_password": SMTP_PASSWORD,
    "smtp_from": SMTP_FROM,
    "smtp_use_tls": SMTP_USE_TLS,
    "smtp_use_ssl": SMTP_USE_SSL,
}
EMAIL_LAST_ERROR = ""
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

USER_PERMISSIONS = [
    "dashboard:view",
    "scan:start",
    "scan:configure",
    "finding:view",
    "finding:triage",
    "report:export",
]

OWNER_PROFILE = {
    "email": OWNER_EMAIL,
    "name": OWNER_NAME,
    "initials": "".join(part[:1] for part in OWNER_NAME.split()[:2]).upper() or "OW",
    "role": "Admin",
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


def init_mongo():
    global MONGO_CLIENT, MONGO_DB
    if not MONGO_URI or MongoClient is None:
        return False
    try:
        MONGO_CLIENT = MongoClient(MONGO_URI, serverSelectionTimeoutMS=MONGO_TIMEOUT_MS)
        MONGO_CLIENT.admin.command("ping")
        MONGO_DB = MONGO_CLIENT[MONGO_DB_NAME]
        return True
    except Exception as exc:
        MONGO_CLIENT = None
        MONGO_DB = None
        print(f"[!] MongoDB unavailable, using file storage fallback: {exc}")
        return False


def mongo_enabled():
    return MONGO_DB is not None


def mongo_collection(name):
    if not mongo_enabled():
        return None
    return MONGO_DB[name]


def ensure_mongo_indexes():
    if not mongo_enabled():
        return
    try:
        MONGO_DB.users.create_index("email_normalized", unique=True, sparse=True)
        MONGO_DB.users.create_index("username_normalized", unique=True, sparse=True)
        MONGO_DB.users.create_index("role")
        MONGO_DB.users.create_index("is_active")
        MONGO_DB.pending_email_verifications.create_index("token_hash", unique=True)
        MONGO_DB.pending_email_verifications.create_index("email_normalized")
        MONGO_DB.pending_email_verifications.create_index("expires_at", expireAfterSeconds=0)
        MONGO_DB.scans.create_index("started_at")
        MONGO_DB.scans.create_index("user_email")
        MONGO_DB.findings.create_index("scan_id")
        MONGO_DB.request_logs.create_index("scan_id")
    except Exception as exc:
        print(f"[!] MongoDB index setup failed: {exc}")


def strip_mongo_id(document):
    if isinstance(document, dict):
        document.pop("_id", None)
    return document


def mongo_upsert_single(collection_name, key, value):
    collection = mongo_collection(collection_name)
    if collection is None:
        return False
    try:
        collection.replace_one({"_key": key}, {"_key": key, "value": value}, upsert=True)
        return True
    except Exception as exc:
        print(f"[!] MongoDB write failed for {collection_name}: {exc}")
        return False


def mongo_load_single(collection_name, key):
    collection = mongo_collection(collection_name)
    if collection is None:
        return None
    try:
        document = collection.find_one({"_key": key}, {"_id": 0})
        return document.get("value") if document else None
    except Exception as exc:
        print(f"[!] MongoDB read failed for {collection_name}: {exc}")
        return None


def empty_account_state():
    return {
        "latest_scan": None,
        "history": [],
        "template_reports": [],
        "schedules": {},
        "triage": {},
    }


def normalize_email(email):
    return str(email or "").strip().lower()


def account_state_key(email):
    return normalize_email(email) or "owner"


def is_owner_email(email):
    return normalize_email(email) == normalize_email(owner_email())


def load_user_state(email):
    if is_owner_email(email):
        return STATE
    state = empty_account_state()
    mongo_state = mongo_load_single("user_state", account_state_key(email))
    if isinstance(mongo_state, dict):
        state.update({
            "latest_scan": mongo_state.get("latest_scan"),
            "history": mongo_state.get("history", []),
            "template_reports": mongo_state.get("template_reports", []),
            "schedules": mongo_state.get("schedules", {}),
            "triage": mongo_state.get("triage", {}),
        })
    for entry in state["history"]:
        annotate_report_findings(entry.get("report"))
    annotate_report_findings(state["latest_scan"])
    return state


def save_user_state(email, state):
    if is_owner_email(email):
        save_state()
        save_automation_state()
        save_triage_state()
        return
    mongo_upsert_single("user_state", account_state_key(email), {
        "latest_scan": state.get("latest_scan"),
        "history": state.get("history", []),
        "template_reports": state.get("template_reports", []),
        "schedules": state.get("schedules", {}),
        "triage": state.get("triage", {}),
        "updated": iso_now(),
    })


def state_owns_report_file(state, filename):
    filename = Path(str(filename or "")).name
    if not filename:
        return False
    for entry in state.get("history", []):
        for report_path in (entry.get("report_files") or {}).values():
            if Path(str(report_path)).name == filename:
                return True
    for report in state.get("template_reports", []):
        for report_path in (report.get("report_files") or {}).values():
            if Path(str(report_path)).name == filename:
                return True
    latest = state.get("latest_scan") or {}
    for report_path in (latest.get("report_files") or {}).values():
        if Path(str(report_path)).name == filename:
            return True
    return False


def load_state():
    mongo_history = mongo_load_single("app_state", "history")
    mongo_automation = mongo_load_single("app_state", "automation")
    mongo_triage = mongo_load_single("app_state", "triage")
    if isinstance(mongo_history, list):
        STATE["history"] = mongo_history
        STATE["latest_scan"] = mongo_history[0].get("report") if mongo_history else None
    if isinstance(mongo_automation, dict):
        STATE["template_reports"] = mongo_automation.get("template_reports", [])
        STATE["schedules"] = mongo_automation.get("schedules", {})
    if isinstance(mongo_triage, dict):
        STATE["triage"] = mongo_triage

    if mongo_history is None and HISTORY_PATH.exists():
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
    if mongo_automation is None and AUTOMATION_PATH.exists():
        try:
            with open(AUTOMATION_PATH, "r", encoding="utf-8") as file:
                automation = json.load(file)
            STATE["template_reports"] = automation.get("template_reports", [])
            STATE["schedules"] = automation.get("schedules", {})
        except Exception:
            STATE["template_reports"] = []
            STATE["schedules"] = {}
    if mongo_triage is None and TRIAGE_PATH.exists():
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


def load_security_state():
    mongo_security = mongo_load_single("app_state", "security")
    if isinstance(mongo_security, dict):
        SECURITY_STATE.update({
            "owner_password_hash": mongo_security.get("owner_password_hash", ""),
            "owner_email": mongo_security.get("owner_email", ""),
            "owner_name": mongo_security.get("owner_name", ""),
            "updated": mongo_security.get("updated"),
        })
        return

    if not SECURITY_PATH.exists():
        return
    try:
        with open(SECURITY_PATH, "r", encoding="utf-8") as file:
            security = json.load(file)
        if isinstance(security, dict):
            SECURITY_STATE.update({
                "owner_password_hash": security.get("owner_password_hash", ""),
                "owner_email": security.get("owner_email", ""),
                "owner_name": security.get("owner_name", ""),
                "updated": security.get("updated"),
            })
    except Exception:
        SECURITY_STATE.update({"owner_password_hash": "", "owner_email": "", "owner_name": "", "updated": None})


def save_security_state():
    mongo_upsert_single("app_state", "security", SECURITY_STATE)
    with open(SECURITY_PATH, "w", encoding="utf-8") as file:
        json.dump(SECURITY_STATE, file, indent=2)


def env_mail_settings_present():
    return any(os.environ.get(key) for key in ("MAIL_SERVER", "MAIL_USERNAME", "MAIL_PASSWORD", "MAIL_DEFAULT_SENDER"))


def coerce_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def load_email_settings():
    settings = mongo_load_single("app_state", "email_settings")
    if isinstance(settings, dict) and not env_mail_settings_present():
        EMAIL_SETTINGS.update({
            "smtp_host": settings.get("smtp_host", EMAIL_SETTINGS.get("smtp_host", "")),
            "smtp_port": int(settings.get("smtp_port") or 587),
            "smtp_username": settings.get("smtp_username", EMAIL_SETTINGS.get("smtp_username", "")),
            "smtp_password": str(settings.get("smtp_password", EMAIL_SETTINGS.get("smtp_password", ""))).replace(" ", ""),
            "smtp_from": settings.get("smtp_from") or settings.get("smtp_username") or EMAIL_SETTINGS.get("smtp_from", ""),
            "smtp_use_tls": coerce_bool(settings.get("smtp_use_tls"), True),
            "smtp_use_ssl": coerce_bool(settings.get("smtp_use_ssl"), False),
        })


def public_email_settings():
    return {
        "smtp_host": EMAIL_SETTINGS.get("smtp_host", ""),
        "smtp_port": EMAIL_SETTINGS.get("smtp_port", 587),
        "smtp_username": EMAIL_SETTINGS.get("smtp_username", ""),
        "smtp_from": EMAIL_SETTINGS.get("smtp_from", ""),
        "smtp_use_tls": bool(EMAIL_SETTINGS.get("smtp_use_tls", True)),
        "smtp_use_ssl": bool(EMAIL_SETTINGS.get("smtp_use_ssl", False)),
        "smtp_configured": smtp_configured(),
    }


def save_email_settings(settings):
    existing_password = EMAIL_SETTINGS.get("smtp_password", "")
    password = str(settings.get("smtp_password") or "").strip().replace(" ", "") or existing_password
    try:
        port = int(settings.get("smtp_port") or 587)
    except (TypeError, ValueError):
        raise ValueError("SMTP port must be a number.")
    candidate = {
        "smtp_host": str(settings.get("smtp_host") or "").strip(),
        "smtp_port": port,
        "smtp_username": str(settings.get("smtp_username") or "").strip(),
        "smtp_password": password,
        "smtp_from": str(settings.get("smtp_from") or settings.get("smtp_username") or "").strip(),
        "smtp_use_tls": coerce_bool(settings.get("smtp_use_tls"), True),
        "smtp_use_ssl": coerce_bool(settings.get("smtp_use_ssl"), False),
    }
    if not all([
        candidate["smtp_host"],
        candidate["smtp_port"],
        candidate["smtp_username"],
        candidate["smtp_password"],
        candidate["smtp_from"],
    ]):
        raise ValueError("Complete SMTP host, port, username, app password, and sender email before enabling real OTP.")

    if not DEV_MODE:
        try:
            send_plain_email(
                candidate,
                candidate["smtp_username"],
                "CyberScan SMTP test",
                "CyberScan SMTP is configured correctly. Real email verification and OTP delivery can now be used.",
            )
        except Exception as exc:
            raise ValueError(f"SMTP test failed: {smtp_error_message(exc)}") from exc
    else:
        print("[DEV] SMTP settings saved without sending a test email because DEV_MODE=True.", flush=True)

    EMAIL_SETTINGS.update(candidate)
    try:
        from flask import current_app
        apply_mail_config_to_app(current_app)
    except RuntimeError:
        pass
    mongo_upsert_single("app_state", "email_settings", EMAIL_SETTINGS)
    write_audit_log("email_settings_updated", {
        "smtp_host": EMAIL_SETTINGS["smtp_host"],
        "smtp_username": EMAIL_SETTINGS["smtp_username"],
        "smtp_from": EMAIL_SETTINGS["smtp_from"],
        "password_stored": bool(EMAIL_SETTINGS["smtp_password"]),
    })
    return public_email_settings()


def migrate_legacy_created_owner_to_user():
    legacy_email = SECURITY_STATE.get("owner_email", "").strip()
    legacy_hash = SECURITY_STATE.get("owner_password_hash", "").strip()
    if not legacy_email or normalize_email(legacy_email) == normalize_email(OWNER_PROFILE["email"]) or not legacy_hash:
        return False
    if find_user_account(legacy_email):
        SECURITY_STATE.update({"owner_email": "", "owner_name": "", "owner_password_hash": "", "updated": iso_now()})
        save_security_state()
        return True
    collection = mongo_collection("users")
    if collection is None:
        return False
    account = {
        "email": legacy_email,
        "email_normalized": normalize_email(legacy_email),
        "name": SECURITY_STATE.get("owner_name") or "User",
        "role": "User",
        "password_hash": legacy_hash,
        "created": SECURITY_STATE.get("updated") or iso_now(),
        "updated": iso_now(),
        "migrated_from": "legacy_owner_security",
    }
    collection.insert_one(account)
    mongo_upsert_single("user_state", account_state_key(legacy_email), {**empty_account_state(), "updated": iso_now()})
    SECURITY_STATE.update({"owner_email": "", "owner_name": "", "owner_password_hash": "", "updated": iso_now()})
    save_security_state()
    write_audit_log("legacy_owner_account_migrated_to_user", {"email": legacy_email, "role": "User"})
    return True


def save_state():
    mongo_upsert_single("app_state", "history", STATE["history"])
    scans = mongo_collection("scans")
    if scans is not None:
        try:
            scans.delete_many({})
            if STATE["history"]:
                scans.insert_many(json.loads(json.dumps(STATE["history"])))
        except Exception as exc:
            print(f"[!] MongoDB scan history mirror failed: {exc}")
    with open(HISTORY_PATH, "w", encoding="utf-8") as file:
        json.dump(STATE["history"], file, indent=2)


def save_automation_state():
    mongo_upsert_single("app_state", "automation", {
        "template_reports": STATE["template_reports"],
        "schedules": STATE["schedules"],
    })
    with open(AUTOMATION_PATH, "w", encoding="utf-8") as file:
        json.dump({
            "template_reports": STATE["template_reports"],
            "schedules": STATE["schedules"],
        }, file, indent=2)


def save_triage_state():
    mongo_upsert_single("app_state", "triage", STATE["triage"])
    with open(TRIAGE_PATH, "w", encoding="utf-8") as file:
        json.dump(STATE["triage"], file, indent=2)


def load_json_file(path, default):
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)
        return data if isinstance(data, type(default)) else default
    except Exception:
        return default


def save_json_file(path, data):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(json_ready(data), file, indent=2)


def load_file_users():
    return load_json_file(USERS_PATH, [])


def save_file_users(users):
    save_json_file(USERS_PATH, users)


def load_file_verifications():
    return load_json_file(EMAIL_VERIFICATIONS_PATH, [])


def save_file_verifications(verifications):
    save_json_file(EMAIL_VERIFICATIONS_PATH, verifications)


def write_audit_log(action, details=None, actor=None):
    actor = actor or owner_email()
    now = datetime.now()
    entry = {
        "timestamp": now.isoformat(timespec="seconds"),
        "created_at": now,
        "actor": actor,
        "username": actor,
        "action": action,
        "details": details or {},
        "ip_address": "127.0.0.1",
    }
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as file:
        file.write(json.dumps(json_ready(entry)) + "\n")
    collection = mongo_collection("audit_logs")
    if collection is not None:
        try:
            collection.insert_one(entry)
        except Exception as exc:
            print(f"[!] MongoDB audit log write failed: {exc}")


def load_report_shares():
    mongo_shares = mongo_load_single("app_state", "report_shares")
    if isinstance(mongo_shares, dict):
        return mongo_shares
    if not REPORT_SHARES_PATH.exists():
        return {}
    try:
        with open(REPORT_SHARES_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_report_shares(shares):
    mongo_upsert_single("app_state", "report_shares", shares)
    with open(REPORT_SHARES_PATH, "w", encoding="utf-8") as file:
        json.dump(shares, file, indent=2)


def create_report_share(report_file):
    filename = Path(str(report_file or "")).name
    file_path = REPORTS_DIR / filename
    if not filename or not file_path.exists():
        raise ValueError("Report file is not available for sharing.")
    token = secrets.token_urlsafe(18)
    shares = load_report_shares()
    shares[token] = {
        "file": filename,
        "created": iso_now(),
        "expires": (datetime.now() + timedelta(days=7)).isoformat(timespec="seconds"),
        "access_count": 0,
    }
    save_report_shares(shares)
    write_audit_log("report_share_created", {"file": filename, "token": token[:8] + "..."})
    return token, shares[token]


def build_compliance_summary(report):
    findings = (report or {}).get("findings", []) or []
    owasp_categories = sorted({
        finding.get("owasp_category", "Unmapped")
        for finding in findings
        if finding.get("owasp_category")
    })
    cwe_mappings = sorted({
        finding.get("cwe", "CWE-N/A")
        for finding in findings
        if finding.get("cwe")
    })
    return {
        "frameworks": ["OWASP Top 10", "CWE"],
        "owasp_categories": owasp_categories,
        "cwe_mappings": cwe_mappings,
        "summary": "Findings are mapped to OWASP and CWE references where available for remediation planning.",
    }


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
    if SECURITY_STATE.get("owner_password_hash"):
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(digest, SECURITY_STATE["owner_password_hash"])
    if OWNER_PASSWORD_HASH:
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(digest, OWNER_PASSWORD_HASH)
    return hmac.compare_digest(password, OWNER_PASSWORD)


def password_hash(password):
    return hashlib.sha256(str(password or "").encode("utf-8")).hexdigest()


def verification_token_hash(token):
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def owner_email():
    return (SECURITY_STATE.get("owner_email") or OWNER_PROFILE["email"]).strip()


def owner_name():
    return (SECURITY_STATE.get("owner_name") or OWNER_PROFILE["name"]).strip()


def email_matches_owner(email):
    return str(email or "").strip().lower() == owner_email().lower()


def find_user_account(email):
    collection = mongo_collection("users")
    if collection is None:
        normalized = normalize_email(email)
        for user in load_file_users():
            if normalize_email(user.get("email")) == normalized:
                return user
        return None
    try:
        return collection.find_one({"email_normalized": normalize_email(email)}, {"_id": 0})
    except Exception as exc:
        print(f"[!] MongoDB user lookup failed: {exc}")
        return None


def find_user_by_username(username):
    collection = mongo_collection("users")
    if collection is None:
        normalized = str(username or "").strip().lower()
        for user in load_file_users():
            if str(user.get("username_normalized") or user.get("username") or "").strip().lower() == normalized:
                return user
        return None
    try:
        return collection.find_one({"username_normalized": str(username or "").strip().lower()}, {"_id": 0})
    except Exception as exc:
        print(f"[!] MongoDB username lookup failed: {exc}")
        return None


def account_for_login(identifier):
    if email_matches_owner(identifier):
        return {
            "email": owner_email(),
            "name": owner_name(),
            "role": "Admin",
            "password_hash": SECURITY_STATE.get("owner_password_hash") or "",
            "legacy_owner": True,
        }
    user = find_user_account(identifier)
    if not user:
        user = find_user_by_username(identifier)
    if user:
        return user
    return None


def account_password_is_valid(identifier, password):
    account = account_for_login(identifier)
    if not account:
        return False
    if account.get("legacy_owner") and not account.get("password_hash"):
        return password_is_valid(password)
    stored_hash = account.get("password_hash", "")
    if stored_hash.startswith(("scrypt:", "pbkdf2:", "argon2:")):
        return check_password_hash(stored_hash, password)
    digest = password_hash(password)
    return hmac.compare_digest(digest, stored_hash)


def password_policy_error(password):
    password = str(password or "")
    if len(password) < 8:
        return "Password must be at least 8 characters."
    return ""


def email_policy_error(email):
    email = str(email or "").strip()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return "Enter a valid email address."
    return ""


def update_owner_account(email, password, name="Owner"):
    email_error = email_policy_error(email)
    if email_error:
        raise ValueError(email_error)
    error = password_policy_error(password)
    if error:
        raise ValueError(error)
    SECURITY_STATE["owner_email"] = str(email).strip()
    SECURITY_STATE["owner_name"] = str(name or "Owner").strip() or "Owner"
    SECURITY_STATE["owner_password_hash"] = hashlib.sha256(password.encode("utf-8")).hexdigest()
    SECURITY_STATE["updated"] = iso_now()
    save_security_state()
    write_audit_log("owner_account_created", {"email": SECURITY_STATE["owner_email"], "password_stored": False})


def create_user_account(email, password, name="User", username="", email_verified=False):
    email_error = email_policy_error(email)
    if email_error:
        raise ValueError(email_error)
    error = password_policy_error(password)
    if error:
        raise ValueError(error)
    username = str(username or name or "").strip()
    if not username:
        raise ValueError("Username is required.")
    if email_matches_owner(email) or find_user_account(email):
        raise ValueError("An account already exists for that email.")
    if find_user_by_username(username):
        raise ValueError("That username is already taken.")
    collection = mongo_collection("users")
    if collection is None:
        account = {
            "id": secrets.token_urlsafe(10),
            "email": str(email).strip(),
            "email_normalized": normalize_email(email),
            "name": str(name or "User").strip() or "User",
            "username": username,
            "username_normalized": username.lower(),
            "role": "user",
            "password_hash": generate_password_hash(password),
            "email_verified": bool(email_verified),
            "is_active": True,
            "created": iso_now(),
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "updated": iso_now(),
        }
        users = load_file_users()
        users.append(account)
        save_file_users(users)
        save_user_state(account["email"], empty_account_state())
        write_audit_log("user_registered", {"email": account["email"], "role": "user", "password_stored": False})
        account.pop("password_hash", None)
        return account
    account = {
        "email": str(email).strip(),
        "email_normalized": normalize_email(email),
        "name": str(name or "User").strip() or "User",
        "username": username,
        "username_normalized": username.lower(),
        "role": "user",
        "password_hash": generate_password_hash(password),
        "email_verified": bool(email_verified),
        "is_active": True,
        "created": iso_now(),
        "created_at": datetime.now(),
        "updated": iso_now(),
    }
    collection.insert_one(account)
    save_user_state(account["email"], empty_account_state())
    write_audit_log("user_registered", {"email": account["email"], "role": "user", "password_stored": False})
    account.pop("password_hash", None)
    return account


def update_user_password(email, password):
    error = password_policy_error(password)
    if error:
        raise ValueError(error)
    collection = mongo_collection("users")
    if collection is None:
        users = load_file_users()
        for user in users:
            if normalize_email(user.get("email")) == normalize_email(email):
                user["password_hash"] = generate_password_hash(password)
                user["updated"] = iso_now()
                save_file_users(users)
                write_audit_log("user_password_reset", {"email": email, "password_stored": False}, actor=email)
                return
        raise ValueError("Account was not found.")
    result = collection.update_one(
        {"email_normalized": normalize_email(email)},
        {"$set": {"password_hash": generate_password_hash(password), "updated": iso_now()}},
    )
    if result.matched_count < 1:
        raise ValueError("Account was not found.")
    write_audit_log("user_password_reset", {"email": email, "password_stored": False}, actor=email)


def update_owner_password(password):
    error = password_policy_error(password)
    if error:
        raise ValueError(error)
    SECURITY_STATE["owner_password_hash"] = hashlib.sha256(password.encode("utf-8")).hexdigest()
    SECURITY_STATE["updated"] = iso_now()
    save_security_state()
    write_audit_log("owner_password_reset", {"storage": "data/security.json", "password_stored": False})


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
    account_email = email or owner_email()
    account = account_for_login(account_email)
    if account and not account.get("legacy_owner"):
        role = normalize_role(account.get("role"))
        permissions = OWNER_PERMISSIONS if role == "admin" else USER_PERMISSIONS
        user = {
            "email": account.get("email", account_email),
            "name": account.get("name", "User"),
            "username": account.get("username", account.get("name", "User")),
            "role": role,
            "is_active": account.get("is_active", True) is not False,
            "permissions": permissions,
        }
    else:
        user = OWNER_PROFILE.copy()
        user["email"] = owner_email()
        user["name"] = owner_name()
        user["username"] = owner_name()
        user["role"] = "admin"
        user["is_active"] = True
    initials = "".join(part[:1] for part in user["name"].split()[:2]).upper()
    user["initials"] = initials or "OW"
    return user


def smtp_configured():
    return bool(
        EMAIL_SETTINGS.get("smtp_host")
        and EMAIL_SETTINGS.get("smtp_port")
        and EMAIL_SETTINGS.get("smtp_from")
        and EMAIL_SETTINGS.get("smtp_username")
        and EMAIL_SETTINGS.get("smtp_password")
    )


def mail_config_payload(settings=None):
    settings = settings or EMAIL_SETTINGS
    return {
        "MAIL_SERVER": settings.get("smtp_host"),
        "MAIL_PORT": int(settings.get("smtp_port") or 587),
        "MAIL_USE_TLS": bool(settings.get("smtp_use_tls", True)),
        "MAIL_USE_SSL": bool(settings.get("smtp_use_ssl", False)),
        "MAIL_USERNAME": settings.get("smtp_username"),
        "MAIL_PASSWORD": settings.get("smtp_password"),
        "MAIL_DEFAULT_SENDER": settings.get("smtp_from") or settings.get("smtp_username"),
    }


def apply_mail_config_to_app(flask_app):
    flask_app.config.update(mail_config_payload())


def print_mail_debug():
    print("MAIL_SERVER loaded:", "yes" if EMAIL_SETTINGS.get("smtp_host") else "no", flush=True)
    print("MAIL_USERNAME loaded:", "yes" if EMAIL_SETTINGS.get("smtp_username") else "no", flush=True)
    print("MAIL_PASSWORD loaded:", "yes" if EMAIL_SETTINGS.get("smtp_password") else "no", flush=True)
    print("MAIL_DEFAULT_SENDER loaded:", "yes" if EMAIL_SETTINGS.get("smtp_from") else "no", flush=True)
    print("DEV_MODE value:", DEV_MODE, flush=True)
    print("BASE_URL value:", BASE_URL, flush=True)


def print_dev_verification_link(verification_link):
    print("==============================", flush=True)
    print("DEV VERIFICATION LINK:", flush=True)
    print(verification_link, flush=True)
    print("==========================================", flush=True)


def smtp_error_message(exc):
    message = str(exc).strip()
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "Gmail rejected the login. Use a 16-character Gmail App Password, not your normal Gmail password."
    if isinstance(exc, smtplib.SMTPConnectError):
        return "CyberScan could not connect to the SMTP server. Check smtp.gmail.com, port 587, and your internet connection."
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return "The SMTP server disconnected. Check the host, port, TLS setting, and internet connection."
    if isinstance(exc, TimeoutError):
        return "SMTP connection timed out. Check your internet connection and firewall."
    return message or exc.__class__.__name__


def send_plain_email(settings, recipient, subject, body):
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings["smtp_from"]
    message["To"] = recipient
    message.set_content(body)
    smtp_client = smtplib.SMTP_SSL if settings.get("smtp_use_ssl", False) else smtplib.SMTP
    with smtp_client(settings["smtp_host"], int(settings["smtp_port"]), timeout=15) as smtp:
        smtp.ehlo()
        if settings.get("smtp_use_tls", True) and not settings.get("smtp_use_ssl", False):
            smtp.starttls()
            smtp.ehlo()
        smtp.login(settings["smtp_username"], settings["smtp_password"])
        smtp.send_message(message)
    return True


def send_otp_email(email, code):
    if not smtp_configured():
        return False

    return send_plain_email(
        EMAIL_SETTINGS,
        email,
        "Your CyberScan verification code",
        "Your CyberScan verification code is:\n\n"
        f"{code}\n\n"
        f"This code expires in {OTP_TTL_MINUTES} minutes. If you did not request this, ignore this email.",
    )


def send_verification_email(email, verification_link, allow_dev_link=False):
    global EMAIL_LAST_ERROR
    EMAIL_LAST_ERROR = ""
    subject = "CyberScan Email Verification"
    body = (
        "Welcome to CyberScan.\n\n"
        "Please verify your email address to continue creating your account.\n"
        "This verification link will expire in 15 minutes.\n\n"
        f"{verification_link}\n\n"
        "If you did not request this account, ignore this email."
    )
    print_mail_debug()
    if DEV_MODE and allow_dev_link:
        print_dev_verification_link(verification_link)
        return True

    if not smtp_configured():
        missing = []
        if not EMAIL_SETTINGS.get("smtp_host"):
            missing.append("MAIL_SERVER")
        if not EMAIL_SETTINGS.get("smtp_username"):
            missing.append("MAIL_USERNAME")
        if not EMAIL_SETTINGS.get("smtp_password"):
            missing.append("MAIL_PASSWORD")
        if not EMAIL_SETTINGS.get("smtp_from"):
            missing.append("MAIL_DEFAULT_SENDER")
        EMAIL_LAST_ERROR = f"SMTP is incomplete. Missing: {', '.join(missing)}."
        print(f"[EMAIL ERROR] {EMAIL_LAST_ERROR}", flush=True)
        return False

    try:
        send_plain_email(
            EMAIL_SETTINGS,
            email,
            subject,
            body,
        )
        return True
    except Exception as exc:
        EMAIL_LAST_ERROR = smtp_error_message(exc)
        print(f"[EMAIL ERROR] {EMAIL_LAST_ERROR}", flush=True)
        return False


def send_account_verification_email(email, verification_link):
    return send_verification_email(email, verification_link)


def local_verification_links_allowed(base_url):
    host = urlparse(str(base_url or "")).hostname or ""
    return DEV_MODE and host.lower() in {"127.0.0.1", "localhost", "::1"}


def start_email_verification(email, base_url):
    email_error = email_policy_error(email)
    if email_error:
        raise ValueError(email_error)
    if email_matches_owner(email) or find_user_account(email):
        raise ValueError("An account already exists for that email.")
    email = str(email).strip()
    normalized = normalize_email(email)
    collection = mongo_collection("pending_email_verifications")
    latest = None
    if collection is not None:
        latest = collection.find_one({"email_normalized": normalized, "used": False}, sort=[("created_at", DESCENDING)])
    else:
        pending = [item for item in load_file_verifications() if item.get("email_normalized") == normalized and not item.get("used")]
        pending.sort(key=lambda item: item.get("created_at", ""), reverse=True)
        latest = pending[0] if pending else None
    if latest:
        created = latest.get("last_sent_at") or latest.get("created_at")
        if isinstance(created, str):
            created = parse_iso(created)
        if created and datetime.now() - created < timedelta(seconds=60):
            raise ValueError("Please wait 60 seconds before requesting another verification email.")
    token = secrets.token_urlsafe(32)
    token_hash = verification_token_hash(token)
    now = datetime.now()
    document = {
        "email": email,
        "email_normalized": normalized,
        "token_hash": token_hash,
        "expires_at": now + timedelta(minutes=15),
        "used": False,
        "created_at": now,
        "last_sent_at": now,
    }
    verification_link = f"{(base_url or BASE_URL).rstrip('/')}/verify-email/{token}"
    allow_dev_link = local_verification_links_allowed(base_url or BASE_URL)
    sent = send_verification_email(email, verification_link, allow_dev_link=allow_dev_link)
    if not sent and not allow_dev_link:
        detail = EMAIL_LAST_ERROR or "Check Gmail SMTP settings on Render."
        raise ValueError(f"Verification email could not be sent. {detail}")
    if collection is not None:
        collection.insert_one(document)
    else:
        verifications = load_file_verifications()
        verifications.append(document)
        save_file_verifications(verifications)
    if not sent:
        print_dev_verification_link(verification_link)
        write_audit_log("registration_verification_local_link", {"email": email, "delivery": "local_link"})
    else:
        write_audit_log("registration_verification_sent", {"email": email, "delivery": "development_terminal" if DEV_MODE else "email"})
    return {
        "email": email,
        "sent": True,
        "development_mode": allow_dev_link or not sent,
        "development_link": verification_link if allow_dev_link or not sent else "",
    }


def consume_email_verification(token):
    collection = mongo_collection("pending_email_verifications")
    token_hash = verification_token_hash(token)
    document = None
    if collection is not None:
        document = collection.find_one({"token_hash": token_hash, "used": False}, {"_id": 0})
    else:
        for item in load_file_verifications():
            if item.get("token_hash") == token_hash and not item.get("used"):
                document = item
                break
    if not document:
        raise ValueError("Verification link is invalid or has already been used.")
    expires = document.get("expires_at")
    if isinstance(expires, str):
        expires = parse_iso(expires)
    if not expires or expires < datetime.now():
        raise ValueError("Verification link has expired.")
    if collection is not None:
        collection.update_one({"token_hash": token_hash}, {"$set": {"used": True, "used_at": datetime.now()}})
    else:
        verifications = load_file_verifications()
        for item in verifications:
            if item.get("token_hash") == token_hash:
                item["used"] = True
                item["used_at"] = datetime.now().isoformat(timespec="seconds")
                break
        save_file_verifications(verifications)
    return document["email"]


def create_otp_challenge(email):
    code = f"{secrets.randbelow(1_000_000):06d}"
    challenge_id = secrets.token_urlsafe(24)
    expires_at = datetime.now() + timedelta(minutes=OTP_TTL_MINUTES)
    if not smtp_configured():
        raise ValueError("Real email OTP is not configured. Sign in as Admin and configure Gmail SMTP/App Password in Settings.")
    try:
        send_otp_email(email, code)
    except Exception as exc:
        raise ValueError(f"Could not send OTP email. {smtp_error_message(exc)}") from exc
    with OTP_LOCK:
        PENDING_OTPS[challenge_id] = {
            "email": email,
            "code_hash": hashlib.sha256(code.encode("utf-8")).hexdigest(),
            "expires_at": expires_at,
            "attempts": 0,
        }
    return challenge_id, expires_at, True, None


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
    return None


def has_permission(user, permission):
    return bool(user and permission in user.get("permissions", []))


def normalize_role(role):
    role = str(role or "user").strip().lower()
    return "admin" if role == "admin" else "user"


def is_admin_user(user):
    return normalize_role((user or {}).get("role")) == "admin"


def role_payload():
    return {"admin": OWNER_PERMISSIONS, "user": USER_PERMISSIONS}


def sync_roles_to_mongo():
    collection = mongo_collection("roles")
    if collection is None:
        return False
    try:
        for role, permissions in role_payload().items():
            collection.replace_one(
                {"name": role},
                {"name": role, "permissions": permissions, "updated": iso_now()},
                upsert=True,
            )
        return True
    except Exception as exc:
        print(f"[!] MongoDB role sync failed: {exc}")
        return False


def valid_object_id(value):
    if ObjectId is None:
        return None
    try:
        return ObjectId(str(value))
    except Exception:
        return None


def create_default_admin():
    users = mongo_collection("users")
    if users is None:
        existing = [user for user in load_file_users() if normalize_role(user.get("role")) == "admin"]
        if existing:
            return False
        if not ADMIN_EMAIL or not ADMIN_PASSWORD:
            print("[!] ADMIN_EMAIL and ADMIN_PASSWORD are required to create the default admin account.")
            return False
        now = datetime.now().isoformat(timespec="seconds")
        file_users = load_file_users()
        file_users.append({
            "id": secrets.token_urlsafe(10),
            "email": ADMIN_EMAIL,
            "email_normalized": normalize_email(ADMIN_EMAIL),
            "username": ADMIN_USERNAME,
            "username_normalized": ADMIN_USERNAME.lower(),
            "name": ADMIN_USERNAME,
            "password_hash": generate_password_hash(ADMIN_PASSWORD),
            "email_verified": True,
            "role": "admin",
            "is_active": True,
            "created": now,
            "created_at": now,
            "updated": now,
        })
        save_file_users(file_users)
        write_audit_log("default_admin_created", {"email": ADMIN_EMAIL, "username": ADMIN_USERNAME}, actor=ADMIN_EMAIL)
        print(f"[+] Default file-based admin account created: {ADMIN_EMAIL}", flush=True)
        return True
    existing = users.find_one({"role": {"$in": ["admin", "Admin"]}})
    if existing:
        return False
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        print("[!] ADMIN_EMAIL and ADMIN_PASSWORD are required to create the default admin account.")
        return False
    now = datetime.now()
    users.insert_one({
        "email": ADMIN_EMAIL,
        "email_normalized": normalize_email(ADMIN_EMAIL),
        "username": ADMIN_USERNAME,
        "username_normalized": ADMIN_USERNAME.lower(),
        "name": ADMIN_USERNAME,
        "password_hash": generate_password_hash(ADMIN_PASSWORD),
        "email_verified": True,
        "role": "admin",
        "is_active": True,
        "created": now.isoformat(timespec="seconds"),
        "created_at": now,
        "updated": now.isoformat(timespec="seconds"),
    })
    write_audit_log("default_admin_created", {"email": ADMIN_EMAIL, "username": ADMIN_USERNAME}, actor=ADMIN_EMAIL)
    print(f"[+] Default admin account created: {ADMIN_EMAIL}", flush=True)
    return True


def all_users():
    users = mongo_collection("users")
    if users is None:
        return [{key: value for key, value in user.items() if key != "password_hash"} for user in load_file_users()]
    return [json_ready(user) for user in users.find({}, {"password_hash": 0}).sort("created_at", DESCENDING)]


def default_system_settings():
    return {
        "default_max_pages": 10,
        "default_rate_limit": 1,
        "default_scan_type": "light",
        "max_fuzzer_requests": 20,
        "max_password_attempts": 5,
        "registration_enabled": True,
        "email_verification_enabled": True,
        "report_output_folder": "reports",
        "authorization_reminder": "Only scan websites you own or have written permission to test.",
    }


def load_system_settings():
    settings = default_system_settings()
    collection = mongo_collection("system_settings")
    stored = collection.find_one({"_key": "global"}, {"_id": 0}) if collection is not None else None
    if isinstance(stored, dict):
        stored.pop("_key", None)
        settings.update(stored)
    return settings


def save_system_settings(payload):
    settings = {
        "default_max_pages": int(payload.get("default_max_pages") or 10),
        "default_rate_limit": int(payload.get("default_rate_limit") or 1),
        "default_scan_type": str(payload.get("default_scan_type") or "light"),
        "max_fuzzer_requests": int(payload.get("max_fuzzer_requests") or 20),
        "max_password_attempts": int(payload.get("max_password_attempts") or 5),
        "registration_enabled": payload.get("registration_enabled") in {"on", True, "true", "1"},
        "email_verification_enabled": payload.get("email_verification_enabled") in {"on", True, "true", "1"},
        "report_output_folder": str(payload.get("report_output_folder") or "reports").strip() or "reports",
        "authorization_reminder": str(payload.get("authorization_reminder") or default_system_settings()["authorization_reminder"]).strip(),
        "updated_at": datetime.now(),
    }
    collection = mongo_collection("system_settings")
    if collection is not None:
        collection.replace_one({"_key": "global"}, {"_key": "global", **settings}, upsert=True)
    return settings


def default_tool_settings():
    categories = {}
    for category, keys in TOOL_CATEGORIES.items():
        for key in keys:
            categories.setdefault(key, category)
    return [
        {
            "tool_key": key,
            "tool_name": TOOL_LABELS.get(key, key.replace("_", " ").title()),
            "enabled": True,
            "category": categories.get(key, "Tools"),
            "updated_at": datetime.now(),
        }
        for key in TOOL_LABELS
    ]


def ensure_tool_settings():
    collection = mongo_collection("tool_settings")
    if collection is None:
        return default_tool_settings()
    for tool in default_tool_settings():
        collection.update_one(
            {"tool_key": tool["tool_key"]},
            {"$setOnInsert": tool},
            upsert=True,
        )
    return list(collection.find({}).sort("tool_name", 1))


def tool_is_enabled(tool_key):
    collection = mongo_collection("tool_settings")
    if collection is None:
        return True
    document = collection.find_one({"tool_key": tool_key})
    return document is None or document.get("enabled", True) is not False


def admin_scan_rows():
    scans = []
    if mongo_enabled():
        scans = list(MONGO_DB.scans.find({}).sort("started_at", DESCENDING).limit(200))
        for scan in scans:
            scan["findings_count"] = MONGO_DB.findings.count_documents({"scan_id": scan["_id"]})
    else:
        for entry in STATE.get("history", []):
            scans.append(entry)
    return json_ready(scans)


def admin_report_rows():
    rows = []
    for scan in admin_scan_rows():
        files = scan.get("report_files") or {}
        if not files and scan.get("report"):
            files = scan["report"].get("report_files") or {}
        for fmt, path in files.items():
            rows.append({
                "report_name": Path(str(path)).name,
                "user_email": scan.get("user_email") or scan.get("owner_email", ""),
                "target": scan.get("target", ""),
                "tool": scan.get("tool") or scan.get("scan_name", ""),
                "format": fmt.upper(),
                "created_at": scan.get("finished_at") or scan.get("started_at") or scan.get("started", ""),
                "scan_id": scan.get("scan_id") or scan.get("_id", ""),
                "path": path,
            })
    return rows


def admin_audit_rows(limit=200):
    logs = []
    collection = mongo_collection("audit_logs")
    if collection is not None:
        logs = list(collection.find({}).sort("created_at", DESCENDING).limit(limit))
        if not logs:
            logs = list(collection.find({}).sort("timestamp", DESCENDING).limit(limit))
    elif AUDIT_LOG_PATH.exists():
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as file:
            logs = [json.loads(line) for line in file if line.strip()][-limit:]
            logs.reverse()
    return json_ready(logs)


def admin_dashboard_metrics():
    users = all_users()
    scans = admin_scan_rows()
    reports = admin_report_rows()
    findings = []
    if mongo_enabled():
        findings = list(MONGO_DB.findings.find({}))
    else:
        for scan in scans:
            findings.extend((scan.get("report") or scan).get("findings", []))
    critical = sum(1 for finding in findings if str(finding.get("severity", "")).lower() == "critical")
    high = sum(1 for finding in findings if str(finding.get("severity", "")).lower() == "high")
    return {
        "total_users": len(users),
        "active_users": sum(1 for user in users if user.get("is_active", True) is not False),
        "disabled_users": sum(1 for user in users if user.get("is_active", True) is False),
        "total_scans": len(scans),
        "total_findings": len(findings),
        "critical_findings": critical,
        "high_findings": high,
        "reports_generated": len(reports),
        "recent_activity": admin_audit_rows(10),
        "recent_scans": scans[:10],
    }


def iso_now():
    return datetime.now().isoformat(timespec="seconds")


def parse_iso(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def latest_report_data(state=None):
    state = state or STATE
    if state["latest_scan"]:
        return state["latest_scan"]
    if state["history"]:
        return state["history"][0].get("report")
    return None


def template_report_html(template, report, generated_at, source):
    findings = report.get("findings", []) if report else []
    prevention_plan = report.get("prevention_plan", []) if report else []
    summary = report.get("summary", {}) if report else {}
    scan = report.get("scan", {}) if report else {}
    coverage = report.get("coverage", {}) if report else {}
    password_audit = report.get("password_audit") if report else None
    authorization = report.get("authorization", {}) if report else {}
    compliance = report.get("compliance") or build_compliance_summary(report or {})
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
    compliance_rows = "".join(
        f"<li>{html_escape(str(item))}</li>"
        for item in (compliance.get("owasp_categories") or compliance.get("cwe_mappings") or [])
    ) or "<li>No mapped findings yet.</li>"
    if password_audit:
        password_audit_section = (
            "<section>"
            "<h2>Authorized Password Security Audit</h2>"
            f"<p><strong>Target Login URL:</strong> {html_escape(str(password_audit.get('login_url', '')))}</p>"
            f"<p><strong>Attempt Count:</strong> {html_escape(str(password_audit.get('attempt_count', 0)))}</p>"
            f"<p><strong>Finding Severity:</strong> {html_escape(str(password_audit.get('severity', 'Info')))}</p>"
            f"<p><strong>Evidence:</strong> {html_escape(str(password_audit.get('evidence', '')))}</p>"
            f"<p><strong>Recommendation:</strong> {html_escape(str(password_audit.get('recommendation', 'Use strong password policies, rate limiting, account lockout, MFA, failed-login monitoring, and avoid default credentials.')))}</p>"
            f"<p><strong>Disclaimer:</strong> {html_escape(str(password_audit.get('disclaimer', 'This report is generated for authorized security testing only.')))}</p>"
            "</section>"
        )
    else:
        password_audit_section = (
            "<section>"
            "<h2>Authorized Password Security Audit</h2>"
            "<p>Password audit was not enabled for this scan.</p>"
            "<p><strong>Disclaimer:</strong> This report is generated for authorized security testing only.</p>"
            "</section>"
        )

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
      <p><strong>Authorized Organization:</strong> {html_escape(str(authorization.get("organization") or "Not provided"))}</p>
      <p><strong>Authorized Contact:</strong> {html_escape(str(authorization.get("contact") or "Not provided"))}</p>
      <p><strong>Approved Scope:</strong> {html_escape(str(authorization.get("scope") or target))}</p>
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
      <h2>Compliance Mapping</h2>
      <p>{html_escape(str(compliance.get("summary", "Findings are mapped for remediation planning.")))}</p>
      <ul>{compliance_rows}</ul>
    </section>
    {password_audit_section}
    <section>
      <h2>How to Prevent Recurrence</h2>
      <div class="prevention-grid">{''.join(prevention_cards)}</div>
    </section>
  </main>
</body>
</html>"""


def create_template_report(template, source="manual", state=None):
    if template not in TEMPLATE_CONFIG:
        raise ValueError("Unknown report template.")

    state = state or STATE
    report = latest_report_data(state)
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
    state["template_reports"] = [entry] + state["template_reports"][:24]
    return entry


def schedule_payload(state=None):
    state = state or STATE
    return {
        template: config
        for template, config in state["schedules"].items()
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


def mask_password(value):
    value = str(value or "")
    if not value:
        return ""
    return "*" * min(max(len(value), 4), 12)


def password_audit_check(
    login_url,
    username,
    password_list,
    max_attempts,
    delay_seconds,
    authorization_confirmed,
    stop_on_success=True,
    include_masked_evidence=True,
):
    if not authorization_confirmed:
        return {
            "status": "skipped",
            "severity": "Info",
            "title": "Password audit skipped because authorization was not confirmed",
            "login_url": login_url or "",
            "username": username or "",
            "attempt_count": 0,
            "weak_credential_detected": False,
            "response_status": "not_run",
            "evidence": "Authorization confirmation was not provided, so the password audit did not run.",
            "recommendation": "Only run password security auditing against systems you own or have written permission to test.",
            "disclaimer": "This module is for educational and authorized testing only.",
        }

    if isinstance(password_list, str):
        candidates = [item.strip() for item in re.split(r"[\n,]", password_list) if item.strip()]
    else:
        candidates = [str(item).strip() for item in (password_list or []) if str(item).strip()]

    try:
        requested_attempts = int(max_attempts or 0)
    except (TypeError, ValueError):
        requested_attempts = 0
    attempt_limit = max(1, min(10, requested_attempts or len(candidates) or 1))

    try:
        configured_delay = float(delay_seconds or 0)
    except (TypeError, ValueError):
        configured_delay = 0
    configured_delay = max(0, min(5, configured_delay))
    safe_runtime_delay = min(configured_delay, 0.25)

    limited_candidates = candidates[:attempt_limit]
    weak_values = {
        "admin",
        "admin123",
        "password",
        "password1",
        "password123",
        "123456",
        "12345678",
        "qwerty",
        "letmein",
        "default",
        "changeme",
        "welcome",
    }
    if username:
        normalized_user = str(username).strip().lower()
        weak_values.update({normalized_user, f"{normalized_user}123", f"{normalized_user}@123"})

    detected_password = ""
    attempts_used = 0
    for candidate in limited_candidates:
        attempts_used += 1
        if safe_runtime_delay and attempts_used > 1:
            time.sleep(safe_runtime_delay)
        if candidate.lower() in weak_values:
            detected_password = candidate
            if stop_on_success:
                break

    if detected_password:
        masked = mask_password(detected_password) if include_masked_evidence else "[masked]"
        return {
            "status": "detected",
            "severity": "High",
            "title": "Weak/default credential detected",
            "login_url": login_url or "",
            "username": username or "",
            "attempt_count": attempts_used,
            "attempt_limit": attempt_limit,
            "configured_delay_seconds": configured_delay,
            "weak_credential_detected": True,
            "response_status": "simulated_safe_match",
            "masked_password": masked,
            "evidence": f"Controlled audit matched a weak/default password candidate after {attempts_used} limited attempt(s). Password evidence is masked: {masked}.",
            "recommendation": "Use strong password policies, avoid default credentials, enable MFA, add rate limiting, enable account lockout, and monitor failed login attempts.",
            "disclaimer": "This module is for educational and authorized testing only.",
        }

    return {
        "status": "not_detected",
        "severity": "Info",
        "title": "No weak credential detected within limited attempts",
        "login_url": login_url or "",
        "username": username or "",
        "attempt_count": attempts_used,
        "attempt_limit": attempt_limit,
        "configured_delay_seconds": configured_delay,
        "weak_credential_detected": False,
        "response_status": "simulated_limited_audit_complete",
        "evidence": f"Controlled audit completed {attempts_used} limited attempt(s) with no weak/default credential match. Password values were not stored.",
        "recommendation": "Continue using strong password policies, MFA, rate limiting, account lockout, and failed-login monitoring.",
        "disclaimer": "This module is for educational and authorized testing only.",
    }


def execute_scan_payload(payload):
    scan_id, cancel_event, scanner = build_scanner_from_payload(payload)
    actor_email = payload.get("actor_email") or owner_email()
    with ACTIVE_SCANS_LOCK:
        ACTIVE_SCANS[scan_id] = cancel_event
    write_audit_log("scan_started", {
        "scan_id": scan_id,
        "target": payload.get("target"),
        "scan_name": payload.get("scan_name"),
    }, actor=actor_email)

    try:
        scanner.scan()
        password_audit = payload.get("password_audit") or {}
        password_audit_result = None
        if password_audit.get("enabled"):
            password_audit_result = password_audit_check(
                password_audit.get("login_url"),
                password_audit.get("username"),
                password_audit.get("password_list"),
                password_audit.get("max_attempts"),
                password_audit.get("delay_seconds"),
                password_audit.get("authorization_confirmed"),
                password_audit.get("stop_on_success", True),
            )
            scanner.password_audit_result = password_audit_result
            scanner.add_result(
                password_audit_result["title"],
                password_audit_result["severity"],
                "A07: Identification and Authentication Failures",
                password_audit_result["evidence"],
                password_audit_result["recommendation"],
                evidence=password_audit_result["evidence"],
                url=password_audit_result.get("login_url") or scanner.target_url,
                cwe="CWE-521",
                confidence="Medium" if password_audit_result["status"] == "detected" else "Low",
                validation_status="Needs Manual Validation" if password_audit_result["status"] == "detected" else "Informational",
            )
        report = scanner.build_report_data()
        if password_audit_result:
            report["password_audit"] = password_audit_result
        report["authorization"] = {
            "confirmed": bool(payload.get("authorized")),
            "organization": (payload.get("authorization") or {}).get("organization", ""),
            "contact": (payload.get("authorization") or {}).get("contact", ""),
            "scope": (payload.get("authorization") or {}).get("scope", ""),
            "confirmed_at": iso_now(),
            "disclaimer": "Scan was launched only after authorized-testing confirmation.",
        }
        report["compliance"] = build_compliance_summary(report)
        with STATE_LOCK:
            account_state = load_user_state(actor_email)
            previous_report = account_state["history"][0].get("report") if account_state["history"] else None
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
            "owner_email": actor_email,
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
            account_state = load_user_state(actor_email)
            account_state["latest_scan"] = report
            account_state["history"] = [history_entry] + account_state["history"][:9]
            save_user_state(actor_email, account_state)
        write_audit_log("scan_completed", {
            "scan_id": scan_id,
            "target": report.get("target"),
            "findings_count": len(report.get("findings", [])),
            "report_files": report_files,
        }, actor=actor_email)

        return report
    except Exception as exc:
        write_audit_log("scan_failed", {
            "scan_id": scan_id,
            "target": payload.get("target"),
            "error": str(exc),
        }, actor=actor_email)
        raise
    finally:
        with ACTIVE_SCANS_LOCK:
            ACTIVE_SCANS.pop(scan_id, None)


TOOL_SLUGS = {
    "website-scanner": "website_scanner",
    "network-scanner": "network_scanner",
    "subdomain-finder": "subdomain_finder",
    "port-scanner": "port_scanner",
    "url-fuzzer": "url_fuzzer",
    "website-recon": "website_recon",
    "domain-finder": "domain_finder",
    "virtual-host-finder": "virtual_host_finder",
    "waf-detector": "waf_detector",
    "ssl-scanner": "ssl_scanner",
    "api-scanner": "api_scanner",
    "wordpress-scanner": "wordpress_scanner",
    "drupal-scanner": "drupal_scanner",
    "joomla-scanner": "joomla_scanner",
    "password-audit": "password_audit",
    "sql-checker": "sql_checker",
    "xss-checker": "xss_checker",
    "request-logger": "request_logger",
    "report-generator": "report_generator",
    "html-report-generator": "report_generator",
    "json-report-generator": "report_generator",
    "csv-report-generator": "report_generator",
    "executive-summary-report": "report_generator",
    "risk-summary-report": "report_generator",
    "cloud-check": "cloud_check",
    "cloud-configuration-check": "cloud_check",
    "kubernetes-configuration-check": "kubernetes_check",
    "form-inspector": "form_inspector",
    "form-security-inspector": "form_inspector",
    "exposed-path": "exposed_path",
    "exposed-path-checker": "exposed_path",
    "http-request-logger": "request_logger",
}

TOOL_LABELS = {
    "website_scanner": "Website Scanner",
    "network_scanner": "Network Scanner",
    "subdomain_finder": "Subdomain Finder",
    "port_scanner": "Port Scanner",
    "url_fuzzer": "URL Fuzzer",
    "website_recon": "Website Recon",
    "domain_finder": "Domain Finder",
    "virtual_host_finder": "Virtual Host Finder",
    "waf_detector": "WAF Detector",
    "ssl_scanner": "SSL/TLS Scanner",
    "api_scanner": "API Scanner",
    "wordpress_scanner": "WordPress Scanner",
    "drupal_scanner": "Drupal Scanner",
    "joomla_scanner": "Joomla Scanner",
    "password_audit": "Password Security Audit",
    "sql_checker": "SQL Error Pattern Checker",
    "xss_checker": "Reflected XSS Safe Marker Checker",
    "request_logger": "Request Logger",
    "report_generator": "Report Generator",
    "cloud_check": "Cloud Exposure Check",
    "kubernetes_check": "Kubernetes Configuration Check",
    "form_inspector": "Form Inspector",
    "exposed_path": "Exposed Path Check",
}

TOOL_DESCRIPTIONS = {
    "website_scanner": "Combined safe web checks for headers, TLS, cookies, forms, exposed paths, recon, and mixed content.",
    "network_scanner": "Safe selected-port TCP checks with no subnet sweep, banner grabbing, or exploitation.",
    "subdomain_finder": "Small-list DNS resolver for authorized domain inventory.",
    "port_scanner": "Controlled TCP connect checks against selected common ports.",
    "url_fuzzer": "Capped URL discovery using a small wordlist and request delay.",
    "report_generator": "Generate safe scan reports for existing scan results.",
    "website_recon": "Collect status, title, headers, and basic page structure metadata.",
    "domain_finder": "Resolve a domain and check whether HTTP/HTTPS responds.",
    "virtual_host_finder": "Safe Host-header indicator checks using a small host list.",
    "waf_detector": "Look for possible WAF/CDN indicators without bypass attempts.",
    "api_scanner": "GET-only checks for common API and documentation paths.",
    "wordpress_scanner": "Safe WordPress indicator checks without plugin exploitation.",
    "drupal_scanner": "Safe Drupal indicator checks without module exploitation.",
    "joomla_scanner": "Safe Joomla indicator checks without component exploitation.",
    "ssl_scanner": "Basic HTTPS and certificate availability checks.",
    "cloud_check": "Checklist-style public cloud exposure prototype with no credentials or private APIs.",
    "kubernetes_check": "GET-only public Kubernetes indicator checks with no credentials.",
    "sql_checker": "Visible SQL error pattern analysis with optional harmless marker parameter.",
    "xss_checker": "Harmless reflected marker check; no script payloads or JavaScript execution.",
    "form_inspector": "Review forms for GET sensitive submissions, CSRF indicators, and external actions.",
    "exposed_path": "Small fixed-list exposed path checks with delays.",
    "request_logger": "Record safe request metadata without cookies, passwords, or sensitive headers.",
    "password_audit": "Limited authorized password audit prototype with masked values and strict attempt caps.",
}

TOOL_CATEGORIES = {
    "Most Used": ["website_scanner", "network_scanner", "subdomain_finder", "port_scanner", "url_fuzzer", "report_generator"],
    "Recon Tools": ["website_recon", "domain_finder", "subdomain_finder", "virtual_host_finder", "url_fuzzer", "waf_detector"],
    "Vulnerability Scanners": ["website_scanner", "api_scanner", "wordpress_scanner", "drupal_scanner", "joomla_scanner", "network_scanner", "ssl_scanner", "cloud_check", "kubernetes_check"],
    "Safe Security Testing Tools": ["sql_checker", "xss_checker", "form_inspector", "exposed_path", "request_logger", "password_audit"],
    "Reporting Tools": ["report_generator"],
}

TOOL_SLUG_BY_KEY = {}
for slug, key in TOOL_SLUGS.items():
    TOOL_SLUG_BY_KEY.setdefault(key, slug)


def tools_catalog_payload():
    return {
        category: [
            {
                "key": key,
                "slug": TOOL_SLUG_BY_KEY.get(key, key.replace("_", "-")),
                "name": TOOL_LABELS.get(key, key.replace("_", " ").title()),
                "description": TOOL_DESCRIPTIONS.get(key, "Safe authorized CyberScan prototype tool."),
            }
            for key in keys
        ]
        for category, keys in TOOL_CATEGORIES.items()
    }


def json_ready(value):
    if ObjectId is not None and isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    return value


def summarize_tool_findings(findings):
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        key = str(finding.get("severity") or "Info").lower()
        if key in summary:
            summary[key] += 1
    return summary


def normalize_tool_target(tool, payload):
    options = payload.get("options") or {}
    target = (payload.get("target") or options.get("target") or "").strip()
    if tool in {"port_scanner", "network_scanner", "subdomain_finder", "domain_finder", "virtual_host_finder"}:
        if not target:
            raise ValueError("Target host or domain is required.")
        return target
    if not target and tool == "report_generator":
        return str(options.get("scan_id") or payload.get("scan_id") or "latest")
    if not target:
        raise ValueError("Target URL is required.")
    return target


def run_safe_tool(tool, target, payload):
    options = payload.get("options") or {}
    authorized = bool(payload.get("authorization_confirmed"))
    if tool == "website_scanner":
        return tool_website_scanner(target, options)
    if tool == "network_scanner":
        return tool_network_scanner(target)
    if tool == "subdomain_finder":
        names = str(options.get("subdomains") or "").splitlines() or None
        return tool_subdomain_finder(target, names, options.get("delay", 0.2))
    if tool == "domain_finder":
        return tool_domain_finder(target)
    if tool == "virtual_host_finder":
        names = str(options.get("host_list") or options.get("wordlist") or "").splitlines() or None
        return tool_virtual_host_finder(target, names, options.get("delay", 0.3))
    if tool == "port_scanner":
        ports = [int(item) for item in re.split(r"[\s,]+", str(options.get("ports") or "")) if item.isdigit()] or None
        return tool_port_scanner(target, ports, options.get("timeout", 1))
    if tool == "url_fuzzer":
        words = str(options.get("wordlist") or "").splitlines() or None
        return tool_url_fuzzer(target, words, options.get("max_requests", 10), options.get("delay", 0.5))
    if tool == "website_recon":
        return tool_website_recon(target)
    if tool == "waf_detector":
        return tool_waf_detector(target)
    if tool == "ssl_scanner":
        return tool_ssl_scanner(target)
    if tool == "api_scanner":
        return tool_api_scanner(target)
    if tool == "wordpress_scanner":
        return tool_wordpress_scanner(target)
    if tool == "drupal_scanner":
        return tool_drupal_scanner(target)
    if tool == "joomla_scanner":
        return tool_joomla_scanner(target)
    if tool == "password_audit":
        return tool_password_audit(
            options.get("login_url") or target,
            options.get("username") or "",
            options.get("password_list") or "",
            options.get("max_attempts", 5),
            options.get("delay", 1),
            authorized,
            options.get("stop_on_success", True),
        )
    if tool == "sql_checker":
        return tool_sql_checker(target, authorized)
    if tool == "xss_checker":
        return tool_xss_checker(target, authorized)
    if tool == "request_logger":
        return {"findings": [], "requests": [tool_request_logger(target)]}
    if tool == "report_generator":
        return tool_report_generator(options.get("scan_id") or target)
    if tool == "cloud_check":
        return tool_cloud_check(target)
    if tool == "kubernetes_check":
        return tool_kubernetes_check(target)
    if tool == "form_inspector":
        return tool_form_inspector(target)
    if tool == "exposed_path":
        return tool_exposed_path(target)
    raise ValueError("Tool not supported.")


def save_tool_scan(actor_email, tool, target, scan_type, result):
    started = datetime.now()
    finished = datetime.now()
    findings = result.get("findings", [])
    request_logs = result.get("requests", [])
    summary = summarize_tool_findings(findings)
    scan_doc = {
        "user_email": actor_email,
        "tool": tool,
        "target": target,
        "scan_type": scan_type,
        "status": "completed",
        "started_at": started,
        "finished_at": finished,
        "summary": summary,
    }

    scan_id = secrets.token_urlsafe(10)
    if mongo_enabled():
        inserted = MONGO_DB.scans.insert_one(scan_doc)
        scan_id = str(inserted.inserted_id)
        stored_id = inserted.inserted_id
        if findings:
            MONGO_DB.findings.insert_many([{**finding, "scan_id": stored_id, "created_at": finished} for finding in findings])
        if request_logs:
            MONGO_DB.request_logs.insert_many([{**log, "scan_id": stored_id, "created_at": finished} for log in request_logs])

    report = {
        "scan_id": scan_id,
        "target": target,
        "scan_date": started.isoformat(timespec="seconds"),
        "duration_seconds": 0,
        "tool": tool,
        "scan": {"name": TOOL_LABELS.get(tool, tool), "type": scan_type, "targets": [target]},
        "summary": {"total": len(findings), **summary},
        "findings": findings,
        "request_logs": request_logs,
        "authorization": {"confirmed": True, "disclaimer": "This report is generated for authorized security testing only."},
        "report_files": {},
    }
    history_entry = {
        "owner_email": actor_email,
        "scan_id": scan_id,
        "scan_name": TOOL_LABELS.get(tool, tool),
        "target": target,
        "type": scan_type,
        "started": report["scan_date"],
        "duration_seconds": 0,
        "status": "Complete",
        "summary": report["summary"],
        "findings_count": len(findings),
        "report_files": {},
        "report": report,
    }
    with STATE_LOCK:
        account_state = load_user_state(actor_email)
        account_state["latest_scan"] = report
        account_state["history"] = [history_entry] + account_state["history"][:9]
        save_user_state(actor_email, account_state)
    return scan_id, report


def load_tool_scan(actor_email, scan_id=None):
    if scan_id and mongo_enabled() and ObjectId is not None:
        try:
            oid = ObjectId(scan_id)
            scan = MONGO_DB.scans.find_one({"_id": oid})
            if scan:
                findings = list(MONGO_DB.findings.find({"scan_id": oid}))
                logs = list(MONGO_DB.request_logs.find({"scan_id": oid}))
                scan["scan_id"] = str(scan["_id"])
                scan["findings"] = findings
                scan["request_logs"] = logs
                return json_ready(scan)
        except Exception:
            pass
    state = load_user_state(actor_email)
    if not scan_id:
        return state.get("latest_scan")
    for entry in state.get("history", []):
        report = entry.get("report") or {}
        if str(report.get("scan_id") or entry.get("scan_id") or "") == str(scan_id):
            return report
    return None


def start_scan_job(payload):
    scan_id = (payload.get("scan_id") or secrets.token_urlsafe(12)).strip()
    payload = {**payload, "scan_id": scan_id}
    job = {
        "scan_id": scan_id,
        "owner_email": payload.get("actor_email") or owner_email(),
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


def create_flask_app():
    from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, session, url_for

    flask_app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
    flask_app.secret_key = os.environ.get("SECRET_KEY", os.environ.get("CYBERSCAN_FLASK_SECRET", secrets.token_hex(32)))
    flask_app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    apply_mail_config_to_app(flask_app)
    if Mail is not None:
        Mail(flask_app)

    @flask_app.after_request
    def add_flask_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.path.startswith("/login") or request.path.startswith("/api/login") or request.path.startswith("/api/account") or request.path.startswith("/api/otp") or request.path.startswith("/api/password-reset"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    tools = [
        {"key": "website", "name": "Website Vulnerability Scanner", "description": "Baseline safe website checks.", "checked": True},
        {"key": "headers", "name": "Security Header Check", "description": "Reviews missing or weak HTTP security headers.", "checked": True},
        {"key": "tls", "name": "SSL/TLS Check", "description": "Checks HTTPS use and certificate indicators.", "checked": True},
        {"key": "cookies", "name": "Cookie Security Check", "description": "Reviews Secure, HttpOnly, and SameSite flags.", "checked": True},
        {"key": "forms", "name": "Form Security Inspection", "description": "Finds form handling and authentication surface issues.", "checked": True},
        {"key": "xss", "name": "Reflected XSS Safe Marker Check", "description": "Uses harmless marker reflection checks.", "checked": True},
        {"key": "sql", "name": "SQL Error Pattern Check", "description": "Looks for database error indicators safely.", "checked": True},
        {"key": "paths", "name": "Exposed Sensitive Path Check", "description": "Checks common sensitive paths without exploitation.", "checked": True},
        {"key": "listing", "name": "Directory Listing Check", "description": "Detects visible directory index pages.", "checked": True},
        {"key": "mixed", "name": "Mixed Content Check", "description": "Looks for insecure HTTP assets on HTTPS pages.", "checked": True},
        {"key": "port", "name": "Basic Safe TCP Port Check", "description": "Optional connect-only checks for common ports.", "checked": False},
    ]

    def page_context(page, title, heading, subtitle, **extra):
        user = build_user(email=session.get("email")) if session.get("authenticated") else None
        return {
            "page": page,
            "title": title,
            "heading": heading,
            "subtitle": subtitle,
            "current_user": user,
            "roles": role_payload(),
            **extra,
        }

    def require_login(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("authenticated"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Sign in is required."}), 401
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def require_permission(permission):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                if not session.get("authenticated"):
                    return jsonify({"error": "Sign in is required.", "required_permission": permission}), 401
                user = build_user(email=session.get("email"))
                if not has_permission(user, permission):
                    return jsonify({
                        "error": "You do not have permission to perform this action.",
                        "required_permission": permission,
                        "role": user.get("role"),
                    }), 403
                return view(*args, **kwargs)
            return wrapped
        return decorator

    def require_page_permission(permission):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                if not session.get("authenticated"):
                    return redirect(url_for("login"))
                user = build_user(email=session.get("email"))
                if not has_permission(user, permission):
                    return redirect(url_for("dashboard"))
                return view(*args, **kwargs)
            return wrapped
        return decorator

    def admin_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("authenticated"):
                return redirect(url_for("login"))
            user = build_user(email=session.get("email"))
            if not is_admin_user(user):
                return render_template("verification_error.html", **page_context(
                    "login",
                    "Access Denied",
                    "Access Denied",
                    "Admin access is required.",
                    error="You do not have permission to open admin pages.",
                )), 403
            return view(*args, **kwargs)
        return wrapped

    def admin_context(page, title, heading, subtitle, **extra):
        return page_context(page, title, heading, subtitle, admin_nav=[
            ("Admin Dashboard", "admin_dashboard"),
            ("Manage Users", "admin_users"),
            ("Scan Monitoring", "admin_scans"),
            ("Reports", "admin_reports"),
            ("Tool Management", "admin_tools"),
            ("System Settings", "admin_settings"),
            ("Audit Logs", "admin_audit_logs"),
            ("User Dashboard", "dashboard"),
        ], **extra)

    def update_user_status_or_role(user_id, updates, action, success):
        oid = valid_object_id(user_id)
        if oid is None:
            return redirect(url_for("admin_users"))
        current_email = normalize_email(session.get("email"))
        users = mongo_collection("users")
        target = users.find_one({"_id": oid}) if users is not None else None
        if not target:
            return redirect(url_for("admin_users"))
        if normalize_email(target.get("email")) == current_email:
            if updates.get("is_active") is False or normalize_role(updates.get("role", target.get("role"))) != "admin":
                session["admin_message"] = "You cannot disable your own admin account or remove your own admin role."
                return redirect(url_for("admin_users"))
        users.update_one({"_id": oid}, {"$set": {**updates, "updated": iso_now()}})
        write_audit_log(action, {"email": target.get("email"), "updates": updates}, actor=session.get("email"))
        session["admin_message"] = success
        return redirect(url_for("admin_users"))

    @flask_app.route("/")
    def root():
        return render_template("index.html", **page_context("landing", "Website Vulnerability Scanner", "CyberScan", "Authorized website vulnerability scanning."))

    @flask_app.route("/login")
    def login():
        message = session.pop("registration_success", "")
        return render_template("login.html", **page_context("login", "Login", "Login", "Sign in to CyberScan.", registration_success=message))

    @flask_app.route("/smtp-setup", methods=["GET", "POST"])
    def smtp_setup():
        return redirect(url_for("register"))
        if request.method == "GET":
            return render_template("smtp_setup.html", **page_context(
                "login",
                "SMTP Setup",
                "SMTP Setup",
                "Configure Gmail SMTP for real email verification.",
                settings=public_email_settings(),
            ))

        admin_email = (request.form.get("admin_email") or "").strip()
        admin_password = request.form.get("admin_password") or ""
        if not is_owner_email(admin_email) or not account_password_is_valid(admin_email, admin_password):
            return render_template("smtp_setup.html", **page_context(
                "login",
                "SMTP Setup",
                "SMTP Setup",
                "Configure Gmail SMTP for real email verification.",
                settings=public_email_settings(),
                error="Admin email or password is incorrect.",
            )), 401

        try:
            settings = save_email_settings(request.form)
        except ValueError as exc:
            return render_template("smtp_setup.html", **page_context(
                "login",
                "SMTP Setup",
                "SMTP Setup",
                "Configure Gmail SMTP for real email verification.",
                settings=public_email_settings(),
                error=str(exc),
            )), 400

        success_message = (
            "SMTP saved. DEV_MODE=True, so no test email was sent yet."
            if DEV_MODE
            else "SMTP saved and test email sent. You can now log in and receive OTP by email."
        )
        return render_template("smtp_setup.html", **page_context(
            "login",
            "SMTP Setup",
            "SMTP Setup",
            "Configure Gmail SMTP for real email verification.",
            settings=settings,
            success=success_message,
        ))

    @flask_app.get("/register")
    def register():
        return render_template("verify_email_start.html", **page_context("login", "Verify Email", "Verify Email", "Begin creating your CyberScan account."))

    @flask_app.post("/send-verification")
    def send_verification():
        email = (request.form.get("email") or "").strip()
        email_error = email_policy_error(email)
        if email_error:
            return render_template("verification_error.html", **page_context("login", "Verification Error", "Verification Error", "Enter a valid email address.", error=email_error)), 400
        try:
            result = start_email_verification(email, request.url_root.rstrip("/"))
        except ValueError as exc:
            return render_template("verification_error.html", **page_context("login", "Verification Error", "Verification Error", "Request a new email verification link.", error=str(exc))), 400
        except Exception as exc:
            write_audit_log("registration_verification_failed", {"email": email, "error": smtp_error_message(exc)})
            return render_template("verification_error.html", **page_context(
                "login",
                "Verification Error",
                "Verification Error",
                "Request a new local verification link.",
                error=f"Could not create a verification link. {smtp_error_message(exc)}",
            )), 400
        if not result.get("sent"):
            return render_template("verification_error.html", **page_context(
                "login",
                "Verification Error",
                "Verification Error",
                "Request a new local verification link.",
                error="Could not create a verification link. Please try again.",
            )), 400
        session["pending_registration_email"] = email
        return render_template("verify_email_sent.html", **page_context(
            "login",
            "Verification Sent",
            "Verification Sent",
            "Open the local verification link to continue creating your account.",
            email=email,
            development_mode=result.get("development_mode", False),
            development_link=result.get("development_link", ""),
        ))

    @flask_app.route("/verify-email/<token>")
    def verify_email(token):
        try:
            email = consume_email_verification(token)
        except ValueError as exc:
            return render_template("verification_error.html", **page_context(
                "login",
                "Verification Error",
                "Verification Error",
                "Request a new email verification link.",
                error=str(exc),
            )), 400
        session["verified_registration_email"] = email
        session.pop("pending_registration_email", None)
        return redirect(url_for("create_account"))

    @flask_app.route("/create-account", methods=["GET", "POST"])
    def create_account():
        email = session.get("verified_registration_email")
        if not email:
            return redirect(url_for("register"))
        if request.method == "GET":
            return render_template("create_account.html", **page_context(
                "login",
                "Create Account",
                "Create Account",
                "Finish setting up your CyberScan account.",
                verified_email=email,
            ))
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        if not username:
            return render_template("create_account.html", **page_context("login", "Create Account", "Create Account", "Finish setting up your CyberScan account.", verified_email=email, error="Username is required.")), 400
        if len(password) < 8:
            return render_template("create_account.html", **page_context("login", "Create Account", "Create Account", "Finish setting up your CyberScan account.", verified_email=email, error="Password must be at least 8 characters.")), 400
        if password != confirm_password:
            return render_template("create_account.html", **page_context("login", "Create Account", "Create Account", "Finish setting up your CyberScan account.", verified_email=email, error="Password and confirm password must match.")), 400
        try:
            create_user_account(email, password, name=username, username=username, email_verified=True)
        except ValueError as exc:
            return render_template("create_account.html", **page_context("login", "Create Account", "Create Account", "Finish setting up your CyberScan account.", verified_email=email, error=str(exc))), 400
        session.pop("verified_registration_email", None)
        session["registration_success"] = "Account created successfully. You may now log in."
        return redirect(url_for("login"))

    @flask_app.post("/resend-verification")
    def resend_verification():
        email = (request.form.get("email") or session.get("pending_registration_email") or "").strip()
        try:
            result = start_email_verification(email, request.url_root.rstrip("/"))
        except ValueError as exc:
            return render_template("verification_error.html", **page_context(
                "login",
                "Verification Error",
                "Verification Error",
                "Request a new email verification link.",
                error=str(exc),
            )), 400
        except Exception as exc:
            write_audit_log("registration_verification_failed", {"email": email, "error": smtp_error_message(exc)})
            return render_template("verification_error.html", **page_context(
                "login",
                "Verification Error",
                "Verification Error",
                "Request a new local verification link.",
                error=f"Could not create a verification link. {smtp_error_message(exc)}",
            )), 400
        if not result.get("sent"):
            return render_template("verification_error.html", **page_context(
                "login",
                "Verification Error",
                "Verification Error",
                "Request a new local verification link.",
                error="Could not create a verification link. Please try again.",
            )), 400
        return render_template("verify_email_sent.html", **page_context("login", "Verification Sent", "Verification Sent", "Open the local verification link to continue creating your account.", email=email, development_mode=result.get("development_mode", False), development_link=result.get("development_link", "")))

    @flask_app.route("/dashboard")
    @require_page_permission("dashboard:view")
    def dashboard():
        return render_template("dashboard.html", **page_context("dashboard", "Dashboard", "Dashboard", "Overview of scan activity, risk, and recent findings."))

    @flask_app.route("/new-scan")
    @require_page_permission("scan:configure")
    def new_scan():
        selected_tool = request.args.get("tool", "website_scanner")
        return render_template("new_scan.html", **page_context("new-scan", "New Scan", "New Scan", "Configure safe scan options for an authorized target.", tools=tools, selected_tool=selected_tool, tool_labels=TOOL_LABELS))

    @flask_app.route("/tools")
    @require_page_permission("scan:configure")
    def tools_page():
        categories = tools_catalog_payload()
        if not is_admin_user(build_user(email=session.get("email"))):
            categories = {
                category: [tool for tool in items if tool_is_enabled(tool["key"])]
                for category, items in categories.items()
            }
        return render_template("tools.html", **page_context(
            "tools",
            "Tools",
            "Tools",
            "Open safe, authorized CyberScan modules.",
            tool_categories=categories,
        ))

    @flask_app.route("/tool/<tool_slug>")
    @require_page_permission("scan:configure")
    def tool_page(tool_slug):
        selected_tool = TOOL_SLUGS.get(tool_slug)
        if not selected_tool:
            return render_template("verification_error.html", **page_context("login", "Tool Not Found", "Tool Not Found", "Choose a supported CyberScan tool.", error="Tool not supported.")), 404
        if not tool_is_enabled(selected_tool) and not is_admin_user(build_user(email=session.get("email"))):
            return render_template("verification_error.html", **page_context("login", "Tool Disabled", "Tool Disabled", "Choose another enabled CyberScan tool.", error="This tool is currently disabled by the administrator.")), 403
        return render_template("tool_page.html", **page_context(
            "tools",
            TOOL_LABELS[selected_tool],
            TOOL_LABELS[selected_tool],
            "Run this safe tool against an authorized target.",
            selected_tool=selected_tool,
            selected_slug=tool_slug,
            tool_name=TOOL_LABELS[selected_tool],
            tool_description=TOOL_DESCRIPTIONS.get(selected_tool, "Safe authorized CyberScan prototype tool."),
            tool_labels=TOOL_LABELS,
        ))

    @flask_app.route("/scan-progress")
    @require_page_permission("scan:start")
    def scan_progress():
        return render_template("scan_progress.html", **page_context("scan-progress", "Scanning in Progress", "Scanning in Progress", "CyberScan is performing safe and authorized checks on the selected target."))

    @flask_app.route("/results")
    @flask_app.route("/results/<scan_id>")
    @require_page_permission("finding:view")
    def results(scan_id=None):
        return render_template("results.html", **page_context("results", "Results", "Results", "Review findings and open detailed evidence.", scan_id=scan_id or ""))

    @flask_app.route("/finding-details")
    @flask_app.route("/finding-details/<finding_id>")
    @require_page_permission("finding:view")
    def finding_details(finding_id=None):
        return render_template("finding_details.html", **page_context("finding-details", "Finding Details", "Finding Details", "Review evidence, impact, recommendation, and status."))

    @flask_app.route("/reports")
    @require_page_permission("report:export")
    def reports():
        return render_template("reports.html", **page_context("reports", "Reports", "Reports", "Generate and download professional reports."))

    @flask_app.route("/reports/<fmt>/<scan_id>")
    @require_page_permission("report:export")
    def download_tool_report(fmt, scan_id):
        actor_email = session.get("email") or owner_email()
        scan = load_tool_scan(actor_email, scan_id)
        if not scan:
            return jsonify({"error": "Scan not found."}), 404
        fmt = fmt.lower()
        if fmt not in {"html", "json", "csv"}:
            return jsonify({"error": "Report format not supported."}), 400
        report_name = f"{slugify(scan.get('tool') or scan.get('scan', {}).get('name') or 'tool')}_{slugify(scan_id)}.{fmt}"
        report_path = REPORTS_DIR / report_name
        findings_data = scan.get("findings") or []
        if fmt == "json":
            report_path.write_text(json.dumps(json_ready(scan), indent=2), encoding="utf-8")
        elif fmt == "csv":
            with report_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["severity", "title", "affected_url", "evidence", "impact", "recommendation", "status"])
                writer.writeheader()
                for finding in findings_data:
                    writer.writerow({key: finding.get(key, "") for key in writer.fieldnames})
        else:
            rows = "".join(
                f"<tr><td>{html_escape(str(f.get('severity','')))}</td><td>{html_escape(str(f.get('title','')))}</td><td>{html_escape(str(f.get('affected_url','')))}</td><td>{html_escape(str(f.get('evidence','')))}</td><td>{html_escape(str(f.get('impact','')))}</td><td>{html_escape(str(f.get('recommendation','')))}</td></tr>"
                for f in findings_data
            )
            report_path.write_text(
                f"<html><head><title>CyberScan Report</title></head><body><h1>CyberScan Report</h1><p>This report is generated for authorized security testing only.</p><p><strong>Target:</strong> {html_escape(str(scan.get('target','')))}</p><p><strong>Tool:</strong> {html_escape(str(scan.get('tool') or scan.get('scan', {}).get('name','')))}</p><p><strong>Scan date:</strong> {html_escape(str(scan.get('started_at') or scan.get('scan_date','')))}</p><table border='1' cellspacing='0' cellpadding='6'><thead><tr><th>Severity</th><th>Finding</th><th>Affected URL</th><th>Evidence</th><th>Impact</th><th>Recommendation</th></tr></thead><tbody>{rows}</tbody></table></body></html>",
                encoding="utf-8",
            )
        return send_from_directory(REPORTS_DIR, report_name, as_attachment=True)

    @flask_app.route("/settings")
    @require_page_permission("settings:manage")
    def settings():
        return render_template("settings.html", **page_context("settings", "Settings", "Settings", "Configure default scan and report preferences."))

    @flask_app.route("/help")
    @require_login
    def help_page():
        return render_template("help.html", **page_context("help", "Help / FAQ", "Help / FAQ", "Capstone-friendly explanations and responsible-use guidance."))

    @flask_app.get("/admin/dashboard")
    @admin_required
    def admin_dashboard():
        return render_template("admin_dashboard.html", **admin_context(
            "admin-dashboard",
            "Admin Dashboard",
            "Admin Dashboard",
            "Manage CyberScan users, scans, reports, tools, settings, and audit logs.",
            metrics=admin_dashboard_metrics(),
        ))

    @flask_app.get("/admin/users")
    @admin_required
    def admin_users():
        message = session.pop("admin_message", "")
        return render_template("admin_users.html", **admin_context(
            "admin-users",
            "Manage Users",
            "Manage Users",
            "Enable accounts, disable accounts, and assign roles.",
            users=all_users(),
            message=message,
        ))

    @flask_app.post("/admin/users/<user_id>/disable")
    @admin_required
    def admin_disable_user(user_id):
        return update_user_status_or_role(user_id, {"is_active": False}, "user_disabled", "User account disabled successfully.")

    @flask_app.post("/admin/users/<user_id>/enable")
    @admin_required
    def admin_enable_user(user_id):
        return update_user_status_or_role(user_id, {"is_active": True}, "user_enabled", "User account enabled successfully.")

    @flask_app.post("/admin/users/<user_id>/make-admin")
    @admin_required
    def admin_make_admin(user_id):
        return update_user_status_or_role(user_id, {"role": "admin"}, "user_role_changed", "User role updated successfully.")

    @flask_app.post("/admin/users/<user_id>/make-user")
    @admin_required
    def admin_make_user(user_id):
        return update_user_status_or_role(user_id, {"role": "user"}, "user_role_changed", "User role updated successfully.")

    @flask_app.get("/admin/scans")
    @admin_required
    def admin_scans():
        scans = admin_scan_rows()
        return render_template("admin_scans.html", **admin_context(
            "admin-scans",
            "Scan Monitoring",
            "Scan Monitoring",
            "Review scan activity across all users.",
            scans=scans,
        ))

    @flask_app.get("/admin/reports")
    @admin_required
    def admin_reports():
        return render_template("admin_reports.html", **admin_context(
            "admin-reports",
            "Admin Reports",
            "Reports",
            "Review generated reports across users.",
            reports=admin_report_rows(),
        ))

    @flask_app.get("/admin/reports/file/<path:filename>")
    @admin_required
    def admin_report_file(filename):
        safe_name = Path(str(filename or "")).name
        if not safe_name or not (REPORTS_DIR / safe_name).exists():
            return "Report not found.", 404
        return send_from_directory(REPORTS_DIR, safe_name, as_attachment=True)

    @flask_app.get("/admin/tools")
    @admin_required
    def admin_tools():
        message = session.pop("admin_message", "")
        return render_template("admin_tools.html", **admin_context(
            "admin-tools",
            "Tool Management",
            "Tool Management",
            "Enable or disable CyberScan tools for normal users.",
            tools=ensure_tool_settings(),
            message=message,
        ))

    @flask_app.post("/admin/tools/update")
    @admin_required
    def admin_tools_update():
        collection = mongo_collection("tool_settings")
        if collection is not None:
            enabled = set(request.form.getlist("enabled_tools"))
            for tool in ensure_tool_settings():
                tool_key = tool.get("tool_key")
                is_enabled = tool_key in enabled
                collection.update_one(
                    {"tool_key": tool_key},
                    {"$set": {"enabled": is_enabled, "updated_at": datetime.now()}},
                    upsert=True,
                )
                write_audit_log("tool_enabled" if is_enabled else "tool_disabled", {"tool_key": tool_key}, actor=session.get("email"))
        session["admin_message"] = "Tool settings updated successfully."
        return redirect(url_for("admin_tools"))

    @flask_app.get("/admin/settings")
    @admin_required
    def admin_settings():
        message = session.pop("admin_message", "")
        return render_template("admin_settings.html", **admin_context(
            "admin-settings",
            "System Settings",
            "System Settings",
            "Configure safe defaults and platform reminders.",
            settings=load_system_settings(),
            message=message,
        ))

    @flask_app.post("/admin/settings")
    @admin_required
    def admin_settings_save():
        save_system_settings(request.form)
        write_audit_log("settings_updated", {"settings": "system_settings"}, actor=session.get("email"))
        session["admin_message"] = "System settings updated successfully."
        return redirect(url_for("admin_settings"))

    @flask_app.get("/admin/audit-logs")
    @admin_required
    def admin_audit_logs():
        return render_template("admin_audit_logs.html", **admin_context(
            "admin-audit-logs",
            "Audit Logs",
            "Audit Logs",
            "Review important account, scan, report, and admin actions.",
            logs=admin_audit_rows(),
        ))

    @flask_app.get("/api/state")
    @require_login
    def flask_state():
        user = build_user(email=session.get("email")) if session.get("authenticated") else None
        with STATE_LOCK:
            account_state = load_user_state(user["email"]) if user else empty_account_state()
            payload = {
                "latest_scan": account_state["latest_scan"],
                "history": account_state["history"],
                "template_reports": account_state["template_reports"],
                "schedules": schedule_payload(account_state),
                "triage": account_state["triage"],
                "current_user": user,
                "roles": role_payload(),
            }
        return jsonify(payload)

    @flask_app.get("/api/health")
    def flask_health():
        with STATE_LOCK:
            latest = STATE["history"][0] if STATE["history"] else None
            audit_entries = 0
            if AUDIT_LOG_PATH.exists():
                with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as file:
                    audit_entries = sum(1 for _ in file)
            return jsonify({
                "status": "ok",
                "service": "CyberScan",
                "commercial_mode": "file-based commercial-oriented capstone",
                "storage_backend": "mongodb+files" if mongo_enabled() else "files",
                "mongo_configured": bool(MONGO_URI),
                "mongo_connected": mongo_enabled(),
                "reports_dir": str(REPORTS_DIR),
                "saved_scans": len(STATE["history"]),
                "saved_reports": len(STATE["template_reports"]),
                "latest_scan": latest.get("started") if latest else None,
                "audit_log_entries": audit_entries,
            })

    @flask_app.get("/api/settings/email")
    @require_permission("settings:manage")
    def flask_get_email_settings():
        return jsonify(public_email_settings())

    @flask_app.post("/api/settings/email")
    @require_permission("settings:manage")
    def flask_save_email_settings():
        payload = request.get_json(silent=True) or {}
        try:
            settings = save_email_settings(payload)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"message": "Real email OTP settings saved.", "settings": settings})

    @flask_app.post("/api/login")
    def flask_login():
        payload = request.get_json(silent=True) or {}
        password = (payload.get("password") or "").strip()
        identifier = (payload.get("email") or "").strip() or owner_email()
        account = account_for_login(identifier)
        if not account:
            write_audit_log("login_failed_unknown_email", {"email": identifier})
            return jsonify({"error": "Invalid username/email or password. Please try again."}), 401
        if not account.get("legacy_owner") and account.get("is_active", True) is False:
            write_audit_log("login_failed_disabled", {"email": identifier})
            return jsonify({"error": "Your account has been disabled. Please contact the system administrator."}), 403
        if not account.get("legacy_owner") and not account.get("email_verified"):
            return jsonify({"error": "Please verify your email before logging in."}), 403
        if not account_password_is_valid(identifier, password):
            write_audit_log("login_failed", {"email": identifier})
            return jsonify({"error": "Invalid username/email or password. Please try again."}), 401
        email = account.get("email") or owner_email()
        session["authenticated"] = True
        session["email"] = email
        user = build_user(email=email)
        session["role"] = user.get("role", "user")
        write_audit_log("login_success", {"email": email, "otp_required": False}, actor=email)
        return jsonify({
            "otp_required": False,
            "email": email,
            "redirect": url_for("admin_dashboard") if is_admin_user(user) else url_for("dashboard"),
            "message": "Login successful.",
            "current_user": user,
        })

    @flask_app.post("/api/account/create")
    def flask_create_account():
        payload = request.get_json(silent=True) or {}
        verified_email = session.get("verified_registration_email", "")
        requested_email = (payload.get("email") or "").strip()
        if not verified_email or normalize_email(verified_email) != normalize_email(requested_email):
            return jsonify({"error": "Verify your email before creating an account."}), 403
        try:
            account = create_user_account(
                payload.get("email"),
                payload.get("password"),
                payload.get("name") or payload.get("username") or "User",
                username=payload.get("username") or payload.get("name") or "",
                email_verified=True,
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        session.pop("verified_registration_email", None)
        session.clear()
        return jsonify({
            "message": "Account created. Sign in with your new credentials.",
            "current_user": build_user(email=account["email"]),
        })

    @flask_app.post("/api/otp/setup")
    def flask_setup_email_otp():
        payload = request.get_json(silent=True) or {}
        admin_email = (payload.get("admin_email") or "").strip() or owner_email()
        admin_password = (payload.get("admin_password") or "").strip()
        if not is_owner_email(admin_email) or not account_password_is_valid(admin_email, admin_password):
            write_audit_log("email_otp_setup_denied", {"email": admin_email})
            return jsonify({"error": "Admin credentials are required to configure real email OTP."}), 401
        try:
            settings = save_email_settings(payload)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"message": "Real email OTP is configured. You can now sign in and receive OTP by email.", "settings": settings})

    @flask_app.post("/api/verify-otp")
    def flask_verify_otp():
        payload = request.get_json(silent=True) or {}
        try:
            email = verify_otp_challenge(payload.get("challenge_id"), payload.get("code"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 401
        session["authenticated"] = True
        session["email"] = email
        write_audit_log("login_success", {"email": email}, actor=email)
        return jsonify({"current_user": build_user(email=email), "roles": role_payload()})

    @flask_app.post("/api/password-reset/request")
    def flask_password_reset_request():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip() or owner_email()
        if not account_for_login(email):
            write_audit_log("password_reset_requested_unknown_email", {"email": email})
            return jsonify({
                "message": "If the email matches the owner account, a reset code will be sent.",
                "delivery": "email",
            })
        try:
            challenge_id, expires_at, sent_email, demo_code = create_otp_challenge(email)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        write_audit_log("password_reset_requested", {"email": email, "delivery": "email" if sent_email else "temporary"})
        return jsonify({
            "challenge_id": challenge_id,
            "expires_at": expires_at.isoformat(timespec="seconds"),
            "delivery": "email" if sent_email else "temporary",
            "message": "Password reset code sent through Gmail SMTP.",
        })

    @flask_app.post("/api/password-reset/confirm")
    def flask_password_reset_confirm():
        payload = request.get_json(silent=True) or {}
        try:
            email = verify_otp_challenge(payload.get("challenge_id"), payload.get("code"))
            if is_owner_email(email):
                update_owner_password(payload.get("new_password"))
            else:
                update_user_password(email, payload.get("new_password"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        session.clear()
        write_audit_log("password_reset_completed", {"email": email}, actor=email)
        return jsonify({"message": "Password reset complete. Please sign in with the new password."})

    @flask_app.post("/api/logout")
    @require_login
    def flask_logout():
        payload = request.get_json(silent=True) or {}
        actor = session.get("email") or OWNER_PROFILE["email"]
        write_audit_log("logout", {"reason": payload.get("reason", "manual")}, actor=actor)
        session.clear()
        return jsonify({"current_user": None, "roles": role_payload()})

    @flask_app.post("/api/scan")
    @require_permission("scan:start")
    def flask_scan():
        payload = request.get_json(silent=True) or {}
        if not payload.get("authorized"):
            return jsonify({"error": "Confirm authorized testing before starting."}), 400
        payload["actor_email"] = session.get("email") or owner_email()
        try:
            if payload.get("background"):
                return jsonify(start_scan_job(payload)), 202
            return jsonify(execute_scan_payload(payload))
        except ScanCancelled as exc:
            return jsonify({"error": str(exc), "cancelled": True, "scan_id": payload.get("scan_id")}), 499
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": f"Scan failed: {exc}"}), 500

    @flask_app.post("/api/run-tool")
    @require_permission("scan:start")
    def flask_run_tool():
        payload = request.get_json(silent=True) or {}
        tool = str(payload.get("tool") or "website_scanner").strip().replace("-", "_")
        if tool not in set(TOOL_SLUGS.values()):
            return jsonify({"success": False, "message": "Tool not supported."}), 400
        if not tool_is_enabled(tool) and not is_admin_user(build_user(email=session.get("email"))):
            return jsonify({"success": False, "message": "This tool is currently disabled by the administrator."}), 403
        if not payload.get("authorization_confirmed"):
            return jsonify({"success": False, "message": "Authorization confirmation is required before scanning."}), 400
        actor_email = session.get("email") or owner_email()
        try:
            target = normalize_tool_target(tool, payload)
            scan_type = str(payload.get("scan_type") or "light").strip().lower() or "light"
            result = run_safe_tool(tool, target, payload)
            scan_id, report = save_tool_scan(actor_email, tool, target, scan_type, result)
            write_audit_log("tool_scan_completed", {"scan_id": scan_id, "tool": tool, "target": target, "findings_count": len(result.get("findings", []))}, actor=actor_email)
            return jsonify({"success": True, "scan_id": scan_id, "message": "Scan completed successfully", "findings": result.get("findings", []), "report": report})
        except ValueError as exc:
            return jsonify({"success": False, "message": str(exc)}), 400
        except requests.exceptions.Timeout:
            return jsonify({"success": False, "message": "Connection timed out while running the safe tool."}), 408
        except requests.exceptions.SSLError:
            return jsonify({"success": False, "message": "SSL/TLS connection failed during the safe check."}), 400
        except requests.exceptions.ConnectionError:
            return jsonify({"success": False, "message": "Could not connect to the target. Check the URL or host."}), 400
        except Exception as exc:
            return jsonify({"success": False, "message": f"Tool failed safely: {exc}"}), 500

    @flask_app.get("/api/scans")
    @require_permission("finding:view")
    def flask_tool_scans():
        actor_email = session.get("email") or owner_email()
        scans = []
        if mongo_enabled():
            scans = list(MONGO_DB.scans.find({"user_email": actor_email}).sort("started_at", DESCENDING).limit(50))
        if not scans:
            state = load_user_state(actor_email)
            scans = [entry.get("report") or entry for entry in state.get("history", [])]
        return jsonify({"scans": json_ready(scans)})

    @flask_app.get("/api/scan/<scan_id>")
    @require_permission("finding:view")
    def flask_tool_scan(scan_id):
        actor_email = session.get("email") or owner_email()
        scan = load_tool_scan(actor_email, scan_id)
        if not scan:
            return jsonify({"error": "Scan not found."}), 404
        return jsonify({"scan": json_ready(scan)})

    @flask_app.get("/api/findings/<scan_id>")
    @require_permission("finding:view")
    def flask_tool_findings(scan_id):
        actor_email = session.get("email") or owner_email()
        scan = load_tool_scan(actor_email, scan_id)
        if not scan:
            return jsonify({"error": "Scan not found."}), 404
        return jsonify({"findings": json_ready(scan.get("findings", []))})

    @flask_app.get("/api/scan/jobs/<scan_id>")
    @require_permission("scan:start")
    def flask_scan_job(scan_id):
        actor_email = session.get("email") or owner_email()
        with SCAN_JOBS_LOCK:
            job = SCAN_JOBS.get(scan_id)
            payload = dict(job) if job else None
        if not payload:
            return jsonify({"error": "Scan job not found."}), 404
        if payload.get("owner_email") != actor_email:
            return jsonify({"error": "You do not have permission to view this scan job."}), 403
        return jsonify(payload)

    @flask_app.post("/api/scan/cancel")
    @require_permission("scan:start")
    def flask_cancel_scan():
        payload = request.get_json(silent=True) or {}
        scan_id = (payload.get("scan_id") or "").strip()
        actor_email = session.get("email") or owner_email()
        with SCAN_JOBS_LOCK:
            job = SCAN_JOBS.get(scan_id)
            if job and job.get("owner_email") != actor_email:
                return jsonify({"error": "You do not have permission to cancel this scan job."}), 403
        with ACTIVE_SCANS_LOCK:
            cancel_event = ACTIVE_SCANS.get(scan_id)
        if not cancel_event:
            return jsonify({"status": "not_found", "message": "No active scan found for that ID."}), 404
        cancel_event.set()
        return jsonify({"status": "cancelling", "scan_id": scan_id})

    @flask_app.post("/api/report/generate")
    @require_permission("report:export")
    def flask_generate_report():
        payload = request.get_json(silent=True) or {}
        template = (payload.get("template") or "Full Technical Report").strip()
        actor_email = session.get("email") or owner_email()
        try:
            with STATE_LOCK:
                account_state = load_user_state(actor_email)
                entry = create_template_report(template, source="manual", state=account_state)
                save_user_state(actor_email, account_state)
            write_audit_log("report_generated", {
                "template": template,
                "report_files": entry.get("report_files", {}),
            }, actor=actor_email)
            return jsonify({"report": entry, "template_reports": account_state["template_reports"], "schedules": schedule_payload(account_state)})
        except Exception as exc:
            return jsonify({"error": f"Report generation failed: {exc}"}), 400

    @flask_app.post("/api/findings/triage")
    @require_permission("finding:triage")
    def flask_triage():
        payload = request.get_json(silent=True) or {}
        updates = payload.get("updates") or []
        if isinstance(updates, dict):
            updates = [updates]
        actor_email = session.get("email") or owner_email()
        with STATE_LOCK:
            account_state = load_user_state(actor_email)
            for update in updates:
                key = str(update.get("fingerprint") or update.get("key") or "").strip()
                if not key:
                    continue
                entry = account_state["triage"].get(key, {})
                if "status" in update:
                    entry["status"] = str(update.get("status") or "").strip()
                entry["updated"] = iso_now()
                account_state["triage"][key] = entry
            annotate_report_findings(account_state["latest_scan"])
            for history_entry in account_state["history"]:
                annotate_report_findings(history_entry.get("report"))
            save_user_state(actor_email, account_state)
        write_audit_log("finding_triage_updated", {"updates": len(updates)}, actor=actor_email)
        return jsonify({"triage": account_state["triage"], "latest_scan": account_state["latest_scan"]})

    @flask_app.post("/api/report/share")
    @require_permission("report:export")
    def flask_share_report():
        payload = request.get_json(silent=True) or {}
        report_file = payload.get("report_file")
        if not report_file:
            latest = latest_report_data(load_user_state(session.get("email") or owner_email())) or {}
            report_file = (latest.get("report_files") or {}).get("html")
        try:
            token, share = create_report_share(report_file)
            return jsonify({
                "token": token,
                "share": share,
                "url": f"/shared-report/{token}",
            })
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @flask_app.get("/shared-report/<token>")
    def flask_shared_report(token):
        shares = load_report_shares()
        share = shares.get(token)
        if not share:
            return "Shared report link not found.", 404
        expires = parse_iso(share.get("expires"))
        if expires and expires < datetime.now():
            return "Shared report link has expired.", 410
        share["access_count"] = int(share.get("access_count") or 0) + 1
        shares[token] = share
        save_report_shares(shares)
        write_audit_log("shared_report_accessed", {"file": share.get("file"), "token": token[:8] + "..."})
        return send_from_directory(REPORTS_DIR, share["file"])

    @flask_app.get("/reports/<path:filename>")
    @require_login
    def flask_report_file(filename):
        actor_email = session.get("email") or owner_email()
        if not state_owns_report_file(load_user_state(actor_email), filename):
            return "Report not found for this account.", 404
        return send_from_directory(REPORTS_DIR, filename)

    return flask_app


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

        app_routes = {
            "/",
            "/index.html",
            "/prototype.html",
            "/login",
            "/dashboard",
            "/new-scan",
            "/scan-progress",
            "/results",
            "/reports",
            "/settings",
            "/help",
        }

        if path in app_routes:
            if not INDEX_PATH.exists():
                self.send_error(404, "CyberScan web UI not found")
                return
            content = INDEX_PATH.read_bytes()
            send_bytes(self, content, "text/html; charset=utf-8")
            return

        if path == "/api/state":
            user = current_user(self)
            with STATE_LOCK:
                account_state = load_user_state(user["email"]) if user else empty_account_state()
                payload = {
                    "latest_scan": account_state["latest_scan"],
                    "history": account_state["history"],
                    "template_reports": account_state["template_reports"],
                    "schedules": schedule_payload(account_state),
                    "triage": account_state["triage"],
                    "current_user": user,
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
                    "commercial_mode": "file-based commercial-oriented capstone",
                    "storage_backend": "mongodb+files" if mongo_enabled() else "files",
                    "mongo_configured": bool(MONGO_URI),
                    "mongo_connected": mongo_enabled(),
                    "reports_dir": str(REPORTS_DIR),
                    "saved_scans": len(STATE["history"]),
                    "saved_reports": len(STATE["template_reports"]),
                    "latest_scan": latest.get("started") if latest else None,
                    "audit_log_entries": sum(1 for _ in open(AUDIT_LOG_PATH, "r", encoding="utf-8")) if AUDIT_LOG_PATH.exists() else 0,
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
            user = current_user(self)
            if not user or not state_owns_report_file(load_user_state(user["email"]), filename):
                self.send_error(404, "Report not found for this account")
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

            email = (payload.get("email") or "").strip() or owner_email()
            password = (payload.get("password") or "").strip()
            if not account_for_login(email) or not password or not account_password_is_valid(email, password):
                send_json(self, {"error": "Invalid owner credentials."}, status=401)
                return
            account = account_for_login(email)
            if not account.get("legacy_owner") and not account.get("email_verified"):
                send_json(self, {"error": "Please verify your email before logging in."}, status=403)
                return

            send_json(self, {
                "otp_required": False,
                "email": email,
                "redirect": "/dashboard",
                "message": "Login successful.",
            })
            return

        if path == "/api/account/create":
            try:
                payload = parse_json_body(self)
            except Exception as exc:
                send_json(self, {"error": f"Invalid JSON payload: {exc}"}, status=400)
                return

            try:
                account = create_user_account(
                    payload.get("email"),
                    payload.get("password"),
                    payload.get("name") or "User",
                )
            except ValueError as exc:
                send_json(self, {"error": str(exc)}, status=400)
                return

            send_json(self, {
                "message": "Account created. Sign in with your new credentials.",
                "current_user": build_user(email=account["email"]),
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
    parser.add_argument("--debug", action="store_true", default=os.environ.get("CYBERSCAN_DEBUG", "true").strip().lower() in {"1", "true", "yes", "on"}, help="Enable Flask debug mode for local capstone development")
    args = parser.parse_args()

    init_mongo()
    ensure_mongo_indexes()
    sync_roles_to_mongo()
    create_default_admin()
    ensure_tool_settings()
    load_state()
    load_security_state()
    load_email_settings()
    migrate_legacy_created_owner_to_user()
    scheduler_stop = threading.Event()
    start_scheduler(scheduler_stop)
    try:
        flask_app = create_flask_app()
        print(f"CyberScan Flask web app running at http://{args.host}:{args.port}")
        print(f"Storage backend: {'MongoDB + files' if mongo_enabled() else 'files'}")
        flask_app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False, threaded=True)
    except ImportError:
        server = ThreadingHTTPServer((args.host, args.port), CyberScanHandler)
        print(f"CyberScan fallback web app running at http://{args.host}:{args.port}")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down CyberScan web app...")
    finally:
        scheduler_stop.set()


if __name__ == "__main__":
    main()
