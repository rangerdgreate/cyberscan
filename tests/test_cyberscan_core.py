import tempfile
import json
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer

import app
from cyberscan import CyberScan
from app import compare_report_findings, password_is_valid, verify_post_origin


class FakeResponse:
    def __init__(self, url, text, content_type="text/html", status_code=200):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = {"Content-Type": content_type}


class FakeHandler:
    def __init__(self, headers):
        self.headers = headers


class CyberScanCoreTests(unittest.TestCase):
    def run_test_server_request(self, method, path, payload=None):
        server = ThreadingHTTPServer(("127.0.0.1", 0), app.CyberScanHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_address[1]}{path}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if payload is not None else {},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                body = response.read().decode("utf-8")
                return response.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8")
            return exc.code, json.loads(body) if body else {}
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_scan_profile_defaults_are_applied(self):
        scanner = CyberScan("https://example.test", scan_type="Full")

        self.assertEqual(scanner.scan_type, "Full")
        self.assertEqual(scanner.max_depth, 3)
        self.assertEqual(scanner.max_pages, 100)
        self.assertEqual(scanner.rate_limit, 10)

    def test_findings_include_cwe_confidence_and_validation(self):
        scanner = CyberScan("https://example.test")

        scanner.add_result(
            "Possible SQL Injection Error Indicator: id",
            "High",
            "A03: Injection",
            "A safe quote probe caused a database-style error response.",
            "Use parameterized queries.",
            evidence="Parameter id produced sql syntax",
            status_code=500,
        )

        finding = scanner.results[0]
        self.assertEqual(finding["cwe"], "CWE-89")
        self.assertEqual(finding["confidence"], "Medium")
        self.assertEqual(finding["validation_status"], "Needs Manual Validation")
        self.assertEqual(finding["detector"], "CyberScan")

    def test_extract_links_includes_form_actions_and_inline_routes(self):
        scanner = CyberScan("https://example.test", scan_type="Full")
        response = FakeResponse(
            "https://example.test/start",
            """
            <a href="/account">Account</a>
            <form action="/api/update-profile"></form>
            <script>const route = "/admin/settings";</script>
            <a href="https://outside.test/skip">Outside</a>
            """,
        )

        links = scanner._extract_links(response)

        self.assertIn("https://example.test/account", links)
        self.assertIn("https://example.test/api/update-profile", links)
        self.assertIn("https://example.test/admin/settings", links)

    def test_report_exports_include_metadata_columns(self):
        scanner = CyberScan("https://example.test")
        scanner.add_result(
            "Missing Security Header: Content-Security-Policy",
            "High",
            "A03: Injection",
            "Content Security Policy is missing.",
            "Add a strong Content-Security-Policy header.",
        )

        report = scanner.build_report_data()
        self.assertIn("cwe_summary", report)
        self.assertIn("confidence_summary", report)
        self.assertEqual(report["findings"][0]["cwe"], "CWE-79")

        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "report.csv"
            scanner.save_csv_report(str(csv_path))
            csv_text = csv_path.read_text(encoding="utf-8")

        self.assertIn("CWE", csv_text)
        self.assertIn("Confidence", csv_text)

    def test_report_includes_scan_coverage_summary(self):
        scanner = CyberScan("https://example.test", scan_type="Quick", max_pages=2)
        scanner.crawled_urls = ["https://example.test", "https://example.test/login"]
        scanner.safe_probe_count = scanner.safe_probe_limit

        report = scanner.build_report_data()

        self.assertIn("coverage", report)
        self.assertEqual(report["coverage"]["urls_scanned"], 2)
        self.assertTrue(report["coverage"]["page_limit_reached"])
        self.assertTrue(report["coverage"]["safe_probe_limit_reached"])
        self.assertIn("Run an Authenticated scan", " ".join(report["coverage"]["notes"]))

    def test_port_scan_settings_are_limited_and_reported(self):
        scanner = CyberScan("https://example.test", port_scan=True, ports="22,80,443,70000,abc,8000-8002")

        report = scanner.build_report_data()

        self.assertTrue(report["scan"]["settings"]["port_scan_enabled"])
        self.assertEqual(report["scan"]["settings"]["port_scan_ports"], [22, 80, 443, 8000, 8001, 8002])
        self.assertTrue(report["coverage"]["port_scan_enabled"])

    def test_open_port_check_adds_observed_finding(self):
        scanner = CyberScan("https://example.test", port_scan=True, ports="443")

        with patch("socket.create_connection") as create_connection:
            create_connection.return_value.__enter__.return_value = object()
            scanner.check_open_ports()

        self.assertEqual(scanner.open_ports, [{"host": "example.test", "port": 443, "service": "HTTPS"}])
        self.assertEqual(scanner.results[0]["title"], "Open Network Port Detected: example.test:443")
        self.assertEqual(scanner.results[0]["validation_status"], "Observed")

    def test_report_includes_deduplicated_prevention_plan(self):
        scanner = CyberScan("https://example.test")
        for path in ["/", "/admin"]:
            scanner.add_result(
                "Missing Security Header: X-Frame-Options",
                "Medium",
                "A05: Security Misconfiguration",
                "X-Frame-Options header is missing.",
                "Add X-Frame-Options: DENY or SAMEORIGIN.",
                url=f"https://example.test{path}",
            )

        report = scanner.build_report_data()

        self.assertIn("prevention_plan", report)
        self.assertEqual(len(report["prevention_plan"]), 1)
        self.assertEqual(report["prevention_plan"][0]["count"], 2)
        self.assertEqual(report["prevention_plan"][0]["recommendation"], "Add X-Frame-Options: DENY or SAMEORIGIN.")

    def test_compare_report_findings_marks_new_existing_and_fixed(self):
        previous = {
            "findings": [
                {
                    "title": "Missing Security Header",
                    "severity": "High",
                    "owasp_category": "A05: Security Misconfiguration",
                    "cwe": "CWE-693",
                    "affected_url": "https://example.test",
                },
                {
                    "title": "Old Finding",
                    "severity": "Low",
                    "owasp_category": "A05: Security Misconfiguration",
                    "cwe": "CWE-200",
                    "affected_url": "https://example.test/old",
                },
            ]
        }
        current = {
            "findings": [
                {
                    "title": "Missing Security Header",
                    "severity": "High",
                    "owasp_category": "A05: Security Misconfiguration",
                    "cwe": "CWE-693",
                    "affected_url": "https://example.test",
                },
                {
                    "title": "New Finding",
                    "severity": "Medium",
                    "owasp_category": "A03: Injection",
                    "cwe": "CWE-79",
                    "affected_url": "https://example.test/search",
                },
            ]
        }

        comparison = compare_report_findings(current, previous)

        self.assertEqual(comparison["new"], 1)
        self.assertEqual(comparison["existing"], 1)
        self.assertEqual(comparison["fixed"], 1)
        self.assertEqual(current["findings"][0]["lifecycle_status"], "Existing")
        self.assertEqual(current["findings"][1]["lifecycle_status"], "New")

    def test_crawl_scope_patterns_respect_include_and_exclude(self):
        scanner = CyberScan(
            "https://example.test",
            include_paths="/api/.*",
            exclude_paths="/api/private",
        )

        self.assertTrue(scanner._path_in_scope("https://example.test/start", is_seed=True))
        self.assertTrue(scanner._path_in_scope("https://example.test/api/users"))
        self.assertFalse(scanner._path_in_scope("https://example.test/dashboard"))
        self.assertFalse(scanner._path_in_scope("https://example.test/api/private/secrets"))

    def test_password_check_supports_plain_and_hash_configuration(self):
        self.assertTrue(password_is_valid("password"))
        with patch("app.OWNER_PASSWORD_HASH", "03f99ad2bb8f470ab4a6b65dd51dca8f63c4a36d52a66b22d706c14dbfec5983"):
            self.assertTrue(password_is_valid("owner-secret"))
            self.assertFalse(password_is_valid("password"))

    def test_post_origin_rejects_cross_origin_requests(self):
        self.assertTrue(verify_post_origin(FakeHandler({})))
        self.assertTrue(verify_post_origin(FakeHandler({"Origin": "http://127.0.0.1:8006"})))
        self.assertFalse(verify_post_origin(FakeHandler({"Origin": "https://evil.example"})))

    def test_login_endpoint_rejects_wrong_password(self):
        status, payload = self.run_test_server_request(
            "POST",
            "/api/login",
            {"email": "owner@company.com", "password": "wrong"},
        )

        self.assertEqual(status, 401)
        self.assertIn("Invalid owner credentials", payload["error"])

    def test_login_endpoint_creates_temporary_otp_without_smtp(self):
        status, payload = self.run_test_server_request(
            "POST",
            "/api/login",
            {"email": "owner@company.com", "password": "password"},
        )

        self.assertEqual(status, 200)
        self.assertTrue(payload["otp_required"])
        self.assertIn("challenge_id", payload)
        self.assertEqual(payload["delivery"], "temporary")
        self.assertRegex(payload["demo_otp"], r"^\d{6}$")

    def test_login_endpoint_marks_email_delivery_when_smtp_sends(self):
        with patch("app.send_otp_email", return_value=True):
            status, payload = self.run_test_server_request(
                "POST",
                "/api/login",
                {"email": "owner@company.com", "password": "password"},
            )

        self.assertEqual(status, 200)
        self.assertEqual(payload["delivery"], "email")
        self.assertIsNone(payload["demo_otp"])

    def test_verify_otp_endpoint_creates_session(self):
        original_otps = app.PENDING_OTPS.copy()
        challenge_id = "unit-challenge"
        code = "123456"
        app.PENDING_OTPS[challenge_id] = {
            "email": "owner@company.com",
            "code_hash": app.hashlib.sha256(code.encode("utf-8")).hexdigest(),
            "expires_at": app.datetime.now() + app.timedelta(minutes=5),
            "attempts": 0,
        }
        try:
            status, payload = self.run_test_server_request(
                "POST",
                "/api/verify-otp",
                {"challenge_id": challenge_id, "code": code},
            )
        finally:
            app.PENDING_OTPS.clear()
            app.PENDING_OTPS.update(original_otps)

        self.assertEqual(status, 200)
        self.assertEqual(payload["current_user"]["email"], "owner@company.com")

    def test_report_generation_endpoint_returns_template_entry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_reports_dir = app.REPORTS_DIR
            original_automation_path = app.AUTOMATION_PATH
            original_state = app.STATE
            app.REPORTS_DIR = Path(temp_dir)
            app.AUTOMATION_PATH = Path(temp_dir) / "automation.json"
            app.STATE = {
                "latest_scan": {
                    "target": "https://example.test",
                    "scan": {"name": "Unit Scan"},
                    "summary": {"High": 1},
                    "findings": [],
                },
                "history": [],
                "template_reports": [],
                "schedules": {},
                "triage": {},
            }
            try:
                status, payload = self.run_test_server_request(
                    "POST",
                    "/api/report/generate",
                    {"template": "Executive Summary"},
                )
            finally:
                app.REPORTS_DIR = original_reports_dir
                app.AUTOMATION_PATH = original_automation_path
                app.STATE = original_state

        self.assertEqual(status, 200)
        self.assertEqual(payload["report"]["template"], "Executive Summary")

    def test_template_report_includes_coverage_and_finding_details(self):
        report = {
            "target": "https://example.test",
            "scan": {"name": "Unit Scan", "settings": {"crawled_urls": ["https://example.test"]}},
            "summary": {"High": 1},
            "coverage": {
                "urls_scanned": 1,
                "max_pages": 25,
                "max_depth": 1,
                "safe_probes_used": 2,
                "safe_probe_limit": 6,
                "notes": ["Run an Authenticated scan for logged-in workflows."],
            },
            "findings": [
                {
                    "severity": "High",
                    "title": "Missing Security Header",
                    "owasp_category": "A05: Security Misconfiguration",
                    "cwe": "CWE-693",
                    "confidence": "High",
                    "validation_status": "Observed",
                    "affected_url": "https://example.test",
                    "evidence": "Content-Security-Policy header missing",
                    "recommendation": "Add a strong Content-Security-Policy header.",
                }
            ],
        }

        html = app.template_report_html("Executive Summary", report, "2026-06-04T10:00:00", "manual")

        self.assertIn("Scan Coverage", html)
        self.assertIn("URLs Scanned", html)
        self.assertIn("Affected URL", html)
        self.assertIn("Content-Security-Policy header missing", html)
        self.assertIn("Run an Authenticated scan", html)

    def test_background_scan_job_tracks_completion(self):
        fake_report = {
            "target": "https://example.test",
            "scan": {"name": "Fake Scan", "targets": ["https://example.test"]},
            "scan_date": "2026-05-19T10:00:00",
            "summary": {},
            "findings": [],
            "report_files": {},
        }

        with patch("app.execute_scan_payload", return_value=fake_report):
            job = app.start_scan_job({"scan_id": "unit-job", "target": "https://example.test"})
            for _ in range(20):
                with app.SCAN_JOBS_LOCK:
                    status = app.SCAN_JOBS["unit-job"]["status"]
                    report = app.SCAN_JOBS["unit-job"]["report"]
                if status == "complete":
                    break
                threading.Event().wait(0.05)

        self.assertEqual(job["scan_id"], "unit-job")
        self.assertEqual(status, "complete")
        self.assertEqual(report["target"], "https://example.test")

    def test_triage_annotation_applies_status_and_hides_findings(self):
        report = {
            "findings": [
                {
                    "title": "Finding A",
                    "severity": "High",
                    "owasp_category": "A05",
                    "cwe": "CWE-693",
                    "affected_url": "https://example.test/a",
                },
                {
                    "title": "Finding B",
                    "severity": "Low",
                    "owasp_category": "A05",
                    "cwe": "CWE-200",
                    "affected_url": "https://example.test/b",
                },
            ]
        }
        key_a = app.finding_fingerprint(report["findings"][0])
        key_b = app.finding_fingerprint(report["findings"][1])
        original_triage = app.STATE.get("triage", {})
        app.STATE["triage"] = {
            key_a: {"status": "Accepted Risk", "owner_review": "Owner Review"},
            key_b: {"hidden": True},
        }
        try:
            app.annotate_report_findings(report)
        finally:
            app.STATE["triage"] = original_triage

        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["lifecycle_status"], "Accepted Risk")
        self.assertEqual(report["findings"][0]["owner_review"], "Owner Review")


if __name__ == "__main__":
    unittest.main()
