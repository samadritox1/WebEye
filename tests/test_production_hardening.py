import asyncio
import json
import logging
import socket
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.config import settings
from app.core.batch_manager import batch_manager
from app.core.concurrency import reset_loop_semaphores
from app.core.observability import (
    StructuredJsonFormatter,
    metrics,
    redact_sensitive_text,
)
from app.core.security_middleware import rate_limiter
from app.main import app, scoring_engine
from app.models.database import check_db_ready, get_schema_status, init_db


class TestProductionHardening(unittest.TestCase):
    def setUp(self):
        init_db()
        rate_limiter.reset()
        reset_loop_semaphores()

    def tearDown(self):
        rate_limiter.reset()
        reset_loop_semaphores()

    def test_database_migrations_and_indexes(self):
        status = get_schema_status()
        self.assertEqual(status["backend"], "sqlite")
        self.assertGreaterEqual(status["current_version"], 3)
        self.assertEqual(status["current_version"], status["latest_version"])

        expected_indexes = {
            "idx_scans_timestamp",
            "idx_scans_domain",
            "idx_cti_cache_expires",
            "idx_sandbox_timestamp",
            "idx_email_timestamp",
            "idx_batch_jobs_status",
        }
        for idx_name in expected_indexes:
            self.assertIn(idx_name, status["indexes"])

        ready_db = check_db_ready()
        self.assertTrue(ready_db["ok"])

    def test_observability_health_metrics_and_secret_redaction(self):
        client = TestClient(app)

        h = client.get("/health")
        self.assertEqual(h.status_code, 200)
        self.assertEqual(h.json()["status"], "ok")
        self.assertIn("X-Request-ID", h.headers)

        r = client.get("/ready")
        self.assertEqual(r.status_code, 200)
        r_data = r.json()
        self.assertEqual(r_data["status"], "ready")
        self.assertEqual(r_data["checks"]["database"]["status"], "ok")

        prom = client.get("/metrics")
        self.assertEqual(prom.status_code, 200)
        self.assertIn("phishpulse_http_requests_total", prom.text)
        self.assertIn("phishpulse_ssrf_blocks_total", prom.text)

        m_json = client.get("/api/v1/metrics")
        self.assertEqual(m_json.status_code, 200)
        self.assertIn("scanning", m_json.json())
        self.assertIn("batch_jobs", m_json.json())

        # Structured logging & redaction must mask Bearer tokens and query secrets
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="phishpulse.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="Calling upstream Authorization: Bearer super_secret_tok_999 https://x.test?api_key=abc123secret",
            args=(),
            exc_info=None,
        )
        record.fields = {"api_key": "plaintext-must-hide", "target": "example.com"}
        formatted = json.loads(formatter.format(record))
        self.assertNotIn("super_secret_tok_999", formatted["message"])
        self.assertNotIn("abc123secret", formatted["message"])
        self.assertEqual(formatted["api_key"], "[REDACTED]")
        self.assertEqual(redact_sensitive_text(settings.JWT_SECRET_KEY), "[REDACTED]")

        sec_cfg = client.get("/api/v1/config/security")
        self.assertEqual(sec_cfg.status_code, 200)
        cfg_json = sec_cfg.json()
        self.assertIn(cfg_cfg := cfg_json["settings"]["jwt_secret_key"], {"[EPHEMERAL]", settings.mask_secret(settings.JWT_SECRET_KEY)})
        self.assertTrue(cfg_cfg)

    def test_api_versioning_and_legacy_deprecation_headers(self):
        client = TestClient(app)

        v1_resp = client.get("/api/v1/stats")
        self.assertEqual(v1_resp.status_code, 200)
        self.assertEqual(v1_resp.headers.get("X-API-Version"), "v1")
        self.assertIsNone(v1_resp.headers.get("Deprecation"))

        legacy_resp = client.get("/api/stats")
        self.assertEqual(legacy_resp.status_code, 200)
        self.assertEqual(legacy_resp.headers.get("X-API-Version"), "v1")
        self.assertEqual(legacy_resp.headers.get("Deprecation"), "true")
        self.assertIn("/api/v1/", legacy_resp.headers.get("Link", ""))

    def test_authentication_api_key_and_jwt_exchange(self):
        orig_required = settings.AUTH_REQUIRED
        orig_keys = settings.API_KEYS
        try:
            settings.AUTH_REQUIRED = True
            settings.API_KEYS = ("pp-unit-key-alpha-1234", "pp-unit-key-beta-5678")
            client = TestClient(app)

            # Health remains public even when auth is strictly enforced
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.get("/api/v1/ready").status_code, 200)

            # Missing credentials rejected with 401
            unauth = client.get("/api/v1/scans")
            self.assertEqual(unauth.status_code, 401)
            self.assertIn("Bearer", unauth.headers.get("WWW-Authenticate", ""))

            # Wrong key rejected
            bad_key = client.get("/api/v1/scans", headers={"X-API-Key": "wrong-key"})
            self.assertEqual(bad_key.status_code, 401)

            # Valid key accepted
            ok_key = client.get("/api/v1/scans", headers={"X-API-Key": "pp-unit-key-alpha-1234"})
            self.assertEqual(ok_key.status_code, 200)

            # Exchange API key for short-lived Bearer JWT
            tok_resp = client.post(
                "/api/v1/auth/token",
                headers={"X-API-Key": "pp-unit-key-beta-5678"},
                json={"subject": "soc-automation", "ttl_minutes": 15},
            )
            self.assertEqual(tok_resp.status_code, 200)
            token = tok_resp.json()["access_token"]
            self.assertEqual(tok_resp.json()["token_type"], "bearer")

            ok_jwt = client.get("/api/v1/stats", headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(ok_jwt.status_code, 200)

            tampered_jwt = client.get("/api/v1/stats", headers={"Authorization": f"Bearer {token}tampered"})
            self.assertEqual(tampered_jwt.status_code, 401)
        finally:
            settings.AUTH_REQUIRED = orig_required
            settings.API_KEYS = orig_keys

    def test_sliding_window_rate_limiting_and_spoof_resistance(self):
        orig_enabled = settings.RATE_LIMIT_ENABLED
        orig_read_max = settings.RATE_LIMIT_READ_MAX
        orig_trust_proxy = settings.TRUST_PROXY_HEADERS
        try:
            rate_limiter.reset()
            settings.RATE_LIMIT_ENABLED = True
            settings.RATE_LIMIT_READ_MAX = 3
            settings.TRUST_PROXY_HEADERS = False
            client = TestClient(app)

            for idx in range(3):
                # Forging X-Forwarded-For must NOT bypass client IP rate bucket
                resp = client.get("/api/v1/stats", headers={"X-Forwarded-For": f"10.0.0.{idx + 1}"})
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(resp.headers.get("X-RateLimit-Limit"), "3")

            blocked = client.get("/api/v1/stats", headers={"X-Forwarded-For": "10.0.0.99"})
            self.assertEqual(blocked.status_code, 429)
            self.assertIn("Retry-After", blocked.headers)
        finally:
            settings.RATE_LIMIT_ENABLED = orig_enabled
            settings.RATE_LIMIT_READ_MAX = orig_read_max
            settings.TRUST_PROXY_HEADERS = orig_trust_proxy
            rate_limiter.reset()

    def test_async_batch_25_urls_bounded_concurrency_and_polling(self):
        urls = [f"https://batch-target-{i}.example/login" for i in range(24)] + [
            "http://169.254.169.254/latest/meta-data/"
        ]
        tracker = {"in_flight": 0, "peak": 0, "calls": 0}

        async def _fake_execute_scan(url: str, fetch_content: bool = True, deep_dns: bool = True, refresh_intel: bool = False):
            tracker["in_flight"] += 1
            tracker["calls"] += 1
            if tracker["in_flight"] > tracker["peak"]:
                tracker["peak"] = tracker["in_flight"]
            try:
                await asyncio.sleep(0.025)
                return {
                    "scan_id": f"SCN-B{tracker['calls']:06d}",
                    "target_url": url,
                    "target_domain": url.split("/")[2],
                    "overall_score": 12.0,
                    "verdict": "BENIGN",
                    "verdict_color": "#10b981",
                    "summary": f"Mocked scan for {url}",
                }
            finally:
                tracker["in_flight"] -= 1

        fake_addr = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with (
            TestClient(app) as client,
            patch("app.core.security_guard.socket.getaddrinfo", return_value=fake_addr),
            patch.object(scoring_engine, "execute_scan", side_effect=_fake_execute_scan),
        ):
            # 25-URL batch via v1 returns 202 Accepted cleanly with bounded concurrency=3
            submit = client.post(
                "/api/v1/scan/batch",
                json={"urls": urls, "concurrency": 3},
            )
            self.assertEqual(submit.status_code, 202)
            created = submit.json()
            job_id = created["job_id"]
            self.assertEqual(created["total_urls"], 25)
            self.assertEqual(created["concurrency_limit"], 3)
            self.assertTrue(created["status_url"].endswith(f"/jobs/{job_id}"))

            # Poll until background job finishes cleanly
            deadline = time.monotonic() + 8.0
            final_job = None
            while time.monotonic() < deadline:
                poll = client.get(f"/api/v1/jobs/{job_id}")
                self.assertEqual(poll.status_code, 200)
                final_job = poll.json()
                if final_job["status"] in ("completed", "completed_with_errors", "failed", "cancelled"):
                    break
                time.sleep(0.04)

            self.assertIsNotNone(final_job)
            self.assertEqual(final_job["status"], "completed_with_errors")
            self.assertEqual(final_job["completed_urls"], 25)
            self.assertEqual(final_job["failed_urls"], 1)
            self.assertEqual(final_job["progress_pct"], 100.0)
            self.assertEqual(len(final_job["results"]), 25)
            # SSRF item at index 24 must fail cleanly with SSRF error without blocking the other 24
            self.assertIn("SSRF", final_job["results"][24]["error"])
            self.assertEqual(final_job["results"][0]["verdict"], "BENIGN")
            # Crucial assertion: peak concurrent workers never exceeded requested bound of 3
            self.assertLessEqual(tracker["peak"], 3)
            self.assertGreaterEqual(tracker["peak"], 2)

            jobs_list = client.get("/api/v1/jobs?limit=5")
            self.assertEqual(jobs_list.status_code, 200)
            self.assertTrue(any(j["job_id"] == job_id for j in jobs_list.json()))

    def test_batch_job_cancellation_and_dashboard_ui(self):
        async def _slow_scan(url: str, fetch_content: bool = True, deep_dns: bool = True, refresh_intel: bool = False):
            await asyncio.sleep(0.12)
            return {
                "scan_id": "SCN-SLOW001",
                "target_url": url,
                "target_domain": url.split("/")[2],
                "overall_score": 10.0,
                "verdict": "BENIGN",
                "verdict_color": "#10b981",
                "summary": "ok",
            }

        fake_addr = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with (
            TestClient(app) as client,
            patch("app.core.security_guard.socket.getaddrinfo", return_value=fake_addr),
            patch.object(scoring_engine, "execute_scan", side_effect=_slow_scan),
        ):
            resp = client.post(
                "/api/v1/jobs/batch",
                json={"urls": [f"https://cancel-{i}.example" for i in range(6)], "concurrency": 2},
            )
            self.assertEqual(resp.status_code, 202)
            job_id = resp.json()["job_id"]

            time.sleep(0.05)
            cancel_resp = client.post(f"/api/v1/jobs/{job_id}/cancel")
            self.assertEqual(cancel_resp.status_code, 200)

            deadline = time.monotonic() + 5.0
            final_state = None
            while time.monotonic() < deadline:
                st = client.get(f"/api/v1/jobs/{job_id}").json()
                if st["status"] == "cancelled":
                    final_state = st
                    break
                time.sleep(0.03)
            self.assertIsNotNone(final_state)
            self.assertEqual(final_state["status"], "cancelled")
            self.assertLess(final_state["completed_urls"], 6)

            html = client.get("/").text
            self.assertIn("WebEye", html)
            self.assertNotIn("PhishPulse", html)
            self.assertNotIn("Anarisk", html)
            for ui_id in (
                "webeye-telemetry-scans",
                "webeye-telemetry-posture",
                "batch-concurrency-select",
                "batch-progress-panel",
                "batch-progress-bar",
                "btn-batch-cancel",
                "batch-jobs-tbody",
            ):
                self.assertIn(ui_id, html)

    def test_scoring_engine_enforces_global_scan_concurrency_bound(self):
        orig_cap = settings.SCAN_MAX_CONCURRENCY
        state = {"in_flight": 0, "peak": 0}
        fake_addr = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

        async def _slow_impl(url: str, fetch_content: bool = True, deep_dns: bool = True, refresh_intel: bool = False):
            state["in_flight"] += 1
            if state["in_flight"] > state["peak"]:
                state["peak"] = state["in_flight"]
            try:
                await asyncio.sleep(0.04)
                return {
                    "scan_id": "SCN-BOUND01",
                    "target_url": url,
                    "target_domain": url.split("/")[2],
                    "overall_score": 15.0,
                    "verdict": "BENIGN",
                    "verdict_color": "#10b981",
                    "summary": "bounded ok",
                }
            finally:
                state["in_flight"] -= 1

        async def _run_burst():
            tasks = [
                scoring_engine.execute_scan(f"https://bound-{i}.example", fetch_content=False, deep_dns=False)
                for i in range(8)
            ]
            return await asyncio.gather(*tasks)

        try:
            settings.SCAN_MAX_CONCURRENCY = 2
            reset_loop_semaphores()
            with (
                patch("app.core.security_guard.socket.getaddrinfo", return_value=fake_addr),
                patch.object(scoring_engine, "_execute_scan_impl", side_effect=_slow_impl),
            ):
                results = asyncio.run(_run_burst())
            self.assertEqual(len(results), 8)
            self.assertEqual(state["peak"], 2)
        finally:
            settings.SCAN_MAX_CONCURRENCY = orig_cap
            reset_loop_semaphores()


if __name__ == "__main__":
    unittest.main()
