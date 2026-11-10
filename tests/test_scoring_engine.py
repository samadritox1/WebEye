import unittest
import asyncio
from unittest.mock import AsyncMock, patch
from app.models.database import init_db
from app.core.scoring_engine import ScoringEngine
from tests.test_explainable_scoring import _make_test_cert_der_b64

class TestScoringEngine(unittest.TestCase):
    def setUp(self):
        init_db()
        self.engine = ScoringEngine()

    def test_phishing_scoring(self):
        # Scan a synthetic phishing target with homoglyph
        async def run_scan():
            return await self.engine.execute_scan(
                url="http://paypa1-security-verification.xyz/login",
                fetch_content=False,
                deep_dns=False
            )

        report = asyncio.run(run_scan())
        self.assertIn("overall_score", report)
        self.assertIn("verdict", report)
        self.assertIn("threat_analysis", report)
        self.assertIn(report["verdict"], ["SUSPICIOUS", "HIGH_RISK", "MALICIOUS"])
        self.assertTrue(report["threat_analysis"]["impersonated_brand"] == "PayPal")

    def test_benign_domain(self):
        async def run_scan():
            return await self.engine.execute_scan(
                url="https://www.google.com",
                fetch_content=False,
                deep_dns=False
            )

        report = asyncio.run(run_scan())
        self.assertIn(report["verdict"], ["BENIGN", "SUSPICIOUS"])
        self.assertLess(report["overall_score"], 40.0)

    def test_gmail_and_mail_google_score_benign(self):
        filler = "x=1;" * 1500
        html_body = (
            "<html><title>Gmail</title><body>"
            "<form action='/v3/signin/identifier'><input type='password' name='Passwd'></form>"
            "<script>var ev='keydown';</script>"
            f"<script>D.eval(U.createScript('1'));function f(I){{return eval(I)}}{filler}String.fromCharCode.apply(null,a);</script>"
            "<script>bb.prototype.preventDefault=function(){};</script>"
            "</body></html>"
        )
        for target, final_url, domain, redirect_chain in (
            (
                "https://gmail.com",
                "https://accounts.google.com/v3/signin/identifier",
                "gmail.com",
                [
                    {"hop": 1, "status_code": 301, "url": "https://gmail.com"},
                    {"hop": 2, "status_code": 302, "url": "https://mail.google.com/mail/u/0/"},
                    {"hop": 3, "status_code": 302, "url": "https://accounts.google.com/ServiceLogin"},
                    {"hop": 4, "status_code": 200, "url": "https://accounts.google.com/v3/signin/identifier"},
                ],
            ),
            (
                "https://mail.google.com",
                "https://accounts.google.com/v3/signin/identifier",
                "mail.google.com",
                [
                    {"hop": 1, "status_code": 301, "url": "https://mail.google.com"},
                    {"hop": 2, "status_code": 301, "url": "https://mail.google.com/mail/"},
                    {"hop": 3, "status_code": 302, "url": "https://mail.google.com/mail/u/0/"},
                    {"hop": 4, "status_code": 302, "url": "https://accounts.google.com/ServiceLogin"},
                    {"hop": 5, "status_code": 200, "url": "https://accounts.google.com/v3/signin/identifier"},
                ],
            ),
        ):
            fake_bundle = {
                "target_url": target,
                "final_url": final_url,
                "status_code": 200,
                "headers": {
                    "strict-transport-security": "max-age=31536000; includeSubDomains",
                    "content-security-policy": "script-src 'nonce-abc123' 'unsafe-inline'; object-src 'none'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                },
                "body_text": html_body,
                "bytes_read": len(html_body),
                "truncated": False,
                "redirect_chain": redirect_chain,
                "redirect_downgrade": False,
                "resolved_ip": "142.251.126.17",
                "error": None,
                "error_type": None,
                "tls_cert_der_b64": _make_test_cert_der_b64(domain, age_days=33),
                "tls_version": "TLSv1.3",
                "tls_cipher": "TLS_AES_256_GCM_SHA384",
                "tls_error": None,
            }

            with patch("app.core.scoring_engine.run_in_restricted_worker", new=AsyncMock(return_value=fake_bundle)):
                with patch.object(self.engine.threat_intel, "query_urlhaus", new=AsyncMock(return_value=None)):
                    with patch.object(self.engine.threat_intel, "query_phishtank", new=AsyncMock(return_value=None)):
                        report = asyncio.run(self.engine.execute_scan(
                            url=target,
                            fetch_content=True,
                            deep_dns=True,
                        ))
            self.assertEqual(report["verdict"], "BENIGN", f"{target} scored {report['overall_score']}: {report['score_breakdown']}")
            self.assertLess(report["overall_score"], 25.0)
            self.assertIsNone(report["threat_analysis"]["impersonated_brand"])

if __name__ == "__main__":
    unittest.main()
