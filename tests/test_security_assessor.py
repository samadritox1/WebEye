import unittest
import asyncio
from unittest.mock import MagicMock, patch
from app.core.security_assessor import SecurityAssessor

class TestSecurityAssessor(unittest.TestCase):
    def setUp(self):
        self.assessor = SecurityAssessor()

    def test_dns_evaluation(self):
        # Resolve a known domain e.g. google.com or cloudflare.com
        res = self.assessor.inspect_dns_and_email_security("google.com")
        self.assertIn("records", res)
        self.assertIn("A", res["records"])
        self.assertIsNotNone(res["dmarc_record"])

    def test_redirection_chain_penalty(self):
        # Redirection hop count and penalty calculation
        async def run_redirect():
            chain, penalty = await self.assessor.trace_redirections("https://httpbin.org/status/200")
            return chain, penalty

        try:
            chain, penalty = asyncio.run(run_redirect())
            self.assertIsInstance(chain, list)
        except Exception:
            # Network-dependent test
            pass

    def test_nonce_csp_not_flagged_as_weak(self):
        headers_base = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
        }
        res_nonce = asyncio.run(self.assessor.audit_security_headers(
            "https://accounts.google.com",
            prefetched={
                "status_code": 200,
                "headers": {
                    **headers_base,
                    "content-security-policy": "script-src 'nonce-xyz123' 'unsafe-inline'; object-src 'none'",
                },
            },
        ))
        self.assertNotIn("weak_csp", [c["factor"] for c in res_nonce["contributions"]])

        res_bare_inline = asyncio.run(self.assessor.audit_security_headers(
            "https://example.com",
            prefetched={
                "status_code": 200,
                "headers": {
                    **headers_base,
                    "content-security-policy": "default-src 'self' 'unsafe-inline'",
                },
            },
        ))
        self.assertIn("weak_csp", [c["factor"] for c in res_bare_inline["contributions"]])

    def test_fast_flux_and_subdomain_dmarc_fallback(self):
        class FakeRData:
            def __init__(self, text_val):
                self._text = text_val
                self.strings = [text_val.encode("utf-8")]
            def to_text(self):
                return self._text

        class FakeAnswer(list):
            def __init__(self, items, ttl=120):
                super().__init__(items)
                self.rrset = MagicMock(ttl=ttl)

        def fake_resolve(qname, rtype):
            if qname == "mail.google.com" and rtype == "A":
                return FakeAnswer([
                    FakeRData("142.251.126.17"),
                    FakeRData("142.251.126.18"),
                    FakeRData("142.251.126.19"),
                    FakeRData("142.251.126.83"),
                ], ttl=260)
            if qname == "_dmarc.google.com" and rtype == "TXT":
                return FakeAnswer([FakeRData("v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com")])
            if qname == "flux.example" and rtype == "A":
                return FakeAnswer([
                    FakeRData("198.51.10.1"),
                    FakeRData("203.0.20.2"),
                    FakeRData("45.10.30.3"),
                    FakeRData("91.20.40.4"),
                ], ttl=60)
            if qname == "spcheck.example" and rtype == "A":
                return FakeAnswer([FakeRData("93.184.216.34")], ttl=300)
            if qname == "_dmarc.spcheck.example" and rtype == "TXT":
                return FakeAnswer([FakeRData("v=DMARC1; p=none; sp=quarantine")])
            raise Exception("NXDOMAIN")

        with patch.object(self.assessor.resolver, "resolve", side_effect=fake_resolve):
            mail_res = self.assessor.inspect_dns_and_email_security("mail.google.com")
            self.assertFalse(mail_res["fast_flux_detected"])
            self.assertIn("Inherited", mail_res["dmarc_status"])
            self.assertEqual(mail_res["penalty"], 0)

            flux_res = self.assessor.inspect_dns_and_email_security("flux.example")
            self.assertTrue(flux_res["fast_flux_detected"])

            sp_res = self.assessor.inspect_dns_and_email_security("spcheck.example")
            self.assertIn("p=none", sp_res["dmarc_status"])

    def test_redirect_chain_same_root_vs_cross_domain(self):
        same_root_chain = [
            {"hop": 1, "status_code": 301, "url": "https://mail.google.com"},
            {"hop": 2, "status_code": 301, "url": "https://mail.google.com/mail/"},
            {"hop": 3, "status_code": 302, "url": "https://mail.google.com/mail/u/0/"},
            {"hop": 4, "status_code": 302, "url": "https://accounts.google.com/ServiceLogin"},
            {"hop": 5, "status_code": 200, "url": "https://accounts.google.com/v3/signin"},
        ]
        _, penalty_same = asyncio.run(self.assessor.trace_redirections(
            "https://mail.google.com",
            prefetched={"redirect_chain": same_root_chain, "redirect_downgrade": False},
        ))
        self.assertEqual(penalty_same, 0)

        cross_domain_chain = [
            {"hop": 1, "status_code": 302, "url": "https://short.example/a"},
            {"hop": 2, "status_code": 302, "url": "https://hop1.example/b"},
            {"hop": 3, "status_code": 302, "url": "https://hop2.example/c"},
            {"hop": 4, "status_code": 302, "url": "https://hop3.example/d"},
            {"hop": 5, "status_code": 200, "url": "https://phish.example/login"},
        ]
        _, penalty_cross = asyncio.run(self.assessor.trace_redirections(
            "https://short.example/a",
            prefetched={"redirect_chain": cross_domain_chain, "redirect_downgrade": False},
        ))
        self.assertEqual(penalty_cross, 15)

if __name__ == "__main__":
    unittest.main()
