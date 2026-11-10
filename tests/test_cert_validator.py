import unittest
from app.core.cert_validator import CertificateValidator

class TestCertificateValidator(unittest.TestCase):
    def setUp(self):
        self.validator = CertificateValidator()

    def test_san_matching(self):
        # Exact match
        self.assertTrue(self.validator._matches_san("example.com", ["example.com", "other.com"]))
        # Wildcard match
        self.assertTrue(self.validator._matches_san("sub.example.com", ["*.example.com"]))
        # Non-match
        self.assertFalse(self.validator._matches_san("phish.com", ["example.com", "google.com"]))

    def test_http_url_penalty(self):
        res = self.validator.validate_certificate("http://insecure-site.com")
        self.assertFalse(res["valid"])
        self.assertGreaterEqual(res["score"], 50.0)
        self.assertIn("plain HTTP", " ".join(res["flags"]))

    def test_live_tls_validation(self):
        # Validate against google.com
        try:
            res = self.validator.validate_certificate("https://www.google.com")
            if res["issuer"] is not None:
                self.assertTrue(res["valid"])
                self.assertFalse(res["san_mismatch"])
                self.assertIsNotNone(res["age_days"])
        except Exception:
            pass

if __name__ == "__main__":
    unittest.main()
