import unittest
from fastapi.testclient import TestClient
from app.models.database import init_db
from app.main import app

class TestAPI(unittest.TestCase):
    def setUp(self):
        init_db()
        self.client = TestClient(app)

    def test_root_dashboard(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue("PhishPulse" in resp.text or "PHISH" in resp.text.upper())

    def test_platform_stats_endpoint(self):
        resp = self.client.get("/api/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total_scans", data)
        self.assertIn("total_iocs", data)

    def test_iocs_endpoint(self):
        resp = self.client.get("/api/iocs")
        self.assertEqual(resp.status_code, 200)
        iocs = resp.json()
        self.assertIsInstance(iocs, list)
        self.assertGreater(len(iocs), 0)

    def test_scan_api(self):
        resp = self.client.post("/api/scan", json={
            "url": "http://paypa1-update-center.xyz/auth",
            "fetch_content": False,
            "deep_dns": False
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("scan_id", data)
        self.assertIn("verdict", data)
        self.assertIn("threat_analysis", data)
        self.assertIn("web_security", data)
        self.assertIn("cert_validation", data)
        self.assertIn("threat_intel", data)

    def test_community_submission(self):
        resp = self.client.post("/api/community/report", json={
            "url": "http://netflix-billing-fraud.xyz/pay",
            "tags": ["#netflix", "#scam"],
            "notes": "Fake payment form",
            "reported_by": "SOC_Lead"
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "success")

    def test_stix_feed_export(self):
        resp = self.client.get("/api/export/stix")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("type"), "bundle")
        self.assertIn("objects", data)

if __name__ == "__main__":
    unittest.main()
