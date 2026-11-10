import unittest
from app.models.database import init_db, add_ioc, query_ioc, record_vote, get_stats, get_connection
from app.core.threat_intel import ThreatIntelHub

class TestThreatIntel(unittest.TestCase):
    def setUp(self):
        init_db()
        self.intel_hub = ThreatIntelHub()

    def test_database_and_voting(self):
        test_url = "http://malicious-test-phish-domain.xyz/login"
        add_ioc(
            indicator=test_url,
            indicator_type="url",
            tags=["#test", "#phish"],
            source="Unit Test",
            confidence=95.0,
            notes="Automated test indicator"
        )

        ioc = query_ioc(test_url)
        self.assertIsNotNone(ioc)
        self.assertIn("#phish", ioc["tags"])

        # Cast a vote
        record_vote(test_url, "malicious", "Confirmed phishing lure")
        updated_ioc = query_ioc(test_url)
        self.assertGreaterEqual(updated_ioc["votes_malicious"], 2)

    def test_query_ioc_does_not_match_lookalike_substring(self):
        lookalike_url = "http://fake-google.example/login"
        add_ioc(
            indicator=lookalike_url,
            indicator_type="url",
            tags=["#test"],
            source="Unit Test",
            confidence=90.0,
            notes="Lookalike domain test",
        )
        try:
            self.assertIsNone(query_ioc("google.example"))
            self.assertIsNotNone(query_ioc("fake-google.example"))
        finally:
            conn = get_connection()
            conn.execute("DELETE FROM threat_iocs WHERE indicator = ?", (lookalike_url,))
            conn.commit()
            conn.close()

    def test_stats(self):
        stats = get_stats()
        self.assertIn("total_iocs", stats)
        self.assertGreater(stats["total_iocs"], 0)

if __name__ == "__main__":
    unittest.main()
