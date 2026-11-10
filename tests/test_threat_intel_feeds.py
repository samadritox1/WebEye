import asyncio
import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from app.core.threat_intel import ThreatIntelHub
from app.main import app
from app.models.database import get_connection, get_cti_cache, init_db, set_cti_cache
from cli import cmd_scan


def _clear_test_cache(prefix: str = "https://cti-test-") -> None:
    conn = get_connection()
    conn.execute("DELETE FROM cti_cache WHERE indicator LIKE ?", (f"{prefix}%",))
    conn.commit()
    conn.close()


def _make_mock_resp(status_code: int, payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    raw = json.dumps(payload).encode("utf-8")
    resp.content = raw
    resp.json.return_value = payload
    return resp


class TestThreatIntelFeeds(unittest.TestCase):
    def setUp(self):
        init_db()
        _clear_test_cache()

    def tearDown(self):
        _clear_test_cache()

    def test_all_five_cti_integrations_positive_provenance_and_metadata(self):
        target_url = "https://cti-test-phish.example/login"
        hub = ThreatIntelHub()
        hub.vt_api_key = "vt-test-key"
        hub.gsb_api_key = "gsb-test-key"
        hub.otx_api_key = "otx-test-key"
        hub.urlhaus_api_key = "uh-test-key"
        hub.phishtank_api_key = "pt-test-key"
        hub.abuseipdb_api_key = ""

        seen_headers = {}

        async def fake_post(url, data=None, json=None, headers=None):
            if "urlhaus-api.abuse.ch" in url:
                seen_headers["urlhaus"] = headers or {}
                return _make_mock_resp(200, {
                    "query_status": "ok",
                    "threat": "malware_download",
                    "url_status": "online",
                    "date_added": "2026-11-10 04:00:00 UTC",
                    "reporter": "abuse_analyst",
                    "tags": ["phishing", "kit"],
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/99999/",
                })
            if "safebrowsing.googleapis.com" in url:
                seen_headers["gsb"] = headers or {}
                return _make_mock_resp(200, {
                    "matches": [{
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threatEntryType": "URL",
                    }]
                })
            if "phishtank.com" in url:
                return _make_mock_resp(200, {
                    "results": {
                        "url": target_url,
                        "in_database": True,
                        "verified": True,
                        "valid": True,
                        "phish_id": "887766",
                        "phish_detail_page": "https://phishtank.org/phish_detail.php?phish_id=887766",
                        "verified_at": "2026-11-10T03:30:00+00:00",
                    }
                })
            return _make_mock_resp(404, {})

        async def fake_get(url, headers=None, params=None):
            if "virustotal.com/api/v3/urls/" in url:
                seen_headers["vt"] = headers or {}
                return _make_mock_resp(200, {
                    "data": {
                        "attributes": {
                            "last_analysis_date": 1794280000,
                            "last_analysis_stats": {
                                "malicious": 9,
                                "suspicious": 2,
                                "harmless": 60,
                                "undetected": 10,
                            },
                            "reputation": -45,
                            "categories": {"Forcepoint": "phishing"},
                        }
                    }
                })
            if "otx.alienvault.com" in url:
                seen_headers["otx"] = headers or {}
                return _make_mock_resp(200, {
                    "pulse_info": {
                        "count": 3,
                        "pulses": [
                            {
                                "name": "Credential Harvester 2026",
                                "modified": "2026-11-10T02:15:00",
                                "tags": ["phishing", "credential"],
                            }
                        ],
                    }
                })
            return _make_mock_resp(404, {})

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=fake_post)
        mock_client.get = AsyncMock(side_effect=fake_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_client
        mock_ctx.__aexit__.return_value = None

        with patch("app.core.threat_intel.httpx.AsyncClient", return_value=mock_ctx):
            res = asyncio.run(hub.evaluate(target_url, refresh=True))

        # Verify auth headers sent properly
        self.assertEqual(seen_headers["urlhaus"].get("Auth-Key"), "uh-test-key")
        self.assertEqual(seen_headers["gsb"].get("X-Goog-Api-Key"), "gsb-test-key")
        self.assertEqual(seen_headers["vt"].get("x-apikey"), "vt-test-key")
        self.assertEqual(seen_headers["otx"].get("X-OTX-API-KEY"), "otx-test-key")

        self.assertGreaterEqual(res["score"], 95.0)
        providers_by_id = {p["provider"]: p for p in res["providers"]}

        for key in ("virustotal", "google_safe_browsing", "phishtank", "urlhaus", "alienvault_otx"):
            p = providers_by_id[key]
            self.assertEqual(p["status"], "matched")
            self.assertTrue(p["matched"])
            self.assertGreater(p["match_confidence"], 75.0)
            self.assertIsNotNone(p["last_updated"])
            self.assertTrue(len(p["provenance"]) > 0)
            self.assertFalse(p["cached"])

        self.assertIn("9/81 malicious", providers_by_id["virustotal"]["provenance"])
        self.assertIn("SOCIAL_ENGINEERING", providers_by_id["google_safe_browsing"]["provenance"])
        self.assertIn("887766", providers_by_id["phishtank"]["provenance"])
        self.assertIn("abuse_analyst", providers_by_id["urlhaus"]["provenance"])
        self.assertIn("Credential Harvester 2026", providers_by_id["alienvault_otx"]["provenance"])

    def test_persistent_cti_cache_avoids_duplicate_requests_and_respects_expiry_and_refresh(self):
        target_url = "https://cti-test-cache.example/path"
        hub = ThreatIntelHub()
        hub.vt_api_key = ""
        hub.gsb_api_key = "gsb-key"
        hub.otx_api_key = ""
        hub.abuseipdb_api_key = ""

        http_calls = {"post": 0}

        async def fake_post(url, data=None, json=None, headers=None):
            http_calls["post"] += 1
            if "urlhaus-api.abuse.ch" in url:
                return _make_mock_resp(200, {"query_status": "no_results"})
            if "phishtank.com" in url:
                return _make_mock_resp(200, {"results": {"in_database": False}})
            if "safebrowsing.googleapis.com" in url:
                return _make_mock_resp(200, {})
            return _make_mock_resp(404, {})

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=fake_post)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_client
        mock_ctx.__aexit__.return_value = None

        with patch("app.core.threat_intel.httpx.AsyncClient", return_value=mock_ctx):
            # 1. Cold cache: hits all 3 live POST endpoints
            res1 = asyncio.run(hub.evaluate(target_url, refresh=False))
            self.assertEqual(http_calls["post"], 3)
            self.assertEqual(res1["cache_hits"], 0)

            # 2. Warm cache: 0 HTTP requests made, all 3 providers marked cached=True!
            res2 = asyncio.run(hub.evaluate(target_url, refresh=False))
            self.assertEqual(http_calls["post"], 3)
            self.assertEqual(res2["cache_hits"], 3)
            by_id = {p["provider"]: p for p in res2["providers"]}
            self.assertTrue(by_id["urlhaus"]["cached"])
            self.assertTrue(by_id["phishtank"]["cached"])
            self.assertTrue(by_id["google_safe_browsing"]["cached"])

            # 3. refresh=True bypasses cache and performs fresh queries
            res3 = asyncio.run(hub.evaluate(target_url, refresh=True))
            self.assertEqual(http_calls["post"], 6)
            self.assertEqual(res3["cache_hits"], 0)

        # 4. Expired cache entry is automatically purged and treated as miss
        past_exp = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        set_cti_cache(
            f"urlhaus:{target_url}",
            "urlhaus",
            target_url,
            {"status": "clean", "matched": False},
            ttl_seconds=60,
        )
        conn = get_connection()
        conn.execute("UPDATE cti_cache SET expires_at = ? WHERE cache_key = ?", (past_exp, f"urlhaus:{target_url}"))
        conn.commit()
        conn.close()
        self.assertIsNone(get_cti_cache(f"urlhaus:{target_url}"))

    def test_transient_outages_are_not_cached_and_appear_in_missing_evidence(self):
        target_url = "https://cti-test-outage.example/login"
        hub = ThreatIntelHub()
        hub.vt_api_key = ""
        hub.gsb_api_key = ""
        hub.otx_api_key = "otx-key"
        hub.abuseipdb_api_key = ""

        async def failing_post(url, data=None, json=None, headers=None):
            return _make_mock_resp(429, {"error": "rate limited"})

        async def failing_get(url, headers=None, params=None):
            return _make_mock_resp(503, {"error": "service unavailable"})

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=failing_post)
        mock_client.get = AsyncMock(side_effect=failing_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_client
        mock_ctx.__aexit__.return_value = None

        with patch("app.core.threat_intel.httpx.AsyncClient", return_value=mock_ctx):
            res = asyncio.run(hub.evaluate(target_url))

        by_id = {p["provider"]: p for p in res["providers"]}
        self.assertEqual(by_id["urlhaus"]["status"], "unavailable")
        self.assertEqual(by_id["phishtank"]["status"], "unavailable")
        self.assertEqual(by_id["alienvault_otx"]["status"], "unavailable")
        self.assertEqual(by_id["virustotal"]["status"], "unconfigured")
        self.assertEqual(by_id["google_safe_browsing"]["status"], "unconfigured")

        # Outages must NOT be persisted in cti_cache
        self.assertIsNone(get_cti_cache(f"urlhaus:{target_url}"))
        self.assertIsNone(get_cti_cache(f"phishtank:{target_url}"))
        self.assertIsNone(get_cti_cache(f"alienvault_otx:{target_url}"))

        gap_checks = {m["check"] for m in res["missing_evidence"]}
        self.assertIn("URLhaus (abuse.ch) Live Feed", gap_checks)
        self.assertIn("PhishTank Live Feed", gap_checks)
        self.assertIn("AlienVault OTX Threat Pulses", gap_checks)

    def test_api_metadata_ui_and_cli_expose_expanded_cti_and_cache(self):
        client = TestClient(app)
        meta = client.get("/api/engine-metadata").json()
        intel_feeds = meta["pipeline"][3]["metrics"]["feeds"]
        for expected in ("VirusTotal v3", "Google Safe Browsing v4", "PhishTank", "URLhaus (abuse.ch)", "AlienVault OTX"):
            self.assertIn(expected, intel_feeds)

        html = client.get("/").text
        self.assertIn("container-cti-providers", html)
        self.assertIn("opt-refresh-intel", html)
        self.assertIn("val-cache-hits", html)

        resp = client.post("/api/scan", json={
            "url": "https://cti-test-api.example/auth",
            "fetch_content": False,
            "deep_dns": False,
            "refresh_intel": True,
        })
        self.assertEqual(resp.status_code, 200)
        ti = resp.json()["threat_intel"]
        self.assertIn("providers", ti)
        self.assertIn("cache_hits", ti)
        self.assertGreaterEqual(len(ti["providers"]), 6)

        buf = io.StringIO()
        with redirect_stdout(buf):
            asyncio.run(cmd_scan(
                url="https://cti-test-cli.example/login",
                fetch_content=False,
                deep_dns=False,
                refresh_intel=True,
            ))
        out = buf.getvalue()
        self.assertIn("Real-Time Threat Intelligence", out)
        self.assertIn("Provenance:", out)
        self.assertIn("VirusTotal v3", out)
        self.assertIn("Google Safe Browsing v4", out)
        self.assertIn("PhishTank", out)
        self.assertIn("URLhaus (abuse.ch)", out)
        self.assertIn("AlienVault OTX", out)

    def test_phishtank_invalidated_historical_entry_not_flagged(self):
        target_url = "https://cti-test-invalidated.example/"
        hub = ThreatIntelHub()
        hub.vt_api_key = ""
        hub.gsb_api_key = ""
        hub.otx_api_key = ""
        hub.abuseipdb_api_key = ""

        async def fake_post(url, data=None, json=None, headers=None):
            if "phishtank.com" in url:
                return _make_mock_resp(200, {
                    "results": {
                        "url": target_url,
                        "in_database": True,
                        "verified": True,
                        "valid": False,
                        "phish_id": 1983370,
                        "phish_detail_page": "https://www.phishtank.com/phish_detail.php?phish_id=1983370",
                        "verified_at": "2013-08-20T12:59:52+00:00",
                    }
                })
            return _make_mock_resp(200, {"query_status": "no_results"})

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=fake_post)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__.return_value = mock_client
        mock_ctx.__aexit__.return_value = None

        with patch("app.core.threat_intel.httpx.AsyncClient", return_value=mock_ctx):
            res = asyncio.run(hub.evaluate(target_url, refresh=True))

        self.assertEqual(res["score"], 0.0)
        by_id = {p["provider"]: p for p in res["providers"]}
        self.assertEqual(by_id["phishtank"]["status"], "clean")
        self.assertFalse(by_id["phishtank"]["matched"])
        self.assertIn("invalid", by_id["phishtank"]["provenance"].lower())


if __name__ == "__main__":
    unittest.main()
