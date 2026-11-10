import unittest
from fastapi.testclient import TestClient

from app.core.cert_validator import CertificateValidator
from app.core.threat_graph import ThreatGraphBuilder
from app.main import app
from app.models.database import init_db
from tests.test_explainable_scoring import _make_test_cert_der_b64


def _make_scan_report(
    scan_id: str,
    url: str,
    domain: str,
    verdict: str,
    score: float,
    ips=None,
    ns_records=None,
    server_header=None,
    cert_fp=None,
    cert_serial=None,
    cert_issuer="Let's Encrypt (R3)",
    san_domains=None,
    impersonated_brand=None,
    redirect_chain=None,
    exfil_domain=None,
    abuse_isp=None,
    otx_pulses=None,
):
    contributions = []
    content_flags = []
    if exfil_domain:
        contributions.append({
            "engine": "threat_analysis",
            "factor": "cross_origin_form",
            "label": f"Cross-origin form submission to '{exfil_domain}'",
            "raw_points": 40.0,
            "points": 14.0,
            "severity": "critical",
            "evidence": exfil_domain,
        })
        content_flags.append(f"Critical: Form action posts credentials to disparate domain '{exfil_domain}'")

    providers = []
    ti_details = {}
    if abuse_isp:
        ti_details["abuseipdb_isp"] = abuse_isp
        ti_details["abuseipdb_country"] = "NL"
        ti_details["abuseipdb_usage_type"] = "Data Center/Web Hosting/Transit"
        providers.append({
            "provider": "abuseipdb",
            "source": "AbuseIPDB v2",
            "status": "matched",
            "matched": True,
            "provenance": f"AbuseIPDB v2 (12 report(s), ISP: {abuse_isp})",
        })
    if otx_pulses:
        providers.append({
            "provider": "alienvault_otx",
            "source": "AlienVault OTX",
            "status": "matched",
            "matched": True,
            "provenance": f"AlienVault OTX ({len(otx_pulses)} pulse(s): {', '.join(otx_pulses)})",
        })

    present_headers = {}
    if server_header:
        present_headers["server"] = server_header

    cert_details = {}
    if cert_fp:
        cert_details["sha256_fingerprint"] = cert_fp
    if cert_serial:
        cert_details["serial_number"] = cert_serial

    return {
        "scan_id": scan_id,
        "target_url": url,
        "target_domain": domain,
        "timestamp": "2026-11-10T06:00:00+00:00",
        "overall_score": score,
        "verdict": verdict,
        "threat_analysis": {
            "score": score,
            "entropy": 3.4,
            "homoglyph_detected": verdict != "BENIGN",
            "impersonated_brand": impersonated_brand,
            "has_password_input": bool(exfil_domain),
            "has_cross_origin_form": bool(exfil_domain),
            "lexical_flags": [],
            "content_flags": content_flags,
            "contributions": contributions,
        },
        "web_security": {
            "score": 25.0,
            "headers_grade": "C",
            "present_headers": present_headers,
            "dns_records": {
                "A": list(ips or []),
                "AAAA": [],
                "MX": [],
                "TXT": [],
                "NS": list(ns_records or []),
            },
            "spf_status": "Missing",
            "dmarc_status": "Missing",
            "redirect_chain": list(redirect_chain or []),
            "ip_address": ips[0] if ips else None,
            "details": {"fast_flux_detected": False},
        },
        "cert_validation": {
            "score": 30.0 if verdict != "BENIGN" else 0.0,
            "valid": True,
            "issuer": cert_issuer,
            "subject": domain,
            "san_domains": list(san_domains or [domain]),
            "age_days": 1 if verdict != "BENIGN" else 90,
            "is_free_automated_ca": True,
            "is_wildcard": False,
            "tls_version": "TLSv1.3",
            "details": cert_details,
        },
        "threat_intel": {
            "score": 0.0,
            "feed_hits": [],
            "tags": [],
            "providers": providers,
            "details": ti_details,
        },
    }


class TestThreatGraph(unittest.TestCase):
    def setUp(self):
        init_db()

    def test_shared_certificate_ip_hosting_and_campaign_clusters(self):
        shared_fp = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        scan1 = _make_scan_report(
            scan_id="SCN-PHISH01",
            url="https://paypa1-billing-auth.xyz/login",
            domain="paypa1-billing-auth.xyz",
            verdict="MALICIOUS",
            score=91.0,
            ips=["198.51.100.44"],
            ns_records=["ns1.cloudflare.com.", "ns2.cloudflare.com."],
            server_header="cloudflare",
            cert_fp=shared_fp,
            san_domains=["paypa1-billing-auth.xyz", "paypa1-resolution-desk.xyz"],
            impersonated_brand="PayPal",
            exfil_domain="drop-collector.evil",
            abuse_isp="Bulletproof VPS Hosting Ltd",
        )
        scan2 = _make_scan_report(
            scan_id="SCN-PHISH02",
            url="https://paypa1-resolution-desk.xyz/verify",
            domain="paypa1-resolution-desk.xyz",
            verdict="HIGH_RISK",
            score=72.0,
            ips=["198.51.100.44"],
            ns_records=["ns1.cloudflare.com."],
            cert_fp=shared_fp,
            san_domains=["paypa1-billing-auth.xyz", "paypa1-resolution-desk.xyz"],
            impersonated_brand="PayPal",
        )
        scan_benign = _make_scan_report(
            scan_id="SCN-GOOGLE01",
            url="https://www.google.com",
            domain="www.google.com",
            verdict="BENIGN",
            score=5.0,
            ips=["142.250.190.4"],
            ns_records=["ns1.google.com."],
            cert_fp="ffffffffffffffff0000000000000000ffffffffffffffff0000000000000000",
            cert_issuer="Google Trust Services (WE2)",
            san_domains=["www.google.com"],
            impersonated_brand=None,
        )
        iocs = [
            {
                "id": 99,
                "indicator": "http://paypal-security-update-center.com/login",
                "indicator_type": "url",
                "tags": ["#paypal", "#credential_harvesting"],
                "source": "URLhaus Feed",
                "confidence": 98.0,
                "notes": "Fake PayPal portal",
            }
        ]

        graph = ThreatGraphBuilder().build_graph([scan1, scan2, scan_benign], iocs=iocs)
        counts = graph["summary"]["node_counts"]

        # All 6 entity types must be represented
        for entity_type in ("domain", "url", "ip", "certificate", "hosting", "campaign"):
            self.assertGreater(counts[entity_type], 0, f"Expected >0 nodes for {entity_type}")

        # Benign google.com must NOT be tied to PayPal phishing campaign
        edges = graph["edges"]
        self.assertFalse(
            any(e["source"] == "domain:www.google.com" and e["target"] == "campaign:paypal" for e in edges)
        )

        # Verify shared certificate, shared IP, shared hosting, campaign, and exfiltration clusters detected
        cluster_types = {c["pivot_type"] for c in graph["clusters"]}
        self.assertIn("certificate", cluster_types)
        self.assertIn("ip", cluster_types)
        self.assertIn("hosting", cluster_types)
        self.assertIn("campaign", cluster_types)
        self.assertIn("exfiltration", cluster_types)

        cert_cluster = next(c for c in graph["clusters"] if c["pivot_type"] == "certificate")
        self.assertIn("paypa1-billing-auth.xyz", cert_cluster["domains"])
        self.assertIn("paypa1-resolution-desk.xyz", cert_cluster["domains"])

        # Threats-only filter excludes benign google.com
        threat_graph = ThreatGraphBuilder().build_graph([scan1, scan2, scan_benign], iocs=iocs, threats_only=True)
        threat_ids = {n["id"] for n in threat_graph["nodes"]}
        self.assertNotIn("domain:www.google.com", threat_ids)
        self.assertIn("domain:paypa1-billing-auth.xyz", threat_ids)
        self.assertIn("hosting:bulletproof_vps_hosting_ltd", threat_ids)

        # Scan focus pulls in sibling domain sharing the same certificate and IP
        focused = ThreatGraphBuilder().build_graph([scan1, scan2, scan_benign], iocs=iocs, scan_id="SCN-PHISH01")
        focused_ids = {n["id"] for n in focused["nodes"]}
        self.assertIn("domain:paypa1-resolution-desk.xyz", focused_ids)
        self.assertIn("domain:drop-collector.evil", focused_ids)
        self.assertNotIn("domain:www.google.com", focused_ids)

    def test_redirect_chain_and_query_filtering(self):
        scan_redir = _make_scan_report(
            scan_id="SCN-REDIR01",
            url="https://lure-short.example/go",
            domain="lure-short.example",
            verdict="SUSPICIOUS",
            score=42.0,
            ips=["203.0.113.10"],
            redirect_chain=[
                {"hop": 1, "status_code": 302, "url": "https://lure-short.example/go", "resolved_ip": "203.0.113.10", "server": "cloudflare"},
                {"hop": 2, "status_code": 200, "url": "https://landing-kit.example/auth?token=abc", "resolved_ip": "203.0.113.55", "server": "nginx"},
            ],
            otx_pulses=["Credential Kit Wave 4"],
        )
        graph = ThreatGraphBuilder().build_graph([scan_redir], iocs=[], query="landing-kit.example")
        rels = {(e["source"], e["relation"], e["target"]) for e in graph["edges"]}
        self.assertIn(("domain:landing-kit.example", "RESOLVES_TO", "ip:203.0.113.55"), rels)

        full = ThreatGraphBuilder().build_graph([scan_redir], iocs=[])
        full_rels = {e["relation"] for e in full["edges"]}
        self.assertIn("REDIRECTS_TO", full_rels)
        self.assertTrue(any(n["type"] == "campaign" and "Credential Kit Wave 4" in n["label"] for n in full["nodes"]))

    def test_cert_validator_records_sha256_fingerprint(self):
        der_b64 = _make_test_cert_der_b64("cert-graph-test.example", age_days=2)
        res = CertificateValidator().validate_certificate(
            "https://cert-graph-test.example",
            prefetched={"tls_cert_der_b64": der_b64, "tls_version": "TLSv1.3", "tls_cipher": "TLS_AES_256_GCM_SHA384"},
        )
        fp = res["details"].get("sha256_fingerprint")
        self.assertIsNotNone(fp)
        self.assertEqual(len(fp), 64)

    def test_api_graph_endpoint_and_dashboard_ui(self):
        client = TestClient(app)
        resp = client.get("/api/graph")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("clusters", data)
        self.assertIn("summary", data)
        self.assertGreater(len(data["nodes"]), 0)

        threats_resp = client.get("/api/graph?threats_only=true")
        self.assertEqual(threats_resp.status_code, 200)
        threats_data = threats_resp.json()
        for n in threats_data["nodes"]:
            if n["type"] == "domain" and n["label"] == "www.google.com":
                self.fail("Benign www.google.com should not appear in threats_only=true graph")

        query_resp = client.get("/api/graph?q=paypal")
        self.assertEqual(query_resp.status_code, 200)
        self.assertGreater(len(query_resp.json()["nodes"]), 0)

        html = client.get("/").text
        self.assertIn("tab-graph", html)
        self.assertIn("threat-graph-canvas", html)
        self.assertIn("btn-view-in-graph", html)
        self.assertIn("graph-clusters-list", html)


if __name__ == "__main__":
    unittest.main()
