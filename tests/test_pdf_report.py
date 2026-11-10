import asyncio
import base64
import io
import os
import re
import tempfile
import unittest
import zlib
from contextlib import redirect_stdout
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.core.scoring_engine import ScoringEngine
from app.export.pdf_exporter import PDFIncidentReportExporter
from app.export.stix_exporter import STIX21Exporter
from app.main import app
from app.models.database import init_db
from cli import cmd_scan


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Decompress ReportLab ASCII85+FlateDecode PDF streams and collect rendered text."""
    chunks = []
    for match in re.finditer(rb"stream[\r\n]+(.*?)[\r\n]*endstream", pdf_bytes, re.DOTALL):
        raw = match.group(1).strip()
        decoded = ""
        for decoder in (
            lambda b: zlib.decompress(base64.a85decode(b, adobe=True)),
            lambda b: zlib.decompress(b),
            lambda b: b,
        ):
            try:
                decoded = decoder(raw).decode("latin-1", errors="ignore")
                break
            except Exception:
                continue
        if decoded:
            chunks.append(decoded)
    joined = "\n".join(chunks)
    literals = re.findall(r"\(((?:\\.|[^\\()])*)\)", joined)
    cleaned = [lit.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\") for lit in literals]
    return re.sub(r"\s+", " ", " ".join(cleaned))


class TestPDFIncidentReport(unittest.TestCase):
    def setUp(self):
        init_db()
        self.engine = ScoringEngine()

    def test_pdf_contains_all_six_required_sections_and_matching_stix_ref(self):
        report = {
            "scan_id": "SCN-PDFTEST1",
            "target_url": "https://paypa1-verify.example/auth?x=1&y=<script>",
            "target_domain": "paypa1-verify.example",
            "timestamp": "2026-11-10T05:30:00+00:00",
            "overall_score": 92.0,
            "verdict": "MALICIOUS",
            "verdict_color": "rose",
            "summary": "MALICIOUS PHISHING DETECTED: Impersonating PayPal with credential harvesting.",
            "confidence": 88.5,
            "confidence_level": "HIGH",
            "confidence_reason": "High confidence (88.5%): Corroborated across live DOM, cert, and CTI.",
            "engine_scores": [
                {"engine": "threat_analysis", "name": "Heuristic Threat Analyzer", "score": 85.0, "weight": 0.35, "weighted_score": 29.8, "status": "evaluated", "confidence": 100.0},
                {"engine": "web_security", "name": "Web Security Posture Assessor", "score": 40.0, "weight": 0.20, "weighted_score": 8.0, "status": "evaluated", "confidence": 100.0},
                {"engine": "cert_validation", "name": "SSL/TLS Certificate Validator", "score": 30.0, "weight": 0.20, "weighted_score": 6.0, "status": "evaluated", "confidence": 100.0},
                {"engine": "threat_intel", "name": "Collaborative Threat Intel Hub", "score": 95.0, "weight": 0.25, "weighted_score": 23.8, "status": "evaluated", "confidence": 85.0},
            ],
            "score_breakdown": [
                {"engine": "correlation", "engine_label": "Correlation Rule", "factor": "correlation_amplification", "label": "Correlation Amplification: Confirmed CTI match", "raw_points": 24.4, "points": 24.4, "severity": "critical", "evidence": "PhishTank Verified"},
                {"engine": "threat_intel", "engine_label": "Threat Intelligence", "factor": "phishtank_match", "label": "PhishTank match: Verified Phishing (#12345)", "raw_points": 95.0, "points": 23.8, "severity": "critical", "evidence": "PhishTank Verified Phish #12345"},
            ],
            "missing_evidence": [
                {"engine": "threat_intel", "check": "VirusTotal v3 Reputation", "reason": "VIRUSTOTAL_API_KEY not configured", "impact": "low"},
            ],
            "threat_analysis": {
                "score": 85.0,
                "entropy": 3.9,
                "is_ip_domain": False,
                "suspicious_tld": ".example",
                "homoglyph_detected": True,
                "impersonated_brand": "PayPal",
                "lexical_flags": ["Brand deception: 'PayPal' found in non-official domain"],
                "content_flags": ["Credential entry form detected (1 password field(s))"],
                "has_password_input": True,
                "has_cross_origin_form": False,
            },
            "web_security": {
                "score": 40.0,
                "headers_grade": "D",
                "missing_headers": ["Strict-Transport-Security (HSTS)", "Content-Security-Policy (CSP)"],
                "hsts_enabled": False,
                "csp_enabled": False,
                "spf_status": "Missing SPF",
                "dmarc_status": "Missing DMARC",
                "dns_records": {"A": ["93.184.216.34"], "AAAA": [], "MX": [], "TXT": [], "NS": ["ns1.example"]},
                "redirect_chain": [{"hop": 1, "status_code": 200, "url": "https://paypa1-verify.example/auth", "resolved_ip": "93.184.216.34", "server": "nginx"}],
                "ip_address": "93.184.216.34",
            },
            "cert_validation": {
                "score": 30.0,
                "valid": True,
                "issuer": "Let's Encrypt (R3)",
                "subject": "paypa1-verify.example",
                "san_domains": ["paypa1-verify.example"],
                "age_days": 1,
                "days_until_expiry": 89,
                "is_free_automated_ca": True,
                "san_mismatch": False,
                "tls_version": "TLSv1.3",
                "signature_algorithm": "sha256",
                "flags": ["High Anomaly: Certificate minted only 1 day(s) ago (< 72 hours)"],
            },
            "threat_intel": {
                "score": 95.0,
                "feed_hits": ["PhishTank (Verified Phishing (#12345))"],
                "community_votes_malicious": 4,
                "community_votes_benign": 0,
                "tags": ["#paypal", "#phishtank_verified"],
                "providers": [
                    {
                        "provider": "phishtank",
                        "source": "PhishTank",
                        "status": "matched",
                        "matched": True,
                        "match_confidence": 97.0,
                        "last_updated": "2026-11-10T03:00:00+00:00",
                        "provenance": "PhishTank Verified Phish #12345",
                        "cached": False,
                    }
                ],
            },
            "mitigations": [
                "Block domain 'paypa1-verify.example' on perimeter firewalls.",
                "Export and ingest the STIX 2.1 IoC bundle into your SIEM/EDR platform.",
            ],
        }

        stix_bundle = STIX21Exporter.generate_stix_bundle(report)
        pdf_bytes = PDFIncidentReportExporter.generate_pdf_report(report, stix_bundle=stix_bundle)

        self.assertTrue(pdf_bytes.startswith(b"%PDF-1."))
        self.assertGreater(len(pdf_bytes), 3000)

        rendered_text = _extract_pdf_text(pdf_bytes)
        for required_heading in (
            "1. Executive Summary",
            "2. Risk Assessment",
            "3. Technical Findings",
            "4. Evidence and Indicators",
            "5. Recommended Remediation",
            "6. STIX 2.1 Export Reference",
        ):
            self.assertIn(required_heading, rendered_text)

        self.assertIn("SCN-PDFTEST1", rendered_text)
        self.assertIn("paypa1-verify.example", rendered_text)
        self.assertIn("93.184.216.34", rendered_text)
        self.assertIn("PhishTank Verified Phish #12345", rendered_text)
        self.assertIn("T1566.002", rendered_text)
        self.assertIn(stix_bundle["id"], rendered_text)
        self.assertIn("/api/export/stix/SCN-PDFTEST1", rendered_text)

    def test_legacy_minimal_report_generates_valid_pdf(self):
        legacy_report = {
            "scan_id": "SCN-LEGACY01",
            "target_url": "https://legacy-site.example",
            "target_domain": "legacy-site.example",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "overall_score": 12.0,
            "verdict": "BENIGN",
            "summary": "Legacy scan without explainability fields.",
            "threat_analysis": {"score": 0.0, "entropy": 2.5},
            "web_security": {"score": 20.0, "headers_grade": "B"},
            "cert_validation": {"score": 0.0, "valid": True, "issuer": "DigiCert"},
            "threat_intel": {"score": 0.0, "feed_hits": []},
            "mitigations": ["Enable CSP."],
        }
        pdf_bytes = PDFIncidentReportExporter.generate_pdf_report(legacy_report)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1."))
        rendered = _extract_pdf_text(pdf_bytes)
        self.assertIn("SCN-LEGACY01", rendered)
        self.assertIn("6. STIX 2.1 Export Reference", rendered)

    def test_api_pdf_export_endpoint_and_ui_button(self):
        client = TestClient(app)

        # Create a real scan first
        scan_resp = client.post("/api/scan", json={
            "url": "http://paypa1-incident-pdf.example/login",
            "fetch_content": False,
            "deep_dns": False,
        })
        self.assertEqual(scan_resp.status_code, 200)
        scan_id = scan_resp.json()["scan_id"]

        # Fetch STIX bundle and PDF incident report for same scan ID
        stix_resp = client.get(f"/api/export/stix/{scan_id}")
        self.assertEqual(stix_resp.status_code, 200)
        stix_bundle_id = stix_resp.json()["id"]

        pdf_resp = client.get(f"/api/export/pdf/{scan_id}")
        self.assertEqual(pdf_resp.status_code, 200)
        self.assertEqual(pdf_resp.headers["content-type"], "application/pdf")
        self.assertIn(f"incident_report_{scan_id}.pdf", pdf_resp.headers["content-disposition"])
        self.assertTrue(pdf_resp.content.startswith(b"%PDF-1."))

        # Verify PDF references the exact deterministic STIX bundle ID
        pdf_text = _extract_pdf_text(pdf_resp.content)
        self.assertIn(stix_bundle_id, pdf_text)
        self.assertIn(scan_id, pdf_text)

        # Non-existent scan ID returns 404
        missing_resp = client.get("/api/export/pdf/SCN-DOESNOTEXIST")
        self.assertEqual(missing_resp.status_code, 404)

        # Dashboard HTML exposes Download Incident PDF button
        html = client.get("/").text
        self.assertIn("btn-export-pdf", html)
        self.assertIn("Download Incident PDF", html)

    def test_cli_exports_pdf_report_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_pdf = os.path.join(tmp, "incident.pdf")
            buf = io.StringIO()
            with redirect_stdout(buf):
                asyncio.run(cmd_scan(
                    url="http://paypa1-cli-pdf.example/login",
                    fetch_content=False,
                    deep_dns=False,
                    export_pdf=out_pdf,
                ))
            self.assertIn("PDF Incident Report exported to:", buf.getvalue())
            self.assertTrue(os.path.exists(out_pdf))
            with open(out_pdf, "rb") as f:
                data = f.read()
            self.assertTrue(data.startswith(b"%PDF-1."))
            self.assertIn("1. Executive Summary", _extract_pdf_text(data))


if __name__ == "__main__":
    unittest.main()
