import base64
import io
import re
import unittest
import zlib
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.core.mitre_mapper import ATTACK_TACTICS, MitreAttackMapper
from app.export.pdf_exporter import PDFIncidentReportExporter
from app.export.stix_exporter import STIX21Exporter
from app.main import app
from app.models.database import init_db
from tests.test_threat_graph import _make_scan_report


def _extract_pdf_text_fallback(pdf_bytes: bytes) -> str:
    """Extract readable text from ReportLab PDF bytes (ASCII85 + Flate streams)."""
    try:
        from pypdf import PdfReader  # type: ignore

        reader = PdfReader(io.BytesIO(pdf_bytes))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception:
        chunks = [pdf_bytes.decode("latin-1", errors="ignore")]
        start = 0
        while True:
            idx = pdf_bytes.find(b"stream", start)
            if idx == -1:
                break
            s_start = pdf_bytes.find(b"\n", idx) + 1
            s_end = pdf_bytes.find(b"endstream", s_start)
            if s_start <= 0 or s_end == -1:
                break
            raw_stream = pdf_bytes[s_start:s_end].strip(b"\r\n")
            for candidate in (raw_stream,):
                try:
                    a85_input = candidate if candidate.startswith(b"<~") else b"<~" + candidate
                    decoded = base64.a85decode(a85_input, adobe=True)
                    text_stream = zlib.decompress(decoded).decode("latin-1", errors="ignore")
                    merged_stream = re.sub(r"\)\s*Tj\s*\(", "", text_stream)
                    tokens = re.findall(r"\(([^()\\]*(?:\\.[^()\\]*)*)\)", merged_stream)
                    cleaned = " ".join(t.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\") for t in tokens)
                    cleaned = re.sub(r"\s+", " ", cleaned)
                    chunks.append(text_stream + "\n" + cleaned)
                    continue
                except Exception:
                    pass
                try:
                    text_stream = zlib.decompress(candidate).decode("latin-1", errors="ignore")
                    chunks.append(text_stream)
                except Exception:
                    pass
            start = s_end + 9
        return "\n".join(chunks)


def _make_rich_phish_scan(scan_id: str = "SCN-MITRETEST") -> dict:
    report = _make_scan_report(
        scan_id=scan_id,
        url="https://bit.ly/paypal-verify-login",
        domain="paypa1-verify-auth.xyz",
        verdict="MALICIOUS",
        score=92.5,
        ips=["198.51.100.77"],
        ns_records=["ns1.cloudflare.com."],
        server_header="nginx",
        cert_fp="b" * 64,
        cert_serial="998877",
        impersonated_brand="PayPal",
        redirect_chain=[
            {"hop": 1, "status_code": 302, "url": "https://bit.ly/paypal-verify-login"},
            {"hop": 2, "status_code": 200, "url": "https://paypa1-verify-auth.xyz/signin"},
        ],
        exfil_domain="drop-collector.evil",
        abuse_isp="Bulletproof VPS Ltd",
        otx_pulses=["PayPal Credential Phish 2026"],
    )
    report["threat_analysis"]["lexical_flags"] = [
        "URL shortener service detected (bit.ly)",
        "Unicode homoglyph characters detected in domain",
    ]
    report["threat_analysis"]["content_flags"].append(
        "Obfuscated JavaScript detected (eval(atob(...)) payload decoder)"
    )
    report["web_security"]["details"]["fast_flux_detected"] = True
    return report


def _make_rich_sandbox_run(sandbox_id: str = "SBX-MITRETEST") -> dict:
    return {
        "sandbox_id": sandbox_id,
        "target_url": "https://login-check.evil/auth",
        "final_url": "https://harvest-panel.evil/capture",
        "target_domain": "login-check.evil",
        "final_domain": "harvest-panel.evil",
        "timestamp": "2026-11-10T06:30:00+00:00",
        "sandbox_score": 88.0,
        "verdict": "MALICIOUS",
        "page_title": "Sign In to Microsoft Account",
        "redirect_chain": [
            {"hop": 1, "url": "https://login-check.evil/auth", "status_code": 302, "is_cross_origin": True},
            {"hop": 2, "url": "https://harvest-panel.evil/capture", "status_code": 200, "is_cross_origin": False},
        ],
        "network_requests": [
            {"url": "https://c2-drop.evil/beacon", "method": "POST", "resource_type": "fetch", "is_third_party": True},
        ],
        "blocked_requests": [
            {"url": "http://169.254.169.254/latest/meta-data/", "method": "GET", "block_reason": "SSRF private metadata blocked"},
        ],
        "form_destinations": [
            {
                "action_url": "https://drop-collector.evil/steal.php",
                "action_domain": "drop-collector.evil",
                "method": "POST",
                "has_password_input": True,
                "is_cross_origin": True,
            }
        ],
        "suspicious_scripts": [
            {
                "severity": "high",
                "indicators": ["runtime_eval", "obfuscated_eval"],
                "reasons": ["Co-located eval() with Base64 atob() decoder executed dynamically"],
            },
            {
                "severity": "critical",
                "indicators": ["keylogger_exfil"],
                "reasons": ["Keydown event listener paired with external fetch exfiltration"],
            },
        ],
        "runtime_exfil_targets": [
            {"api": "fetch", "method": "POST", "url": "https://drop-collector.evil/beacon", "domain": "drop-collector.evil", "is_cross_origin": True},
        ],
        "telemetry": {"blocked_count": 1, "third_party_requests": 4, "clipboard_ops": 2},
    }


def _make_rich_email_report(email_id: str = "EML-MITRETEST") -> dict:
    return {
        "email_id": email_id,
        "filename": "invoice_urgent.eml",
        "timestamp": "2026-11-10T06:45:00+00:00",
        "overall_score": 94.0,
        "verdict": "MALICIOUS",
        "subject": "Urgent Microsoft 365 Password Expiry & Invoice",
        "authentication": {
            "spf_status": "Fail",
            "dkim_status": "Fail",
            "dmarc_status": "fail",
            "dmarc_result": "fail",
            "alignment_passed": False,
        },
        "sender": {
            "from_address": "support@m1crosoft-billing.xyz",
            "from_domain": "m1crosoft-billing.xyz",
            "from_display": "Microsoft Billing Team",
            "reply_to_address": "collector@proton-drop.evil",
            "return_path_address": "bounce@bulk-relay.ru",
            "impersonated_brand": "Microsoft",
            "spoofing_detected": True,
            "indicators": [
                "Display name spoofs Microsoft from unrelated domain m1crosoft-billing.xyz",
                "Reply-To header redirects replies to collector@proton-drop.evil",
            ],
        },
        "header_anomalies": [
            "Missing or forged Received hop timestamp alignment",
            "Return-Path domain differs from From header domain",
        ],
        "embedded_urls": [
            {
                "url": "https://evil-phish.xyz/login",
                "domain": "evil-phish.xyz",
                "anchor_text": "https://login.microsoftonline.com/verify",
                "anchor_mismatch": True,
                "score": 85.0,
                "reasons": ["Deceptive anchor href does not match visible Microsoft URL"],
            }
        ],
        "attachments": [
            {
                "filename": "invoice.pdf.html",
                "size_bytes": 18400,
                "sha256": "c" * 64,
                "detected_magic_type": "text/html",
                "verdict": "MALICIOUS",
                "is_dangerous": True,
                "extension_mismatch": True,
                "risk_score": 95.0,
                "findings": [
                    "HTML smuggling blob assembly detected (<script> + atob payload)",
                    "Double-extension masquerading HTML credential lure as PDF",
                ],
                "macro_indicators": ["AutoOpen VBA macro stream marker detected"],
            }
        ],
    }


class TestMitreAttackMapping(unittest.TestCase):
    def setUp(self):
        init_db()
        self.mapper = MitreAttackMapper()

    def test_url_scan_maps_behaviors_and_investigation_fields(self):
        scan = _make_rich_phish_scan()
        report = self.mapper.build_investigation_report(
            scans=[scan],
            context_label="URL Scan Test",
            source_id=scan["scan_id"],
        )

        self.assertIn(report["investigation_priority"], {"HIGH", "CRITICAL"})
        self.assertGreaterEqual(len(report["techniques"]), 4)
        self.assertGreater(len(report["attack_narrative"]), 30)
        self.assertGreater(len(report["playbook"]), 0)
        self.assertEqual(len(report["tactic_matrix"]), len(ATTACK_TACTICS))

        tech_ids = {t["technique_id"] for t in report["techniques"]}
        self.assertIn("T1566.002", tech_ids)
        self.assertIn("T1036.005", tech_ids)

        # Verify every technique carries full investigation guidance, not just an ID
        for tech in report["techniques"]:
            self.assertGreater(len(tech["observed_behaviors"]), 0, f"Missing behaviors for {tech['technique_id']}")
            self.assertGreater(len(tech["investigation_questions"]), 0, f"Missing triage Qs for {tech['technique_id']}")
            self.assertGreater(len(tech["hunting_pivots"]), 0, f"Missing pivots for {tech['technique_id']}")
            self.assertTrue(tech.get("detection_guidance"))
            self.assertTrue(tech.get("mitigation"))
            self.assertTrue(tech.get("technique_name"))

    def test_sandbox_run_maps_dynamic_execution_and_exfil(self):
        sbx = _make_rich_sandbox_run()
        report = self.mapper.build_investigation_report(
            sandbox_runs=[sbx],
            context_label="Sandbox Test",
            source_id=sbx["sandbox_id"],
        )
        tech_ids = {t["technique_id"] for t in report["techniques"]}
        self.assertIn("T1059.007", tech_ids)
        self.assertIn("T1027", tech_ids)
        self.assertIn("T1056.001", tech_ids)
        self.assertIn("T1115", tech_ids)
        self.assertIn("T1041", tech_ids)
        self.assertGreaterEqual(len(tech_ids), 6)

        keylog_finding = next(t for t in report["techniques"] if t["technique_id"] == "T1056.001")
        self.assertTrue(any("keystroke" in ev.lower() or "keylogger" in ev.lower() for ev in keylog_finding["observed_behaviors"]))

    def test_email_analysis_maps_auth_spoofing_and_attachments(self):
        eml = _make_rich_email_report()
        report = self.mapper.build_investigation_report(
            email_reports=[eml],
            context_label="Email Test",
            source_id=eml["email_id"],
        )
        tech_ids = {t["technique_id"] for t in report["techniques"]}
        self.assertIn("T1566.001", tech_ids)
        self.assertIn("T1566.002", tech_ids)
        self.assertIn("T1036.005", tech_ids)
        self.assertIn("T1585.002", tech_ids)

    def test_benign_url_scan_yields_low_priority_clean_report(self):
        benign = _make_scan_report(
            scan_id="SCN-BENIGN-MITRE",
            url="https://www.wikipedia.org/",
            domain="www.wikipedia.org",
            verdict="BENIGN",
            score=4.0,
        )
        report = self.mapper.build_investigation_report(scans=[benign])
        self.assertEqual(report["investigation_priority"], "LOW")
        self.assertEqual(report["summary"]["critical_count"] + report["summary"]["high_count"], 0)

    def test_stix_bundle_emits_dynamic_attack_patterns_and_relationships(self):
        scan = _make_rich_phish_scan("SCN-STIX-MITRE")
        bundle = STIX21Exporter.generate_stix_bundle(scan)
        objs = bundle["objects"]

        indicators = [o for o in objs if o["type"] == "indicator"]
        attack_patterns = [o for o in objs if o["type"] == "attack-pattern"]
        rels = [o for o in objs if o["type"] == "relationship"]

        self.assertEqual(len(indicators), 1)
        indicator_id = indicators[0]["id"]
        self.assertGreaterEqual(len(attack_patterns), 4)

        ap_ids = [ap["external_references"][0]["external_id"] for ap in attack_patterns]
        self.assertEqual(ap_ids[0], "T1566.002")
        self.assertEqual(
            attack_patterns[0]["id"],
            f"attack-pattern--{STIX21Exporter._deterministic_uuid('SCN-STIX-MITRE', 'attack-pattern')}",
        )
        self.assertEqual(len(rels), len(attack_patterns))
        rel_targets = {r["target_ref"] for r in rels}
        for ap in attack_patterns:
            self.assertIn(ap["id"], rel_targets)
            self.assertTrue(len(ap.get("kill_chain_phases", [])) > 0)
            self.assertIn("Observed behaviors:", ap["description"])
        for r in rels:
            self.assertEqual(r["source_ref"], indicator_id)
            self.assertEqual(r["relationship_type"], "indicates")

    def test_pdf_exporter_includes_mitre_investigation_section(self):
        scan = _make_rich_phish_scan("SCN-PDF-MITRE")
        stix_bundle = STIX21Exporter.generate_stix_bundle(scan)
        pdf_bytes = PDFIncidentReportExporter.generate_pdf_report(scan, stix_bundle=stix_bundle)
        text = _extract_pdf_text_fallback(pdf_bytes)

        self.assertIn("1. Executive Summary", text)
        self.assertIn("5.1 MITRE ATT&CK Investigation & Hunting Analysis", text)
        self.assertIn("6. STIX 2.1 Export Reference", text)
        self.assertIn("T1566.002", text)
        self.assertIn("T1036.005", text)

    def test_api_mitre_targets_and_dashboard_ui(self):
        client = TestClient(app)

        # Workspace aggregate endpoint
        ws_resp = client.get("/api/mitre")
        self.assertEqual(ws_resp.status_code, 200)
        ws_data = ws_resp.json()
        self.assertEqual(len(ws_data["tactic_matrix"]), 8)
        self.assertIn("attack_narrative", ws_data)
        self.assertIn("playbook", ws_data)

        # Target-scoped endpoints (scan_id, sandbox_id, email_id, missing 404)
        rich_scan = _make_rich_phish_scan("SCN-APIMITRE")
        rich_sbx = _make_rich_sandbox_run("SBX-APIMITRE")
        rich_eml = _make_rich_email_report("EML-APIMITRE")

        with (
            patch("app.models.database.get_scan_by_id", return_value=rich_scan),
            patch("app.models.database.get_sandbox_run_by_id", return_value=rich_sbx),
            patch("app.models.database.get_email_scan_by_id", return_value=rich_eml),
        ):
            r_scan = client.get("/api/mitre?scan_id=SCN-APIMITRE")
            self.assertEqual(r_scan.status_code, 200)
            self.assertEqual(r_scan.json()["source_id"], "SCN-APIMITRE")
            self.assertGreaterEqual(len(r_scan.json()["techniques"]), 4)

            r_sbx = client.get("/api/mitre?sandbox_id=SBX-APIMITRE")
            self.assertEqual(r_sbx.status_code, 200)
            self.assertEqual(r_sbx.json()["source_id"], "SBX-APIMITRE")
            self.assertIn("T1056.001", {t["technique_id"] for t in r_sbx.json()["techniques"]})

            r_eml = client.get("/api/mitre?email_id=EML-APIMITRE")
            self.assertEqual(r_eml.status_code, 200)
            self.assertEqual(r_eml.json()["source_id"], "EML-APIMITRE")
            self.assertIn("T1566.001", {t["technique_id"] for t in r_eml.json()["techniques"]})

        with patch("app.models.database.get_scan_by_id", return_value=None):
            r_missing = client.get("/api/mitre?scan_id=SCN-DOES-NOT-EXIST")
            self.assertEqual(r_missing.status_code, 404)

        # Dashboard HTML contains MITRE ATT&CK matrix & pivot controls
        html = client.get("/").text
        for required_id in (
            "tab-mitre",
            "mitre-tactic-matrix",
            "mitre-techniques-list",
            "mitre-playbook-list",
            "btn-view-in-mitre",
            "btn-sbx-mitre",
            "btn-eml-mitre",
        ):
            self.assertIn(required_id, html)


if __name__ == "__main__":
    unittest.main()
