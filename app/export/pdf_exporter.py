import io
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.export.stix_exporter import STIX21Exporter

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_VERDICT_COLORS = {
    "MALICIOUS": colors.HexColor("#dc2626"),
    "HIGH_RISK": colors.HexColor("#ea580c"),
    "SUSPICIOUS": colors.HexColor("#d97706"),
    "BENIGN": colors.HexColor("#059669"),
}

_DARK_NAVY = colors.HexColor("#0f172a")
_SLATE_BORDER = colors.HexColor("#cbd5e1")
_ROW_ALT_BG = colors.HexColor("#f8fafc")
_HEADER_BG = colors.HexColor("#1e293b")
_ACCENT_BLUE = colors.HexColor("#2563eb")
_MUTED_TEXT = colors.HexColor("#475569")


def _esc(val: Any, max_len: int = 400) -> str:
    """Sanitize and XML-escape untrusted values for ReportLab Paragraph rendering."""
    if val is None:
        return "N/A"
    text = str(val)
    text = _CONTROL_CHARS_RE.sub("", text)
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return xml_escape(text, {'"': "&quot;", "'": "&apos;"})


class PDFIncidentReportExporter:
    """Generates downloadable executive and technical PDF Incident Reports from PhishPulse scans."""

    @staticmethod
    def generate_pdf_report(
        scan_report: Dict[str, Any],
        stix_bundle: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """Render a complete multi-section PDF incident report and return raw PDF bytes."""
        if stix_bundle is None:
            stix_bundle = STIX21Exporter.generate_stix_bundle(scan_report)

        buf = io.BytesIO()
        scan_id = str(scan_report.get("scan_id") or "UNKNOWN")
        domain = str(scan_report.get("target_domain") or "unknown")
        verdict = str(scan_report.get("verdict") or "UNKNOWN").upper()
        generated_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=40,
            rightMargin=40,
            topMargin=52,
            bottomMargin=48,
            title=f"PhishPulse Incident Report - {scan_id} ({domain})",
            author="PhishPulse Threat Intelligence Platform",
        )

        usable_width = letter[0] - 80  # 532 pt
        styles = getSampleStyleSheet()

        s_banner_title = ParagraphStyle(
            "BannerTitle",
            parent=styles["Heading1"],
            fontSize=15,
            leading=19,
            textColor=colors.white,
            fontName="Helvetica-Bold",
            spaceAfter=2,
        )
        s_banner_sub = ParagraphStyle(
            "BannerSub",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#cbd5e1"),
        )
        s_verdict_pill = ParagraphStyle(
            "VerdictPill",
            parent=styles["Normal"],
            fontSize=10,
            leading=13,
            textColor=colors.white,
            fontName="Helvetica-Bold",
            alignment=1,
        )
        s_h2 = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontSize=11.5,
            leading=15,
            textColor=_DARK_NAVY,
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=4,
            keepWithNext=True,
        )
        s_h3 = ParagraphStyle(
            "SectionH3",
            parent=styles["Heading3"],
            fontSize=9.5,
            leading=13,
            textColor=_ACCENT_BLUE,
            fontName="Helvetica-Bold",
            spaceBefore=6,
            spaceAfter=3,
            keepWithNext=True,
        )
        s_body = ParagraphStyle(
            "BodyTextSafe",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#1e293b"),
            wordWrap="CJK",
        )
        s_bullet = ParagraphStyle(
            "BulletSafe",
            parent=s_body,
            leftIndent=12,
            firstLineIndent=-8,
            spaceAfter=2,
        )
        s_cell = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontSize=7.8,
            leading=10.5,
            textColor=colors.HexColor("#1e293b"),
            wordWrap="CJK",
        )
        s_cell_bold = ParagraphStyle(
            "TableCellBold",
            parent=s_cell,
            fontName="Helvetica-Bold",
        )
        s_cell_hdr = ParagraphStyle(
            "TableHeader",
            parent=s_cell,
            fontName="Helvetica-Bold",
            textColor=colors.white,
        )

        def p_cell(val: Any, bold: bool = False, max_len: int = 320) -> Paragraph:
            return Paragraph(_esc(val, max_len=max_len), s_cell_bold if bold else s_cell)

        def p_hdr(val: str) -> Paragraph:
            return Paragraph(_esc(val), s_cell_hdr)

        def styled_table(
            rows: List[List[Any]],
            col_widths: List[float],
            has_header: bool = True,
        ) -> Table:
            tbl = Table(rows, colWidths=col_widths, repeatRows=1 if has_header else 0)
            cmds = [
                ("GRID", (0, 0), (-1, -1), 0.4, _SLATE_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
            if has_header:
                cmds.append(("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG))
                for idx in range(1, len(rows)):
                    if idx % 2 == 0:
                        cmds.append(("BACKGROUND", (0, idx), (-1, idx), _ROW_ALT_BG))
            else:
                for idx in range(len(rows)):
                    if idx % 2 == 1:
                        cmds.append(("BACKGROUND", (0, idx), (-1, idx), _ROW_ALT_BG))
            tbl.setStyle(TableStyle(cmds))
            return tbl

        story: List[Any] = []

        # ------------------------------------------------------------------
        # Header Banner
        # ------------------------------------------------------------------
        verdict_bg = _VERDICT_COLORS.get(verdict, colors.HexColor("#334155"))
        score_val = float(scan_report.get("overall_score") or 0.0)
        banner_left = [
            Paragraph("PHISHPULSE AUTOMATED INCIDENT REPORT", s_banner_title),
            Paragraph(
                f"Scan ID: {_esc(scan_id)}  |  Target: {_esc(domain, max_len=90)}  |  Generated: {generated_utc}",
                s_banner_sub,
            ),
        ]
        banner_right = Paragraph(f"{_esc(verdict)}<br/>{score_val:.1f} / 100", s_verdict_pill)
        banner = Table([[banner_left, banner_right]], colWidths=[usable_width - 115, 115])
        banner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), _DARK_NAVY),
            ("BACKGROUND", (1, 0), (1, 0), verdict_bg),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(banner)
        story.append(Spacer(1, 10))

        # ------------------------------------------------------------------
        # 1. Executive Summary
        # ------------------------------------------------------------------
        story.append(Paragraph("1. Executive Summary", s_h2))
        story.append(HRFlowable(width="100%", thickness=0.7, color=_SLATE_BORDER, spaceAfter=6))

        confidence = scan_report.get("confidence")
        conf_level = scan_report.get("confidence_level") or ""
        conf_str = f"{float(confidence):.1f}% ({conf_level})" if isinstance(confidence, (int, float)) else "Legacy Scan"
        conf_reason = scan_report.get("confidence_reason") or "Standard multi-engine evaluation completed."

        exec_rows = [
            [p_cell("Scan / Incident ID", bold=True), p_cell(scan_id),
             p_cell("Verdict & Score", bold=True), p_cell(f"{verdict} ({score_val:.1f} / 100)")],
            [p_cell("Target URL", bold=True), p_cell(scan_report.get("target_url")),
             p_cell("Assessment Confidence", bold=True), p_cell(conf_str)],
            [p_cell("Target Domain", bold=True), p_cell(domain),
             p_cell("Scan Timestamp (UTC)", bold=True), p_cell(scan_report.get("timestamp"))],
        ]
        story.append(styled_table(exec_rows, [105, 175, 112, 140], has_header=False))
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"<b>Assessment Summary:</b> {_esc(scan_report.get('summary'), max_len=900)}", s_body))
        story.append(Spacer(1, 3))
        story.append(Paragraph(f"<b>Confidence Rationale:</b> {_esc(conf_reason, max_len=500)}", s_body))
        story.append(Spacer(1, 8))

        # ------------------------------------------------------------------
        # 2. Risk Assessment
        # ------------------------------------------------------------------
        story.append(Paragraph("2. Risk Assessment", s_h2))
        story.append(HRFlowable(width="100%", thickness=0.7, color=_SLATE_BORDER, spaceAfter=6))

        threat = scan_report.get("threat_analysis") or {}
        web_sec = scan_report.get("web_security") or {}
        cert = scan_report.get("cert_validation") or {}
        intel = scan_report.get("threat_intel") or {}

        engine_scores = scan_report.get("engine_scores") or [
            {"name": "Heuristic Threat Analyzer", "score": threat.get("score", 0.0), "weight": 0.35, "weighted_score": float(threat.get("score", 0.0)) * 0.35, "status": "evaluated", "confidence": None},
            {"name": "Web Security Posture Assessor", "score": web_sec.get("score", 0.0), "weight": 0.20, "weighted_score": float(web_sec.get("score", 0.0)) * 0.20, "status": "evaluated", "confidence": None},
            {"name": "SSL/TLS Certificate Validator", "score": cert.get("score", 0.0), "weight": 0.20, "weighted_score": float(cert.get("score", 0.0)) * 0.20, "status": "evaluated", "confidence": None},
            {"name": "Collaborative Threat Intel Hub", "score": intel.get("score", 0.0), "weight": 0.25, "weighted_score": float(intel.get("score", 0.0)) * 0.25, "status": "evaluated", "confidence": None},
        ]

        story.append(Paragraph("2.1 Individual Engine Scores", s_h3))
        eng_rows = [[
            p_hdr("Analytical Engine"),
            p_hdr("Score"),
            p_hdr("Weight"),
            p_hdr("Weighted Pts"),
            p_hdr("Status"),
            p_hdr("Confidence"),
        ]]
        for eng in engine_scores:
            eng_conf = eng.get("confidence")
            eng_conf_txt = f"{float(eng_conf):.0f}%" if isinstance(eng_conf, (int, float)) else "N/A"
            eng_rows.append([
                p_cell(eng.get("name")),
                p_cell(f"{float(eng.get('score', 0.0)):.1f}/100"),
                p_cell(f"{int(round(float(eng.get('weight', 0.0)) * 100))}%"),
                p_cell(f"+{float(eng.get('weighted_score', 0.0)):.1f}"),
                p_cell(str(eng.get("status", "evaluated")).upper()),
                p_cell(eng_conf_txt),
            ])
        story.append(styled_table(eng_rows, [182, 65, 55, 80, 75, 75], has_header=True))
        story.append(Spacer(1, 6))

        story.append(Paragraph("2.2 Itemized Risk Score Breakdown", s_h3))
        breakdown = scan_report.get("score_breakdown") or []
        if breakdown:
            bd_rows = [[
                p_hdr("Risk Factor"),
                p_hdr("Engine"),
                p_hdr("Raw Pts"),
                p_hdr("Weighted Pts"),
                p_hdr("Severity"),
                p_hdr("Evidence"),
            ]]
            for item in breakdown:
                pts = float(item.get("points", 0.0))
                raw_pts = float(item.get("raw_points", pts))
                sign = "+" if pts >= 0 else ""
                raw_sign = "+" if raw_pts >= 0 else ""
                bd_rows.append([
                    p_cell(item.get("label")),
                    p_cell(item.get("engine_label") or item.get("engine")),
                    p_cell(f"{raw_sign}{raw_pts:.1f}"),
                    p_cell(f"{sign}{pts:.1f}", bold=True),
                    p_cell(str(item.get("severity", "medium")).upper()),
                    p_cell(item.get("evidence") or "-"),
                ])
            story.append(styled_table(bd_rows, [145, 85, 52, 65, 58, 127], has_header=True))
        else:
            story.append(Paragraph("No penalty factors triggered (or legacy scan without itemized factor data).", s_body))
        story.append(Spacer(1, 8))

        # ------------------------------------------------------------------
        # 3. Technical Findings
        # ------------------------------------------------------------------
        story.append(Paragraph("3. Technical Findings", s_h2))
        story.append(HRFlowable(width="100%", thickness=0.7, color=_SLATE_BORDER, spaceAfter=6))

        # 3.1 Threat Analysis
        story.append(Paragraph("3.1 Heuristic & DOM Threat Analysis", s_h3))
        ta_rows = [
            [p_cell("Shannon Entropy", bold=True), p_cell(threat.get("entropy", 0.0)),
             p_cell("Impersonated Brand", bold=True), p_cell(threat.get("impersonated_brand") or "None")],
            [p_cell("Homoglyph / IDN", bold=True), p_cell("Detected" if threat.get("homoglyph_detected") else "None"),
             p_cell("Direct IP Hostname", bold=True), p_cell("Yes" if threat.get("is_ip_domain") else "No")],
            [p_cell("Password Input Form", bold=True), p_cell("Detected" if threat.get("has_password_input") else "None"),
             p_cell("Cross-Origin Form", bold=True), p_cell("Detected" if threat.get("has_cross_origin_form") else "None")],
        ]
        story.append(styled_table(ta_rows, [115, 151, 115, 151], has_header=False))
        all_ta_flags = list(threat.get("lexical_flags") or []) + list(threat.get("content_flags") or [])
        if all_ta_flags:
            story.append(Spacer(1, 3))
            for fl in all_ta_flags[:12]:
                story.append(Paragraph(f"&bull; {_esc(fl)}", s_bullet))
        story.append(Spacer(1, 5))

        # 3.2 Web Security Posture & Redirects
        story.append(Paragraph("3.2 Web Security Posture & Redirection Trace", s_h3))
        missing_hdrs = ", ".join(web_sec.get("missing_headers") or []) or "None"
        ws_rows = [
            [p_cell("Headers Grade", bold=True), p_cell(web_sec.get("headers_grade", "N/A")),
             p_cell("HSTS / CSP", bold=True), p_cell(f"HSTS={'Yes' if web_sec.get('hsts_enabled') else 'No'}, CSP={'Yes' if web_sec.get('csp_enabled') else 'No'}")],
            [p_cell("SPF Status", bold=True), p_cell(web_sec.get("spf_status", "N/A")),
             p_cell("DMARC Status", bold=True), p_cell(web_sec.get("dmarc_status", "N/A"))],
            [p_cell("Missing Headers", bold=True), p_cell(missing_hdrs),
             p_cell("Resolved Host IP", bold=True), p_cell(web_sec.get("ip_address") or "N/A")],
        ]
        story.append(styled_table(ws_rows, [105, 161, 105, 161], has_header=False))

        chain = web_sec.get("redirect_chain") or []
        if chain:
            story.append(Spacer(1, 4))
            rc_rows = [[p_hdr("Hop"), p_hdr("Status"), p_hdr("URL"), p_hdr("Resolved IP"), p_hdr("Server / Note")]]
            for hop in chain[:8]:
                rc_rows.append([
                    p_cell(hop.get("hop", "-")),
                    p_cell(hop.get("status_code", 0)),
                    p_cell(hop.get("url", "")),
                    p_cell(hop.get("resolved_ip") or "-"),
                    p_cell(hop.get("error") or hop.get("server") or "-"),
                ])
            story.append(styled_table(rc_rows, [32, 45, 255, 95, 105], has_header=True))
        story.append(Spacer(1, 5))

        # 3.3 Certificate Validation
        story.append(Paragraph("3.3 SSL/TLS Certificate Validation", s_h3))
        cert_rows = [
            [p_cell("Certificate Valid", bold=True), p_cell("Valid" if cert.get("valid") else "Invalid / Unencrypted"),
             p_cell("Issuer CA", bold=True), p_cell(cert.get("issuer") or "None")],
            [p_cell("Subject CN", bold=True), p_cell(cert.get("subject") or "None"),
             p_cell("Age / Expiry (days)", bold=True), p_cell(f"Age={cert.get('age_days')}d | Expires={cert.get('days_until_expiry')}d")],
            [p_cell("SAN Mismatch / Auto CA", bold=True), p_cell(f"Mismatch={'Yes' if cert.get('san_mismatch') else 'No'} | FreeCA={'Yes' if cert.get('is_free_automated_ca') else 'No'}"),
             p_cell("TLS / Signature", bold=True), p_cell(f"{cert.get('tls_version') or 'N/A'} / {cert.get('signature_algorithm') or 'N/A'}")],
        ]
        story.append(styled_table(cert_rows, [115, 151, 115, 151], has_header=False))
        cert_flags = cert.get("flags") or []
        if cert_flags:
            story.append(Spacer(1, 3))
            for fl in cert_flags[:8]:
                story.append(Paragraph(f"&bull; {_esc(fl)}", s_bullet))
        story.append(Spacer(1, 5))

        # 3.4 Real-Time Threat Intelligence
        story.append(Paragraph("3.4 Real-Time Threat Intelligence Feeds", s_h3))
        providers = intel.get("providers") or []
        if providers:
            cti_rows = [[
                p_hdr("CTI Source"),
                p_hdr("Status"),
                p_hdr("Match Conf."),
                p_hdr("Last Updated"),
                p_hdr("Cache"),
                p_hdr("Feed Provenance"),
            ]]
            for prov in providers:
                cti_rows.append([
                    p_cell(prov.get("source"), bold=True),
                    p_cell(str(prov.get("status", "clean")).upper()),
                    p_cell(f"{float(prov.get('match_confidence', 0.0)):.0f}%"),
                    p_cell(prov.get("last_updated") or "N/A"),
                    p_cell("CACHED" if prov.get("cached") else "LIVE"),
                    p_cell(prov.get("provenance") or prov.get("summary") or "-"),
                ])
            story.append(styled_table(cti_rows, [95, 65, 55, 92, 45, 180], has_header=True))
        else:
            feed_hits = ", ".join(intel.get("feed_hits") or []) or "None"
            story.append(Paragraph(f"Feed Hits: {_esc(feed_hits)} | URLhaus: {_esc(intel.get('urlhaus_status') or 'Clean')}", s_body))
        story.append(Spacer(1, 8))

        # ------------------------------------------------------------------
        # 4. Evidence and Indicators
        # ------------------------------------------------------------------
        story.append(Paragraph("4. Evidence and Indicators", s_h2))
        story.append(HRFlowable(width="100%", thickness=0.7, color=_SLATE_BORDER, spaceAfter=6))

        dns_rec = web_sec.get("dns_records") or {}
        ioc_rows = [
            [p_hdr("Indicator / Artifact Type"), p_hdr("Observed Value")],
            [p_cell("Target URL", bold=True), p_cell(scan_report.get("target_url"))],
            [p_cell("Target Domain", bold=True), p_cell(domain)],
            [p_cell("Resolved Host IP", bold=True), p_cell(web_sec.get("ip_address") or "Unresolved")],
            [p_cell("DNS A Records", bold=True), p_cell(", ".join(dns_rec.get("A") or []) or "None")],
            [p_cell("DNS AAAA / MX / NS", bold=True), p_cell(
                f"AAAA: {', '.join(dns_rec.get('AAAA') or []) or 'None'} | "
                f"MX: {', '.join(dns_rec.get('MX') or []) or 'None'} | "
                f"NS: {', '.join(dns_rec.get('NS') or []) or 'None'}"
            )],
            [p_cell("Certificate SAN Domains", bold=True), p_cell(", ".join(cert.get("san_domains") or []) or "None")],
            [p_cell("Threat Intelligence Tags", bold=True), p_cell(", ".join(intel.get("tags") or []) or "None")],
            [p_cell("Community Votes", bold=True), p_cell(
                f"+{intel.get('community_votes_malicious', 0)} malicious / "
                f"-{intel.get('community_votes_benign', 0)} benign"
            )],
        ]
        story.append(styled_table(ioc_rows, [145, usable_width - 145], has_header=True))

        missing_ev = scan_report.get("missing_evidence") or []
        story.append(Spacer(1, 6))
        story.append(Paragraph("4.1 Evidence Gaps & Uncollected Checks", s_h3))
        if missing_ev:
            gap_rows = [[p_hdr("Engine"), p_hdr("Check"), p_hdr("Reason"), p_hdr("Impact")]]
            for gap in missing_ev:
                gap_rows.append([
                    p_cell(gap.get("engine")),
                    p_cell(gap.get("check"), bold=True),
                    p_cell(gap.get("reason")),
                    p_cell(str(gap.get("impact", "medium")).upper()),
                ])
            story.append(styled_table(gap_rows, [85, 135, 257, 55], has_header=True))
        else:
            story.append(Paragraph("All expected security and threat intelligence checks completed without gaps.", s_body))
        story.append(Spacer(1, 8))

        # ------------------------------------------------------------------
        # 5. Recommended Remediation
        # ------------------------------------------------------------------
        story.append(Paragraph("5. Recommended Remediation", s_h2))
        story.append(HRFlowable(width="100%", thickness=0.7, color=_SLATE_BORDER, spaceAfter=6))

        mitigations = scan_report.get("mitigations") or []
        if mitigations:
            for idx, item in enumerate(mitigations, start=1):
                story.append(Paragraph(f"{idx}. {_esc(item, max_len=500)}", s_bullet))
        else:
            story.append(Paragraph("Target operates within baseline security parameters; continue routine monitoring.", s_body))
        story.append(Spacer(1, 8))

        # 5.1 MITRE ATT&CK Investigation & Hunting Analysis
        from app.core.mitre_mapper import MitreAttackMapper

        story.append(Paragraph("5.1 MITRE ATT&amp;CK Investigation &amp; Hunting Analysis", s_h3))
        mitre_report = scan_report.get("mitre_attack")
        if not isinstance(mitre_report, dict) or "techniques" not in mitre_report:
            mitre_report = MitreAttackMapper().build_investigation_report(
                scans=[scan_report],
                context_label=f"URL Scan {scan_report.get('scan_id', '')}",
                source_id=scan_report.get("scan_id"),
            )

        priority = str(mitre_report.get("investigation_priority") or "LOW")
        narrative = str(mitre_report.get("attack_narrative") or "No adversarial ATT&CK behaviors mapped for this target.")
        story.append(Paragraph(
            f"<b>Investigation Priority:</b> {_esc(priority, max_len=32)} &mdash; {_esc(narrative, max_len=900)}",
            s_body,
        ))
        story.append(Spacer(1, 4))

        mapped_techs = list(mitre_report.get("techniques") or [])
        if mapped_techs:
            mitre_rows = [[
                p_hdr("Technique"),
                p_hdr("Tactic"),
                p_hdr("Observed Behavioral Evidence"),
                p_hdr("Investigation & Hunting Pivots"),
            ]]
            for tech in mapped_techs[:10]:
                tid = str(tech.get("technique_id") or "")
                tname = str(tech.get("technique_name") or tech.get("name") or "")
                tsev = str(tech.get("severity") or "medium").upper()
                tactic = str(tech.get("tactic_name") or "")
                ev_list = [str(e) for e in (tech.get("observed_behaviors") or tech.get("evidence") or [])[:3]]
                pv_list = [str(p) for p in (tech.get("hunting_pivots") or [])[:2]]
                qs_list = [str(q) for q in (tech.get("investigation_questions") or [])[:1]]
                ev_text = "; ".join(ev_list) if ev_list else "Telemetry threshold triggered."
                pivot_parts = list(pv_list)
                if qs_list:
                    pivot_parts.append(f"Q: {qs_list[0]}")
                pivot_text = "; ".join(pivot_parts) if pivot_parts else "Correlate proxy & DNS logs."

                mitre_rows.append([
                    Paragraph(
                        f"<b>{_esc(tid, max_len=24)}</b><br/>{_esc(tname, max_len=65)} ({_esc(tsev, max_len=16)})",
                        s_cell,
                    ),
                    p_cell(tactic, max_len=40),
                    p_cell(ev_text, max_len=280),
                    p_cell(pivot_text, max_len=280),
                ])
            story.append(styled_table(mitre_rows, [94, 72, 186, 180]))
            story.append(Spacer(1, 6))

            playbook_steps = list(mitre_report.get("playbook") or [])[:4]
            if playbook_steps:
                story.append(Paragraph("<b>Recommended SOC Investigation Playbook:</b>", s_body))
                for step in playbook_steps:
                    if isinstance(step, dict):
                        phase = str(step.get("phase") or "Action")
                        actions = "; ".join(str(a) for a in (step.get("actions") or [])[:2])
                        line = f"<b>{_esc(phase, max_len=80)}:</b> {_esc(actions or step.get('objective', ''), max_len=360)}"
                    else:
                        line = _esc(str(step), max_len=420)
                    story.append(Paragraph(f"&bull; {line}", s_bullet))
        else:
            story.append(Paragraph("No MITRE ATT&amp;CK adversarial techniques exceeded behavioral detection thresholds.", s_body))
        story.append(Spacer(1, 8))

        # ------------------------------------------------------------------
        # 6. STIX 2.1 Export Reference
        # ------------------------------------------------------------------
        story.append(Paragraph("6. STIX 2.1 Export Reference", s_h2))
        story.append(HRFlowable(width="100%", thickness=0.7, color=_SLATE_BORDER, spaceAfter=6))

        stix_objects = stix_bundle.get("objects") or []
        indicator_obj = next((o for o in stix_objects if o.get("type") == "indicator"), {})
        attack_objs = [o for o in stix_objects if o.get("type") == "attack-pattern"]
        attack_obj = attack_objs[0] if attack_objs else {}
        mapped_ap_ids = []
        for ap in attack_objs:
            refs = ap.get("external_references") or []
            if refs and refs[0].get("external_id"):
                mapped_ap_ids.append(str(refs[0]["external_id"]))
        if not mapped_ap_ids:
            mapped_ap_ids = ["T1566.002"]
        mitre_summary = ", ".join(mapped_ap_ids)
        if len(mapped_ap_ids) == 1:
            mitre_cell_val = f"{mapped_ap_ids[0]} - {attack_obj.get('name', 'Spearphishing Link')}"
        else:
            mitre_cell_val = f"{mitre_summary} ({len(mapped_ap_ids)} Attack-Pattern SDOs)"

        stix_rows = [
            [p_hdr("STIX 2.1 Reference Field"), p_hdr("Value / Export URI")],
            [p_cell("STIX Specification", bold=True), p_cell("OASIS STIX 2.1 JSON Bundle")],
            [p_cell("STIX Bundle ID", bold=True), p_cell(stix_bundle.get("id"))],
            [p_cell("Indicator Object ID", bold=True), p_cell(indicator_obj.get("id") or "N/A")],
            [p_cell("STIX Indicator Pattern", bold=True), p_cell(indicator_obj.get("pattern") or "N/A")],
            [p_cell("MITRE ATT&CK Mapping", bold=True), p_cell(mitre_cell_val)],
            [p_cell("REST API Export Endpoint", bold=True), p_cell(f"/api/export/stix/{scan_id}")],
            [p_cell("STIX Bundle Filename", bold=True), p_cell(f"stix_{scan_id}.json")],
        ]
        story.append(styled_table(stix_rows, [145, usable_width - 145], has_header=True))

        def _draw_page_chrome(canvas, doc_obj):
            canvas.saveState()
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(_MUTED_TEXT)
            canvas.drawString(40, letter[1] - 32, f"PhishPulse Threat Intelligence Platform  |  Incident Report: {scan_id}")
            canvas.drawRightString(letter[0] - 40, letter[1] - 32, f"Verdict: {verdict} ({score_val:.1f}/100)")
            canvas.line(40, letter[1] - 36, letter[0] - 40, letter[1] - 36)
            canvas.line(40, 34, letter[0] - 40, 34)
            canvas.drawString(40, 22, f"Generated {generated_utc}  |  STIX Bundle: {stix_bundle.get('id', '')}")
            canvas.drawRightString(letter[0] - 40, 22, f"Page {doc_obj.page}")
            canvas.restoreState()

        doc.build(story, onFirstPage=_draw_page_chrome, onLaterPages=_draw_page_chrome)
        return buf.getvalue()
