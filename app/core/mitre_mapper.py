from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple


# Ordered MITRE ATT&CK Tactics rendered in the investigation matrix
ATTACK_TACTICS: List[Dict[str, str]] = [
    {"id": "TA0043", "name": "Reconnaissance", "short": "Recon"},
    {"id": "TA0042", "name": "Resource Development", "short": "Resource Dev"},
    {"id": "TA0001", "name": "Initial Access", "short": "Initial Access"},
    {"id": "TA0002", "name": "Execution", "short": "Execution"},
    {"id": "TA0005", "name": "Defense Evasion", "short": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access", "short": "Credential Access"},
    {"id": "TA0009", "name": "Collection & Exfil", "short": "Collection / Exfil"},
    {"id": "TA0011", "name": "Command & Control", "short": "Command & Control"},
]

TECHNIQUE_CATALOG: Dict[str, Dict[str, Any]] = {
    "T1598": {
        "id": "T1598",
        "name": "Phishing for Information",
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1598/",
        "summary": "Adversaries craft deceptive security, billing, or account-recovery pretexts to elicit sensitive details from victims.",
        "investigation_questions": [
            "Which organization brand, business workflow, or urgency theme is the lure exploiting?",
            "Have targeted users received similar pretexts via email, SMS, or messaging channels within the last 7 days?",
        ],
        "detection_guidance": "Correlate authentication/urgency lure keywords in URL paths and email subjects with newly observed external sender domains.",
        "mitigation": "Conduct targeted user awareness notifications and add pretext-specific keywords to secure email/web gateway policies.",
    },
    "T1583.001": {
        "id": "T1583.001",
        "name": "Acquire Infrastructure: Domains",
        "tactic_id": "TA0042",
        "tactic_name": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1583/001/",
        "summary": "Adversaries register lookalike, high-entropy, or disposable domains on permissive TLDs to stage phishing infrastructure.",
        "investigation_questions": [
            "When was this domain registered (WHOIS age), and are sibling lookalike domains hosted on the same NS/IP netblock?",
            "Did any internal endpoints resolve this domain via recursive DNS logs?",
        ],
        "detection_guidance": "Monitor passive DNS and proxy logs for newly registered domains matching protected brand edit distances or suspicious TLDs.",
        "mitigation": "Sinkhole or block lookalike domains on perimeter DNS/proxy and submit registrar abuse takedowns.",
    },
    "T1588.004": {
        "id": "T1588.004",
        "name": "Obtain Capabilities: Digital Certificates",
        "tactic_id": "TA0042",
        "tactic_name": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1588/004/",
        "summary": "Adversaries provision automated or mismatched TLS certificates to make phishing portals appear encrypted and trustworthy.",
        "investigation_questions": [
            "What other phishing domains share this exact certificate SHA-256 fingerprint, serial number, or SAN list?",
            "Do Certificate Transparency logs show recently minted certificates referencing your enterprise brand?",
        ],
        "detection_guidance": "Alert on Certificate Transparency logs issuing <72h certificates for brand lookalikes and inspect SAN multi-domain overlaps.",
        "mitigation": "Pivot on the certificate serial/fingerprint in Threat Graph to block co-hosted infrastructure proactively.",
    },
    "T1585.002": {
        "id": "T1585.002",
        "name": "Establish Accounts: Email Accounts",
        "tactic_id": "TA0042",
        "tactic_name": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1585/002/",
        "summary": "Adversaries abuse webmail providers, spoofed display names, or mismatched Reply-To addresses to impersonate trusted entities.",
        "investigation_questions": [
            "Have any recipients replied to the mismatched Reply-To address or engaged in BEC conversation threads?",
            "Are external gateways enforcing strict DMARC alignment and flagging display-name spoofing banners?",
        ],
        "detection_guidance": "Alert on external emails whose display name contains internal VIPs/protected brands or whose Reply-To diverges from From.",
        "mitigation": "Quarantine spoofed sender addresses, block unauthorized Reply-To domains, and enforce DMARC p=reject on owned domains.",
    },
    "T1566.002": {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
        "summary": "Adversaries deliver deceptive HTTP/HTTPS URLs (including anchor-text mismatches and open redirects) to lure users to hostile pages.",
        "investigation_questions": [
            "Which employees clicked this URL in web proxy, firewall, or EDR network telemetry?",
            "Did the email containing this link reach multiple mailboxes across the organization?",
        ],
        "detection_guidance": "Hunt web proxy and email click-protection logs for HTTP GET requests matching the full target URL or redirect chain hosts.",
        "mitigation": "Purge matching emails from mailboxes, block the target URL/domain at web proxies, and inspect clickers for follow-on activity.",
    },
    "T1566.001": {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
        "summary": "Adversaries attach malicious archives, weaponized documents, HTML lures, or executables to achieve code execution or credential capture.",
        "investigation_questions": [
            "Did any recipient save, extract, or open this attachment hash (SHA-256) on an endpoint?",
            "Are other variants with the same file magic type or archive structure queued in mail quarantine?",
        ],
        "detection_guidance": "Query EDR file-creation events for the attachment SHA-256, filename, and extracted archive member names.",
        "mitigation": "Block hazardous attachment extensions and mismatching magic types at the secure email gateway and quarantine endpoints that opened it.",
    },
    "T1204.001": {
        "id": "T1204.001",
        "name": "User Execution: Malicious Link",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "url": "https://attack.mitre.org/techniques/T1204/001/",
        "summary": "Victim interaction with a malicious link triggers client-side redirects, dynamic phishing kits, or drive-by scripts.",
        "investigation_questions": [
            "Did browser sessions follow the multi-hop redirect chain to the terminal credential/payload host?",
            "Were any follow-on files downloaded or browser tokens accessed during the session?",
        ],
        "detection_guidance": "Correlate browser process network connections with suspicious referrer chains and uncategorized destination domains.",
        "mitigation": "Isolate affected browser sessions, revoke active SSO tokens, and detonate suspicious landing pages only in an isolated sandbox.",
    },
    "T1204.002": {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "url": "https://attack.mitre.org/techniques/T1204/002/",
        "summary": "Adversaries rely on users opening attached executables, scripts, macro documents, or PDF /Launch payloads.",
        "investigation_questions": [
            "Did Office, PDF reader, or Windows Explorer spawn wscript.exe, powershell.exe, cmd.exe, or mshta.exe after attachment open?",
            "Which hosts observed the attachment SHA-256 written to Downloads or Outlook SecureTemp folders?",
        ],
        "detection_guidance": "Alert on Office/browser/PDF parent processes spawning script interpreters or unexpected outbound connections.",
        "mitigation": "Enforce Attack Surface Reduction rules blocking child process creation from email/Office apps and purge file hashes via EDR.",
    },
    "T1059.007": {
        "id": "T1059.007",
        "name": "Command & Scripting: JavaScript",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/007/",
        "summary": "Adversaries execute malicious or dynamically evaluated JavaScript in browsers or via attached .js/.hta droppers.",
        "investigation_questions": [
            "What payload did runtime eval()/Function() decode or inject into the DOM during isolated sandbox execution?",
            "Were external .js scripts pulled from uncategorized or high-abuse TLD domains?",
        ],
        "detection_guidance": "Inspect sandbox runtime eval logs, dynamic form injection events, and WScript/JScript execution telemetry on endpoints.",
        "mitigation": "Block third-party untrusted script hosts and disable Windows Script Host / .js file association execution.",
    },
    "T1027": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1027/",
        "summary": "Adversaries conceal payloads using JS packers, charcode/hex encoding, eval()+atob decoding, or encrypted ZIP archives.",
        "investigation_questions": [
            "Did static URL analysis miss obfuscated DOM behavior that only became visible during dynamic sandbox rendering?",
            "Was an archive password provided in the email body to bypass automated gateway scanners?",
        ],
        "detection_guidance": "Flag packed/eval+decoder JavaScript patterns, dense _0x symbol tables, and password-protected inbound email archives.",
        "mitigation": "Block encrypted archive attachments from untrusted senders and rely on headless browser detonation for dynamic scripts.",
    },
    "T1027.006": {
        "id": "T1027.006",
        "name": "Obfuscated Info: HTML Smuggling",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1027/006/",
        "summary": "Adversaries assemble malicious payloads or fake login pages client-side inside HTML/SVG attachments via Blob and Base64 decoding.",
        "investigation_questions": [
            "What embedded Base64 payload or Blob object is assembled by the smuggled HTML/SVG file?",
            "Do proxy or email logs show external users receiving HTML/SVG attachments mimicking invoices or portals?",
        ],
        "detection_guidance": "Inspect inbound HTML/SVG attachments for URL.createObjectURL, msSaveOrOpenBlob, Base64 decoding, and embedded scripts.",
        "mitigation": "Strip or quarantine inbound .html/.htm/.svg email attachments at the gateway and enforce mark-of-the-web controls.",
    },
    "T1036.005": {
        "id": "T1036.005",
        "name": "Masquerading: Match Legitimate Name",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1036/005/",
        "summary": "Adversaries spoof brands via Unicode homoglyphs, Punycode, leetspeak domains, double extensions, or RLO filename characters.",
        "investigation_questions": [
            "Does the domain or display name target an organization brand or an external vendor/SaaS provider used by staff?",
            "Did attachment magic bytes contradict the declared file extension (e.g., PE executable disguised as PDF)?",
        ],
        "detection_guidance": "Correlate IDN/Punycode domains, brand edit-distance alerts, RLO characters, and file magic-type mismatches.",
        "mitigation": "Block spoofed Punycode/brand-lookalike domains at DNS/proxy and reject magic-mismatched attachments at mail gateways.",
    },
    "T1497": {
        "id": "T1497",
        "name": "Virtualization / Sandbox Evasion",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1497/",
        "summary": "Phishing kits use anti-analysis JS (contextmenu blocks, F12/DevTools traps, debugger loops, history manipulation) to hinder inspection.",
        "investigation_questions": [
            "Did the site serve different content or cloaked redirects depending on user-agent or inspection triggers?",
            "Compare static HTTP fetch DOM against rendered isolated Chromium screenshot for cloaking discrepancies.",
        ],
        "detection_guidance": "Flag inline oncontextmenu blocks, keydown F12/Ctrl+Shift+I interceptors, debugger loops, and anti-headless checks.",
        "mitigation": "Perform inspection inside instrumented headless browsers and treat anti-analysis cloaking as a high-confidence phishing signal.",
    },
    "T1221": {
        "id": "T1221",
        "name": "Template Injection",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1221/",
        "summary": "Weaponized Office documents reference remote external templates (`TargetMode='External'`) to fetch malicious payloads at open time.",
        "investigation_questions": [
            "What external URL is referenced in the document's .rels file, and was an HTTP GET observed from victim hosts?",
            "Can the referenced remote template payload still be fetched via isolated sandbox analysis?",
        ],
        "detection_guidance": "Inspect OOXML relationship XMLs for TargetMode='External' pointing to HTTP/SMB locations and hunt proxy logs for template fetches.",
        "mitigation": "Disable automatic Office external template retrieval via Group Policy and block target template host URLs.",
    },
    "T1056.001": {
        "id": "T1056.001",
        "name": "Input Capture: Keylogging",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1056/001/",
        "summary": "Scripts capture live keyboard events on credential forms and stream typed characters to adversary collection endpoints.",
        "investigation_questions": [
            "To which external host do keystroke listeners transmit captured input (fetch/XHR/sendBeacon)?",
            "Did any user partially enter credentials even without submitting the final form?",
        ],
        "detection_guidance": "Alert on JavaScript attaching keydown/keypress/keyup listeners paired with outbound XHR/fetch/sendBeacon requests.",
        "mitigation": "Assume password exposure for any user who typed on the page; force credential reset even if login submission failed.",
    },
    "T1556": {
        "id": "T1556",
        "name": "Credential Harvesting Interface",
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1556/",
        "summary": "Malicious pages present spoofed authentication or payment forms (HTML or dynamically injected JS forms) to steal secrets.",
        "investigation_questions": [
            "Which credentials or payment fields (password, OTP/MFA, card details) are requested by the harvested form?",
            "Did any internal users submit HTTP POST payloads to this page or its form action domain?",
        ],
        "detection_guidance": "Correlate rendered password/payment forms on untrusted or brand-impersonating domains with proxy HTTP POST traffic.",
        "mitigation": "Force password reset, revoke active SSO/OAuth refresh tokens, and enforce phishing-resistant MFA (FIDO2/WebAuthn).",
    },
    "T1115": {
        "id": "T1115",
        "name": "Clipboard Data",
        "tactic_id": "TA0009",
        "tactic_name": "Collection & Exfil",
        "url": "https://attack.mitre.org/techniques/T1115/",
        "summary": "Browser scripts invoke Clipboard APIs (`readText`/`writeText`) to harvest copied secrets or perform clipboard hijacking.",
        "investigation_questions": [
            "Did the page attempt unauthorized clipboard reads or silently overwrite copied wallet/OTP strings?",
        ],
        "detection_guidance": "Monitor runtime navigator.clipboard hooks inside isolated browser sandbox runs on suspicious domains.",
        "mitigation": "Restrict clipboard read permissions by default and alert users on anomalous clipboard replacement behavior.",
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 / Web POST",
        "tactic_id": "TA0009",
        "tactic_name": "Collection & Exfil",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "summary": "Captured credentials are exfiltrated to external collector domains via cross-origin forms, fetch/XHR POSTs, sendBeacon, or mailto traps.",
        "investigation_questions": [
            "What external collector domain/IP received the form POST, XHR, or sendBeacon payload?",
            "Are other phishing URLs in Threat Graph posting stolen credentials to this exact same collector domain?",
        ],
        "detection_guidance": "Search perimeter firewall/proxy logs for HTTP POSTs or DNS queries to the identified cross-origin exfiltration domain.",
        "mitigation": "Immediately block the external exfiltration host, reset credentials for affected sessions, and pivot on collector infrastructure.",
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web",
        "tactic_id": "TA0011",
        "tactic_name": "Command & Control",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "summary": "Adversary kits route victims through multi-hop HTTP redirection chains, unencrypted downgrades, or external web beacons.",
        "investigation_questions": [
            "Trace the complete redirect chain in proxy telemetry — did intermediate redirectors evade URL reputation filters?",
            "Why was HTTPS downgraded to plain HTTP during redirection?",
        ],
        "detection_guidance": "Monitor HTTP 301/302/307 chains crossing multiple distinct registrable domains and protocol downgrade transitions.",
        "mitigation": "Block every intermediate redirector and terminal landing host in the chain across web gateways.",
    },
    "T1568.003": {
        "id": "T1568.003",
        "name": "Dynamic Resolution: Fast Flux DNS",
        "tactic_id": "TA0011",
        "tactic_name": "Command & Control",
        "url": "https://attack.mitre.org/techniques/T1568/003/",
        "summary": "Phishing infrastructure rotates low-TTL DNS A records across dispersed networks or resides on high-abuse hosting IPs.",
        "investigation_questions": [
            "Which ASNs and /24 subnets appear in DNS A records over time, and do they correlate with AbuseIPDB reports?",
            "Are domain-based blocks required rather than IP-only firewall rules due to rapid flux?",
        ],
        "detection_guidance": "Alert on domains returning 4+ A records spanning 3+ /16 prefixes with TTL <= 300s or flagged in AbuseIPDB/OTX.",
        "mitigation": "Enforce domain/RPZ DNS sinkholing alongside IP reputation blocking to prevent evasion via IP rotation.",
    },
}


class MitreAttackMapper:
    """
    Maps observed URL scan, isolated browser sandbox, and email (.eml) phishing telemetry
    into MITRE ATT&CK techniques, tactic coverage matrix, and actionable SOC investigation guidance.
    """

    @staticmethod
    def _record_hit(
        hits: Dict[str, Dict[str, Any]],
        tech_id: str,
        evidence: str,
        source_engine: str,
        severity: str = "medium",
        conf: float = 80.0,
        pivots: Optional[List[str]] = None,
    ) -> None:
        meta = TECHNIQUE_CATALOG.get(tech_id)
        if not meta:
            return
        entry = hits.get(tech_id)
        sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if entry is None:
            entry = {
                "technique_id": tech_id,
                "technique_name": meta["name"],
                "tactic_id": meta["tactic_id"],
                "tactic_name": meta["tactic_name"],
                "mitre_url": meta["url"],
                "summary": meta["summary"],
                "severity": severity,
                "confidence": round(float(conf), 1),
                "observed_behaviors": [],
                "source_engines": [],
                "hunting_pivots": [],
                "investigation_questions": list(meta["investigation_questions"]),
                "detection_guidance": meta["detection_guidance"],
                "mitigation": meta["mitigation"],
            }
            hits[tech_id] = entry

        if sev_rank.get(severity, 0) > sev_rank.get(entry["severity"], 0):
            entry["severity"] = severity
        entry["confidence"] = round(max(float(entry["confidence"]), float(conf)), 1)
        if evidence and evidence not in entry["observed_behaviors"]:
            entry["observed_behaviors"].append(evidence)
        if source_engine and source_engine not in entry["source_engines"]:
            entry["source_engines"].append(source_engine)
        for p in (pivots or []):
            if p and p not in entry["hunting_pivots"]:
                entry["hunting_pivots"].append(p)

    def map_url_scan(self, report: Dict[str, Any], hits: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
        """Map signals from a PhishPulse URL CompositeScanReport."""
        if hits is None:
            hits = {}

        verdict = str(report.get("verdict") or "BENIGN").upper()
        domain = str(report.get("target_domain") or "")
        url = str(report.get("target_url") or "")
        ta = report.get("threat_analysis") or {}
        ws = report.get("web_security") or {}
        cv = report.get("cert_validation") or {}
        ti = report.get("threat_intel") or {}
        ip_addr = ws.get("ip_address")
        is_threat = verdict in ("MALICIOUS", "HIGH_RISK", "SUSPICIOUS")

        base_pivots = [x for x in (domain, ip_addr) if x]
        lflags = list(ta.get("lexical_flags") or [])
        cflags = list(ta.get("content_flags") or [])
        contribs = list(ta.get("contributions") or [])
        contrib_factors = {c.get("factor") for c in contribs}

        # Initial Access: Spearphishing Link when CTI matched or threat verdict
        if ti.get("feed_hits") or is_threat:
            ev = f"URL '{url[:100]}' evaluated as {verdict} (Score {report.get('overall_score', 0)}/100)"
            if ti.get("feed_hits"):
                ev = f"Confirmed Threat Intel feed match: {', '.join(ti['feed_hits'][:2])}"
            self._record_hit(hits, "T1566.002", ev, "Threat Intel / Scoring", "high" if is_threat else "medium", 88.0 if ti.get("feed_hits") else 75.0, [url] + base_pivots)

        # Resource Dev: Domain & Homoglyph Masquerading
        if ta.get("impersonated_brand"):
            self._record_hit(
                hits,
                "T1583.001",
                f"Domain '{domain}' impersonates brand '{ta['impersonated_brand']}'",
                "Heuristic Threat Analyzer",
                "high",
                90.0,
                base_pivots,
            )
            self._record_hit(
                hits,
                "T1036.005",
                f"Brand lookalike / typosquatting targeting '{ta['impersonated_brand']}'",
                "Heuristic Threat Analyzer",
                "high",
                90.0,
                [domain],
            )
        if ta.get("homoglyph_detected"):
            self._record_hit(
                hits,
                "T1036.005",
                f"Unicode / Punycode homoglyph obfuscation detected in '{domain}'",
                "Heuristic Threat Analyzer",
                "critical",
                94.0,
                [domain],
            )
        if ta.get("suspicious_tld") or "high_domain_entropy" in contrib_factors:
            detail = ta.get("suspicious_tld") or f"entropy={ta.get('entropy')}"
            self._record_hit(
                hits,
                "T1583.001",
                f"High-risk TLD / algorithmic domain traits ({detail})",
                "Heuristic Threat Analyzer",
                "medium",
                76.0,
                base_pivots,
            )

        # Phishing for Information pretext keywords
        if "lure_keywords" in contrib_factors or (is_threat and "lure_keyword_single" in contrib_factors):
            kw_ev = next((c.get("evidence") for c in contribs if c.get("factor") in ("lure_keywords", "lure_keyword_single")), "auth/security keywords")
            self._record_hit(
                hits,
                "T1598",
                f"Credential/security pretext keywords observed in URL ({kw_ev})",
                "Heuristic Threat Analyzer",
                "medium",
                78.0,
                [url],
            )

        # Digital Certificates abuse (newly minted <72h, SAN mismatch, self-signed on risky target)
        cert_age = cv.get("age_days")
        cert_fp = (cv.get("details") or {}).get("sha256_fingerprint") or (cv.get("details") or {}).get("serial_number")
        cert_pivots = [str(p) for p in (cert_fp, cv.get("issuer"), domain) if p]
        if cert_age is not None and cert_age < 7 and (is_threat or ta.get("impersonated_brand")):
            self._record_hit(
                hits,
                "T1588.004",
                f"Recently minted TLS certificate ({cert_age}d old) from {cv.get('issuer') or 'unknown CA'} on suspicious host",
                "SSL/TLS Certificate Validator",
                "high" if cert_age < 3 else "medium",
                88.0,
                cert_pivots,
            )
        elif cv.get("san_mismatch") or (cv.get("details") or {}).get("is_self_signed"):
            self._record_hit(
                hits,
                "T1588.004",
                f"Untrusted or SAN-mismatched TLS certificate presented for '{domain}'",
                "SSL/TLS Certificate Validator",
                "high",
                85.0,
                cert_pivots,
            )

        # Credential form & Exfiltration
        if ta.get("has_password_input") and is_threat:
            self._record_hit(
                hits,
                "T1556",
                f"Phishing credential password form rendered on deceptive host '{domain}'",
                "Heuristic Threat Analyzer",
                "high",
                90.0,
                [url, domain],
            )
        if ta.get("has_cross_origin_form"):
            exfil_host = next((c.get("evidence") for c in contribs if c.get("factor") == "cross_origin_form"), "external host")
            self._record_hit(
                hits,
                "T1041",
                f"Credential form action posts captured inputs externally to '{exfil_host}'",
                "Heuristic Threat Analyzer",
                "critical",
                95.0,
                [p for p in (str(exfil_host), url) if p],
            )
        if "mailto_form_trap" in contrib_factors:
            self._record_hit(
                hits,
                "T1041",
                "HTML form submits harvested fields via mailto: exfiltration trap",
                "Heuristic Threat Analyzer",
                "high",
                88.0,
                [url],
            )

        # JS Obfuscation, Anti-Analysis, Execution
        if "obfuscated_js" in contrib_factors:
            self._record_hit(
                hits,
                "T1027",
                "Obfuscated JavaScript (eval + dynamic decoding / long charcode array) detected in DOM",
                "Heuristic Threat Analyzer",
                "high",
                85.0,
                [url],
            )
            self._record_hit(
                hits,
                "T1059.007",
                "Dynamic eval() script execution observed in page source",
                "Heuristic Threat Analyzer",
                "high",
                84.0,
                [url],
            )
        if "anti_analysis_js" in contrib_factors:
            self._record_hit(
                hits,
                "T1497",
                "Anti-analysis DOM trap disables context menu or developer inspection shortcuts",
                "Heuristic Threat Analyzer",
                "medium",
                82.0,
                [url],
            )

        # Web C2 & Redirection / Fast-Flux DNS
        ws_factors = {c.get("factor") for c in (ws.get("contributions") or [])}
        if "multi_hop_redirect" in ws_factors or "https_downgrade" in ws_factors or "open_redirect_param" in contrib_factors:
            self._record_hit(
                hits,
                "T1071.001",
                "Multi-hop cross-domain redirection or HTTPS-to-HTTP downgrade observed",
                "Web Security Assessor",
                "high" if "https_downgrade" in ws_factors else "medium",
                82.0,
                [url] + base_pivots,
            )
            self._record_hit(
                hits,
                "T1204.001",
                "Redirect chain routes link click toward secondary landing infrastructure",
                "Web Security Assessor",
                "medium",
                76.0,
                [url],
            )

        if (ws.get("details") or {}).get("fast_flux_detected") or "abuseipdb_flagged" in {c.get("factor") for c in (ti.get("contributions") or [])}:
            self._record_hit(
                hits,
                "T1568.003",
                "Fast-flux multi-prefix DNS rotation or AbuseIPDB malicious host infrastructure detected",
                "Web Security / Threat Intel",
                "high",
                85.0,
                base_pivots,
            )

        return hits

    def map_sandbox_run(self, sandbox_report: Dict[str, Any], hits: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
        """Map dynamic browser detonation behaviors from a SandboxReport."""
        if hits is None:
            hits = {}

        final_url = str(sandbox_report.get("final_url") or sandbox_report.get("target_url") or "")
        target_domain = str(sandbox_report.get("final_domain") or sandbox_report.get("target_domain") or "")
        tel = sandbox_report.get("telemetry") or {}
        forms = list(sandbox_report.get("form_destinations") or [])
        scripts = list(sandbox_report.get("suspicious_scripts") or [])
        redirects = list(sandbox_report.get("redirect_chain") or [])
        runtime_exfil = list(sandbox_report.get("runtime_exfil_targets") or [])
        blocked = list(sandbox_report.get("blocked_requests") or [])

        if sandbox_report.get("verdict") in ("SUSPICIOUS", "HIGH_RISK", "MALICIOUS"):
            self._record_hit(
                hits,
                "T1204.001",
                f"Dynamic browser execution on '{final_url}' produced {sandbox_report['verdict']} telemetry",
                "Isolated Browser Sandbox",
                "high",
                85.0,
                [final_url, target_domain],
            )

        if any(f.get("has_password_input") or f.get("has_payment_fields") for f in forms) and sandbox_report.get("verdict") != "BENIGN":
            self._record_hit(
                hits,
                "T1556",
                f"Live rendered DOM contains {len(forms)} credential/payment form(s)",
                "Isolated Browser Sandbox",
                "high",
                90.0,
                [final_url],
            )

        for f in forms:
            if f.get("is_cross_origin"):
                self._record_hit(
                    hits,
                    "T1041",
                    f"Rendered form posts credentials externally to '{f.get('action_domain')}'",
                    "Isolated Browser Sandbox",
                    "critical",
                    95.0,
                    [str(f.get("action_url") or ""), str(f.get("action_domain") or "")],
                )

        for rx in runtime_exfil:
            if rx.get("is_cross_origin"):
                self._record_hit(
                    hits,
                    "T1041",
                    f"Runtime {rx.get('api')} ({rx.get('method')}) transmits data to third-party '{rx.get('domain')}'",
                    "Isolated Browser Sandbox",
                    "critical",
                    92.0,
                    [str(rx.get("url") or ""), str(rx.get("domain") or "")],
                )

        for sc in scripts:
            inds = set(sc.get("indicators") or [])
            if inds & {"runtime_eval", "obfuscated_eval", "js_packer", "suspicious_external_script"}:
                self._record_hit(
                    hits,
                    "T1059.007",
                    "; ".join(sc.get("reasons") or ["Suspicious browser script execution"]),
                    "Isolated Browser Sandbox",
                    sc.get("severity", "high"),
                    88.0,
                    [str(sc.get("url") or final_url)],
                )
            if inds & {"obfuscated_eval", "js_packer", "charcode_obfuscation", "hex_obfuscated_identifiers"}:
                self._record_hit(
                    hits,
                    "T1027",
                    "; ".join(sc.get("reasons") or ["Obfuscated script payload"]),
                    "Isolated Browser Sandbox",
                    "high",
                    86.0,
                    [final_url],
                )
            if inds & {"runtime_anti_analysis", "anti_analysis", "inline_anti_analysis"}:
                self._record_hit(
                    hits,
                    "T1497",
                    "; ".join(sc.get("reasons") or ["Anti-analysis script trap observed"]),
                    "Isolated Browser Sandbox",
                    "medium",
                    84.0,
                    [final_url],
                )
            if "keylogger_exfil" in inds:
                self._record_hit(
                    hits,
                    "T1056.001",
                    "Keystroke listener paired with network exfiltration call detected in page script",
                    "Isolated Browser Sandbox",
                    "critical",
                    93.0,
                    [final_url],
                )

        if int(tel.get("clipboard_ops") or 0) > 0:
            self._record_hit(
                hits,
                "T1115",
                f"Page invoked navigator.clipboard API {tel['clipboard_ops']} time(s)",
                "Isolated Browser Sandbox",
                "medium",
                82.0,
                [final_url],
            )

        if len(redirects) >= 2 and any(h.get("is_cross_origin") for h in redirects):
            self._record_hit(
                hits,
                "T1071.001",
                f"Browser followed {len(redirects)}-hop cross-origin redirect chain to '{final_url}'",
                "Isolated Browser Sandbox",
                "medium",
                80.0,
                [str(h.get("url") or "") for h in redirects[:4]],
            )

        if blocked:
            self._record_hit(
                hits,
                "T1071.001",
                f"Sandbox intercepted and blocked {len(blocked)} internal/SSRF subresource request(s)",
                "Isolated Browser Sandbox",
                "high",
                90.0,
                [str(b.get("url") or "") for b in blocked[:3]],
            )

        return hits

    def map_email_report(self, email_report: Dict[str, Any], hits: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Dict[str, Any]]:
        """Map email authentication, spoofing, deceptive URL, and attachment behaviors from EmailAnalysisReport."""
        if hits is None:
            hits = {}

        auth = email_report.get("authentication") or {}
        sender = email_report.get("sender") or {}
        urls = list(email_report.get("embedded_urls") or [])
        atts = list(email_report.get("attachments") or [])
        from_addr = sender.get("from_address") or ""
        from_dom = sender.get("from_domain") or ""
        pivots = [p for p in (from_addr, from_dom, sender.get("reply_to_address")) if p]

        if sender.get("spoofing_detected"):
            for ind in (sender.get("indicators") or []):
                low = ind.lower()
                if "reply-to" in low or "webmail" in low or "return-path" in low:
                    self._record_hit(hits, "T1585.002", ind, "Email (.eml) Forensics", "high", 88.0, pivots)
                if "display name" in low or "homoglyph" in low or "brand" in low or "typosquatting" in low:
                    self._record_hit(hits, "T1036.005", ind, "Email (.eml) Forensics", "high", 90.0, pivots)

        if "Fail" in str(auth.get("spf_status", "")) or "Fail" in str(auth.get("dkim_status", "")) or auth.get("dmarc_result") == "fail":
            self._record_hit(
                hits,
                "T1585.002",
                f"Email authentication failed (SPF={auth.get('spf_status')}, DKIM={auth.get('dkim_status')}, DMARC={auth.get('dmarc_result')})",
                "Email (.eml) Forensics",
                "high",
                88.0,
                pivots,
            )

        # Embedded URLs -> T1566.002 & Masquerading/Domain flags
        risky_urls = [u for u in urls if u.get("score", 0.0) >= 25.0 or u.get("anchor_mismatch")]
        for u in risky_urls[:5]:
            ev = f"Embedded URL '{u['url'][:90]}' flagged (score {u['score']}/100)"
            if u.get("anchor_mismatch"):
                ev = f"Deceptive hyperlink anchor text '{u.get('anchor_text')}' redirects to '{u['domain']}'"
            self._record_hit(
                hits,
                "T1566.002",
                ev,
                "Email (.eml) Forensics",
                "critical" if u.get("score", 0.0) >= 75.0 or u.get("anchor_mismatch") else "high",
                92.0,
                [u["url"], u.get("domain", "")],
            )
            if u.get("anchor_mismatch"):
                self._record_hit(hits, "T1036.005", ev, "Email (.eml) Forensics", "high", 90.0, [u["url"]])

        # Attachments -> T1566.001, T1204.002, T1027.006, T1221, T1036.005, T1059.007
        for att in atts:
            if not att.get("is_dangerous") and float(att.get("risk_score", 0.0)) < 25.0:
                continue
            fname = att.get("filename") or "attachment"
            att_pivots = [x for x in (att.get("sha256"), fname) if x] + list(att.get("extracted_urls") or [])[:3]
            findings = list(att.get("findings") or [])
            summary_ev = f"Attachment '{fname}' flagged ({'; '.join(findings[:2]) or att.get('verdict')})"
            self._record_hit(
                hits,
                "T1566.001",
                summary_ev,
                "Isolated Attachment Analyzer",
                "critical" if att.get("risk_score", 0.0) >= 70.0 else "high",
                92.0,
                att_pivots,
            )

            joined = " ".join(findings).lower()
            if att.get("extension_mismatch") or "rlo" in joined or "double-extension" in joined:
                self._record_hit(hits, "T1036.005", summary_ev, "Isolated Attachment Analyzer", "critical", 94.0, att_pivots)
            if "html smuggling" in joined:
                self._record_hit(hits, "T1027.006", summary_ev, "Isolated Attachment Analyzer", "critical", 92.0, att_pivots)
            if "external relationship/template" in joined:
                self._record_hit(hits, "T1221", summary_ev, "Isolated Attachment Analyzer", "high", 90.0, att_pivots)
            if "password form" in joined or "posts directly to external" in joined:
                self._record_hit(hits, "T1556", summary_ev, "Isolated Attachment Analyzer", "high", 90.0, att_pivots)
                if "posts directly to external" in joined:
                    self._record_hit(hits, "T1041", summary_ev, "Isolated Attachment Analyzer", "high", 90.0, att_pivots)
            if "javascript" in joined or "script" in joined or ".js" in joined:
                self._record_hit(hits, "T1059.007", summary_ev, "Isolated Attachment Analyzer", "high", 86.0, att_pivots)
            if "executable" in joined or "macro" in joined or "launch" in joined or "encrypted archive" in joined:
                self._record_hit(hits, "T1204.002", summary_ev, "Isolated Attachment Analyzer", "high", 88.0, att_pivots)
            if "encrypted archive" in joined or "obfuscated javascript" in joined:
                self._record_hit(hits, "T1027", summary_ev, "Isolated Attachment Analyzer", "high", 85.0, att_pivots)

        return hits

    def build_investigation_report(
        self,
        scans: Optional[List[Dict[str, Any]]] = None,
        sandbox_runs: Optional[List[Dict[str, Any]]] = None,
        email_reports: Optional[List[Dict[str, Any]]] = None,
        context_label: str = "Workspace Threat Posture",
        source_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Aggregate mapped ATT&CK techniques across provided artifacts and assemble an
        investigation-oriented report with tactic matrix, narrative, and SOC hunting playbook.
        """
        hits: Dict[str, Dict[str, Any]] = {}
        for rep in (scans or []):
            if isinstance(rep, dict):
                self.map_url_scan(rep, hits)
        for sbx in (sandbox_runs or []):
            if isinstance(sbx, dict):
                self.map_sandbox_run(sbx, hits)
        for eml in (email_reports or []):
            if isinstance(eml, dict):
                self.map_email_report(eml, hits)

        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        techniques = sorted(
            hits.values(),
            key=lambda t: (sev_rank.get(t["severity"], 0), t["confidence"], len(t["observed_behaviors"])),
            reverse=True,
        )

        # Build tactic-by-tactic column matrix including both matched techniques & unhit catalog baseline
        by_tactic: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        matched_ids = set(hits.keys())
        for tech_id, meta in TECHNIQUE_CATALOG.items():
            matched_item = hits.get(tech_id)
            by_tactic[meta["tactic_id"]].append({
                "technique_id": tech_id,
                "technique_name": meta["name"],
                "tactic_id": meta["tactic_id"],
                "tactic_name": meta["tactic_name"],
                "detected": tech_id in matched_ids,
                "severity": matched_item["severity"] if matched_item else "none",
                "confidence": matched_item["confidence"] if matched_item else 0.0,
                "evidence_count": len(matched_item["observed_behaviors"]) if matched_item else 0,
            })

        tactic_matrix: List[Dict[str, Any]] = []
        active_tactics = 0
        for tac in ATTACK_TACTICS:
            cells = sorted(
                by_tactic[tac["id"]],
                key=lambda c: (1 if c["detected"] else 0, sev_rank.get(c["severity"], 0), c["technique_id"]),
                reverse=True,
            )
            det_count = sum(1 for c in cells if c["detected"])
            if det_count > 0:
                active_tactics += 1
            tactic_matrix.append({
                "tactic_id": tac["id"],
                "tactic_name": tac["name"],
                "tactic_short": tac["short"],
                "detected_count": det_count,
                "total_count": len(cells),
                "techniques": cells,
            })

        # Determine investigation priority & coherent attack narrative
        highest_sev = max((sev_rank.get(t["severity"], 0) for t in techniques), default=0)
        if highest_sev >= 4 or len(techniques) >= 5:
            priority = "CRITICAL"
        elif highest_sev == 3 or len(techniques) >= 3:
            priority = "HIGH"
        elif techniques:
            priority = "MODERATE"
        else:
            priority = "LOW"

        if techniques:
            tactics_flow = " -> ".join(
                t["tactic_name"] for t in tactic_matrix if t["detected_count"] > 0
            )
            top_names = ", ".join(f"{t['technique_id']} ({t['technique_name']})" for t in techniques[:3])
            narrative = (
                f"Detected {len(techniques)} ATT&CK technique(s) spanning {active_tactics} tactic stage(s) "
                f"({tactics_flow}). Primary adversarial behaviors: {top_names}."
            )
        else:
            narrative = "No malicious or suspicious MITRE ATT&CK behaviors observed across the evaluated telemetry."

        # Build concrete SOC Investigation Playbook populated with real pivots
        all_pivots: List[str] = []
        for t in techniques:
            for p in t["hunting_pivots"]:
                if p not in all_pivots:
                    all_pivots.append(p)

        playbook: List[Dict[str, Any]] = []
        if techniques:
            playbook.append({
                "phase": "1. Scope & Threat Hunting",
                "objective": "Identify all users, endpoints, or mailboxes exposed to mapped indicators.",
                "pivots": all_pivots[:8],
                "actions": [
                    f"Query SIEM/proxy/EDR logs for mapped pivots: {', '.join(all_pivots[:4]) or 'target indicators'}.",
                    "Check Threat Graph for co-hosted domains sharing certificates, IPs, or exfiltration hosts.",
                ],
            })
            if any(t["tactic_id"] in ("TA0006", "TA0009", "TA0001") for t in techniques):
                playbook.append({
                    "phase": "2. Credential & Session Containment",
                    "objective": "Interrupt credential theft, session hijacking, and external data exfiltration.",
                    "pivots": [t["technique_id"] for t in techniques if t["tactic_id"] in ("TA0006", "TA0009")][:4],
                    "actions": [
                        "Force password resets and revoke active SSO/OAuth sessions for any user who accessed flagged forms or links.",
                        "Block destination collector domains/IPs identified under T1041 and T1566.002 on perimeter firewalls and web proxies.",
                    ],
                })
            if any(t["tactic_id"] in ("TA0002", "TA0005") for t in techniques):
                playbook.append({
                    "phase": "3. Endpoint & Script Forensics",
                    "objective": "Verify no payload staging, script execution, or template injection occurred.",
                    "pivots": [t["technique_id"] for t in techniques if t["tactic_id"] in ("TA0002", "TA0005")][:4],
                    "actions": [
                        "Inspect EDR process trees for suspicious script interpreters, downloads, or document child processes.",
                        "Detonate unverified landing URLs inside PhishPulse Isolated Browser Sandbox before allowing access.",
                    ],
                })
        else:
            playbook.append({
                "phase": "1. Baseline Verification",
                "objective": "Confirm defensive hygiene and maintain continuous monitoring.",
                "pivots": [],
                "actions": [
                    "No active ATT&CK techniques require incident containment.",
                    "Retain indicator history for future Threat Graph correlation.",
                ],
            })

        return {
            "context_label": context_label,
            "source_id": source_id,
            "investigation_priority": priority,
            "attack_narrative": narrative,
            "summary": {
                "mapped_techniques_count": len(techniques),
                "active_tactics_count": active_tactics,
                "total_catalog_techniques": len(TECHNIQUE_CATALOG),
                "total_tactics": len(ATTACK_TACTICS),
                "critical_count": sum(1 for t in techniques if t["severity"] == "critical"),
                "high_count": sum(1 for t in techniques if t["severity"] == "high"),
                "pivots_count": len(all_pivots),
            },
            "techniques": techniques,
            "tactic_matrix": tactic_matrix,
            "playbook": playbook,
        }


def build_mitre_report_for_target(
    scan_id: Optional[str] = None,
    sandbox_id: Optional[str] = None,
    email_id: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Load target or aggregate telemetry from SQLite and build an investigation-oriented ATT&CK report."""
    from app.models.database import (
        get_email_scan_by_id,
        get_full_scans,
        get_recent_email_scans,
        get_recent_sandbox_runs,
        get_sandbox_run_by_id,
        get_scan_by_id,
    )

    mapper = MitreAttackMapper()
    if scan_id:
        rep = get_scan_by_id(scan_id)
        if not rep:
            return {"not_found": f"Scan ID '{scan_id}' not found"}
        return mapper.build_investigation_report(
            scans=[rep],
            context_label=f"URL Scan: {rep.get('target_domain', scan_id)}",
            source_id=scan_id,
        )

    if sandbox_id:
        sbx = get_sandbox_run_by_id(sandbox_id)
        if not sbx:
            return {"not_found": f"Sandbox ID '{sandbox_id}' not found"}
        return mapper.build_investigation_report(
            sandbox_runs=[sbx],
            context_label=f"Browser Sandbox: {sbx.get('final_domain') or sbx.get('target_domain', sandbox_id)}",
            source_id=sandbox_id,
        )

    if email_id:
        eml = get_email_scan_by_id(email_id)
        if not eml:
            return {"not_found": f"Email Analysis ID '{email_id}' not found"}
        return mapper.build_investigation_report(
            email_reports=[eml],
            context_label=f"Email (.eml): {eml.get('subject') or eml.get('filename', email_id)}",
            source_id=email_id,
        )

    # Aggregate workspace posture across recent distinct scans, sandbox runs, and emails
    scans = get_full_scans(limit=limit, deduplicate_urls=True)
    sbx_list = [
        run for row in get_recent_sandbox_runs(limit=25)
        if (run := get_sandbox_run_by_id(row["sandbox_id"])) is not None
    ]
    eml_list = [
        rep for row in get_recent_email_scans(limit=25)
        if (rep := get_email_scan_by_id(row["email_id"])) is not None
    ]

    return mapper.build_investigation_report(
        scans=scans,
        sandbox_runs=sbx_list,
        email_reports=eml_list,
        context_label=f"Aggregated Workspace Intelligence ({len(scans)} scans, {len(sbx_list)} sandbox runs, {len(eml_list)} emails)",
        source_id="WORKSPACE",
    )
