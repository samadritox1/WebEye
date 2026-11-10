import asyncio
import base64
import email
import hashlib
import re
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import dns.resolver
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from lxml import html as lxml_html

from app.config import settings
from app.core.attachment_worker import inspect_attachments_isolated_sync
from app.core.mitre_mapper import MitreAttackMapper
from app.core.security_assessor import SecurityAssessor
from app.core.threat_analyzer import ThreatAnalyzer
from app.models.database import query_ioc, save_email_scan


_PLAIN_URL_RE = re.compile(r"https?://[^\s<>'\"\)\]]+", re.I)
_EMAIL_IN_NAME_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_IP_IN_RECEIVED_RE = re.compile(r"[\[\(\s](\d{1,3}(?:\.\d{1,3}){3})[\]\)\s]")

_FREE_WEBMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "proton.me", "protonmail.com", "mail.ru", "yandex.ru",
})


def _norm_domain(domain: str) -> str:
    return (domain or "").strip().lower().rstrip(".")


def _org_domain(domain: str) -> str:
    return SecurityAssessor._registrable_domain(domain) if domain else ""


def _domains_aligned(domain_a: str, domain_b: str) -> bool:
    if not domain_a or not domain_b:
        return False
    return _org_domain(domain_a) == _org_domain(domain_b)


def _split_raw_headers_and_body(raw_bytes: bytes) -> Tuple[bytes, bytes]:
    """Split raw RFC 822 message into raw header bytes and raw body bytes preserving exact line endings."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw_bytes.find(sep)
        if idx != -1:
            return raw_bytes[:idx], raw_bytes[idx + len(sep):]
    return raw_bytes, b""


def _unfold_header_lines(raw_headers: bytes) -> List[Tuple[str, str]]:
    text = raw_headers.decode("latin-1", errors="replace")
    lines = re.split(r"\r?\n", text)
    unfolded: List[str] = []
    for line in lines:
        if line.startswith((" ", "\t")) and unfolded:
            unfolded[-1] += "\r\n" + line
        elif line:
            unfolded.append(line)
    pairs: List[Tuple[str, str]] = []
    for raw_line in unfolded:
        if ":" in raw_line:
            name, val = raw_line.split(":", 1)
            pairs.append((name.strip().lower(), val))
    return pairs


def _canonicalize_body(body_bytes: bytes, mode: str = "simple") -> bytes:
    """RFC 6376 body canonicalization ('simple' or 'relaxed')."""
    # Normalize lone LF -> CRLF per RFC 6376
    norm = body_bytes.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    lines = norm.split(b"\r\n")

    if mode == "relaxed":
        canon_lines: List[bytes] = []
        for line in lines:
            # Reduce WSP sequences to a single SP and strip trailing WSP
            collapsed = re.sub(rb"[ \t]+", b" ", line).rstrip(b" \t")
            canon_lines.append(collapsed)
    else:
        canon_lines = lines

    while canon_lines and canon_lines[-1] == b"":
        canon_lines.pop()

    if not canon_lines:
        return b"\r\n"
    return b"\r\n".join(canon_lines) + b"\r\n"


def _canonicalize_relaxed_header(name: str, value: str) -> bytes:
    val_unfolded = re.sub(r"\r?\n[ \t]*", " ", value)
    val_collapsed = re.sub(r"[ \t]+", " ", val_unfolded).strip(" \t")
    return f"{name.lower()}:{val_collapsed}".encode("latin-1", errors="replace")


def _parse_tag_value_list(raw: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = re.sub(r"\s+", "", v)
    return tags


def extract_eml_from_http_request(content_type: str, body: bytes) -> Tuple[str, bytes]:
    """
    Parse either raw .eml payload or multipart/form-data HTTP upload using Python stdlib `email`,
    avoiding any third-party multipart runtime dependency.
    """
    ct = (content_type or "").strip()
    if "multipart/form-data" in ct.lower():
        synthetic = f"Content-Type: {ct}\r\nMIME-Version: 1.0\r\n\r\n".encode("latin-1") + body
        parsed_multi = BytesParser(policy=policy.default).parsebytes(synthetic)
        for part in parsed_multi.iter_parts():
            disp_name = part.get_param("name", header="content-disposition")
            fname = part.get_filename() or "uploaded.eml"
            payload = part.get_payload(decode=True)
            if payload is None:
                raw_p = part.get_payload()
                if isinstance(raw_p, list):
                    payload = b"\r\n".join(p.as_bytes() for p in raw_p)
                elif isinstance(raw_p, str):
                    payload = raw_p.encode("utf-8", errors="replace")
                else:
                    payload = b""
            if disp_name in ("file", "eml", "email") or fname.lower().endswith(".eml") or b"From:" in payload[:2048]:
                return fname, payload
        raise ValueError("No .eml file field found in multipart upload")

    return "uploaded.eml", body


class EmailPhishingAnalyzer:
    """
    Comprehensive RFC 822 / .eml Phishing Analyzer:
    - SPF, DKIM (body-hash + DNS/RSA verification), DMARC + domain alignment
    - Display-name, Reply-To, Return-Path, and homoglyph sender spoofing detection
    - Received hop chain & header anomaly inspection
    - Embedded URL extraction with anchor-text deception & heuristic/IoC scoring
    - Safe, OS-isolated attachment inspection in an offline restricted subprocess
    """

    def __init__(self) -> None:
        self.threat_analyzer = ThreatAnalyzer()
        self.security_assessor = SecurityAssessor()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.5
        self.resolver.lifetime = 2.5

    def _dns_txt_records(self, qname: str) -> List[str]:
        results: List[str] = []
        try:
            answers = self.resolver.resolve(qname, "TXT")
            for rdata in answers:
                txt = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
                results.append(txt)
        except Exception:
            pass
        return results

    def _verify_dkim(
        self,
        raw_bytes: bytes,
        dkim_headers: List[str],
        auth_headers: List[str],
        from_domain: str,
        verify_dns: bool,
    ) -> Dict[str, Any]:
        # Extract any gateway Authentication-Results dkim= token first
        gateway_dkim = None
        for ah in auth_headers:
            m = re.search(r"\bdkim=([a-zA-Z_-]+)", ah, re.I)
            if m:
                gateway_dkim = m.group(1).lower()
                break

        if not dkim_headers:
            status = f"Missing DKIM-Signature (Gateway: {gateway_dkim})" if gateway_dkim else "No DKIM-Signature Header"
            return {
                "dkim_status": status,
                "dkim_domain": None,
                "dkim_selector": None,
                "dkim_body_hash_valid": None,
                "dkim_signature_valid": None,
                "dkim_aligned": False,
                "gateway_dkim": gateway_dkim,
            }

        raw_hdr_bytes, raw_body_bytes = _split_raw_headers_and_body(raw_bytes)
        header_pairs = _unfold_header_lines(raw_hdr_bytes)

        sig_raw = dkim_headers[0]
        tags = _parse_tag_value_list(sig_raw)
        algo = tags.get("a", "rsa-sha256").lower()
        canon = tags.get("c", "simple/simple").lower()
        dkim_domain = _norm_domain(tags.get("d", ""))
        dkim_selector = tags.get("s", "")
        signed_headers = [h.strip().lower() for h in tags.get("h", "").split(":") if h.strip()]
        bh_expected_b64 = tags.get("bh", "")
        sig_b64 = tags.get("b", "")

        hdr_canon, body_canon = (canon.split("/", 1) + ["simple"])[:2] if "/" in canon else (canon, "simple")

        # 1. Verify cryptographic body hash (bh=) offline using exact RFC 6376 canonicalization
        body_hash_valid: Optional[bool] = None
        try:
            canon_body = _canonicalize_body(raw_body_bytes, mode=body_canon)
            digest_cls = hashlib.sha1 if algo.endswith("sha1") else hashlib.sha256
            computed_bh = base64.b64encode(digest_cls(canon_body).digest()).decode("ascii")
            body_hash_valid = (computed_bh == bh_expected_b64) if bh_expected_b64 else None
        except Exception:
            body_hash_valid = None

        # 2. Optional DNS DKIM public key lookup & RSA/Ed25519 signature verification
        sig_valid: Optional[bool] = None
        if verify_dns and dkim_selector and dkim_domain and sig_b64:
            qname = f"{dkim_selector}._domainkey.{dkim_domain}"
            txt_records = self._dns_txt_records(qname)
            pub_b64 = None
            for txt in txt_records:
                key_tags = _parse_tag_value_list(txt)
                if "p" in key_tags:
                    pub_b64 = key_tags["p"]
                    break
            if pub_b64 == "":
                sig_valid = False  # Revoked DKIM key (`p=`)
            elif pub_b64:
                try:
                    # Collect signed headers bottom-up per RFC 6376
                    unused_idx = list(range(len(header_pairs)))
                    data_chunks: List[bytes] = []
                    for hname in signed_headers:
                        for pos in range(len(unused_idx) - 1, -1, -1):
                            real_i = unused_idx[pos]
                            if header_pairs[real_i][0] == hname:
                                unused_idx.pop(pos)
                                val = header_pairs[real_i][1]
                                if hdr_canon == "relaxed":
                                    data_chunks.append(_canonicalize_relaxed_header(hname, val) + b"\r\n")
                                else:
                                    data_chunks.append(f"{hname}:{val}\r\n".encode("latin-1", errors="replace"))
                                break

                    # Append DKIM-Signature header with b=<sig> cleared to b=
                    dkim_raw_vals = [v for k, v in header_pairs if k == "dkim-signature"]
                    if dkim_raw_vals:
                        dk_val = re.sub(r"(\bb\s*=\s*)[^;]*", r"\1", dkim_raw_vals[0], count=1, flags=re.I)
                        if hdr_canon == "relaxed":
                            data_chunks.append(_canonicalize_relaxed_header("dkim-signature", dk_val))
                        else:
                            data_chunks.append(f"DKIM-Signature:{dk_val}".encode("latin-1", errors="replace"))

                    signing_input = b"".join(data_chunks)
                    sig_bytes = base64.b64decode(sig_b64)
                    pub_key = load_der_public_key(base64.b64decode(pub_b64))
                    if isinstance(pub_key, rsa.RSAPublicKey):
                        hash_alg = hashes.SHA1() if algo.endswith("sha1") else hashes.SHA256()
                        pub_key.verify(sig_bytes, signing_input, padding.PKCS1v15(), hash_alg)
                        sig_valid = True
                    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                        pub_key.verify(sig_bytes, signing_input)
                        sig_valid = True
                except Exception:
                    sig_valid = False

        aligned = _domains_aligned(dkim_domain, from_domain)

        if body_hash_valid is False:
            status = "Fail (Body Hash Tampered)"
        elif sig_valid is False:
            status = "Fail (Invalid Cryptographic Signature)"
        elif sig_valid is True and body_hash_valid is True:
            status = f"Pass (Verified RSA/DKIM · {'Aligned' if aligned else 'Unaligned'})"
        elif gateway_dkim == "pass" and body_hash_valid is not False:
            status = f"Pass (Header Auth-Results · {'Aligned' if aligned else 'Unaligned'})"
        elif gateway_dkim in ("fail", "permerror", "temperror"):
            status = f"Fail (Header reports dkim={gateway_dkim})"
        elif body_hash_valid is True:
            status = f"Body Hash Valid (DNS Key Unverified · {'Aligned' if aligned else 'Unaligned'})"
        else:
            status = f"Present ({dkim_domain or 'unknown'})"

        return {
            "dkim_status": status,
            "dkim_domain": dkim_domain or None,
            "dkim_selector": dkim_selector or None,
            "dkim_body_hash_valid": body_hash_valid,
            "dkim_signature_valid": sig_valid,
            "dkim_aligned": aligned,
            "gateway_dkim": gateway_dkim,
        }

    def _inspect_authentication(
        self,
        raw_bytes: bytes,
        msg: email.message.Message,
        from_domain: str,
        return_path_domain: str,
        verify_dns: bool,
    ) -> Dict[str, Any]:
        auth_headers = [str(v) for v in (msg.get_all("Authentication-Results") or []) + (msg.get_all("ARC-Authentication-Results") or [])]
        rec_spf_headers = [str(v) for v in (msg.get_all("Received-SPF") or [])]

        # 1. SPF assessment (header telemetry + optional DNS TXT check)
        gateway_spf = None
        for hdr in rec_spf_headers + auth_headers:
            m = re.search(r"\bspf=([a-zA-Z_-]+)", hdr, re.I)
            if m:
                gateway_spf = m.group(1).lower()
                break
            if hdr in rec_spf_headers:
                m2 = re.match(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", hdr, re.I)
                if m2:
                    gateway_spf = m2.group(1).lower()
                    break

        spf_domain = return_path_domain or from_domain
        spf_record = None
        if verify_dns and spf_domain:
            for txt in self._dns_txt_records(spf_domain):
                if txt.lower().startswith("v=spf1"):
                    spf_record = txt
                    break

        spf_aligned = _domains_aligned(spf_domain, from_domain) if spf_domain and from_domain else False
        if gateway_spf in ("fail", "softfail", "permerror"):
            spf_status = f"Fail (Header reports spf={gateway_spf})"
        elif spf_record and ("+all" in spf_record or "?all" in spf_record):
            spf_status = f"Permissive Policy ({'Aligned' if spf_aligned else 'Unaligned'})"
        elif gateway_spf == "pass":
            spf_status = f"Pass (Header spf=pass · {'Aligned' if spf_aligned else 'Unaligned'})"
        elif spf_record:
            qualifier = "-all" if "-all" in spf_record else ("~all" if "~all" in spf_record else "active")
            spf_status = f"Policy Present ({qualifier} · {'Aligned' if spf_aligned else 'Unaligned'})"
        elif verify_dns:
            spf_status = "Missing SPF DNS Record"
        else:
            spf_status = f"Unchecked ({gateway_spf or 'No Received-SPF header'})"

        # 2. DKIM assessment
        dkim_headers = [str(v) for v in (msg.get_all("DKIM-Signature") or [])]
        dkim_info = self._verify_dkim(raw_bytes, dkim_headers, auth_headers, from_domain, verify_dns=verify_dns)

        # 3. DMARC assessment (header telemetry + RFC 7489 organizational domain fallback)
        gateway_dmarc = None
        for ah in auth_headers:
            m = re.search(r"\bdmarc=([a-zA-Z_-]+)", ah, re.I)
            if m:
                gateway_dmarc = m.group(1).lower()
                break

        dmarc_record = None
        dmarc_policy = None
        dmarc_org = _org_domain(from_domain)
        if verify_dns and from_domain:
            candidates = [from_domain] + ([dmarc_org] if dmarc_org and dmarc_org != from_domain else [])
            for cand in candidates:
                for txt in self._dns_txt_records(f"_dmarc.{cand}"):
                    if txt.startswith("v=DMARC1"):
                        dmarc_record = txt
                        pm = re.search(r"(?:^|[;\s])p=([a-zA-Z]+)", txt, re.I)
                        if pm:
                            dmarc_policy = pm.group(1).lower()
                        break
                if dmarc_record:
                    break

        spf_passes = (gateway_spf == "pass" and spf_aligned)
        dkim_passes = (
            dkim_info["dkim_aligned"]
            and dkim_info["dkim_body_hash_valid"] is not False
            and (dkim_info["dkim_signature_valid"] is True or dkim_info["gateway_dkim"] == "pass")
        )

        if gateway_dmarc == "fail" or dkim_info["dkim_body_hash_valid"] is False or dkim_info["dkim_signature_valid"] is False:
            dmarc_result = "fail"
        elif spf_passes or dkim_passes or (gateway_dmarc == "pass" and (spf_aligned or dkim_info["dkim_aligned"])):
            dmarc_result = "pass"
        elif dmarc_policy is None and verify_dns and from_domain:
            dmarc_result = "missing"
        else:
            dmarc_result = gateway_dmarc or "fail"

        if dmarc_result == "pass":
            dmarc_status = f"Pass (Policy p={dmarc_policy or 'enforced'} · Aligned)"
        elif dmarc_result == "missing":
            dmarc_status = "Missing DMARC DNS Record"
        elif dmarc_policy == "none":
            dmarc_status = f"Fail / Weak Policy (p=none, alignment={'ok' if (spf_aligned or dkim_info['dkim_aligned']) else 'failed'})"
        else:
            dmarc_status = f"Fail (Unaligned or failed auth; p={dmarc_policy or 'unknown'})"

        return {
            "spf_status": spf_status,
            "spf_domain": spf_domain or None,
            "spf_record": spf_record,
            "spf_aligned": spf_aligned,
            "dkim_status": dkim_info["dkim_status"],
            "dkim_domain": dkim_info["dkim_domain"],
            "dkim_selector": dkim_info["dkim_selector"],
            "dkim_body_hash_valid": dkim_info["dkim_body_hash_valid"],
            "dkim_signature_valid": dkim_info["dkim_signature_valid"],
            "dkim_aligned": dkim_info["dkim_aligned"],
            "dmarc_status": dmarc_status,
            "dmarc_domain": dmarc_org or None,
            "dmarc_policy": dmarc_policy,
            "dmarc_record": dmarc_record,
            "dmarc_result": dmarc_result,
            "auth_results_headers": auth_headers[:6],
        }

    def _analyze_sender_spoofing(
        self,
        msg: email.message.Message,
        auth: Dict[str, Any],
    ) -> Dict[str, Any]:
        from_display, from_addr = parseaddr(str(msg.get("From") or ""))
        reply_display, reply_addr = parseaddr(str(msg.get("Reply-To") or ""))
        _, ret_addr = parseaddr(str(msg.get("Return-Path") or ""))

        from_addr = from_addr.strip().lower()
        reply_addr = reply_addr.strip().lower()
        ret_addr = ret_addr.strip().lower()

        from_dom = _norm_domain(from_addr.split("@", 1)[1]) if "@" in from_addr else ""
        reply_dom = _norm_domain(reply_addr.split("@", 1)[1]) if "@" in reply_addr else ""
        ret_dom = _norm_domain(ret_addr.split("@", 1)[1]) if "@" in ret_addr else ""

        indicators: List[str] = []
        impersonated_brand: Optional[str] = None
        spoofing_detected = False

        # 1. Check Display Name claiming an embedded email from a different domain
        if from_display:
            disp_email_match = _EMAIL_IN_NAME_RE.search(from_display)
            if disp_email_match:
                claimed_dom = _norm_domain(disp_email_match.group(1))
                if claimed_dom and from_dom and not _domains_aligned(claimed_dom, from_dom):
                    spoofing_detected = True
                    indicators.append(
                        f"Display name embeds spoofed address '@{claimed_dom}' while actual sender is '{from_addr}'"
                    )

            # Display name brand impersonation check
            disp_low = from_display.lower()
            for brand in self.threat_analyzer.brands:
                b_name = brand["name"].lower()
                if any(al.lower() in disp_low for al in brand.get("aliases", [b_name])):
                    if from_dom and not self.threat_analyzer._is_official_brand_domain(from_dom, brand):
                        spoofing_detected = True
                        impersonated_brand = brand["name"]
                        indicators.append(
                            f"Display name impersonates '{brand['name']}' using non-official sender domain '{from_dom}'"
                        )
                        break

        # 2. Homoglyph / typosquatting check on sender domains
        for role, dom in (("From", from_dom), ("Reply-To", reply_dom), ("Return-Path", ret_dom)):
            if not dom:
                continue
            homo, brand_hit, b_flags = self.threat_analyzer.check_homoglyphs_and_brands(dom)
            if homo or brand_hit:
                spoofing_detected = True
                if brand_hit and not impersonated_brand:
                    impersonated_brand = brand_hit
                indicators.extend(f"{role} domain: {f}" for f in b_flags)

        # 3. Reply-To mismatch deception
        if reply_dom and from_dom and not _domains_aligned(reply_dom, from_dom):
            spoofing_detected = True
            indicators.append(
                f"Reply-To domain '{reply_dom}' differs from visible From domain '{from_dom}' (reply hijacking indicator)"
            )

        # 4. Return-Path mismatch paired with alignment failure
        if ret_dom and from_dom and not _domains_aligned(ret_dom, from_dom) and auth.get("dmarc_result") != "pass":
            spoofing_detected = True
            indicators.append(
                f"Envelope Return-Path '{ret_dom}' misaligned with From domain '{from_dom}'"
            )

        # 5. Free webmail pretending corporate/support display name
        if from_dom in _FREE_WEBMAIL_DOMAINS and re.search(r"(security|billing|support|helpdesk|verify|admin|payroll|invoice)", from_display, re.I):
            spoofing_detected = True
            indicators.append(
                f"Free webmail sender '{from_addr}' uses authoritative display name '{from_display}'"
            )

        return {
            "from_display": from_display,
            "from_address": from_addr,
            "from_domain": from_dom,
            "reply_to_address": reply_addr,
            "reply_to_domain": reply_dom,
            "return_path_address": ret_addr,
            "return_path_domain": ret_dom,
            "spoofing_detected": spoofing_detected,
            "impersonated_brand": impersonated_brand,
            "indicators": list(dict.fromkeys(indicators)),
        }

    def _inspect_headers_and_hops(
        self,
        msg: email.message.Message,
        sender: Dict[str, Any],
        auth: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]], List[str]]:
        received_raw = [str(v) for v in (msg.get_all("Received") or [])]
        # Received headers are prepended by MTAs -> reverse to get chronological origin-to-destination order
        hops: List[Dict[str, Any]] = []
        for idx, rec in enumerate(reversed(received_raw), start=1):
            m_from = re.search(r"\bfrom\s+([^\s\(\);]+)", rec, re.I)
            m_by = re.search(r"\bby\s+([^\s\(\);]+)", rec, re.I)
            ips = _IP_IN_RECEIVED_RE.findall(f" {rec} ")
            ts_part = rec.rsplit(";", 1)[1].strip() if ";" in rec else ""
            hops.append({
                "hop": idx,
                "from_host": m_from.group(1) if m_from else "",
                "by_host": m_by.group(1) if m_by else "",
                "ip": ips[0] if ips else "",
                "timestamp": ts_part[:60],
                "raw": re.sub(r"\s+", " ", rec).strip()[:260],
            })

        anomalies: List[str] = []
        message_id = str(msg.get("Message-ID") or "").strip()
        date_hdr = str(msg.get("Date") or "").strip()
        from_dom = sender.get("from_domain", "")

        if not message_id:
            anomalies.append("Missing Message-ID header (common in scripted phishing mailers)")
        elif "@" in message_id and from_dom:
            mid_dom = _norm_domain(message_id.split("@", 1)[1].rstrip("> "))
            if mid_dom and not _domains_aligned(mid_dom, from_dom) and auth.get("dmarc_result") != "pass":
                anomalies.append(f"Message-ID domain '{mid_dom}' differs from sender domain '{from_dom}'")

        if not date_hdr:
            anomalies.append("Missing Date header")
        if not received_raw:
            anomalies.append("No Received MTA transport hops present")

        x_prio = str(msg.get("X-Priority") or msg.get("Importance") or "").strip().lower()
        if x_prio.startswith("1") or x_prio == "high":
            anomalies.append(f"Urgency header set ({x_prio}) — common social-engineering pressure tactic")

        if "Fail" in auth.get("spf_status", ""):
            anomalies.append(f"Header authentication anomaly: {auth['spf_status']}")
        if "Fail" in auth.get("dkim_status", ""):
            anomalies.append(f"DKIM verification failure: {auth['dkim_status']}")

        headers_list: List[Dict[str, str]] = []
        for k, v in list(msg.items())[:45]:
            headers_list.append({
                "name": str(k),
                "value": re.sub(r"\s+", " ", str(v)).strip()[:500],
            })

        return hops, headers_list, anomalies

    def _extract_and_score_urls(
        self,
        msg: email.message.Message,
        extra_attachment_urls: List[str],
    ) -> List[Dict[str, Any]]:
        url_anchors: Dict[str, str] = {}

        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disp = str(part.get_content_disposition() or "").lower()
            if disp == "attachment":
                continue

            ctype = (part.get_content_type() or "").lower()
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    raw_str = part.get_payload()
                    text = raw_str if isinstance(raw_str, str) else ""
                else:
                    charset = part.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace")
            except Exception:
                continue

            if ctype == "text/html":
                try:
                    parser = lxml_html.HTMLParser(recover=True, collect_ids=False, no_network=True)
                    tree = lxml_html.fromstring(text, parser=parser)
                    for a_el in tree.xpath("//a[@href]"):
                        href = (a_el.get("href") or "").strip()
                        if href.lower().startswith(("http://", "https://")):
                            vis = re.sub(r"\s+", " ", "".join(a_el.itertext())).strip()[:120]
                            if not url_anchors.get(href):
                                url_anchors[href] = vis
                    for form_el in tree.xpath("//form[@action]"):
                        act = (form_el.get("action") or "").strip()
                        if act.lower().startswith(("http://", "https://")):
                            if not url_anchors.get(act):
                                url_anchors[act] = "[HTML Form Action]"
                except Exception:
                    pass
                for u in _PLAIN_URL_RE.findall(text):
                    url_anchors.setdefault(u.rstrip(".,;"), "")
            elif ctype == "text/plain":
                for u in _PLAIN_URL_RE.findall(text):
                    url_anchors.setdefault(u.rstrip(".,;"), "")

        for u in extra_attachment_urls:
            clean_u = str(u or "").strip().rstrip(".,;")
            if clean_u.lower().startswith(("http://", "https://")):
                url_anchors.setdefault(clean_u, "[Extracted from Attachment]")

        analyzed: List[Dict[str, Any]] = []
        for u, anchor_text in list(url_anchors.items())[:40]:
            lex = self.threat_analyzer.analyze_lexical_url(u)
            dom = lex["domain"]
            flags = list(lex["lexical_flags"])
            score = float(lex["raw_penalty"])

            # Detect anchor-text URL deception (e.g. text says https://paypal.com while href goes elsewhere)
            anchor_mismatch = False
            if anchor_text:
                m_vis = re.search(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", anchor_text, re.I)
                if m_vis:
                    vis_dom = _norm_domain(m_vis.group(1))
                    if vis_dom and dom and not _domains_aligned(vis_dom, dom):
                        anchor_mismatch = True
                        score += 40.0
                        flags.append(f"Deceptive link text displays '{vis_dom}' while actual destination is '{dom}'")

            ioc_hit = query_ioc(u) or query_ioc(dom)
            ioc_source = None
            if ioc_hit:
                ioc_source = ioc_hit.get("source")
                score = max(score, 90.0)
                flags.append(f"Matches active Threat IoC DB ({ioc_source})")

            score = min(100.0, round(score, 1))
            if score >= settings.RISK_THRESHOLD_HIGH:
                verdict = "MALICIOUS"
            elif score >= settings.RISK_THRESHOLD_SUSPICIOUS:
                verdict = "HIGH_RISK"
            elif score >= settings.RISK_THRESHOLD_BENIGN:
                verdict = "SUSPICIOUS"
            else:
                verdict = "BENIGN"

            analyzed.append({
                "url": u[:500],
                "domain": dom,
                "anchor_text": anchor_text[:120],
                "anchor_mismatch": anchor_mismatch,
                "score": score,
                "verdict": verdict,
                "ioc_match": ioc_source,
                "flags": flags,
            })

        analyzed.sort(key=lambda x: x["score"], reverse=True)
        return analyzed

    @staticmethod
    def _collect_attachments(msg: email.message.Message) -> List[Dict[str, Any]]:
        attachments: List[Dict[str, Any]] = []
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            disp = str(part.get_content_disposition() or "").lower()
            ctype = (part.get_content_type() or "application/octet-stream").lower()
            fname = part.get_filename()
            # Treat explicit attachments OR non-plain/non-alternative HTML files with filenames as attachments
            if disp == "attachment" or fname or (ctype not in ("text/plain", "text/html") and part.get_content_maintype() != "multipart"):
                # Skip inline CID images only if tiny/no filename? No, inspect even named inline SVGs/HTMLs cleanly
                if ctype in ("text/plain", "text/html") and not fname and disp != "attachment":
                    continue
                payload = part.get_payload(decode=True)
                if payload is None:
                    raw_p = part.get_payload()
                    if isinstance(raw_p, list):
                        payload = b"\r\n".join(p.as_bytes() for p in raw_p)
                    elif isinstance(raw_p, str):
                        payload = raw_p.encode("utf-8", errors="replace")
                    else:
                        payload = b""
                if len(payload) > settings.MAX_ATTACHMENT_BYTES:
                    payload = payload[:settings.MAX_ATTACHMENT_BYTES]
                attachments.append({
                    "filename": str(fname or f"part.{ctype.split('/')[-1]}"),
                    "content_type": ctype,
                    "data_b64": base64.b64encode(payload).decode("ascii"),
                })
                if len(attachments) >= 15:
                    break
        return attachments

    async def analyze_eml(
        self,
        raw_bytes: bytes,
        filename: str = "uploaded.eml",
        verify_dns: bool = True,
    ) -> Dict[str, Any]:
        """Parse and evaluate an .eml email across auth, spoofing, headers, URLs, and isolated attachments."""
        if not raw_bytes:
            raise ValueError("Uploaded .eml file is empty")
        if len(raw_bytes) > settings.MAX_EMAIL_BYTES:
            raise ValueError(f"Email size ({len(raw_bytes)} bytes) exceeds limit ({settings.MAX_EMAIL_BYTES} bytes)")

        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        email_id = f"EML-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        _, from_addr = parseaddr(str(msg.get("From") or ""))
        _, ret_addr = parseaddr(str(msg.get("Return-Path") or ""))
        from_domain = _norm_domain(from_addr.split("@", 1)[1]) if "@" in from_addr else ""
        ret_domain = _norm_domain(ret_addr.split("@", 1)[1]) if "@" in ret_addr else ""

        auth = await asyncio.to_thread(
            self._inspect_authentication,
            raw_bytes,
            msg,
            from_domain,
            ret_domain,
            verify_dns,
        )
        sender = self._analyze_sender_spoofing(msg, auth)
        hops, headers_list, header_anomalies = self._inspect_headers_and_hops(msg, sender, auth)

        raw_attachments = self._collect_attachments(msg)
        iso_res = await asyncio.to_thread(inspect_attachments_isolated_sync, raw_attachments)
        attachments = iso_res["results"]
        worker_pid = iso_res["worker_pid"]

        extra_att_urls = [u for att in attachments for u in (att.get("extracted_urls") or [])]
        embedded_urls = self._extract_and_score_urls(msg, extra_att_urls)

        # Compute Composite Email Risk Score
        score = 0.0
        reasons: List[str] = []

        if auth["dkim_body_hash_valid"] is False or auth["dkim_signature_valid"] is False:
            score += 40.0
            reasons.append("DKIM cryptographic verification failed")
        if "Fail" in auth["spf_status"]:
            score += 30.0
            reasons.append("SPF validation failed")
        elif "Missing" in auth["spf_status"]:
            score += 12.0
        if auth["dmarc_result"] == "fail":
            score += 25.0
            reasons.append("DMARC alignment/auth failed")
        elif auth["dmarc_result"] == "missing":
            score += 10.0

        if sender["spoofing_detected"]:
            score += 40.0 if sender["impersonated_brand"] else 30.0
            reasons.append(
                f"sender spoofing ({sender['impersonated_brand'] or 'domain/display mismatch'})"
            )

        if header_anomalies:
            score += min(20.0, len(header_anomalies) * 7.0)

        max_url_score = max((u["score"] for u in embedded_urls), default=0.0)
        if max_url_score >= 50.0:
            score = max(score, max_url_score)
            score = min(100.0, score + 15.0)
            reasons.append("malicious/deceptive embedded URL(s)")
        elif max_url_score >= 25.0:
            score += 18.0
            reasons.append("suspicious embedded URL")

        max_att_score = max((a["risk_score"] for a in attachments), default=0.0)
        if max_att_score >= 50.0:
            score = max(score, max_att_score)
            score = min(100.0, score + 15.0)
            reasons.append("malicious/weaponized attachment detected")
        elif max_att_score >= 25.0:
            score += 15.0
            reasons.append("suspicious email attachment")

        overall_score = min(100.0, round(score, 1))
        if overall_score >= settings.RISK_THRESHOLD_HIGH:
            verdict = "MALICIOUS"
        elif overall_score >= settings.RISK_THRESHOLD_SUSPICIOUS:
            verdict = "HIGH_RISK"
        elif overall_score >= settings.RISK_THRESHOLD_BENIGN:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        subject = str(msg.get("Subject") or "(No Subject)")
        if reasons:
            summary = f"Email Verdict {verdict} ({overall_score}/100): detected {', '.join(dict.fromkeys(reasons))}."
        else:
            summary = f"Email Verdict BENIGN ({overall_score}/100): authentication, sender identity, links, and attachments look clean."

        mitigations: List[str] = []
        if verdict in ("MALICIOUS", "HIGH_RISK"):
            mitigations.append(f"Quarantine message '{subject[:60]}' and purge similar messages from user mailboxes.")
            if sender["from_address"]:
                mitigations.append(f"Block sender address '{sender['from_address']}' and domain '{sender['from_domain']}' on email gateway.")
            if embedded_urls:
                mitigations.append("Detonate high-risk embedded URLs in the Isolated Browser Sandbox and block domains at web proxy.")
            if any(a.get("is_dangerous") for a in attachments):
                mitigations.append("Block dangerous attachment SHA-256 hashes in EDR/AV policies.")
        else:
            mitigations.append("No critical phishing indicators detected; continue standard DMARC/DKIM gateway enforcement.")

        report = {
            "email_id": email_id,
            "filename": filename,
            "timestamp": timestamp,
            "subject": subject,
            "date_header": str(msg.get("Date") or ""),
            "message_id": str(msg.get("Message-ID") or ""),
            "overall_score": overall_score,
            "verdict": verdict,
            "summary": summary,
            "isolated_worker_pid": worker_pid,
            "authentication": {
                k: v for k, v in auth.items() if k != "gateway_dkim"
            },
            "sender": sender,
            "received_hops": hops,
            "headers": headers_list,
            "header_anomalies": header_anomalies,
            "embedded_urls": embedded_urls,
            "attachments": attachments,
            "mitigations": mitigations,
        }
        report["mitre_attack"] = MitreAttackMapper().build_investigation_report(
            email_reports=[report],
            context_label=f"Email (.eml): {subject[:60]}",
            source_id=email_id,
        )
        save_email_scan(report)
        return report
