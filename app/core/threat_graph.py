import hashlib
import re
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


RISK_RANK: Dict[str, int] = {
    "neutral": 0,
    "benign": 1,
    "suspicious": 2,
    "high_risk": 3,
    "malicious": 4,
}

_BRAND_CAMPAIGNS: Dict[str, Tuple[str, str]] = {
    "paypal": ("paypal", "PayPal Phishing Campaign"),
    "microsoft": ("microsoft_o365", "Microsoft / Office 365 Phishing"),
    "o365": ("microsoft_o365", "Microsoft / Office 365 Phishing"),
    "office365": ("microsoft_o365", "Microsoft / Office 365 Phishing"),
    "onedrive": ("microsoft_o365", "Microsoft / Office 365 Phishing"),
    "apple": ("apple_icloud", "Apple / iCloud Phishing"),
    "icloud": ("apple_icloud", "Apple / iCloud Phishing"),
    "netflix": ("netflix", "Netflix Billing Phishing"),
    "binance": ("binance", "Binance / Crypto Drainer Campaign"),
    "coinbase": ("coinbase", "Coinbase / Crypto Phishing"),
    "google": ("google", "Google Account Phishing"),
    "gmail": ("google", "Google Account Phishing"),
    "amazon": ("amazon", "Amazon Account Phishing"),
    "chase": ("chase", "Chase Banking Phishing"),
    "wells fargo": ("wellsfargo", "Wells Fargo Banking Phishing"),
    "wellsfargo": ("wellsfargo", "Wells Fargo Banking Phishing"),
    "bank of america": ("bankofamerica", "Bank of America Phishing"),
    "facebook": ("meta", "Meta / Facebook Phishing"),
    "instagram": ("meta", "Meta / Instagram Phishing"),
    "whatsapp": ("meta", "Meta / WhatsApp Phishing"),
    "dhl": ("dhl", "DHL Delivery Phishing"),
    "dropbox": ("dropbox", "Dropbox Phishing Campaign"),
    "adobe": ("adobe", "Adobe Cloud Phishing"),
    "linkedin": ("linkedin", "LinkedIn Phishing Campaign"),
}

_FUNCTIONAL_CAMPAIGNS: Dict[str, Tuple[str, str]] = {
    "wallet_drainer": ("wallet_drainer", "Crypto Wallet Drainer Campaign"),
    "creditcard_stealer": ("creditcard_stealer", "Payment Card Stealer Campaign"),
    "credential_harvesting": ("credential_harvesting", "Credential Harvesting Campaign"),
    "credential_stealer": ("credential_harvesting", "Credential Harvesting Campaign"),
    "credential_theft": ("credential_harvesting", "Credential Harvesting Campaign"),
    "cross_origin_exfil": ("credential_harvesting", "Credential Harvesting Campaign"),
}

_NS_PROVIDER_PATTERNS: Tuple[Tuple[re.Pattern, str, str], ...] = (
    (re.compile(r"(?:^|\.)cloudflare\.com$", re.I), "cloudflare", "Cloudflare (DNS / CDN)"),
    (re.compile(r"(?:^|\.)awsdns-\d+\.", re.I), "aws_route53", "Amazon AWS Route53"),
    (re.compile(r"(?:^|\.)amazonaws\.com$", re.I), "aws", "Amazon Web Services (AWS)"),
    (re.compile(r"(?:^|\.)azure-dns\.", re.I), "azure_dns", "Microsoft Azure DNS"),
    (re.compile(r"(?:^|\.)(?:googledomains|google)\.com$", re.I), "google_cloud", "Google Infrastructure / DNS"),
    (re.compile(r"(?:^|\.)domaincontrol\.com$", re.I), "godaddy", "GoDaddy Hosting / DNS"),
    (re.compile(r"(?:^|\.)(?:registrar-servers|namecheaphosting)\.com$", re.I), "namecheap", "Namecheap DNS / Hosting"),
    (re.compile(r"(?:^|\.)digitalocean\.com$", re.I), "digitalocean", "DigitalOcean"),
    (re.compile(r"(?:^|\.)hetzner\.(?:com|de)$", re.I), "hetzner", "Hetzner Online"),
    (re.compile(r"(?:^|\.)ovh\.(?:net|com)$", re.I), "ovh", "OVHcloud"),
    (re.compile(r"(?:^|\.)linode\.com$", re.I), "linode", "Akamai / Linode"),
    (re.compile(r"(?:^|\.)vultr\.com$", re.I), "vultr", "Vultr Cloud"),
    (re.compile(r"(?:^|\.)hostinger\.", re.I), "hostinger", "Hostinger"),
    (re.compile(r"(?:^|\.)bluehost\.com$", re.I), "bluehost", "Bluehost"),
    (re.compile(r"(?:^|\.)ns\.apple\.com$", re.I), "apple_infra", "Apple Infrastructure"),
    (re.compile(r"(?:^|\.)vercel-dns\.com$", re.I), "vercel", "Vercel Cloud"),
    (re.compile(r"(?:^|\.)netlify\.com$", re.I), "netlify", "Netlify Cloud"),
    (re.compile(r"(?:^|\.)fastly\.net$", re.I), "fastly", "Fastly CDN"),
    (re.compile(r"(?:^|\.)akam\.net$", re.I), "akamai", "Akamai Edge DNS"),
    (re.compile(r"(?:^|\.)dnsmadeeasy\.com$", re.I), "dnsmadeeasy", "DNS Made Easy"),
    (re.compile(r"(?:^|\.)porkbun\.com$", re.I), "porkbun", "Porkbun DNS"),
    (re.compile(r"(?:^|\.)hostgator\.com$", re.I), "hostgator", "HostGator"),
)

_SERVER_PROVIDER_MAP: Tuple[Tuple[re.Pattern, str, str], ...] = (
    (re.compile(r"^cloudflare", re.I), "cloudflare", "Cloudflare (DNS / CDN)"),
    (re.compile(r"^(?:gws|esf|gse|sffe)$", re.I), "google_cloud", "Google Infrastructure / DNS"),
    (re.compile(r"^apple$", re.I), "apple_infra", "Apple Infrastructure"),
    (re.compile(r"^vercel$", re.I), "vercel", "Vercel Cloud"),
    (re.compile(r"^netlify$", re.I), "netlify", "Netlify Cloud"),
    (re.compile(r"^(?:cloudfront|amazons3)", re.I), "aws", "Amazon Web Services (AWS)"),
    (re.compile(r"^akamaighost", re.I), "akamai", "Akamai Edge CDN"),
    (re.compile(r"^ddos-guard", re.I), "ddos_guard", "DDoS-Guard Hosting"),
)

_MULTI_PART_PUBLIC_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "com.mx"
})


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", (value or "").lower()).strip("_")
    return slug or "unknown"


def _norm_domain(domain: str) -> str:
    return (domain or "").strip().lower().rstrip(".")


def _registrable_domain(domain: str) -> str:
    parts = [p for p in _norm_domain(domain).split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in _MULTI_PART_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _norm_url(raw_url: str, strip_query: bool = False) -> str:
    val = (raw_url or "").strip()
    if not val:
        return ""
    if "://" not in val:
        val = "https://" + val
    parsed = urlparse(val)
    scheme = (parsed.scheme or "https").lower()
    host = _norm_domain(parsed.hostname or "")
    if not host:
        return val.lower()
    port = parsed.port
    default_port = 443 if scheme == "https" else 80
    netloc = f"{host}:{port}" if (port and port != default_port) else host
    path = parsed.path or ""
    if path == "/":
        path = ""
    query = "" if strip_query else (f"?{parsed.query}" if parsed.query else "")
    return f"{scheme}://{netloc}{path}{query}"


def _short_url_label(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = _norm_domain(parsed.hostname or url)
    path = parsed.path or ""
    if path in ("", "/"):
        return host
    text = f"{host}{path}"
    return text if len(text) <= 44 else (text[:41] + "...")


def _verdict_to_risk(verdict: Optional[str]) -> str:
    v = (verdict or "").upper()
    if v == "MALICIOUS":
        return "malicious"
    if v == "HIGH_RISK":
        return "high_risk"
    if v == "SUSPICIOUS":
        return "suspicious"
    if v == "BENIGN":
        return "benign"
    return "neutral"


def _higher_risk(a: str, b: str) -> str:
    return a if RISK_RANK.get(a, 0) >= RISK_RANK.get(b, 0) else b


def _classify_ns_provider(ns_entry: str) -> Optional[Tuple[str, str]]:
    """Map an authoritative NS record string into a canonical (slug, display_label)."""
    tokens = (ns_entry or "").strip().split()
    if not tokens:
        return None
    ns_host = _norm_domain(tokens[-1])
    if not ns_host or "." not in ns_host:
        return None
    for pattern, slug, label in _NS_PROVIDER_PATTERNS:
        if pattern.search(ns_host):
            return slug, label
    root = _registrable_domain(ns_host)
    if not root or root in ("example", "invalid", "localhost"):
        return None
    return f"dns_{_slugify(root)}", f"DNS Provider: {root}"


def _classify_server_provider(server_header: str) -> Optional[Tuple[str, str]]:
    raw = (server_header or "").strip()
    if not raw or raw.lower() in ("unknown", "nginx", "apache", "iis", "openresty", "lighttpd"):
        return None
    for pattern, slug, label in _SERVER_PROVIDER_MAP:
        if pattern.search(raw):
            return slug, label
    return None


def _extract_abuseipdb_isp(threat_intel: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    details = threat_intel.get("details") or {}
    isp = details.get("abuseipdb_isp")
    country = details.get("abuseipdb_country")
    usage = details.get("abuseipdb_usage_type")
    if isp and str(isp).lower() != "unknown":
        return str(isp).strip(), country, usage
    for prov in (threat_intel.get("providers") or []):
        if prov.get("provider") == "abuseipdb":
            match = re.search(r"ISP:\s*([^)]+)", str(prov.get("provenance") or ""))
            if match:
                val = match.group(1).strip()
                if val and val.lower() != "unknown":
                    return val, country, usage
    return None, country, usage


def _extract_cross_origin_targets(threat_analysis: Dict[str, Any]) -> List[str]:
    targets: List[str] = []
    for item in (threat_analysis.get("contributions") or []):
        if item.get("factor") == "cross_origin_form" and item.get("evidence"):
            dom = _norm_domain(str(item["evidence"]))
            if dom:
                targets.append(dom)
    for flag in (threat_analysis.get("content_flags") or []):
        m = re.search(r"disparate domain '([^']+)'", str(flag), re.I)
        if m:
            dom = _norm_domain(m.group(1))
            if dom:
                targets.append(dom)
    return list(dict.fromkeys(targets))


def _infer_campaigns(
    verdict: str,
    impersonated_brand: Optional[str],
    tags: List[str],
    threat_intel: Dict[str, Any],
    is_ioc: bool = False,
) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Identify phishing campaigns / threat clusters for non-benign detections or active IoCs."""
    if not is_ioc and _verdict_to_risk(verdict) not in ("malicious", "high_risk", "suspicious"):
        return []

    campaigns: Dict[str, Tuple[str, str, Dict[str, Any]]] = {}

    if impersonated_brand:
        key = impersonated_brand.strip().lower()
        slug, label = _BRAND_CAMPAIGNS.get(key, (_slugify(key), f"{impersonated_brand} Phishing Campaign"))
        campaigns[slug] = (slug, label, {"category": "Brand Impersonation", "brand": impersonated_brand})

    for tag in tags or []:
        clean_tag = str(tag).strip().lower().lstrip("#")
        if not clean_tag:
            continue
        if clean_tag in _BRAND_CAMPAIGNS:
            slug, label = _BRAND_CAMPAIGNS[clean_tag]
            campaigns[slug] = (slug, label, {"category": "Brand Impersonation", "tag": f"#{clean_tag}"})

    # Parse AlienVault OTX threat pulses if matched
    for prov in (threat_intel.get("providers") or []):
        if prov.get("provider") == "alienvault_otx" and prov.get("matched"):
            prov_str = str(prov.get("provenance") or "")
            m = re.search(r"pulse\(s\):\s*([^)]+)", prov_str, re.I)
            if m:
                for pulse in m.group(1).split(",")[:2]:
                    pname = pulse.strip()
                    if pname and pname.lower() != "active threat pulses":
                        pslug = f"otx_{_slugify(pname)}"
                        campaigns[pslug] = (pslug, f"OTX Campaign: {pname}", {"category": "CTI Pulse", "source": "AlienVault OTX"})

    # Functional campaign classification when no specific brand/pulse campaign matched
    if not campaigns:
        for tag in tags or []:
            clean_tag = str(tag).strip().lower().lstrip("#")
            if clean_tag in _FUNCTIONAL_CAMPAIGNS:
                slug, label = _FUNCTIONAL_CAMPAIGNS[clean_tag]
                campaigns[slug] = (slug, label, {"category": "Threat TTP", "tag": f"#{clean_tag}"})

    if not campaigns and (is_ioc or _verdict_to_risk(verdict) == "malicious"):
        for hit in (threat_intel.get("feed_hits") or []):
            hlow = str(hit).lower()
            if "urlhaus" in hlow:
                campaigns["urlhaus_active"] = ("urlhaus_active", "URLhaus Active Threat Cluster", {"category": "CTI Feed", "feed": "URLhaus"})
            elif "phishtank" in hlow:
                campaigns["phishtank_active"] = ("phishtank_active", "PhishTank Phishing Cluster", {"category": "CTI Feed", "feed": "PhishTank"})

    return list(campaigns.values())


class ThreatGraphBuilder:
    """
    Correlates domains, URLs, IP addresses, SSL/TLS certificates, hosting/DNS providers,
    and phishing campaigns across scan reports and threat IoCs into an interactive graph.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[str, Dict[str, Any]] = {}

    def _upsert_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        risk_level: str = "neutral",
        score: Optional[float] = None,
        scan_id: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        props = dict(properties or {})
        existing = self._nodes.get(node_id)
        if existing is None:
            scan_ids = [scan_id] if scan_id else []
            if scan_ids:
                props.setdefault("scan_ids", scan_ids)
            node = {
                "id": node_id,
                "type": node_type,
                "label": label,
                "risk_level": risk_level,
                "score": round(float(score), 1) if score is not None else None,
                "degree": 0,
                "properties": props,
            }
            self._nodes[node_id] = node
            return node

        existing["risk_level"] = _higher_risk(existing["risk_level"], risk_level)
        if score is not None:
            if existing["score"] is None:
                existing["score"] = round(float(score), 1)
            else:
                existing["score"] = round(max(float(existing["score"]), float(score)), 1)

        ex_props = existing["properties"]
        if scan_id:
            sids = list(ex_props.get("scan_ids") or [])
            if scan_id not in sids:
                sids.append(scan_id)
            ex_props["scan_ids"] = sids

        for k, v in props.items():
            if v is None or v == "" or v == []:
                continue
            if isinstance(v, list) and isinstance(ex_props.get(k), list):
                merged = list(ex_props[k])
                for item in v:
                    if item not in merged:
                        merged.append(item)
                ex_props[k] = merged
            elif k not in ex_props or ex_props[k] in (None, "", []):
                ex_props[k] = v
        return existing

    def _add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        label: str,
        evidence: str = "",
    ) -> None:
        if not source or not target or source == target:
            return
        edge_id = f"{source}|{relation}|{target}"
        if edge_id not in self._edges:
            self._edges[edge_id] = {
                "id": edge_id,
                "source": source,
                "target": target,
                "relation": relation,
                "label": label,
                "evidence": evidence,
            }

    def _ingest_scan(self, report: Dict[str, Any]) -> None:
        scan_id = report.get("scan_id")
        raw_url = report.get("target_url") or ""
        norm_url = _norm_url(raw_url)
        domain = _norm_domain(report.get("target_domain") or (urlparse(norm_url).hostname or ""))
        if not domain:
            return

        verdict = report.get("verdict", "BENIGN")
        score = float(report.get("overall_score", 0.0))
        risk = _verdict_to_risk(verdict)

        ta = report.get("threat_analysis") or {}
        ws = report.get("web_security") or {}
        cv = report.get("cert_validation") or {}
        ti = report.get("threat_intel") or {}

        dom_id = f"domain:{domain}"
        self._upsert_node(
            dom_id,
            "domain",
            domain,
            risk_level=risk,
            score=score,
            scan_id=scan_id,
            properties={
                "domain": domain,
                "verdict": verdict,
                "headers_grade": ws.get("headers_grade"),
                "spf_status": ws.get("spf_status"),
                "dmarc_status": ws.get("dmarc_status"),
                "impersonated_brand": ta.get("impersonated_brand"),
                "homoglyph_detected": ta.get("homoglyph_detected"),
                "entropy": ta.get("entropy"),
            },
        )

        url_id = f"url:{norm_url}" if norm_url else ""
        if url_id:
            self._upsert_node(
                url_id,
                "url",
                _short_url_label(norm_url),
                risk_level=risk,
                score=score,
                scan_id=scan_id,
                properties={
                    "url": norm_url,
                    "verdict": verdict,
                    "has_password_input": ta.get("has_password_input"),
                    "has_cross_origin_form": ta.get("has_cross_origin_form"),
                    "tags": list(ti.get("tags") or []),
                },
            )
            self._add_edge(url_id, dom_id, "BELONGS_TO", "hosted on domain", f"Scan {scan_id}")

        # 1. DNS IPs & Fast-Flux
        dns_records = ws.get("dns_records") or {}
        domain_ips: List[str] = []
        for candidate_ip in [ws.get("ip_address")] + list(dns_records.get("A") or []) + list(dns_records.get("AAAA") or []):
            ip_val = str(candidate_ip or "").strip()
            if ip_val and ip_val not in domain_ips:
                domain_ips.append(ip_val)

        abuse_isp, abuse_country, abuse_usage = _extract_abuseipdb_isp(ti)
        fast_flux = bool((ws.get("details") or {}).get("fast_flux_detected"))

        for ip_val in domain_ips:
            ip_id = f"ip:{ip_val}"
            subnet = ".".join(ip_val.split(".")[:3]) + ".0/24" if "." in ip_val and ":" not in ip_val else None
            self._upsert_node(
                ip_id,
                "ip",
                ip_val,
                risk_level="neutral",
                scan_id=scan_id,
                properties={
                    "ip": ip_val,
                    "subnet": subnet,
                    "fast_flux": fast_flux,
                    "isp": abuse_isp,
                    "country": abuse_country,
                    "abuseipdb_status": ti.get("abuseipdb_status"),
                },
            )
            self._add_edge(dom_id, ip_id, "RESOLVES_TO", "resolves to IP", f"DNS resolution ({scan_id})")

        # 2. AbuseIPDB ISP -> Hosting Provider
        if abuse_isp:
            isp_slug = _slugify(abuse_isp)
            host_id = f"hosting:{isp_slug}"
            self._upsert_node(
                host_id,
                "hosting",
                abuse_isp,
                risk_level="neutral",
                scan_id=scan_id,
                properties={
                    "provider": abuse_isp,
                    "kind": "ISP / Hosting Provider",
                    "country": abuse_country,
                    "usage_type": abuse_usage,
                },
            )
            if domain_ips:
                self._add_edge(f"ip:{domain_ips[0]}", host_id, "HOSTED_BY", "operated by ISP", f"AbuseIPDB ({abuse_country or 'N/A'})")
            else:
                self._add_edge(dom_id, host_id, "HOSTED_BY", "operated by ISP", "AbuseIPDB")

        # 3. Nameservers (NS) -> Hosting / DNS Providers
        for ns_entry in (dns_records.get("NS") or []):
            classified = _classify_ns_provider(str(ns_entry))
            if classified:
                slug, label = classified
                host_id = f"hosting:{slug}"
                self._upsert_node(
                    host_id,
                    "hosting",
                    label,
                    risk_level="neutral",
                    scan_id=scan_id,
                    properties={
                        "provider": label,
                        "kind": "Authoritative DNS / Cloud",
                        "nameservers": [str(ns_entry).strip().rstrip(".")],
                    },
                )
                self._add_edge(dom_id, host_id, "USES_DNS", "uses DNS provider", str(ns_entry).strip().rstrip("."))

        # 4. Server Header / CDN Signatures -> Hosting Providers
        present_headers = ws.get("present_headers") or {}
        server_candidates = []
        if present_headers.get("server"):
            server_candidates.append((dom_id, present_headers["server"]))
        chain = ws.get("redirect_chain") or []
        for hop in chain:
            hop_url = _norm_url(str(hop.get("url") or ""))
            hop_host = _norm_domain(urlparse(hop_url).hostname or "") if hop_url else ""
            if hop_host and hop.get("server"):
                server_candidates.append((f"domain:{hop_host}", str(hop["server"])))

        for target_dom_id, srv in server_candidates:
            classified_srv = _classify_server_provider(srv)
            if classified_srv and target_dom_id in self._nodes:
                slug, label = classified_srv
                host_id = f"hosting:{slug}"
                self._upsert_node(
                    host_id,
                    "hosting",
                    label,
                    risk_level="neutral",
                    scan_id=scan_id,
                    properties={"provider": label, "kind": "CDN / Cloud Edge", "server_banners": [srv]},
                )
                self._add_edge(target_dom_id, host_id, "HOSTED_BY", "served behind CDN/infra", f"HTTP Server: {srv}")

        # 5. Redirect Chain Cross-Domain & Resolved IP Pivots
        prev_url_id = url_id
        for hop in chain:
            hop_raw = str(hop.get("url") or "")
            hop_norm = _norm_url(hop_raw, strip_query=True)
            hop_host = _norm_domain(urlparse(hop_norm).hostname or "") if hop_norm else ""
            if not hop_host:
                continue
            hop_dom_id = f"domain:{hop_host}"
            self._upsert_node(
                hop_dom_id,
                "domain",
                hop_host,
                risk_level=risk if hop_host == domain else "neutral",
                scan_id=scan_id,
                properties={"domain": hop_host},
            )
            hop_ip = str(hop.get("resolved_ip") or "").strip()
            if hop_ip:
                hop_ip_id = f"ip:{hop_ip}"
                subnet = ".".join(hop_ip.split(".")[:3]) + ".0/24" if "." in hop_ip and ":" not in hop_ip else None
                self._upsert_node(
                    hop_ip_id,
                    "ip",
                    hop_ip,
                    risk_level="neutral",
                    scan_id=scan_id,
                    properties={"ip": hop_ip, "subnet": subnet},
                )
                self._add_edge(hop_dom_id, hop_ip_id, "RESOLVES_TO", "resolves to IP", f"Redirect hop #{hop.get('hop', '?')}")

            if hop_host != domain and hop_norm:
                hop_url_id = f"url:{hop_norm}"
                self._upsert_node(
                    hop_url_id,
                    "url",
                    _short_url_label(hop_norm),
                    risk_level="neutral",
                    scan_id=scan_id,
                    properties={"url": hop_norm, "status_code": hop.get("status_code")},
                )
                self._add_edge(hop_url_id, hop_dom_id, "BELONGS_TO", "hosted on domain", "Redirect destination")
                if prev_url_id and prev_url_id != hop_url_id:
                    self._add_edge(prev_url_id, hop_url_id, "REDIRECTS_TO", "redirects to", f"HTTP {hop.get('status_code', 302)}")
                prev_url_id = hop_url_id

        # 6. Cross-Origin Credential Exfiltration
        for exfil_dom in _extract_cross_origin_targets(ta):
            exfil_id = f"domain:{exfil_dom}"
            self._upsert_node(
                exfil_id,
                "domain",
                exfil_dom,
                risk_level="high_risk",
                scan_id=scan_id,
                properties={"domain": exfil_dom, "role": "Credential Exfiltration Receiver"},
            )
            src = url_id or dom_id
            self._add_edge(src, exfil_id, "EXFILTRATES_TO", "posts credentials to", "Cross-origin <form action>")

        # 7. SSL/TLS Certificate & Shared SAN Links
        issuer = cv.get("issuer")
        if issuer and issuer != "None (Unencrypted HTTP)":
            cv_details = cv.get("details") or {}
            fp = cv_details.get("sha256_fingerprint")
            serial = cv_details.get("serial_number")
            subject = cv.get("subject") or domain
            not_before = cv.get("not_before") or ""

            if fp:
                cert_key = f"cert:sha256:{str(fp)[:16].lower()}"
            elif serial:
                digest = hashlib.sha1(f"{issuer}|{serial}".encode("utf-8")).hexdigest()[:14]
                cert_key = f"cert:ser:{digest}"
            else:
                digest = hashlib.sha1(f"{issuer}|{subject}|{not_before}".encode("utf-8")).hexdigest()[:14]
                cert_key = f"cert:sub:{digest}"

            issuer_short = str(issuer).split("(")[0].strip() or str(issuer)
            cert_label = f"{issuer_short[:20]} · {subject[:22]}"
            san_list = [_norm_domain(s) for s in (cv.get("san_domains") or []) if s]

            self._upsert_node(
                cert_key,
                "certificate",
                cert_label,
                risk_level="neutral",
                scan_id=scan_id,
                properties={
                    "issuer": issuer,
                    "subject": subject,
                    "serial_number": serial,
                    "sha256_fingerprint": fp,
                    "age_days": cv.get("age_days"),
                    "valid": cv.get("valid"),
                    "is_free_automated_ca": cv.get("is_free_automated_ca"),
                    "is_wildcard": cv.get("is_wildcard"),
                    "san_domains": san_list,
                    "tls_version": cv.get("tls_version"),
                },
            )
            self._add_edge(dom_id, cert_key, "PRESENTS_CERT", "presents certificate", f"TLS {cv.get('tls_version') or ''}".strip())

            # Materialize co-hosted non-wildcard SANs on non-benign certs to uncover cert-sharing kits immediately
            if risk in ("malicious", "high_risk", "suspicious"):
                extra_added = 0
                for san in san_list:
                    if san.startswith("*.") or san == domain:
                        continue
                    san_dom_id = f"domain:{san}"
                    self._upsert_node(
                        san_dom_id,
                        "domain",
                        san,
                        risk_level="suspicious",
                        scan_id=scan_id,
                        properties={"domain": san, "role": "Co-hosted SAN on threat certificate"},
                    )
                    self._add_edge(cert_key, san_dom_id, "COVERS_SAN", "SAN covers", "Shared certificate SAN")
                    extra_added += 1
                    if extra_added >= 5:
                        break

        # 8. Phishing Campaigns (only for non-benign detections)
        for slug, camp_label, cmeta in _infer_campaigns(
            verdict=verdict,
            impersonated_brand=ta.get("impersonated_brand"),
            tags=list(ti.get("tags") or []),
            threat_intel=ti,
            is_ioc=False,
        ):
            camp_id = f"campaign:{slug}"
            self._upsert_node(
                camp_id,
                "campaign",
                camp_label,
                risk_level=risk,
                scan_id=scan_id,
                properties=cmeta,
            )
            self._add_edge(dom_id, camp_id, "ATTRIBUTED_TO", "linked to campaign", f"Verdict: {verdict}")

    def _ingest_ioc(self, ioc: Dict[str, Any]) -> None:
        raw_ind = str(ioc.get("indicator") or "").strip()
        ind_type = str(ioc.get("indicator_type") or "url").lower()
        tags = list(ioc.get("tags") or [])
        conf = float(ioc.get("confidence", 85.0))
        source = str(ioc.get("source") or "Community Threat DB")

        if ind_type == "ip":
            ip_id = f"ip:{raw_ind}"
            self._upsert_node(
                ip_id,
                "ip",
                raw_ind,
                risk_level="malicious",
                score=conf,
                properties={"ip": raw_ind, "source": source, "tags": tags, "notes": ioc.get("notes")},
            )
            primary_id = ip_id
        elif ind_type == "domain":
            dom = _norm_domain(raw_ind)
            dom_id = f"domain:{dom}"
            self._upsert_node(
                dom_id,
                "domain",
                dom,
                risk_level="malicious",
                score=conf,
                properties={"domain": dom, "ioc_source": source, "tags": tags, "notes": ioc.get("notes")},
            )
            primary_id = dom_id
        else:
            norm_u = _norm_url(raw_ind)
            host = _norm_domain(urlparse(norm_u).hostname or "")
            if not host:
                return
            dom_id = f"domain:{host}"
            url_id = f"url:{norm_u}"
            self._upsert_node(
                dom_id,
                "domain",
                host,
                risk_level="malicious",
                score=conf,
                properties={"domain": host, "ioc_source": source, "tags": tags},
            )
            self._upsert_node(
                url_id,
                "url",
                _short_url_label(norm_u),
                risk_level="malicious",
                score=conf,
                properties={
                    "url": norm_u,
                    "ioc_id": ioc.get("id"),
                    "source": source,
                    "tags": tags,
                    "notes": ioc.get("notes"),
                },
            )
            self._add_edge(url_id, dom_id, "BELONGS_TO", "IoC hosted on domain", source)
            primary_id = dom_id

        for slug, camp_label, cmeta in _infer_campaigns(
            verdict="MALICIOUS",
            impersonated_brand=None,
            tags=tags,
            threat_intel={"feed_hits": [source]},
            is_ioc=True,
        ):
            camp_id = f"campaign:{slug}"
            self._upsert_node(
                camp_id,
                "campaign",
                camp_label,
                risk_level="malicious",
                properties=cmeta,
            )
            self._add_edge(primary_id, camp_id, "ATTRIBUTED_TO", "attributed to campaign", source)

    def _link_cross_domain_sans(self) -> None:
        """Connect existing domain nodes that appear inside any certificate's SAN list."""
        for node_id, node in list(self._nodes.items()):
            if node["type"] != "certificate":
                continue
            for san in (node["properties"].get("san_domains") or []):
                if san.startswith("*."):
                    continue
                target_dom_id = f"domain:{_norm_domain(san)}"
                if target_dom_id in self._nodes:
                    # Skip if domain already directly presents this cert
                    already_presents = f"{target_dom_id}|PRESENTS_CERT|{node_id}" in self._edges
                    if not already_presents:
                        self._add_edge(node_id, target_dom_id, "COVERS_SAN", "SAN covers", f"Cert SAN '{san}'")

    def _link_shared_subnets(self) -> None:
        """Connect IPs from distinct domains that share an unlisted /24 hosting subnet."""
        subnet_to_domains: Dict[str, Set[str]] = defaultdict(set)
        subnet_to_ips: Dict[str, Set[str]] = defaultdict(set)

        for edge in self._edges.values():
            if edge["relation"] == "RESOLVES_TO" and edge["source"].startswith("domain:") and edge["target"].startswith("ip:"):
                ip_node = self._nodes.get(edge["target"])
                subnet = (ip_node or {}).get("properties", {}).get("subnet")
                if subnet:
                    subnet_to_domains[subnet].add(edge["source"])
                    subnet_to_ips[subnet].add(edge["target"])

        for subnet, doms in subnet_to_domains.items():
            ips = subnet_to_ips[subnet]
            # Only create a shared /24 hosting node when multiple distinct domains share multiple IPs in the same /24
            if len(doms) >= 2 and len(ips) >= 2:
                host_id = f"hosting:subnet_{_slugify(subnet)}"
                self._upsert_node(
                    host_id,
                    "hosting",
                    f"Netblock {subnet}",
                    risk_level="neutral",
                    properties={"subnet": subnet, "kind": "Shared IPv4 /24 Netblock"},
                )
                for ip_id in ips:
                    self._add_edge(ip_id, host_id, "HOSTED_BY", "in /24 netblock", subnet)

    def _propagate_infrastructure_risk(self) -> None:
        """Elevate risk level of shared IPs, certs, and campaigns linked to high-risk/malicious domains."""
        for _ in range(2):
            for edge in self._edges.values():
                src = self._nodes.get(edge["source"])
                tgt = self._nodes.get(edge["target"])
                if not src or not tgt:
                    continue
                if tgt["type"] in ("ip", "certificate", "campaign"):
                    if RISK_RANK.get(src["risk_level"], 0) >= RISK_RANK["suspicious"]:
                        tgt["risk_level"] = _higher_risk(tgt["risk_level"], src["risk_level"])
                if src["type"] in ("certificate", "campaign") and tgt["type"] == "domain":
                    if src["type"] == "certificate" and RISK_RANK.get(tgt["risk_level"], 0) >= RISK_RANK["suspicious"]:
                        src["risk_level"] = _higher_risk(src["risk_level"], tgt["risk_level"])

    @staticmethod
    def _filter_subgraph(
        nodes: Dict[str, Dict[str, Any]],
        edges: Dict[str, Dict[str, Any]],
        scan_id: Optional[str] = None,
        query: Optional[str] = None,
        threats_only: bool = False,
    ) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        adj: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        for e in edges.values():
            adj[e["source"]].append((e["target"], e["relation"]))
            adj[e["target"]].append((e["source"], e["relation"]))

        keep: Optional[Set[str]] = None

        if threats_only:
            threat_seeds = {
                nid for nid, n in nodes.items()
                if (
                    n["type"] in ("domain", "url")
                    and RISK_RANK.get(n["risk_level"], 0) >= RISK_RANK["suspicious"]
                ) or n["type"] == "campaign"
            }
            keep = set(threat_seeds)
            for nid in threat_seeds:
                for nbr, _ in adj.get(nid, []):
                    keep.add(nbr)
                    if nbr.startswith("ip:"):
                        for ip_nbr, rel in adj.get(nbr, []):
                            if rel == "HOSTED_BY" and ip_nbr.startswith("hosting:"):
                                keep.add(ip_nbr)

        if scan_id:
            seeds = {
                nid for nid, n in nodes.items()
                if scan_id in (n.get("properties", {}).get("scan_ids") or [])
                and (keep is None or nid in keep)
            }
            visited: Set[str] = set(seeds)
            q_bfs: deque[Tuple[str, int]] = deque((s, 0) for s in seeds)
            while q_bfs:
                curr, depth = q_bfs.popleft()
                if depth >= 2:
                    continue
                curr_node = nodes.get(curr)
                # Avoid exploding through high-fanout public DNS/CDN hubs (e.g., Cloudflare) during focus mode
                if depth == 1 and curr_node and curr_node["type"] == "hosting" and len(adj.get(curr, [])) > 12:
                    continue
                for nbr, _ in adj.get(curr, []):
                    if keep is not None and nbr not in keep:
                        continue
                    if nbr not in visited:
                        visited.add(nbr)
                        q_bfs.append((nbr, depth + 1))
            keep = visited

        if query:
            q_low = query.strip().lower()
            matches = set()
            for nid, n in nodes.items():
                if keep is not None and nid not in keep:
                    continue
                haystack = " ".join([
                    nid.lower(),
                    str(n.get("label", "")).lower(),
                    str(n.get("type", "")).lower(),
                    str(n.get("properties", "")).lower(),
                ])
                if q_low in haystack:
                    matches.add(nid)
            expanded = set(matches)
            for nid in matches:
                for nbr, _ in adj.get(nid, []):
                    if keep is None or nbr in keep:
                        expanded.add(nbr)
            keep = expanded

        if keep is None:
            return dict(nodes), dict(edges)

        filtered_edges = {
            eid: e for eid, e in edges.items()
            if e["source"] in keep and e["target"] in keep
        }
        filtered_nodes = {nid: nodes[nid] for nid in keep if nid in nodes}
        return filtered_nodes, filtered_edges

    @staticmethod
    def _detect_clusters(
        nodes: Dict[str, Dict[str, Any]],
        edges: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Identify shared certificate, IP, hosting, campaign, and credential-exfiltration pivots."""
        pivot_domains: Dict[str, Set[str]] = defaultdict(set)
        pivot_nodes: Dict[str, Set[str]] = defaultdict(set)

        for e in edges.values():
            src, tgt, rel = e["source"], e["target"], e["relation"]
            s_node = nodes.get(src)
            t_node = nodes.get(tgt)
            if not s_node or not t_node:
                continue

            if t_node["type"] in ("certificate", "ip", "hosting", "campaign"):
                if s_node["type"] == "domain":
                    pivot_domains[tgt].add(src)
                pivot_nodes[tgt].add(src)
                pivot_nodes[tgt].add(tgt)
            if s_node["type"] == "certificate" and t_node["type"] == "domain":
                pivot_domains[src].add(tgt)
                pivot_nodes[src].add(src)
                pivot_nodes[src].add(tgt)
            if rel == "HOSTED_BY" and s_node["type"] == "ip" and t_node["type"] == "hosting":
                # Attach domains resolving to this IP onto the hosting pivot
                for e2 in edges.values():
                    if e2["relation"] == "RESOLVES_TO" and e2["target"] == src and e2["source"].startswith("domain:"):
                        pivot_domains[tgt].add(e2["source"])
                        pivot_nodes[tgt].add(e2["source"])
                        pivot_nodes[tgt].add(src)

        clusters: List[Dict[str, Any]] = []
        for pivot_id, dom_ids in pivot_domains.items():
            if len(dom_ids) < 2:
                continue
            pnode = nodes[pivot_id]
            ptype = pnode["type"]
            domain_names = sorted(nodes[d]["label"] for d in dom_ids if d in nodes)
            max_risk = max((RISK_RANK.get(nodes[d]["risk_level"], 0) for d in dom_ids if d in nodes), default=0)

            if max_risk >= RISK_RANK["malicious"]:
                severity = "critical"
            elif max_risk >= RISK_RANK["high_risk"]:
                severity = "high"
            elif max_risk >= RISK_RANK["suspicious"]:
                severity = "medium"
            else:
                severity = "info"

            title_map = {
                "certificate": f"Shared SSL Certificate ({len(domain_names)} domains)",
                "ip": f"Shared IP Address {pnode['label']} ({len(domain_names)} domains)",
                "hosting": f"Shared Infrastructure: {pnode['label']} ({len(domain_names)} domains)",
                "campaign": f"{pnode['label']} ({len(domain_names)} domains)",
            }
            desc_map = {
                "certificate": f"Domains {', '.join(domain_names[:4])} present or share SAN coverage on '{pnode['label']}'.",
                "ip": f"Multiple domains ({', '.join(domain_names[:4])}) resolve to the same host IP {pnode['label']}.",
                "hosting": f"{len(domain_names)} domains share infrastructure/DNS on {pnode['label']}.",
                "campaign": f"{len(domain_names)} correlated targets attributed to {pnode['label']}.",
            }
            clusters.append({
                "cluster_id": pivot_id,
                "pivot_type": ptype,
                "pivot_node_id": pivot_id,
                "pivot_label": pnode["label"],
                "severity": severity,
                "title": title_map.get(ptype, f"Cluster ({len(domain_names)} domains)"),
                "description": desc_map.get(ptype, ""),
                "domains": domain_names,
                "node_ids": sorted(pivot_nodes[pivot_id]),
            })

        # Add explicit cross-origin credential exfiltration pivots even if single pair
        for e in edges.values():
            if e["relation"] == "EXFILTRATES_TO":
                src_node = nodes.get(e["source"])
                tgt_node = nodes.get(e["target"])
                if src_node and tgt_node:
                    clusters.append({
                        "cluster_id": f"exfil:{e['target']}",
                        "pivot_type": "exfiltration",
                        "pivot_node_id": e["target"],
                        "pivot_label": tgt_node["label"],
                        "severity": "critical",
                        "title": f"Credential Exfiltration -> {tgt_node['label']}",
                        "description": f"Credential form on '{src_node['label']}' posts data externally to '{tgt_node['label']}'.",
                        "domains": [tgt_node["label"]],
                        "node_ids": [e["source"], e["target"]],
                    })

        sev_order = {"critical": 4, "high": 3, "medium": 2, "info": 1}
        clusters.sort(key=lambda c: (sev_order.get(c["severity"], 0), len(c["domains"])), reverse=True)
        return clusters

    def build_graph(
        self,
        scans: List[Dict[str, Any]],
        iocs: Optional[List[Dict[str, Any]]] = None,
        scan_id: Optional[str] = None,
        query: Optional[str] = None,
        threats_only: bool = False,
    ) -> Dict[str, Any]:
        """Build a deduplicated, correlated Threat Relationship Graph from scans and IoCs."""
        self._nodes = {}
        self._edges = {}

        # Deduplicate scans by normalized URL (keeping newest scan report in input order)
        seen_urls: Set[str] = set()
        for report in scans:
            if not isinstance(report, dict):
                continue
            nurl = _norm_url(str(report.get("target_url") or report.get("target_domain") or ""))
            key = f"{nurl}|{report.get('scan_id')}" if (scan_id and report.get("scan_id") == scan_id) else nurl
            if key and key in seen_urls:
                continue
            if key:
                seen_urls.add(key)
            self._ingest_scan(report)

        for ioc in (iocs or []):
            if isinstance(ioc, dict):
                self._ingest_ioc(ioc)

        self._link_cross_domain_sans()
        self._link_shared_subnets()
        self._propagate_infrastructure_risk()

        nodes, edges = self._filter_subgraph(
            self._nodes,
            self._edges,
            scan_id=scan_id,
            query=query,
            threats_only=threats_only,
        )

        # Recompute exact node degrees for the returned graph
        degree_counts: Dict[str, int] = defaultdict(int)
        for e in edges.values():
            degree_counts[e["source"]] += 1
            degree_counts[e["target"]] += 1

        node_list: List[Dict[str, Any]] = []
        node_counts: Dict[str, int] = {
            "domain": 0,
            "url": 0,
            "ip": 0,
            "certificate": 0,
            "hosting": 0,
            "campaign": 0,
        }
        for nid, n in nodes.items():
            node_copy = dict(n)
            node_copy["degree"] = degree_counts.get(nid, 0)
            node_list.append(node_copy)
            ntype = node_copy["type"]
            node_counts[ntype] = node_counts.get(ntype, 0) + 1

        edge_list = list(edges.values())
        clusters = self._detect_clusters(nodes, edges)
        threat_clusters = [c for c in clusters if c["severity"] in ("critical", "high", "medium")]

        return {
            "nodes": node_list,
            "edges": edge_list,
            "clusters": clusters,
            "summary": {
                "total_nodes": len(node_list),
                "total_edges": len(edge_list),
                "node_counts": node_counts,
                "shared_clusters_count": len(clusters),
                "threat_clusters_count": len(threat_clusters),
                "focus_scan_id": scan_id,
                "query": query,
                "threats_only": threats_only,
            },
        }


def build_threat_graph_from_db(
    scan_id: Optional[str] = None,
    query: Optional[str] = None,
    threats_only: bool = False,
    limit: int = 120,
) -> Dict[str, Any]:
    """Load persisted scan reports and community/feed IoCs from SQLite and construct the Threat Graph."""
    from app.models.database import get_all_iocs, get_full_scans, get_scan_by_id

    scans = get_full_scans(limit=limit)
    if scan_id and not any(s.get("scan_id") == scan_id for s in scans):
        target_scan = get_scan_by_id(scan_id)
        if target_scan:
            scans = [target_scan] + scans

    iocs = get_all_iocs(limit=200)
    return ThreatGraphBuilder().build_graph(
        scans=scans,
        iocs=iocs,
        scan_id=scan_id,
        query=query,
        threats_only=threats_only,
    )
