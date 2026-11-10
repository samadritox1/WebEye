import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple
import dns.resolver
from app.config import settings
from app.core.explainability import make_contribution, make_missing_evidence
from app.core.fetch_worker import run_in_restricted_worker
from app.core.security_guard import (
    SSRFBlockedError,
    is_private_or_reserved_ip,
    validate_target_url,
)

class SecurityAssessor:
    _MULTI_PART_PUBLIC_SUFFIXES = frozenset({
        "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "com.mx"
    })

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 3.0

    @classmethod
    def _registrable_domain(cls, domain: str) -> str:
        """Approximate registrable (eTLD+1) domain for parent fallback and cross-domain checks."""
        parts = [p for p in domain.lower().rstrip(".").split(".") if p]
        if len(parts) <= 2:
            return ".".join(parts)
        if ".".join(parts[-2:]) in cls._MULTI_PART_PUBLIC_SUFFIXES and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    async def audit_security_headers(
        self,
        url: str,
        prefetched: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Fetch and audit HTTP security response headers via isolated worker."""
        headers_dict = {}
        missing_headers = []
        present_headers = {}
        contributions: List[Dict[str, Any]] = []
        missing_evidence: List[Dict[str, Any]] = []
        headers_fetched = False
        penalty = 0

        try:
            fetch_data = prefetched
            if fetch_data is None:
                fetch_data = await run_in_restricted_worker(
                    url=url,
                    mode="http",
                    fetch_content=False,
                    fetch_tls=False,
                    user_agent=settings.SAFETY_USER_AGENT,
                )
            headers_dict = {k.lower(): v for k, v in (fetch_data.get("headers") or {}).items()}
            if fetch_data.get("status_code", 0) > 0 and not fetch_data.get("error"):
                headers_fetched = True
            else:
                reason = fetch_data.get("error") or "No HTTP response received"
                missing_evidence.append(make_missing_evidence(
                    "web_security",
                    "HTTP Security Headers",
                    f"Target HTTP headers unavailable ({str(reason)[:90]})",
                    impact="high",
                ))
        except SSRFBlockedError:
            raise
        except Exception as exc:
            headers_dict = {}
            missing_evidence.append(make_missing_evidence(
                "web_security",
                "HTTP Security Headers",
                f"Failed to fetch HTTP headers ({str(exc)[:90]})",
                impact="high",
            ))

        # 1. HSTS
        hsts = headers_dict.get("strict-transport-security")
        hsts_enabled = False
        if hsts:
            hsts_enabled = True
            present_headers["Strict-Transport-Security"] = hsts
            if "max-age" in hsts:
                try:
                    match = re.search(r"max-age=(\d+)", hsts)
                    if match and int(match.group(1)) < 2592000:  # < 30 days
                        penalty += 5
                        contributions.append(make_contribution(
                            "web_security", "weak_hsts", "Weak HSTS max-age (< 30 days)", 5, "low"
                        ))
                except Exception:
                    pass
        else:
            missing_headers.append("Strict-Transport-Security (HSTS)")
            penalty += 15
            contributions.append(make_contribution(
                "web_security", "missing_hsts", "Missing Strict-Transport-Security (HSTS)", 15, "medium"
            ))

        # 2. Content-Security-Policy
        csp = headers_dict.get("content-security-policy")
        csp_enabled = False
        if csp:
            csp_enabled = True
            present_headers["Content-Security-Policy"] = csp[:120] + ("..." if len(csp) > 120 else "")
            csp_lower = csp.lower()
            # Per CSP Level 2/3, browsers ignore 'unsafe-inline' when a nonce, hash, or 'strict-dynamic' is present
            has_csp_guard = any(
                token in csp_lower
                for token in ("'nonce-", "'sha256-", "'sha384-", "'sha512-", "'strict-dynamic'")
            )
            if "unsafe-eval" in csp_lower or ("unsafe-inline" in csp_lower and not has_csp_guard):
                penalty += 5
                contributions.append(make_contribution(
                    "web_security", "weak_csp", "Permissive CSP (unsafe-inline/unsafe-eval)", 5, "low"
                ))
        else:
            missing_headers.append("Content-Security-Policy (CSP)")
            penalty += 15
            contributions.append(make_contribution(
                "web_security", "missing_csp", "Missing Content-Security-Policy (CSP)", 15, "medium"
            ))

        # 3. X-Frame-Options
        xfo = headers_dict.get("x-frame-options")
        if xfo:
            present_headers["X-Frame-Options"] = xfo
        else:
            missing_headers.append("X-Frame-Options (Clickjacking vulnerability)")
            penalty += 10
            contributions.append(make_contribution(
                "web_security", "missing_xfo", "Missing X-Frame-Options header", 10, "low"
            ))

        # 4. X-Content-Type-Options
        xcto = headers_dict.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            present_headers["X-Content-Type-Options"] = xcto
        else:
            missing_headers.append("X-Content-Type-Options (MIME-sniffing risk)")
            penalty += 8
            contributions.append(make_contribution(
                "web_security", "missing_xcto", "Missing X-Content-Type-Options: nosniff", 8, "low"
            ))

        # 5. Referrer-Policy
        rp = headers_dict.get("referrer-policy")
        if rp:
            present_headers["Referrer-Policy"] = rp
        else:
            missing_headers.append("Referrer-Policy")
            penalty += 5
            contributions.append(make_contribution(
                "web_security", "missing_referrer_policy", "Missing Referrer-Policy header", 5, "low"
            ))

        # 6. Permissions-Policy
        pp = headers_dict.get("permissions-policy")
        if pp:
            present_headers["Permissions-Policy"] = pp
        else:
            missing_headers.append("Permissions-Policy")
            penalty += 4
            contributions.append(make_contribution(
                "web_security", "missing_permissions_policy", "Missing Permissions-Policy header", 4, "low"
            ))

        # Calculate Grade
        if penalty <= 5:
            grade = "A+"
        elif penalty <= 15:
            grade = "A"
        elif penalty <= 25:
            grade = "B"
        elif penalty <= 38:
            grade = "C"
        elif penalty <= 50:
            grade = "D"
        else:
            grade = "F"

        return {
            "grade": grade,
            "missing_headers": missing_headers,
            "present_headers": present_headers,
            "hsts_enabled": hsts_enabled,
            "csp_enabled": csp_enabled,
            "headers_fetched": headers_fetched,
            "contributions": contributions,
            "missing_evidence": missing_evidence,
            "penalty": penalty
        }

    def inspect_dns_and_email_security(self, domain: str) -> Dict[str, Any]:
        """Inspect DNS records, SPF, DMARC, and email authentication posture."""
        validate_target_url(f"https://{domain}")

        records: Dict[str, List[str]] = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "TXT": [],
            "NS": []
        }
        spf_record = None
        spf_status = "Not Configured"
        dmarc_record = None
        dmarc_status = "Not Configured"
        dns_penalty = 0
        ip_address = None
        contributions: List[Dict[str, Any]] = []
        missing_evidence: List[Dict[str, Any]] = []

        # Resolve A
        a_ttl: Optional[int] = None
        try:
            answers = self.resolver.resolve(domain, "A")
            if getattr(answers, "rrset", None) is not None:
                a_ttl = getattr(answers.rrset, "ttl", None)
            for rdata in answers:
                ip_val = rdata.to_text().strip()
                if is_private_or_reserved_ip(ip_val):
                    raise SSRFBlockedError(
                        f"Security Policy Violation: Host '{domain}' resolves via A record to private/internal IP '{ip_val}' (SSRF Defense)."
                    )
                records["A"].append(ip_val)
            if records["A"]:
                ip_address = records["A"][0]
        except SSRFBlockedError:
            raise
        except Exception:
            pass

        # Resolve AAAA
        try:
            answers = self.resolver.resolve(domain, "AAAA")
            for rdata in answers:
                ip_val = rdata.to_text().strip()
                if is_private_or_reserved_ip(ip_val):
                    raise SSRFBlockedError(
                        f"Security Policy Violation: Host '{domain}' resolves via AAAA record to private/internal IP '{ip_val}' (SSRF Defense)."
                    )
                records["AAAA"].append(ip_val)
        except SSRFBlockedError:
            raise
        except Exception:
            pass

        # Resolve MX
        try:
            answers = self.resolver.resolve(domain, "MX")
            for rdata in answers:
                records["MX"].append(rdata.to_text())
        except Exception:
            pass

        # Resolve NS
        try:
            answers = self.resolver.resolve(domain, "NS")
            for rdata in answers:
                records["NS"].append(rdata.to_text())
        except Exception:
            pass

        # Resolve TXT and detect SPF
        try:
            answers = self.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt_val = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                records["TXT"].append(txt_val)
                if txt_val.startswith("v=spf1"):
                    spf_record = txt_val
                    if "-all" in txt_val:
                        spf_status = "Hard Fail (-all) [Hardened]"
                    elif "~all" in txt_val:
                        spf_status = "Soft Fail (~all) [Standard]"
                    elif "?all" in txt_val or "+all" in txt_val:
                        spf_status = "Permissive/Insecure (+all/?all)"
                        dns_penalty += 15
                        contributions.append(make_contribution(
                            "web_security", "permissive_spf", "Permissive SPF policy (+all/?all)", 15, "medium"
                        ))
                    else:
                        spf_status = "Active"
        except Exception:
            pass

        # Check DMARC (with RFC 7489 organizational domain fallback for subdomains)
        org_domain = self._registrable_domain(domain)
        is_subdomain = domain != org_domain and domain.endswith("." + org_domain)
        dmarc_candidates = [domain] + ([org_domain] if is_subdomain else [])
        dmarc_inherited = False

        for candidate in dmarc_candidates:
            dmarc_domain = f"_dmarc.{candidate}"
            try:
                answers = self.resolver.resolve(dmarc_domain, "TXT")
                for rdata in answers:
                    txt_val = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                    if txt_val.startswith("v=DMARC1"):
                        dmarc_record = txt_val
                        dmarc_inherited = candidate != domain
                        p_match = re.search(r"(?:^|[;\s])p=([a-zA-Z]+)", txt_val, re.I)
                        sp_match = re.search(r"(?:^|[;\s])sp=([a-zA-Z]+)", txt_val, re.I)
                        eff_policy = (
                            sp_match.group(1).lower()
                            if (dmarc_inherited and sp_match)
                            else (p_match.group(1).lower() if p_match else "")
                        )
                        suffix = " (Inherited)" if dmarc_inherited else ""
                        if eff_policy == "reject":
                            dmarc_status = f"Enforced (p=reject) [Strong]{suffix}"
                        elif eff_policy == "quarantine":
                            dmarc_status = f"Quarantine (p=quarantine) [Moderate]{suffix}"
                        elif eff_policy == "none":
                            dmarc_status = f"Monitor Only (p=none) [No Protection]{suffix}"
                            dns_penalty += 10
                            contributions.append(make_contribution(
                                "web_security", "weak_dmarc", "Weak DMARC policy (p=none monitor only)", 10, "low"
                            ))
                        else:
                            dmarc_status = f"Active{suffix}"
                        break
            except Exception:
                pass
            if dmarc_record:
                break

        # Evaluate SPF result after DMARC so web-only subdomains with parent DMARC protection aren't penalized
        if not spf_record:
            parent_protected = False
            if is_subdomain and not records["MX"]:
                if dmarc_record and ("p=reject" in dmarc_status or "p=quarantine" in dmarc_status):
                    parent_protected = True
                else:
                    try:
                        p_answers = self.resolver.resolve(org_domain, "TXT")
                        for rdata in p_answers:
                            ptxt = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                            if ptxt.startswith("v=spf1"):
                                parent_protected = True
                                break
                    except Exception:
                        pass

            if parent_protected:
                spf_status = "Not Applicable (Web Subdomain; Parent Policy Enforced)"
            else:
                spf_status = "Missing SPF (Domain Spoofable)"
                dns_penalty += 15
                contributions.append(make_contribution(
                    "web_security", "missing_spf", "Missing SPF DNS record", 15, "medium"
                ))

        if not dmarc_record:
            dmarc_status = "Missing DMARC Record"
            dns_penalty += 15
            contributions.append(make_contribution(
                "web_security", "missing_dmarc", "Missing DMARC DNS record", 15, "medium"
            ))

        # Fast-Flux check: multiple IPs dispersed across >= 3 distinct /16 prefixes with low TTL
        fast_flux_detected = False
        distinct_16_prefixes = {".".join(ip.split(".")[:2]) for ip in records["A"] if "." in ip}
        if len(records["A"]) >= 4 and len(distinct_16_prefixes) >= 3 and (a_ttl is None or a_ttl <= 300):
            dns_penalty += 10
            fast_flux_detected = True
            contributions.append(make_contribution(
                "web_security", "fast_flux_dns", f"Fast-flux DNS indicator ({len(records['A'])} A records)", 10, "medium"
            ))

        if not any(records.values()):
            missing_evidence.append(make_missing_evidence(
                "web_security",
                "DNS Record Resolution",
                f"Domain '{domain}' returned no A/AAAA/MX/TXT/NS DNS records",
                impact="medium",
            ))

        return {
            "records": records,
            "ip_address": ip_address,
            "spf_record": spf_record,
            "spf_status": spf_status,
            "dmarc_record": dmarc_record,
            "dmarc_status": dmarc_status,
            "fast_flux_detected": fast_flux_detected,
            "contributions": contributions,
            "missing_evidence": missing_evidence,
            "penalty": dns_penalty
        }

    @classmethod
    def _is_suspicious_redirect_chain(cls, chain: List[Dict[str, Any]]) -> Tuple[bool, int]:
        """Flag multi-hop redirection cloaking (4+ 3xx redirects across distinct domains, or 6+ redirects)."""
        redirect_hops = [h for h in chain if 300 <= int(h.get("status_code", 0) or 0) < 400]
        redirect_count = len(redirect_hops)
        if redirect_count == 0:
            return False, 0
        distinct_roots = {
            cls._registrable_domain(urlparse(h["url"]).hostname or "")
            for h in chain
            if h.get("url") and urlparse(h["url"]).hostname
        }
        if redirect_count >= 6 or (redirect_count >= 4 and len(distinct_roots) > 1):
            return True, redirect_count
        return False, redirect_count

    async def trace_redirections(
        self,
        url: str,
        prefetched: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Trace full HTTP redirection chain safely inside restricted worker with DNS revalidation on every hop."""
        chain: List[Dict[str, Any]] = []
        penalty = 0

        try:
            fetch_data = prefetched
            if fetch_data is None:
                fetch_data = await run_in_restricted_worker(
                    url=url,
                    mode="http",
                    fetch_content=False,
                    fetch_tls=False,
                    user_agent=settings.USER_AGENT,
                )

            chain = list(fetch_data.get("redirect_chain") or [])
            if fetch_data.get("redirect_downgrade"):
                penalty += 30  # Critical security downgrade

            if fetch_data.get("error"):
                chain.append({
                    "hop": len(chain) + 1,
                    "status_code": 0,
                    "url": fetch_data.get("final_url") or url,
                    "error": fetch_data["error"][:60],
                })

            is_suspicious_chain, _ = self._is_suspicious_redirect_chain(chain)
            if is_suspicious_chain:
                penalty += 15  # Multi-hop redirection cloaking
        except SSRFBlockedError:
            raise
        except Exception as e:
            chain.append({"hop": len(chain) + 1, "status_code": 0, "url": url, "error": str(e)[:60]})

        return chain, penalty

    async def evaluate(
        self,
        url: str,
        deep_dns: bool = True,
        prefetched: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Perform comprehensive web security audit."""
        url = validate_target_url(url)
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()

        if prefetched is None:
            prefetched = await run_in_restricted_worker(
                url=url,
                mode="http",
                fetch_content=False,
                fetch_tls=False,
                user_agent=settings.USER_AGENT,
            )

        # Audit security headers
        headers_res = await self.audit_security_headers(url, prefetched=prefetched)

        # Inspect DNS & Email security
        dns_res = {
            "records": {},
            "ip_address": None,
            "spf_record": None,
            "spf_status": "Skipped",
            "dmarc_record": None,
            "dmarc_status": "Skipped",
            "fast_flux_detected": False,
            "contributions": [],
            "missing_evidence": [
                make_missing_evidence(
                    "web_security",
                    "DNS SPF/DMARC & Record Lookup",
                    "Skipped because deep_dns=False",
                    impact="medium",
                )
            ],
            "penalty": 0
        }
        if deep_dns:
            dns_res = self.inspect_dns_and_email_security(domain)

        # Trace redirection chain
        chain, redirect_penalty = await self.trace_redirections(url, prefetched=prefetched)
        redirect_contribs: List[Dict[str, Any]] = []
        if prefetched.get("redirect_downgrade"):
            redirect_contribs.append(make_contribution(
                "web_security", "https_downgrade", "HTTPS-to-HTTP redirect protocol downgrade", 30, "high"
            ))
        is_suspicious_chain, redirect_count = self._is_suspicious_redirect_chain(chain)
        if is_suspicious_chain:
            redirect_contribs.append(make_contribution(
                "web_security", "multi_hop_redirect", f"Multi-hop redirect chain ({redirect_count} redirects)", 15, "medium"
            ))

        # ASN & Geo approximation
        ip_addr = dns_res["ip_address"] or prefetched.get("resolved_ip")
        asn_info = None
        if ip_addr:
            asn_info = f"Host: {ip_addr}"

        contributions = (
            headers_res.get("contributions", [])
            + dns_res.get("contributions", [])
            + redirect_contribs
        )
        missing_evidence = (
            headers_res.get("missing_evidence", [])
            + dns_res.get("missing_evidence", [])
        )

        total_penalty = headers_res["penalty"] + dns_res["penalty"] + redirect_penalty
        score = min(100.0, float(total_penalty))

        return {
            "score": round(score, 1),
            "headers_grade": headers_res["grade"],
            "missing_headers": headers_res["missing_headers"],
            "present_headers": headers_res["present_headers"],
            "hsts_enabled": headers_res["hsts_enabled"],
            "csp_enabled": headers_res["csp_enabled"],
            "dns_records": dns_res["records"],
            "spf_record": dns_res["spf_record"],
            "spf_status": dns_res["spf_status"],
            "dmarc_record": dns_res["dmarc_record"],
            "dmarc_status": dns_res["dmarc_status"],
            "redirect_chain": chain,
            "ip_address": ip_addr,
            "asn_info": asn_info,
            "contributions": contributions,
            "missing_evidence": missing_evidence,
            "details": {
                "fast_flux_detected": dns_res["fast_flux_detected"],
                "headers_fetched": headers_res.get("headers_fetched", False),
                "penalties": {
                    "headers": headers_res["penalty"],
                    "dns": dns_res["penalty"],
                    "redirects": redirect_penalty
                }
            }
        }
