import re
import math
import json
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Optional, Tuple
from lxml import html
from app.config import SEEDS_DIR, settings
from app.core.explainability import make_contribution, make_missing_evidence
from app.core.fetch_worker import run_in_restricted_worker
from app.core.security_guard import SSRFBlockedError

class ThreatAnalyzer:
    _COMMON_WORD_ALIASES = frozenset({"live", "aws", "msn", "dhl", "bofa", "prime", "steam", "chase", "apple", "azure"})
    _GENERIC_LEVENSHTEIN_SKIP = frozenset({"live", "prime", "steam", "chase", "apple", "gmail", "azure"})
    _MULTI_PART_PUBLIC_SUFFIXES = frozenset({"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "com.mx"})

    _OBFUSCATED_JS_RE = re.compile(
        r"(?<![.\w$])eval\s*\("
        r"(?:[^;{}]{0,200}(?:unescape|atob|decodeURIComponent|String\.fromCharCode)\s*\("
        r"|\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k)"
    )
    _CHARCODE_ARRAY_RE = re.compile(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){24,}\d+\s*\)")
    _CONTEXTMENU_LISTENER_RE = re.compile(r"(?:oncontextmenu\s*=|addEventListener\s*\(\s*['\"]contextmenu['\"])")
    _DEVTOOLS_KEY_RE = re.compile(
        r"(?:keyCode\s*===?\s*123|which\s*===?\s*123|key\s*===?\s*['\"]F12['\"]"
        r"|ctrlKey\s*&&\s*shiftKey\s*&&\s*[^;\n]{0,40}(?:73|74|67|['\"][IJCijc]['\"]))"
    )
    _BLOCK_ACTION_RE = re.compile(r"(?:preventDefault\s*\(|return\s+false\b)")

    def __init__(self):
        self.brands = self._load_brands()
        self.homoglyphs, self.leetspeak = self._load_homoglyphs()
        self.suspicious_tlds = self._load_suspicious_tlds()
        
        self.suspicious_keywords = [
            "login", "signin", "sign-in", "log-in", "banking", "verify", "verification",
            "account", "security", "update", "wallet", "token", "password", "support",
            "confirm", "recover", "recovery", "authenticate", "auth", "validation",
            "billing", "invoice", "payment", "secure", "credential", "suspend", "unlock"
        ]

    def _load_brands(self) -> List[Dict[str, Any]]:
        path = SEEDS_DIR / "brand_dictionary.json"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("brands", [])
        return []

    def _load_homoglyphs(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        path = SEEDS_DIR / "homoglyphs.json"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("unicode_lookalikes", {}), data.get("leetspeak", {})
        return {}, {}

    def _load_suspicious_tlds(self) -> Dict[str, Any]:
        path = SEEDS_DIR / "suspicious_tlds.json"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("high_risk_tlds", {})
        return {}

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return round(entropy, 3)

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Compute the Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return ThreatAnalyzer.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    @staticmethod
    def _get_canonical_domains(brand: Dict[str, Any]) -> List[str]:
        """Return all official canonical domains registered for a brand."""
        domains: List[str] = []
        primary = str(brand.get("canonical_domain", "")).strip().lower()
        if primary:
            domains.append(primary)
        for item in brand.get("canonical_domains", []) or []:
            c = str(item).strip().lower()
            if c and c not in domains:
                domains.append(c)
        return domains

    @classmethod
    def _is_official_brand_domain(cls, domain_lower: str, brand: Dict[str, Any]) -> bool:
        """Check whether domain_lower is an official domain or subdomain of brand."""
        for canonical in cls._get_canonical_domains(brand):
            if domain_lower == canonical or domain_lower.endswith("." + canonical):
                return True
        return False

    @classmethod
    def _alias_matches_domain(cls, alias: str, domain_str: str) -> bool:
        """Match brand alias in domain_str, requiring label boundaries for short/common words."""
        if len(alias) <= 4 or alias in cls._COMMON_WORD_ALIASES:
            return bool(re.search(rf"(?:^|[._-]){re.escape(alias)}(?:$|[._-])", domain_str))
        return alias in domain_str

    def check_homoglyphs_and_brands(self, domain: str) -> Tuple[bool, Optional[str], List[str]]:
        """Check for IDN homoglyphs, brand spoofing, and typosquatting."""
        flags = []
        homoglyph_detected = False
        impersonated_brand = None

        domain_lower = domain.lower()
        parts = domain_lower.split(".")

        # Check Punycode
        if "xn--" in domain_lower:
            homoglyph_detected = True
            flags.append("Punycode (IDN) detected: potential Internationalized Domain Name spoofing")
            try:
                decoded = domain_lower.encode('ascii').decode('idna')
                flags.append(f"Decoded IDN representation: '{decoded}'")
            except Exception:
                pass

        # Check Unicode lookalikes
        normalized = ""
        for ch in domain_lower:
            if ch in self.homoglyphs:
                homoglyph_detected = True
                normalized += self.homoglyphs[ch]
            else:
                normalized += ch

        if homoglyph_detected and "Punycode" not in " ".join(flags):
            flags.append(f"Unicode homoglyph characters detected. Normalized to: '{normalized}'")

        # Substitute leetspeak for deeper brand matching
        leetspeak_normalized = normalized
        for k, v in self.leetspeak.items():
            leetspeak_normalized = leetspeak_normalized.replace(k, v)

        # Extract registrable second-level label cleanly (handles e.g. .co.uk)
        if len(parts) >= 3 and ".".join(parts[-2:]) in self._MULTI_PART_PUBLIC_SUFFIXES:
            domain_core = parts[-3]
        elif len(parts) >= 2:
            domain_core = parts[-2]
        else:
            domain_core = parts[0]

        # Check against protected brand list
        for brand in self.brands:
            b_name = brand["name"].lower()

            # Ignore if this is genuinely one of the brand's official domains
            if self._is_official_brand_domain(domain_lower, brand):
                continue

            # Check if brand is in subdomains or misleading domain labels
            for alias in brand.get("aliases", [b_name]):
                alias = alias.lower()
                # Subdomain / domain token abuse e.g. paypal.com.attacker.com
                if self._alias_matches_domain(alias, domain_lower):
                    impersonated_brand = brand["name"]
                    flags.append(f"Brand deception: '{brand['name']}' found in non-official domain '{domain}'")
                    break

                # Levenshtein distance check on normalized domain core (skip short/generic English tokens)
                if alias not in self._GENERIC_LEVENSHTEIN_SKIP:
                    dist = self.levenshtein_distance(domain_core, alias)
                    max_dist = 2 if (len(alias) >= 8 or alias == "amazon") else 1
                    if len(alias) >= 6 and 1 <= dist <= max_dist:
                        impersonated_brand = brand["name"]
                        flags.append(
                            f"Typosquatting detected: '{domain_core}' closely resembles brand '{brand['name']}' (edit distance: {dist})"
                        )
                        break

                # Leetspeak match e.g., paypa1 -> paypal
                if self._alias_matches_domain(alias, leetspeak_normalized) and not self._alias_matches_domain(alias, domain_lower):
                    impersonated_brand = brand["name"]
                    flags.append(f"Leetspeak typosquatting detected for '{brand['name']}' in '{domain}'")
                    break

            if impersonated_brand:
                break

        return homoglyph_detected, impersonated_brand, flags

    def analyze_lexical_url(self, raw_url: str) -> Dict[str, Any]:
        """Perform comprehensive lexical, entropy, and structural analysis of the URL."""
        if not raw_url.startswith(("http://", "https://")):
            raw_url = "https://" + raw_url

        parsed = urlparse(raw_url)
        domain = (parsed.hostname or parsed.netloc.split(":")[0]).lower()
        path = parsed.path
        query = parsed.query

        lexical_flags = []
        contributions: List[Dict[str, Any]] = []
        score_penalty = 0

        # Check IP-based URLs
        is_ip_domain = False
        ip_v4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_v4_pattern, domain):
            is_ip_domain = True
            lexical_flags.append(f"Direct IP address used as hostname ({domain}) - common evasion tactic")
            score_penalty += 35
            contributions.append(make_contribution(
                "threat_analysis", "direct_ip_hostname", "Direct IP address hostname", 35, "high", domain
            ))

        # Check Hex/Octal IP encoding
        if re.match(r"^0x[0-9a-fA-F]+", domain) or re.match(r"^0[0-7]+", domain):
            is_ip_domain = True
            lexical_flags.append("Obfuscated Hex/Octal IP address used in host")
            score_penalty += 45
            contributions.append(make_contribution(
                "threat_analysis", "obfuscated_ip_hostname", "Obfuscated Hex/Octal IP hostname", 45, "critical", domain
            ))

        # Check Suspicious TLD
        tld = domain.split(".")[-1] if "." in domain else ""
        suspicious_tld_match = None
        if tld in self.suspicious_tlds:
            info = self.suspicious_tlds[tld]
            suspicious_tld_match = f".{tld}"
            weight = info["risk_weight"]
            lexical_flags.append(f"High-risk TLD '.{tld}': {info['reason']}")
            score_penalty += weight
            contributions.append(make_contribution(
                "threat_analysis", "suspicious_tld", f"High-risk TLD (.{tld})", weight, "medium", info["reason"]
            ))

        # Shannon Entropy
        domain_entropy = self.calculate_entropy(domain)
        path_entropy = self.calculate_entropy(path)
        if domain_entropy > 3.8:
            lexical_flags.append(f"High domain entropy ({domain_entropy}) - suggests DGA or randomized domain")
            score_penalty += 20
            contributions.append(make_contribution(
                "threat_analysis", "high_domain_entropy", "High domain entropy (DGA/random pattern)", 20, "medium",
                f"entropy={domain_entropy}"
            ))
        if path_entropy > 4.2 and len(path) > 15:
            lexical_flags.append(f"High path entropy ({path_entropy}) - possible obfuscation or kit payload")
            score_penalty += 15
            contributions.append(make_contribution(
                "threat_analysis", "high_path_entropy", "High URL path entropy", 15, "medium",
                f"entropy={path_entropy}"
            ))

        # Suspicious Characters & Depth
        if "@" in raw_url:
            lexical_flags.append("URL contains '@' character - often used to conceal true destination")
            score_penalty += 30
            contributions.append(make_contribution(
                "threat_analysis", "at_symbol_in_url", "Deceptive '@' character in URL", 30, "high"
            ))

        hyphen_count = domain.count("-")
        if hyphen_count >= 3:
            lexical_flags.append(f"Excessive hyphens in domain ({hyphen_count} hyphens) - classic phishing domain syntax")
            score_penalty += 15
            contributions.append(make_contribution(
                "threat_analysis", "excessive_hyphens", f"Excessive hyphens in domain ({hyphen_count})", 15, "low"
            ))

        subdomain_depth = len(domain.split(".")) - 2
        if subdomain_depth >= 3:
            lexical_flags.append(f"Excessive subdomain nesting (depth: {subdomain_depth})")
            score_penalty += 15
            contributions.append(make_contribution(
                "threat_analysis", "deep_subdomain_nesting", f"Excessive subdomain nesting (depth {subdomain_depth})", 15, "medium"
            ))

        if len(raw_url) > 90:
            lexical_flags.append(f"Unusually long URL ({len(raw_url)} characters) - typical of phishing links")
            score_penalty += 10
            contributions.append(make_contribution(
                "threat_analysis", "long_url", f"Unusually long URL ({len(raw_url)} chars)", 10, "low"
            ))

        # Keywords in URL
        matched_keywords = [kw for kw in self.suspicious_keywords if kw in raw_url.lower()]
        if len(matched_keywords) >= 2:
            kw_pts = min(25, len(matched_keywords) * 8)
            lexical_flags.append(f"Multiple security/auth lure keywords found: {', '.join(matched_keywords[:4])}")
            score_penalty += kw_pts
            contributions.append(make_contribution(
                "threat_analysis", "lure_keywords", "Security/authentication lure keywords", kw_pts, "medium",
                ", ".join(matched_keywords[:4])
            ))
        elif len(matched_keywords) == 1:
            score_penalty += 5
            contributions.append(make_contribution(
                "threat_analysis", "lure_keyword_single", f"Auth lure keyword '{matched_keywords[0]}'", 5, "low",
                matched_keywords[0]
            ))

        # Open Redirect Parameter check
        redirect_params = ["url", "redirect", "next", "dest", "target", "r", "link", "out"]
        parsed_qs = parse_qs(query)
        for param in redirect_params:
            if param in parsed_qs:
                target_val = parsed_qs[param][0]
                if target_val.startswith(("http://", "https://", "//")):
                    lexical_flags.append(f"Potential Open Redirect parameter identified: '{param}={target_val}'")
                    score_penalty += 20
                    contributions.append(make_contribution(
                        "threat_analysis", "open_redirect_param", f"Open redirect parameter '{param}'", 20, "medium",
                        target_val[:80]
                    ))
                    break

        # Homoglyphs and Brand checks
        homoglyph, brand, brand_flags = self.check_homoglyphs_and_brands(domain)
        lexical_flags.extend(brand_flags)
        if homoglyph:
            score_penalty += 35
            contributions.append(make_contribution(
                "threat_analysis", "homoglyph_detected", "Homoglyph / Punycode spoofing detected", 35, "high", domain
            ))
        if brand:
            score_penalty += 45
            contributions.append(make_contribution(
                "threat_analysis", "brand_impersonation", f"Brand impersonation ({brand})", 45, "critical", domain
            ))

        return {
            "target_url": raw_url,
            "domain": domain,
            "path": path,
            "domain_entropy": domain_entropy,
            "path_entropy": path_entropy,
            "is_ip_domain": is_ip_domain,
            "suspicious_tld": suspicious_tld_match,
            "homoglyph_detected": homoglyph,
            "impersonated_brand": brand,
            "lexical_flags": lexical_flags,
            "contributions": contributions,
            "raw_penalty": score_penalty
        }

    async def inspect_live_content(
        self,
        url: str,
        domain: str,
        prefetched: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Safely fetch and inspect DOM, forms, deceptive inputs, and script behaviors via restricted worker."""
        content_flags = []
        contributions: List[Dict[str, Any]] = []
        missing_evidence: List[Dict[str, Any]] = []
        has_password_input = False
        has_cross_origin_form = False
        content_fetch_failed = False
        content_truncated = False
        content_empty = False
        penalty = 0

        try:
            fetch_data = prefetched
            if fetch_data is None:
                fetch_data = await run_in_restricted_worker(
                    url=url,
                    mode="http",
                    fetch_content=True,
                    fetch_tls=False,
                    user_agent=settings.USER_AGENT,
                )

            if fetch_data.get("error"):
                content_fetch_failed = True
                err_msg = fetch_data["error"][:120]
                content_flags.append(f"Live content fetch note: {fetch_data['error'][:90]}")
                missing_evidence.append(make_missing_evidence(
                    "threat_analysis",
                    "Live DOM & Form Inspection",
                    f"Live HTTP content could not be fetched ({err_msg})",
                    impact="high",
                ))

            if fetch_data.get("truncated"):
                content_truncated = True
                bytes_read = fetch_data.get("bytes_read", 0)
                content_flags.append(
                    f"Live content truncated at {bytes_read} bytes (response-size limit)"
                )
                missing_evidence.append(make_missing_evidence(
                    "threat_analysis",
                    "Full HTML Body Inspection",
                    f"Response truncated at {bytes_read} bytes due to size limit",
                    impact="low",
                ))

            html_text = fetch_data.get("body_text", "")
            effective_domain = (urlparse(fetch_data.get("final_url") or url).hostname or domain).lower()

            if html_text and html_text.strip():
                parser = html.HTMLParser(recover=True, collect_ids=False, no_network=True)
                tree = html.fromstring(html_text, parser=parser)
            else:
                tree = None
                if not content_fetch_failed:
                    content_empty = True
                    missing_evidence.append(make_missing_evidence(
                        "threat_analysis",
                        "HTML DOM Parsing",
                        "Target returned an empty or non-HTML response body",
                        impact="medium",
                    ))

            if tree is not None:
                # Check forms
                forms = tree.xpath("//form")
                password_inputs = tree.xpath("//input[@type='password']")
                if len(password_inputs) > 0:
                    has_password_input = True
                    content_flags.append(f"Credential entry form detected ({len(password_inputs)} password field(s))")
                    penalty += 15
                    contributions.append(make_contribution(
                        "threat_analysis",
                        "password_form",
                        f"Credential entry password form ({len(password_inputs)} field(s))",
                        15,
                        "high",
                    ))

                # Form Action verification
                for form in forms:
                    action = form.get("action", "").strip()
                    if action:
                        if action.startswith(("http://", "https://")):
                            action_domain = (urlparse(action).hostname or "").lower()
                            if (
                                action_domain
                                and action_domain != effective_domain
                                and not effective_domain.endswith("." + action_domain)
                            ):
                                has_cross_origin_form = True
                                content_flags.append(
                                    f"Critical: Form action posts credentials to disparate domain '{action_domain}'"
                                )
                                penalty += 40
                                contributions.append(make_contribution(
                                    "threat_analysis",
                                    "cross_origin_form",
                                    f"Cross-origin form submission to '{action_domain}'",
                                    40,
                                    "critical",
                                    action_domain,
                                ))
                                break
                        elif action.startswith("mailto:"):
                            content_flags.append(f"Phishing trap: Form action posts to email '{action}'")
                            penalty += 35
                            contributions.append(make_contribution(
                                "threat_analysis",
                                "mailto_form_trap",
                                "Form posts data directly to mailto: address",
                                35,
                                "high",
                                action[:60],
                            ))

                # Obfuscated Scripts & Traps (evaluate per <script> tag to avoid cross-script false positives)
                script_texts = tree.xpath("//script/text()")
                obfuscated_found = any(
                    self._OBFUSCATED_JS_RE.search(s) or self._CHARCODE_ARRAY_RE.search(s)
                    for s in script_texts
                )
                if obfuscated_found:
                    content_flags.append("Obfuscated JavaScript detected (eval + dynamic decoding patterns)")
                    penalty += 25
                    contributions.append(make_contribution(
                        "threat_analysis",
                        "obfuscated_js",
                        "Obfuscated JavaScript (eval + dynamic decoding)",
                        25,
                        "high",
                    ))

                has_inline_ctx_block = any(
                    "return false" in (el.get("oncontextmenu") or "").lower()
                    or "preventdefault" in (el.get("oncontextmenu") or "").lower()
                    for el in tree.xpath("//*[@oncontextmenu]")
                )
                anti_analysis_found = has_inline_ctx_block or any(
                    (self._CONTEXTMENU_LISTENER_RE.search(s) or self._DEVTOOLS_KEY_RE.search(s))
                    and self._BLOCK_ACTION_RE.search(s)
                    for s in script_texts
                )
                if anti_analysis_found:
                    content_flags.append("Anti-analysis technique: Page disables right-click or F12 developer inspection")
                    penalty += 20
                    contributions.append(make_contribution(
                        "threat_analysis",
                        "anti_analysis_js",
                        "Anti-analysis script disables right-click or DevTools",
                        20,
                        "medium",
                    ))

                # Page title and brand spoofing inside body
                titles = tree.xpath("//title/text()")
                page_title = titles[0].strip() if titles else ""
                if page_title:
                    for brand in self.brands:
                        b_name = brand["name"].lower()
                        if b_name in page_title.lower() and not self._is_official_brand_domain(effective_domain, brand):
                            content_flags.append(
                                f"Deceptive page title '{page_title}' claims identity of '{brand['name']}' on non-official domain"
                            )
                            penalty += 30
                            contributions.append(make_contribution(
                                "threat_analysis",
                                "deceptive_page_title",
                                f"Deceptive page title claims '{brand['name']}'",
                                30,
                                "high",
                                page_title[:80],
                            ))
                            break

                # Hidden zero-size iframes
                iframes = tree.xpath("//iframe")
                for iframe in iframes:
                    style = iframe.get("style", "").lower()
                    width = iframe.get("width", "")
                    height = iframe.get("height", "")
                    if "display:none" in style or "visibility:hidden" in style or width in ("0", "1") or height in ("0", "1"):
                        content_flags.append("Hidden or zero-sized iframe detected (common in drive-by downloads / clickjacking)")
                        penalty += 20
                        contributions.append(make_contribution(
                            "threat_analysis",
                            "hidden_iframe",
                            "Hidden or zero-sized iframe detected",
                            20,
                            "medium",
                        ))
                        break

        except SSRFBlockedError:
            raise
        except Exception as e:
            # Domain could be offline, blocked, or timed out
            content_fetch_failed = True
            content_flags.append(f"Live content fetch note: {str(e)[:90]}")
            missing_evidence.append(make_missing_evidence(
                "threat_analysis",
                "Live DOM & Form Inspection",
                f"Live content inspection failed ({str(e)[:90]})",
                impact="high",
            ))

        return {
            "has_password_input": has_password_input,
            "has_cross_origin_form": has_cross_origin_form,
            "content_flags": content_flags,
            "contributions": contributions,
            "missing_evidence": missing_evidence,
            "content_fetch_failed": content_fetch_failed,
            "content_truncated": content_truncated,
            "content_empty": content_empty,
            "content_penalty": penalty
        }

    async def evaluate(
        self,
        url: str,
        fetch_content: bool = True,
        prefetched: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Combine lexical, structural, and live content inspection into a threat analysis score."""
        lexical = self.analyze_lexical_url(url)
        content_res = {
            "has_password_input": False,
            "has_cross_origin_form": False,
            "content_flags": [],
            "contributions": [],
            "missing_evidence": [],
            "content_fetch_failed": False,
            "content_truncated": False,
            "content_empty": False,
            "content_penalty": 0
        }

        if fetch_content:
            content_res = await self.inspect_live_content(
                lexical["target_url"],
                lexical["domain"],
                prefetched=prefetched,
            )
        else:
            content_res["missing_evidence"].append(make_missing_evidence(
                "threat_analysis",
                "Live DOM & Form Inspection",
                "Skipped because fetch_content=False",
                impact="high",
            ))

        contributions = lexical["contributions"] + content_res["contributions"]
        missing_evidence = content_res["missing_evidence"]
        total_penalty = lexical["raw_penalty"] + content_res["content_penalty"]
        # Normalize score between 0 and 100
        score = min(100.0, float(total_penalty))

        return {
            "score": round(score, 1),
            "entropy": lexical["domain_entropy"],
            "path_entropy": lexical["path_entropy"],
            "is_ip_domain": lexical["is_ip_domain"],
            "suspicious_tld": lexical["suspicious_tld"],
            "homoglyph_detected": lexical["homoglyph_detected"],
            "impersonated_brand": lexical["impersonated_brand"],
            "lexical_flags": lexical["lexical_flags"],
            "content_flags": content_res["content_flags"],
            "has_password_input": content_res["has_password_input"],
            "has_cross_origin_form": content_res["has_cross_origin_form"],
            "contributions": contributions,
            "missing_evidence": missing_evidence,
            "details": {
                "domain": lexical["domain"],
                "path": lexical["path"],
                "content_fetch_failed": content_res["content_fetch_failed"],
                "content_truncated": content_res["content_truncated"],
                "content_empty": content_res["content_empty"],
                "raw_penalties": {
                    "lexical": lexical["raw_penalty"],
                    "content": content_res["content_penalty"]
                }
            }
        }
