import uuid
import asyncio
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, List

from app.config import settings
from app.core.threat_analyzer import ThreatAnalyzer
from app.core.security_assessor import SecurityAssessor
from app.core.cert_validator import CertificateValidator
from app.core.threat_intel import ThreatIntelHub
from app.core.explainability import (
    build_explainable_breakdown,
    compute_engine_confidences,
    compute_overall_confidence,
)
from app.core.concurrency import bounded_scan_slot
from app.core.observability import metrics
from app.core.security_guard import SSRFBlockedError, validate_target_url
from app.core.fetch_worker import run_in_restricted_worker
from app.core.mitre_mapper import MitreAttackMapper
from app.models.database import save_scan, add_ioc

class ScoringEngine:
    def __init__(self):
        self.threat_analyzer = ThreatAnalyzer()
        self.security_assessor = SecurityAssessor()
        self.cert_validator = CertificateValidator()
        self.threat_intel = ThreatIntelHub()

    async def execute_scan(
        self,
        url: str,
        fetch_content: bool = True,
        deep_dns: bool = True,
        refresh_intel: bool = False,
    ) -> Dict[str, Any]:
        """Orchestrate all 4 security engines under strict SSRF controls and bounded concurrency."""
        started = time.perf_counter()
        try:
            url = validate_target_url(url)
        except SSRFBlockedError:
            metrics.record_ssrf_block()
            raise

        async with bounded_scan_slot():
            try:
                report = await self._execute_scan_impl(
                    url=url,
                    fetch_content=fetch_content,
                    deep_dns=deep_dns,
                    refresh_intel=refresh_intel,
                )
            except SSRFBlockedError:
                metrics.record_ssrf_block()
                raise
            except Exception:
                metrics.record_scan_error()
                raise

        metrics.record_scan(
            report.get("verdict", "UNKNOWN"),
            (time.perf_counter() - started) * 1000.0,
        )
        return report

    async def _execute_scan_impl(
        self,
        url: str,
        fetch_content: bool = True,
        deep_dns: bool = True,
        refresh_intel: bool = False,
    ) -> Dict[str, Any]:
        """Execute bounded multi-engine evaluation for a pre-validated target URL."""
        url = validate_target_url(url)

        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        needs_tls = not (parsed.scheme == "http" and port == 80)

        scan_id = f"SCN-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Perform untrusted URL & TLS fetching once inside the OS-isolated restricted worker
        prefetched_bundle = await run_in_restricted_worker(
            url=url,
            mode="bundle",
            fetch_content=fetch_content,
            fetch_tls=needs_tls,
            user_agent=settings.USER_AGENT,
        )

        # Run all 4 evaluations using the safely fetched bundle
        threat_res = await self.threat_analyzer.evaluate(
            url,
            fetch_content=fetch_content,
            prefetched=prefetched_bundle,
        )
        sec_res = await self.security_assessor.evaluate(
            url,
            deep_dns=deep_dns,
            prefetched=prefetched_bundle,
        )
        cert_res = await asyncio.to_thread(
            self.cert_validator.validate_certificate,
            url,
            prefetched=prefetched_bundle,
        )
        intel_res = await self.threat_intel.evaluate(
            url,
            ip_address=sec_res.get("ip_address"),
            refresh=refresh_intel,
        )

        # Baseline weighted composite calculation
        w_threat = settings.WEIGHT_THREAT_ANALYSIS
        w_sec = settings.WEIGHT_WEB_SECURITY
        w_cert = settings.WEIGHT_CERT_VALIDATION
        w_intel = settings.WEIGHT_THREAT_INTEL

        base_composite = (
            (threat_res["score"] * w_threat) +
            (sec_res["score"] * w_sec) +
            (cert_res["score"] * w_cert) +
            (intel_res["score"] * w_intel)
        )
        composite = base_composite

        # Correlation & Amplification Heuristics
        amplification_hits = []
        # 1. Threat Intel confirmed feed hit -> Immediate Critical Malicious override
        if intel_res["feed_hits"]:
            composite = max(composite, 92.0)
            amplification_hits.append((
                "Correlation Amplification: Confirmed threat intelligence match",
                92.0,
                ", ".join(intel_res["feed_hits"][:2]),
            ))

        # 2. Homoglyph or brand impersonation + credential input form -> Classic Phishing Kit
        if (threat_res["homoglyph_detected"] or threat_res["impersonated_brand"]) and threat_res["has_password_input"]:
            composite = max(composite, 88.0)
            amplification_hits.append((
                "Correlation Amplification: Impersonation + credential password form",
                88.0,
                threat_res.get("impersonated_brand") or "Homoglyph spoofing",
            ))

        # 3. Form action posts credentials to cross-origin server
        if threat_res["has_cross_origin_form"]:
            composite = max(composite, 90.0)
            amplification_hits.append((
                "Correlation Amplification: Cross-origin credential exfiltration form",
                90.0,
                "Credential form submits to external domain",
            ))

        # 4. Brand spoofing + newly minted SSL cert (< 3 days)
        if threat_res["impersonated_brand"] and (cert_res.get("age_days") is not None and cert_res["age_days"] < 3):
            composite = max(composite, 85.0)
            amplification_hits.append((
                "Correlation Amplification: Brand spoofing with newly issued cert (<72h)",
                85.0,
                f"{threat_res['impersonated_brand']} + {cert_res['age_days']}d cert",
            ))

        composite = min(100.0, round(composite, 1))

        # Explainability: engine confidences, missing evidence, and reconciled score breakdown
        weights_map = {
            "threat_analysis": w_threat,
            "web_security": w_sec,
            "cert_validation": w_cert,
            "threat_intel": w_intel,
        }
        engine_meta = compute_engine_confidences(
            threat_res=threat_res,
            sec_res=sec_res,
            cert_res=cert_res,
            intel_res=intel_res,
            fetch_content=fetch_content,
            deep_dns=deep_dns,
        )
        missing_evidence = (
            list(threat_res.get("missing_evidence") or [])
            + list(sec_res.get("missing_evidence") or [])
            + list(cert_res.get("missing_evidence") or [])
            + list(intel_res.get("missing_evidence") or [])
        )
        confidence, confidence_level, confidence_reason = compute_overall_confidence(
            engine_meta=engine_meta,
            weights=weights_map,
            threat_res=threat_res,
            sec_res=sec_res,
            cert_res=cert_res,
            intel_res=intel_res,
            missing_evidence=missing_evidence,
        )

        engine_specs = [
            ("threat_analysis", "Heuristic Threat Analyzer", threat_res, w_threat, *engine_meta["threat_analysis"]),
            ("web_security", "Web Security Posture Assessor", sec_res, w_sec, *engine_meta["web_security"]),
            ("cert_validation", "SSL/TLS Certificate Validator", cert_res, w_cert, *engine_meta["cert_validation"]),
            ("threat_intel", "Collaborative Threat Intel Hub", intel_res, w_intel, *engine_meta["threat_intel"]),
        ]
        score_breakdown, engine_scores = build_explainable_breakdown(
            engine_specs=engine_specs,
            amplification_hits=amplification_hits,
            base_composite=base_composite,
            final_score=composite,
        )

        # Propagate weighted points back onto per-engine contributions for consistency
        engine_map = {e["engine"]: e for e in engine_scores}
        threat_res["contributions"] = engine_map["threat_analysis"]["contributions"]
        sec_res["contributions"] = engine_map["web_security"]["contributions"]
        cert_res["contributions"] = engine_map["cert_validation"]["contributions"]
        intel_res["contributions"] = engine_map["threat_intel"]["contributions"]

        # Determine Verdict
        if composite >= settings.RISK_THRESHOLD_HIGH:
            verdict = "MALICIOUS"
            verdict_color = "rose"
        elif composite >= settings.RISK_THRESHOLD_SUSPICIOUS:
            verdict = "HIGH_RISK"
            verdict_color = "orange"
        elif composite >= settings.RISK_THRESHOLD_BENIGN:
            verdict = "SUSPICIOUS"
            verdict_color = "amber"
        else:
            verdict = "BENIGN"
            verdict_color = "emerald"

        # Generate Mitigations
        mitigations = self._generate_mitigations(verdict, threat_res, sec_res, cert_res, intel_res, domain)

        # Generate Executive Summary
        summary = self._generate_summary(verdict, composite, threat_res, sec_res, cert_res, intel_res, domain)

        report = {
            "scan_id": scan_id,
            "target_url": url,
            "target_domain": domain,
            "timestamp": timestamp,
            "overall_score": composite,
            "verdict": verdict,
            "verdict_color": verdict_color,
            "summary": summary,
            "confidence": confidence,
            "confidence_level": confidence_level,
            "confidence_reason": confidence_reason,
            "score_breakdown": score_breakdown,
            "engine_scores": engine_scores,
            "missing_evidence": missing_evidence,
            "threat_analysis": threat_res,
            "web_security": sec_res,
            "cert_validation": cert_res,
            "threat_intel": intel_res,
            "mitigations": mitigations
        }
        report["mitre_attack"] = MitreAttackMapper().build_investigation_report(
            scans=[report],
            context_label=f"URL Scan: {domain}",
            source_id=scan_id,
        )

        # Save to database
        save_scan(report)

        # Collaborative learning: If evaluated as MALICIOUS, automatically record to IoC database
        if verdict == "MALICIOUS":
            tags = ["#automated_detection"]
            if threat_res["impersonated_brand"]:
                tags.append(f"#{threat_res['impersonated_brand'].lower().replace(' ', '_')}")
            if threat_res["has_password_input"]:
                tags.append("#credential_stealer")
            if threat_res["has_cross_origin_form"]:
                tags.append("#cross_origin_exfil")
            
            add_ioc(
                indicator=url,
                indicator_type="url",
                tags=tags,
                source="PhishPulse Engine",
                confidence=composite,
                notes=f"Automated detection: {summary[:120]}"
            )

        return report

    def _generate_summary(self, verdict: str, score: float, threat: Dict, sec: Dict, cert: Dict, intel: Dict, domain: str) -> str:
        if verdict == "MALICIOUS":
            reasons = []
            if intel.get("feed_hits"):
                reasons.append(f"listed in {', '.join(intel['feed_hits'])}")
            if threat.get("impersonated_brand"):
                reasons.append(f"actively impersonating {threat['impersonated_brand']}")
            if threat.get("has_cross_origin_form"):
                reasons.append("harvesting credentials to an external host")
            if cert.get("san_mismatch"):
                reasons.append("presenting a mismatched SSL certificate")
            reason_str = ", ".join(reasons) if reasons else "multiple severe threat signals detected"
            return f"MALICIOUS PHISHING DETECTED (Score {score}/100): Target '{domain}' presents a critical threat due to {reason_str}."

        elif verdict == "HIGH_RISK":
            return f"HIGH RISK WEBSITE (Score {score}/100): Domain '{domain}' exhibits suspicious characteristics including {len(threat.get('lexical_flags', []))} URL anomalies and weak security configurations."

        elif verdict == "SUSPICIOUS":
            return f"SUSPICIOUS POSTURE (Score {score}/100): Domain '{domain}' lacks standard security headers (Grade: {sec.get('headers_grade')}) and email SPF/DMARC protections."

        return f"CLEAN & BENIGN (Score {score}/100): Domain '{domain}' displays normal infrastructure posture, valid certificates, and clean threat intelligence."

    def _generate_mitigations(self, verdict: str, threat: Dict, sec: Dict, cert: Dict, intel: Dict, domain: str) -> List[str]:
        mitigations = []
        if verdict in ("MALICIOUS", "HIGH_RISK"):
            mitigations.append(f"Block domain '{domain}' on enterprise perimeter firewalls, proxies, and DNS sinkholes.")
            mitigations.append("Export and ingest the STIX 2.1 IoC bundle into your SIEM/EDR platform.")
            if threat.get("has_password_input"):
                mitigations.append("Force password reset and invalidate active sessions for any employee who visited this URL.")
            mitigations.append(f"Submit registrar and host takedown requests for abuse on '{domain}'.")
        else:
            if not sec.get("hsts_enabled"):
                mitigations.append("Enable HTTP Strict Transport Security (HSTS) with max-age >= 31536000 and includeSubDomains.")
            if not sec.get("csp_enabled"):
                mitigations.append("Deploy a Content-Security-Policy (CSP) to mitigate cross-site scripting and unauthorized script loading.")
            if "Missing" in sec.get("spf_status", ""):
                mitigations.append(f"Configure SPF DNS TXT record on '{domain}' to prevent email sender spoofing.")
            if "Missing" in sec.get("dmarc_status", "") or "none" in sec.get("dmarc_status", ""):
                mitigations.append("Deploy and enforce DMARC with 'p=reject' or 'p=quarantine'.")

        return mitigations
