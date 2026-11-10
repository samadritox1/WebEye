import base64
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID
from app.core.explainability import make_contribution, make_missing_evidence
from app.core.fetch_worker import run_in_restricted_worker_sync
from app.core.security_guard import SSRFBlockedError, validate_target_url

class CertificateValidator:
    def __init__(self):
        self.automated_cas = [
            "let's encrypt", "zerossl", "cpanel", "cloudflare", "buypass go ssl", "sectigo free"
        ]

    def _matches_san(self, domain: str, san_list: List[str]) -> bool:
        """Check if domain matches any SAN entry (including wildcard support)."""
        domain = domain.lower()
        for san in san_list:
            san = san.lower()
            if san == domain:
                return True
            if san.startswith("*."):
                suffix = san[1:]  # e.g., .example.com
                if domain.endswith(suffix) and domain.count(".") == san.count("."):
                    return True
        return False

    def validate_certificate(
        self,
        target: str,
        prefetched: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Perform deep TLS handshake inside restricted worker, X.509 extraction, and risk profiling."""
        target = validate_target_url(target)

        parsed = urlparse(target)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port or (80 if parsed.scheme == "http" else 443)

        flags: List[str] = []
        contributions: List[Dict[str, Any]] = []
        missing_evidence: List[Dict[str, Any]] = []
        penalty = 0

        # If HTTP URL explicitly provided
        if parsed.scheme == "http" and port == 80:
            flags.append("Insecure plain HTTP connection: No TLS encryption present")
            contributions.append(make_contribution(
                "cert_validation", "plain_http_no_tls", "Insecure plain HTTP (no TLS encryption)", 65.0, "high"
            ))
            missing_evidence.append(make_missing_evidence(
                "cert_validation",
                "X.509 Certificate Inspection",
                "Target uses unencrypted HTTP (no TLS certificate presented)",
                impact="medium",
            ))
            return {
                "score": 65.0,
                "valid": False,
                "issuer": "None (Unencrypted HTTP)",
                "subject": "None",
                "san_domains": [],
                "not_before": None,
                "not_after": None,
                "age_days": None,
                "days_until_expiry": None,
                "is_free_automated_ca": False,
                "is_wildcard": False,
                "san_mismatch": True,
                "signature_algorithm": None,
                "tls_version": None,
                "flags": flags,
                "contributions": contributions,
                "missing_evidence": missing_evidence,
                "details": {"error": "Target does not use SSL/TLS"}
            }

        der_cert = None
        tls_version = None
        cipher_name = None

        try:
            tls_info = prefetched
            if tls_info is None:
                tls_info = run_in_restricted_worker_sync(
                    url=target,
                    mode="tls",
                    fetch_content=False,
                    fetch_tls=True,
                )

            tls_version = tls_info.get("tls_version")
            cipher_name = tls_info.get("tls_cipher")
            tls_error = tls_info.get("tls_error")
            der_b64 = tls_info.get("tls_cert_der_b64") or tls_info.get("der_cert_b64")

            if tls_error and not der_b64:
                raise RuntimeError(tls_error)
            if der_b64:
                der_cert = base64.b64decode(der_b64)
        except SSRFBlockedError:
            raise
        except Exception as e:
            err_str = str(e)[:80]
            flags.append(f"TLS handshake failed: {err_str}")
            contributions.append(make_contribution(
                "cert_validation", "tls_handshake_failed", "TLS handshake failed or unreachable", 50.0, "medium", err_str
            ))
            missing_evidence.append(make_missing_evidence(
                "cert_validation",
                "TLS / X.509 Certificate Validation",
                f"TLS handshake failed ({err_str})",
                impact="high",
            ))
            return {
                "score": 50.0,
                "valid": False,
                "issuer": None,
                "subject": None,
                "san_domains": [],
                "not_before": None,
                "not_after": None,
                "age_days": None,
                "days_until_expiry": None,
                "is_free_automated_ca": False,
                "is_wildcard": False,
                "san_mismatch": False,
                "signature_algorithm": None,
                "tls_version": None,
                "flags": flags,
                "contributions": contributions,
                "missing_evidence": missing_evidence,
                "details": {"handshake_error": str(e)}
            }

        if not der_cert:
            flags.append("No peer certificate presented")
            contributions.append(make_contribution(
                "cert_validation", "no_peer_cert", "No X.509 peer certificate presented", 50.0, "high"
            ))
            missing_evidence.append(make_missing_evidence(
                "cert_validation",
                "TLS / X.509 Certificate Validation",
                "Server presented no peer certificate",
                impact="high",
            ))
            return {
                "score": 50.0,
                "valid": False,
                "issuer": None,
                "subject": None,
                "san_domains": [],
                "not_before": None,
                "not_after": None,
                "age_days": None,
                "days_until_expiry": None,
                "is_free_automated_ca": False,
                "is_wildcard": False,
                "san_mismatch": False,
                "signature_algorithm": None,
                "tls_version": tls_version,
                "flags": flags,
                "contributions": contributions,
                "missing_evidence": missing_evidence,
                "details": {"handshake_error": "No peer certificate presented"}
            }

        try:
            cert = x509.load_der_x509_certificate(der_cert)
        except Exception as e:
            err_str = str(e)[:60]
            flags.append(f"Failed to parse X.509 certificate: {err_str}")
            contributions.append(make_contribution(
                "cert_validation", "cert_parse_error", "Malformed X.509 certificate", 40.0, "medium", err_str
            ))
            missing_evidence.append(make_missing_evidence(
                "cert_validation",
                "X.509 Certificate Parsing",
                f"Certificate could not be parsed ({err_str})",
                impact="high",
            ))
            return {
                "score": 40.0,
                "valid": False,
                "flags": flags,
                "contributions": contributions,
                "missing_evidence": missing_evidence,
                "details": {"handshake_error": err_str}
            }

        # Subject and Issuer
        subject_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        subject_cn = subject_attrs[0].value if subject_attrs else "Unknown"

        issuer_org_attrs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        issuer_cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)

        issuer_org = issuer_org_attrs[0].value if issuer_org_attrs else ""
        issuer_cn = issuer_cn_attrs[0].value if issuer_cn_attrs else ""
        issuer_str = f"{issuer_org} ({issuer_cn})" if issuer_org and issuer_cn else (issuer_org or issuer_cn or "Unknown")

        # Check self-signed
        is_self_signed = (cert.subject == cert.issuer)
        if is_self_signed:
            flags.append("Self-signed certificate detected: untrusted authority")
            penalty += 45
            contributions.append(make_contribution(
                "cert_validation", "self_signed_cert", "Self-signed untrusted SSL certificate", 45, "high"
            ))

        # Automated Free CA profiling
        is_free_automated_ca = any(ca in issuer_str.lower() for ca in self.automated_cas)
        if is_free_automated_ca:
            flags.append(f"Automated / Free Certificate Authority ({issuer_str}) - heavily leveraged in disposable phishing kits")
            # Automated CAs alone add a minor bump, amplified when combined with young certs
            penalty += 10
            contributions.append(make_contribution(
                "cert_validation", "automated_free_ca", f"Automated/Free CA ({issuer_str})", 10, "low"
            ))

        # SAN Domains
        san_domains: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_domains = [str(name) for name in san_ext.value.get_values_for_type(x509.DNSName)]
        except Exception:
            pass

        # Check SAN Mismatch
        san_mismatch = False
        if san_domains:
            if not self._matches_san(hostname, san_domains):
                san_mismatch = True
                flags.append(f"Subject Alternative Name mismatch: Domain '{hostname}' not covered by SANs")
                penalty += 40
                contributions.append(make_contribution(
                    "cert_validation", "san_mismatch", f"Certificate SAN mismatch for '{hostname}'", 40, "high"
                ))
        elif subject_cn.lower() != hostname.lower():
            san_mismatch = True
            flags.append(f"Certificate CN mismatch: Expected '{hostname}', got '{subject_cn}'")
            penalty += 35
            contributions.append(make_contribution(
                "cert_validation", "cn_mismatch", f"Certificate CN mismatch (got '{subject_cn}')", 35, "high"
            ))

        # Wildcard Abuse
        is_wildcard = any(s.startswith("*.") for s in san_domains) or subject_cn.startswith("*.")
        if is_wildcard and len(san_domains) > 25:
            flags.append(f"High-density wildcard multi-tenant certificate ({len(san_domains)} SANs)")
            penalty += 10
            contributions.append(make_contribution(
                "cert_validation", "high_density_wildcard", f"Multi-tenant wildcard cert ({len(san_domains)} SANs)", 10, "low"
            ))

        # Dates & Certificate Age
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        age_days = (now - not_before).days
        days_until_expiry = (not_after - now).days

        # Validity checks
        valid = True
        if now < not_before:
            valid = False
            flags.append("Certificate is not yet valid (future dated)")
            penalty += 40
            contributions.append(make_contribution(
                "cert_validation", "cert_future_dated", "Certificate not yet valid (future dated)", 40, "high"
            ))
        elif now > not_after:
            valid = False
            flags.append(f"Certificate expired {abs(days_until_expiry)} days ago")
            penalty += 35
            contributions.append(make_contribution(
                "cert_validation", "cert_expired", f"Certificate expired {abs(days_until_expiry)} day(s) ago", 35, "high"
            ))

        # Freshly minted certificate heuristic (Phishing hallmark)
        if age_days < 3:
            flags.append(f"High Anomaly: Certificate minted only {age_days} day(s) ago (< 72 hours)")
            penalty += 30
            contributions.append(make_contribution(
                "cert_validation", "fresh_cert_72h", f"Recently issued certificate ({age_days}d old, <72h)", 30, "high"
            ))
        elif age_days < 7:
            flags.append(f"Suspicious: Certificate issued less than a week ago ({age_days} days)")
            penalty += 18
            contributions.append(make_contribution(
                "cert_validation", "fresh_cert_7d", f"Recently issued certificate ({age_days}d old, <7d)", 18, "medium"
            ))
        elif age_days < 30:
            flags.append(f"Relatively new certificate ({age_days} days old)")
            penalty += 8
            contributions.append(make_contribution(
                "cert_validation", "recent_cert_30d", f"Recently issued certificate ({age_days}d old)", 8, "low"
            ))

        # Signature Algorithm
        sig_alg = cert.signature_hash_algorithm.name.lower() if cert.signature_hash_algorithm else "unknown"
        if "sha1" in sig_alg or "md5" in sig_alg:
            flags.append(f"Cryptographically weak signature algorithm ({sig_alg})")
            penalty += 30
            contributions.append(make_contribution(
                "cert_validation", "weak_cert_signature", f"Weak certificate signature algorithm ({sig_alg})", 30, "high"
            ))

        # TLS Version check
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            flags.append(f"Deprecated/vulnerable TLS version ({tls_version})")
            penalty += 25
            contributions.append(make_contribution(
                "cert_validation", "deprecated_tls", f"Deprecated TLS protocol ({tls_version})", 25, "medium"
            ))

        score = min(100.0, float(penalty))

        sha256_fingerprint = cert.fingerprint(hashes.SHA256()).hex()

        return {
            "score": round(score, 1),
            "valid": valid and not san_mismatch and not is_self_signed,
            "issuer": issuer_str,
            "subject": subject_cn,
            "san_domains": san_domains[:15],
            "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "age_days": age_days,
            "days_until_expiry": days_until_expiry,
            "is_free_automated_ca": is_free_automated_ca,
            "is_wildcard": is_wildcard,
            "san_mismatch": san_mismatch,
            "signature_algorithm": sig_alg,
            "tls_version": tls_version,
            "flags": flags,
            "contributions": contributions,
            "missing_evidence": missing_evidence,
            "details": {
                "cipher_suite": cipher_name,
                "serial_number": str(cert.serial_number),
                "sha256_fingerprint": sha256_fingerprint,
                "is_self_signed": is_self_signed,
                "total_sans_count": len(san_domains)
            }
        }
