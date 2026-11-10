import asyncio
import base64
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import quote, urlparse

import httpx

from app.config import settings
from app.core.explainability import make_contribution, make_missing_evidence
from app.core.security_guard import is_public_ip, resolve_and_validate_host
from app.models.database import get_cti_cache, query_ioc, set_cti_cache

_MAX_CTI_RESPONSE_BYTES = 1024 * 1024  # 1 MiB cap for external threat intel JSON responses


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_timestamp(val: Any) -> Optional[str]:
    if val is None or val == "":
        return None
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(float(val), tz=timezone.utc).isoformat()
        except Exception:
            return None
    raw = str(val).strip()
    if not raw:
        return None
    for candidate in (raw, raw.replace(" UTC", "+00:00"), raw.replace("Z", "+00:00")):
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            continue
    return raw


def _make_provider_record(
    provider: str,
    source: str,
    status: str = "clean",
    matched: bool = False,
    match_confidence: float = 0.0,
    last_updated: Optional[str] = None,
    provenance: str = "",
    reference_url: Optional[str] = None,
    summary: str = "",
    tags: Optional[List[str]] = None,
    cached: bool = False,
    checked_at: Optional[str] = None,
    score_target: float = 0.0,
    error: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "provider": provider,
        "source": source,
        "status": status,
        "matched": matched,
        "match_confidence": round(float(match_confidence), 1),
        "last_updated": last_updated,
        "provenance": provenance,
        "reference_url": reference_url,
        "summary": summary,
        "tags": list(tags or []),
        "cached": cached,
        "checked_at": checked_at or _now_iso(),
        "_score_target": float(score_target),
        "_error": error,
        "_meta": dict(meta or {}),
    }


class ThreatIntelHub:
    def __init__(self):
        self.urlhaus_endpoint = settings.URLHAUS_API_URL
        self.urlhaus_api_key = settings.URLHAUS_API_KEY
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.gsb_api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        self.gsb_endpoint = settings.GOOGLE_SAFE_BROWSING_API_URL
        self.phishtank_endpoint = settings.PHISHTANK_API_URL
        self.phishtank_api_key = settings.PHISHTANK_API_KEY
        self.otx_api_key = settings.OTX_API_KEY
        self.otx_base_url = settings.OTX_API_BASE_URL.rstrip("/")
        self.abuseipdb_api_key = settings.ABUSEIPDB_API_KEY

        self._last_urlhaus_error: Optional[str] = None
        self._last_vt_error: Optional[str] = None
        self._last_gsb_error: Optional[str] = None
        self._last_phishtank_error: Optional[str] = None
        self._last_otx_error: Optional[str] = None
        self._last_abuse_error: Optional[str] = None

    @staticmethod
    def _build_client(timeout: float = 4.0) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )

    async def query_urlhaus(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Query live URLhaus threat intelligence API from abuse.ch."""
        self._last_urlhaus_error = None
        headers = {"User-Agent": settings.SAFETY_USER_AGENT}
        if self.urlhaus_api_key:
            headers["Auth-Key"] = self.urlhaus_api_key

        try:
            async with self._build_client(timeout=4.0) as client:
                resp = await client.post(
                    self.urlhaus_endpoint,
                    data={"url": target_url},
                    headers=headers,
                )
                if resp.status_code == 200 and len(resp.content) <= _MAX_CTI_RESPONSE_BYTES:
                    data = resp.json()
                    if data.get("query_status") == "ok":
                        url_status = data.get("url_status", "online")
                        threat = data.get("threat", "Malicious URL")
                        reporter = data.get("reporter")
                        last_updated = _normalize_timestamp(
                            data.get("last_online") or data.get("date_added")
                        ) or _now_iso()
                        prov = f"URLhaus abuse.ch ({threat}, status={url_status}"
                        if reporter:
                            prov += f", reporter={reporter}"
                        prov += ")"
                        return {
                            "source": "URLhaus (abuse.ch)",
                            "threat": threat,
                            "status": url_status,
                            "tags": data.get("tags") or [],
                            "urlhaus_reference": data.get("urlhaus_reference"),
                            "last_updated": last_updated,
                            "match_confidence": 98.0 if url_status == "online" else 90.0,
                            "provenance": prov,
                        }
                    return None
                self._last_urlhaus_error = f"URLhaus HTTP {resp.status_code}"
        except Exception as exc:
            self._last_urlhaus_error = f"URLhaus unreachable ({str(exc)[:80]})"
        return None

    async def query_virustotal(self, url: str, domain: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal v3 API for URL or domain reputation."""
        self._last_vt_error = None
        if not self.vt_api_key:
            return None

        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {
                "x-apikey": self.vt_api_key,
                "User-Agent": settings.SAFETY_USER_AGENT,
            }

            async with self._build_client(timeout=5.0) as client:
                # 1. Try URL lookup
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                )
                if resp.status_code == 200 and len(resp.content) <= _MAX_CTI_RESPONSE_BYTES:
                    attributes = resp.json().get("data", {}).get("attributes", {})
                    return self._parse_vt_attributes(
                        attributes,
                        ref_url=f"https://www.virustotal.com/gui/url/{url_id}",
                        prefix="",
                    )

                # 2. If URL not found, check Domain reputation
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers=headers,
                )
                if resp.status_code == 200 and len(resp.content) <= _MAX_CTI_RESPONSE_BYTES:
                    attributes = resp.json().get("data", {}).get("attributes", {})
                    return self._parse_vt_attributes(
                        attributes,
                        ref_url=f"https://www.virustotal.com/gui/domain/{domain}",
                        prefix="Domain: ",
                    )
                if resp.status_code == 404:
                    return {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "total_engines": 0,
                        "reputation": 0,
                        "categories": [],
                        "last_updated": _now_iso(),
                        "match_confidence": 75.0,
                        "provenance": "VirusTotal v3 URL/Domain Lookup (no prior record)",
                        "reference_url": f"https://www.virustotal.com/gui/domain/{domain}",
                        "status": "Clean / Not listed in VirusTotal",
                    }
                self._last_vt_error = f"VirusTotal HTTP {resp.status_code}"
        except Exception as exc:
            self._last_vt_error = f"VirusTotal unreachable ({str(exc)[:80]})"
        return None

    @staticmethod
    def _parse_vt_attributes(attributes: Dict[str, Any], ref_url: str, prefix: str) -> Dict[str, Any]:
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total_engines = malicious + suspicious + harmless + undetected
        reputation = attributes.get("reputation", 0)
        categories = list((attributes.get("categories") or {}).values())
        last_updated = _normalize_timestamp(
            attributes.get("last_analysis_date") or attributes.get("last_modification_date")
        ) or _now_iso()

        if malicious > 0:
            conf = min(99.0, 65.0 + (malicious * 5.0))
        elif suspicious > 0:
            conf = min(85.0, 50.0 + (suspicious * 8.0))
        else:
            conf = 90.0

        engine_ratio = f"{malicious}/{total_engines}" if total_engines > 0 else f"{malicious}"
        provenance = f"VirusTotal v3 Multi-Engine ({engine_ratio} malicious, {suspicious} suspicious)"
        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total_engines": total_engines,
            "reputation": reputation,
            "categories": categories,
            "last_updated": last_updated,
            "match_confidence": round(conf, 1),
            "provenance": provenance,
            "reference_url": ref_url,
            "status": f"{prefix}{malicious} vendors flagged malicious, {suspicious} suspicious",
        }

    async def query_google_safe_browsing(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Query Google Safe Browsing v4 Threat Matches API."""
        self._last_gsb_error = None
        if not self.gsb_api_key:
            return None

        payload = {
            "client": {"clientId": "phishpulse", "clientVersion": settings.APP_VERSION},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target_url}],
            },
        }
        headers = {
            "X-Goog-Api-Key": self.gsb_api_key,
            "Content-Type": "application/json",
            "User-Agent": settings.SAFETY_USER_AGENT,
        }

        try:
            async with self._build_client(timeout=4.0) as client:
                resp = await client.post(
                    self.gsb_endpoint,
                    json=payload,
                    headers=headers,
                )
                if resp.status_code == 200 and len(resp.content) <= _MAX_CTI_RESPONSE_BYTES:
                    data = resp.json()
                    matches = data.get("matches") or []
                    now_iso = _now_iso()
                    if matches:
                        threat_types = sorted({str(m.get("threatType", "THREAT")) for m in matches})
                        platforms = sorted({str(m.get("platformType", "ANY_PLATFORM")) for m in matches})
                        return {
                            "matched": True,
                            "threat_types": threat_types,
                            "platforms": platforms,
                            "last_updated": now_iso,
                            "match_confidence": 98.0,
                            "provenance": (
                                f"Google Safe Browsing v4 Threat Lists "
                                f"({', '.join(threat_types)} on {', '.join(platforms)})"
                            ),
                            "status": f"Flagged: {', '.join(threat_types)}",
                        }
                    return {
                        "matched": False,
                        "threat_types": [],
                        "platforms": [],
                        "last_updated": now_iso,
                        "match_confidence": 95.0,
                        "provenance": "Google Safe Browsing v4 Threat Lists (no match)",
                        "status": "Clean / Unflagged",
                    }
                self._last_gsb_error = f"Google Safe Browsing HTTP {resp.status_code}"
        except Exception as exc:
            self._last_gsb_error = f"Google Safe Browsing unreachable ({str(exc)[:80]})"
        return None

    async def query_phishtank(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Query PhishTank checkurl API for verified phishing matches."""
        self._last_phishtank_error = None
        form_data = {"url": target_url, "format": "json"}
        if self.phishtank_api_key:
            form_data["app_key"] = self.phishtank_api_key

        headers = {"User-Agent": f"phishtank/{settings.SAFETY_USER_AGENT}"}

        try:
            async with self._build_client(timeout=4.0) as client:
                resp = await client.post(
                    self.phishtank_endpoint,
                    data=form_data,
                    headers=headers,
                )
                if resp.status_code == 200 and len(resp.content) <= _MAX_CTI_RESPONSE_BYTES:
                    data = resp.json()
                    if data.get("errortext"):
                        self._last_phishtank_error = f"PhishTank error: {str(data['errortext'])[:80]}"
                        return None
                    results = data.get("results") or {}
                    now_iso = _now_iso()
                    in_db = bool(results.get("in_database"))
                    is_valid = bool(results.get("valid"))
                    if in_db and is_valid:
                        verified = bool(results.get("verified"))
                        phish_id = results.get("phish_id")
                        detail_page = results.get("phish_detail_page")
                        verified_at = _normalize_timestamp(results.get("verified_at")) or now_iso
                        label = "Verified" if verified else "Submitted"
                        return {
                            "matched": True,
                            "verified": verified,
                            "phish_id": phish_id,
                            "reference_url": detail_page,
                            "last_updated": verified_at,
                            "match_confidence": 97.0 if verified else 80.0,
                            "provenance": f"PhishTank {label} Phish #{phish_id or 'N/A'} (valid=true)",
                            "status": f"{label} Phishing (#{phish_id or 'N/A'})",
                        }
                    if in_db and not is_valid:
                        phish_id = results.get("phish_id")
                        detail_page = results.get("phish_detail_page")
                        verified_at = _normalize_timestamp(results.get("verified_at")) or now_iso
                        return {
                            "matched": False,
                            "verified": False,
                            "phish_id": phish_id,
                            "reference_url": detail_page,
                            "last_updated": verified_at,
                            "match_confidence": 90.0,
                            "provenance": f"PhishTank Historical Entry #{phish_id or 'N/A'} (marked invalid/inactive)",
                            "status": f"Clean / Invalidated (#{phish_id or 'N/A'})",
                        }
                    return {
                        "matched": False,
                        "verified": False,
                        "phish_id": None,
                        "reference_url": None,
                        "last_updated": now_iso,
                        "match_confidence": 85.0,
                        "provenance": "PhishTank checkurl Database (not listed)",
                        "status": "Clean / Not listed",
                    }
                self._last_phishtank_error = f"PhishTank HTTP {resp.status_code}"
        except Exception as exc:
            self._last_phishtank_error = f"PhishTank unreachable ({str(exc)[:80]})"
        return None

    async def query_otx(self, url: str, domain: str) -> Optional[Dict[str, Any]]:
        """Query AlienVault OTX v1 API for URL and domain threat pulses."""
        self._last_otx_error = None
        if not self.otx_api_key:
            return None

        headers = {
            "X-OTX-API-KEY": self.otx_api_key,
            "User-Agent": settings.SAFETY_USER_AGENT,
        }

        try:
            encoded_url = quote(url, safe="")
            encoded_domain = quote(domain, safe="")
            endpoints = [
                (
                    f"{self.otx_base_url}/indicators/url/{encoded_url}/general",
                    f"https://otx.alienvault.com/indicator/url/{encoded_url}",
                ),
                (
                    f"{self.otx_base_url}/indicators/domain/{encoded_domain}/general",
                    f"https://otx.alienvault.com/indicator/domain/{encoded_domain}",
                ),
            ]
            async with self._build_client(timeout=4.0) as client:
                for api_url, ref_url in endpoints:
                    resp = await client.get(api_url, headers=headers)
                    if resp.status_code == 200 and len(resp.content) <= _MAX_CTI_RESPONSE_BYTES:
                        data = resp.json()
                        pulse_info = data.get("pulse_info") or {}
                        pulse_count = int(pulse_info.get("count", 0))
                        pulses = pulse_info.get("pulses") or []
                        if pulse_count > 0:
                            pulse_names = [str(p.get("name", "")).strip() for p in pulses[:3] if p.get("name")]
                            pulse_tags: List[str] = []
                            latest_ts = None
                            for p in pulses[:5]:
                                pulse_tags.extend(str(t) for t in (p.get("tags") or [])[:3])
                                ts = _normalize_timestamp(p.get("modified") or p.get("created"))
                                if ts and (latest_ts is None or ts > latest_ts):
                                    latest_ts = ts
                            conf = min(98.0, 65.0 + (pulse_count * 7.0))
                            names_str = ", ".join(pulse_names) if pulse_names else "Active Threat Pulses"
                            return {
                                "matched": True,
                                "pulse_count": pulse_count,
                                "pulse_names": pulse_names,
                                "tags": list(dict.fromkeys(f"#{t.lower().replace(' ', '_')}" for t in pulse_tags if t)),
                                "last_updated": latest_ts or _now_iso(),
                                "match_confidence": round(conf, 1),
                                "provenance": f"AlienVault OTX ({pulse_count} pulse(s): {names_str})",
                                "reference_url": ref_url,
                                "status": f"{pulse_count} OTX pulse(s) matched",
                            }
                    elif resp.status_code not in (200, 404):
                        self._last_otx_error = f"AlienVault OTX HTTP {resp.status_code}"
                        return None

                return {
                    "matched": False,
                    "pulse_count": 0,
                    "pulse_names": [],
                    "tags": [],
                    "last_updated": _now_iso(),
                    "match_confidence": 85.0,
                    "provenance": "AlienVault OTX Pulse Lookup (0 pulses)",
                    "reference_url": f"https://otx.alienvault.com/indicator/domain/{encoded_domain}",
                    "status": "Clean / 0 pulses",
                }
        except Exception as exc:
            self._last_otx_error = f"AlienVault OTX unreachable ({str(exc)[:80]})"
        return None

    async def query_abuseipdb(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB v2 API for IP reputation."""
        self._last_abuse_error = None
        if not self.abuseipdb_api_key or not ip_address:
            return None

        if not is_public_ip(ip_address):
            return None

        try:
            headers = {
                "Key": self.abuseipdb_api_key,
                "Accept": "application/json",
                "User-Agent": settings.SAFETY_USER_AGENT,
            }
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
            }

            async with self._build_client(timeout=4.0) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params=params,
                )
                if resp.status_code == 200 and len(resp.content) <= _MAX_CTI_RESPONSE_BYTES:
                    data = resp.json().get("data", {})
                    score_pct = int(data.get("abuseConfidenceScore", 0))
                    total_reports = int(data.get("totalReports", 0))
                    last_updated = _normalize_timestamp(data.get("lastReportedAt")) or _now_iso()
                    return {
                        "abuse_score": score_pct,
                        "total_reports": total_reports,
                        "country_code": data.get("countryCode", "Unknown"),
                        "usage_type": data.get("usageType", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "last_updated": last_updated,
                        "match_confidence": max(75.0, float(score_pct)) if score_pct >= 25 else 85.0,
                        "provenance": f"AbuseIPDB v2 ({total_reports} report(s), ISP: {data.get('isp', 'Unknown')})",
                        "reference_url": f"https://www.abuseipdb.com/check/{ip_address}",
                        "status": f"Abuse confidence: {score_pct}% ({total_reports} reports)",
                    }
                self._last_abuse_error = f"AbuseIPDB HTTP {resp.status_code}"
        except Exception as exc:
            self._last_abuse_error = f"AbuseIPDB unreachable ({str(exc)[:80]})"
        return None

    def query_local_collaborative_db(self, url: str, domain: str) -> Optional[Dict[str, Any]]:
        """Query the internal community & analyst IoC database."""
        hit = query_ioc(url)
        if hit:
            return hit
        hit = query_ioc(domain)
        if hit:
            return hit
        return None

    async def _cached_provider_lookup(
        self,
        provider: str,
        source: str,
        indicator: str,
        configured: bool,
        unconfigured_reason: str,
        fetch_coro_factory: Callable[[], Awaitable[Dict[str, Any]]],
        refresh: bool = False,
    ) -> Dict[str, Any]:
        """Execute a CTI provider lookup with SQLite TTL caching for valid results."""
        if not configured:
            return _make_provider_record(
                provider=provider,
                source=source,
                status="unconfigured",
                provenance=unconfigured_reason,
                summary=f"Not configured ({unconfigured_reason})",
            )

        cache_key = f"{provider}:{indicator}"
        if not refresh:
            cached = get_cti_cache(cache_key)
            if cached is not None:
                cached["cached"] = True
                return cached

        record = await fetch_coro_factory()
        if record.get("status") in ("matched", "clean"):
            set_cti_cache(
                cache_key=cache_key,
                provider=provider,
                indicator=indicator,
                payload=record,
                ttl_seconds=settings.CTI_CACHE_TTL_SECONDS,
            )
        return record

    async def _eval_urlhaus(self, target_url: str) -> Dict[str, Any]:
        res = await self.query_urlhaus(target_url)
        if res:
            summary = f"{res['threat']} ({res['status']})"
            return _make_provider_record(
                provider="urlhaus",
                source="URLhaus (abuse.ch)",
                status="matched",
                matched=True,
                match_confidence=res.get("match_confidence", 98.0),
                last_updated=res.get("last_updated") or _now_iso(),
                provenance=res.get("provenance") or "URLhaus abuse.ch Verified Threat",
                reference_url=res.get("urlhaus_reference"),
                summary=summary,
                tags=res.get("tags") or [],
                score_target=95.0,
            )
        if self._last_urlhaus_error:
            return _make_provider_record(
                provider="urlhaus",
                source="URLhaus (abuse.ch)",
                status="unavailable",
                provenance="URLhaus abuse.ch URL Lookup",
                summary=f"Unavailable ({self._last_urlhaus_error})",
                error=self._last_urlhaus_error,
            )
        return _make_provider_record(
            provider="urlhaus",
            source="URLhaus (abuse.ch)",
            status="clean",
            matched=False,
            match_confidence=88.0,
            last_updated=_now_iso(),
            provenance="URLhaus abuse.ch URL Lookup (no match)",
            summary="Clean / Not listed",
        )

    async def _eval_virustotal(self, target_url: str, domain: str) -> Dict[str, Any]:
        res = await self.query_virustotal(target_url, domain)
        if res:
            malicious = int(res.get("malicious", 0))
            suspicious = int(res.get("suspicious", 0))
            if malicious > 0:
                return _make_provider_record(
                    provider="virustotal",
                    source="VirusTotal v3",
                    status="matched",
                    matched=True,
                    match_confidence=res.get("match_confidence", 95.0),
                    last_updated=res.get("last_updated") or _now_iso(),
                    provenance=res.get("provenance") or "VirusTotal Multi-Engine Analysis",
                    reference_url=res.get("reference_url"),
                    summary=res["status"],
                    tags=["#virustotal_malicious"],
                    score_target=min(100.0, 75.0 + (malicious * 4.0)),
                )
            if suspicious > 0:
                return _make_provider_record(
                    provider="virustotal",
                    source="VirusTotal v3",
                    status="matched",
                    matched=True,
                    match_confidence=res.get("match_confidence", 70.0),
                    last_updated=res.get("last_updated") or _now_iso(),
                    provenance=res.get("provenance") or "VirusTotal Multi-Engine Analysis",
                    reference_url=res.get("reference_url"),
                    summary=res["status"],
                    tags=["#virustotal_suspicious"],
                    score_target=45.0,
                )
            return _make_provider_record(
                provider="virustotal",
                source="VirusTotal v3",
                status="clean",
                matched=False,
                match_confidence=res.get("match_confidence", 90.0),
                last_updated=res.get("last_updated") or _now_iso(),
                provenance=res.get("provenance") or "VirusTotal v3 Multi-Engine Lookup (0 detections)",
                reference_url=res.get("reference_url"),
                summary=res["status"],
            )
        return _make_provider_record(
            provider="virustotal",
            source="VirusTotal v3",
            status="unavailable",
            provenance="VirusTotal v3 Multi-Engine Lookup",
            summary=self._last_vt_error or "VirusTotal lookup unavailable",
            error=self._last_vt_error or "VirusTotal lookup unavailable",
        )

    async def _eval_gsb(self, target_url: str) -> Dict[str, Any]:
        res = await self.query_google_safe_browsing(target_url)
        if res:
            if res.get("matched"):
                tags = [f"#gsb_{t.lower()}" for t in res.get("threat_types", [])]
                return _make_provider_record(
                    provider="google_safe_browsing",
                    source="Google Safe Browsing v4",
                    status="matched",
                    matched=True,
                    match_confidence=res.get("match_confidence", 98.0),
                    last_updated=res.get("last_updated") or _now_iso(),
                    provenance=res.get("provenance") or "Google Safe Browsing Threat Lists",
                    summary=res["status"],
                    tags=tags,
                    score_target=95.0,
                )
            return _make_provider_record(
                provider="google_safe_browsing",
                source="Google Safe Browsing v4",
                status="clean",
                matched=False,
                match_confidence=res.get("match_confidence", 95.0),
                last_updated=res.get("last_updated") or _now_iso(),
                provenance=res.get("provenance") or "Google Safe Browsing Threat Lists (no match)",
                summary=res["status"],
            )
        return _make_provider_record(
            provider="google_safe_browsing",
            source="Google Safe Browsing v4",
            status="unavailable",
            provenance="Google Safe Browsing v4 Threat Lists",
            summary=self._last_gsb_error or "Google Safe Browsing unavailable",
            error=self._last_gsb_error or "Google Safe Browsing unavailable",
        )

    async def _eval_phishtank(self, target_url: str) -> Dict[str, Any]:
        res = await self.query_phishtank(target_url)
        if res:
            if res.get("matched"):
                verified = bool(res.get("verified"))
                return _make_provider_record(
                    provider="phishtank",
                    source="PhishTank",
                    status="matched",
                    matched=True,
                    match_confidence=res.get("match_confidence", 97.0 if verified else 80.0),
                    last_updated=res.get("last_updated") or _now_iso(),
                    provenance=res.get("provenance") or "PhishTank Verified Database",
                    reference_url=res.get("reference_url"),
                    summary=res["status"],
                    tags=["#phishtank_verified" if verified else "#phishtank_listed"],
                    score_target=92.0 if verified else 75.0,
                )
            return _make_provider_record(
                provider="phishtank",
                source="PhishTank",
                status="clean",
                matched=False,
                match_confidence=res.get("match_confidence", 85.0),
                last_updated=res.get("last_updated") or _now_iso(),
                provenance=res.get("provenance") or "PhishTank checkurl Database (not listed)",
                reference_url=res.get("reference_url"),
                summary=res["status"],
            )
        return _make_provider_record(
            provider="phishtank",
            source="PhishTank",
            status="unavailable",
            provenance="PhishTank checkurl Database",
            summary=self._last_phishtank_error or "PhishTank unavailable",
            error=self._last_phishtank_error or "PhishTank unavailable",
        )

    async def _eval_otx(self, target_url: str, domain: str) -> Dict[str, Any]:
        res = await self.query_otx(target_url, domain)
        if res:
            if res.get("matched"):
                pulse_count = int(res.get("pulse_count", 0))
                return _make_provider_record(
                    provider="alienvault_otx",
                    source="AlienVault OTX",
                    status="matched",
                    matched=True,
                    match_confidence=res.get("match_confidence", 80.0),
                    last_updated=res.get("last_updated") or _now_iso(),
                    provenance=res.get("provenance") or "AlienVault OTX Threat Pulses",
                    reference_url=res.get("reference_url"),
                    summary=res["status"],
                    tags=res.get("tags") or ["#otx_pulse"],
                    score_target=min(96.0, 65.0 + (pulse_count * 8.0)),
                )
            return _make_provider_record(
                provider="alienvault_otx",
                source="AlienVault OTX",
                status="clean",
                matched=False,
                match_confidence=res.get("match_confidence", 85.0),
                last_updated=res.get("last_updated") or _now_iso(),
                provenance=res.get("provenance") or "AlienVault OTX Pulse Lookup (0 pulses)",
                reference_url=res.get("reference_url"),
                summary=res["status"],
            )
        return _make_provider_record(
            provider="alienvault_otx",
            source="AlienVault OTX",
            status="unavailable",
            provenance="AlienVault OTX Pulse Lookup",
            summary=self._last_otx_error or "AlienVault OTX unavailable",
            error=self._last_otx_error or "AlienVault OTX unavailable",
        )

    async def _eval_abuseipdb(self, resolved_ip: str) -> Dict[str, Any]:
        res = await self.query_abuseipdb(resolved_ip)
        if res:
            score_pct = int(res.get("abuse_score", 0))
            matched = score_pct >= 25
            return _make_provider_record(
                provider="abuseipdb",
                source="AbuseIPDB v2",
                status="matched" if matched else "clean",
                matched=matched,
                match_confidence=res.get("match_confidence", 85.0),
                last_updated=res.get("last_updated") or _now_iso(),
                provenance=res.get("provenance") or "AbuseIPDB IP Reputation",
                reference_url=res.get("reference_url"),
                summary=res["status"],
                tags=[f"#abuseipdb_{score_pct}pct"] if matched else [],
                score_target=float(score_pct) if matched else 0.0,
                meta={
                    "isp": res.get("isp"),
                    "country_code": res.get("country_code"),
                    "usage_type": res.get("usage_type"),
                },
            )
        return _make_provider_record(
            provider="abuseipdb",
            source="AbuseIPDB v2",
            status="unavailable",
            provenance="AbuseIPDB IP Reputation",
            summary=self._last_abuse_error or "AbuseIPDB lookup unavailable",
            error=self._last_abuse_error or "AbuseIPDB lookup unavailable",
        )

    async def evaluate(
        self,
        url: str,
        ip_address: Optional[str] = None,
        refresh: bool = False,
    ) -> Dict[str, Any]:
        """Aggregate cached/live external CTI feeds and internal collaborative intelligence."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()

        feed_hits: List[str] = []
        tags: List[str] = []
        contributions: List[Dict[str, Any]] = []
        missing_evidence: List[Dict[str, Any]] = []
        providers: List[Dict[str, Any]] = []
        penalty = 0.0
        confidence = 0.0
        votes_malicious = 0
        votes_benign = 0
        cache_hits = 0

        # 1. Local Collaborative Threat Database (Analyst verified & seeded IoCs)
        local_hit = self.query_local_collaborative_db(url, domain)
        if local_hit:
            feed_hits.append(f"Collaborative Threat DB ({local_hit['source']})")
            tags.extend(local_hit.get("tags", []))
            votes_malicious += local_hit.get("votes_malicious", 0)
            votes_benign += local_hit.get("votes_benign", 0)
            local_conf = float(local_hit.get("confidence", 85.0))
            confidence = max(confidence, local_conf)
            penalty += 85.0
            contributions.append(make_contribution(
                "threat_intel",
                "local_cti_match",
                f"Threat intelligence match ({local_hit['source']})",
                85.0,
                "critical",
                local_hit.get("indicator"),
            ))
            providers.append(_make_provider_record(
                provider="local_ioc_db",
                source="PhishPulse Collaborative DB",
                status="matched",
                matched=True,
                match_confidence=local_conf,
                last_updated=_normalize_timestamp(local_hit.get("last_seen")) or _now_iso(),
                provenance=f"{local_hit['source']} (verified IoC #{local_hit.get('id', '?')})",
                summary=local_hit.get("notes") or "Matched local IoC indicator",
                tags=local_hit.get("tags", []),
            ))
        else:
            providers.append(_make_provider_record(
                provider="local_ioc_db",
                source="PhishPulse Collaborative DB",
                status="clean",
                matched=False,
                match_confidence=85.0,
                last_updated=_now_iso(),
                provenance="Local SQLite Collaborative IoC Repository (no match)",
                summary="Clean / Not listed",
            ))

        # Resolve public IP for AbuseIPDB if not already supplied
        resolved_ip = ip_address
        if not resolved_ip and self.abuseipdb_api_key and domain:
            try:
                ips = resolve_and_validate_host(domain, 443, allow_local=False, require_resolution=False)
                if ips:
                    resolved_ip = ips[0]
            except Exception:
                pass

        # 2. Query external CTI providers concurrently (with SQLite TTL cache)
        abuse_task = (
            self._cached_provider_lookup(
                provider="abuseipdb",
                source="AbuseIPDB v2",
                indicator=resolved_ip or "",
                configured=bool(self.abuseipdb_api_key and resolved_ip and is_public_ip(resolved_ip)),
                unconfigured_reason=(
                    "ABUSEIPDB_API_KEY not configured"
                    if not self.abuseipdb_api_key
                    else "No public host IP resolved for AbuseIPDB check"
                ),
                fetch_coro_factory=lambda: self._eval_abuseipdb(resolved_ip or ""),
                refresh=refresh,
            )
        )

        ext_records = await asyncio.gather(
            self._cached_provider_lookup(
                provider="virustotal",
                source="VirusTotal v3",
                indicator=url,
                configured=bool(self.vt_api_key),
                unconfigured_reason="VIRUSTOTAL_API_KEY not configured",
                fetch_coro_factory=lambda: self._eval_virustotal(url, domain),
                refresh=refresh,
            ),
            self._cached_provider_lookup(
                provider="google_safe_browsing",
                source="Google Safe Browsing v4",
                indicator=url,
                configured=bool(self.gsb_api_key),
                unconfigured_reason="GOOGLE_SAFE_BROWSING_API_KEY not configured",
                fetch_coro_factory=lambda: self._eval_gsb(url),
                refresh=refresh,
            ),
            self._cached_provider_lookup(
                provider="phishtank",
                source="PhishTank",
                indicator=url,
                configured=True,
                unconfigured_reason="",
                fetch_coro_factory=lambda: self._eval_phishtank(url),
                refresh=refresh,
            ),
            self._cached_provider_lookup(
                provider="urlhaus",
                source="URLhaus (abuse.ch)",
                indicator=url,
                configured=True,
                unconfigured_reason="",
                fetch_coro_factory=lambda: self._eval_urlhaus(url),
                refresh=refresh,
            ),
            self._cached_provider_lookup(
                provider="alienvault_otx",
                source="AlienVault OTX",
                indicator=url,
                configured=bool(self.otx_api_key),
                unconfigured_reason="OTX_API_KEY not configured",
                fetch_coro_factory=lambda: self._eval_otx(url, domain),
                refresh=refresh,
            ),
            abuse_task,
        )

        vt_rec, gsb_rec, pt_rec, uh_rec, otx_rec, abuse_rec = ext_records

        # Map provider statuses, missing evidence, and incremental score contributions
        provider_checks = [
            (vt_rec, "virustotal_match", "VirusTotal v3 Reputation", "low"),
            (gsb_rec, "google_safe_browsing_match", "Google Safe Browsing v4", "low"),
            (pt_rec, "phishtank_match", "PhishTank Live Feed", "medium"),
            (uh_rec, "urlhaus_match", "URLhaus (abuse.ch) Live Feed", "medium"),
            (otx_rec, "alienvault_otx_match", "AlienVault OTX Threat Pulses", "low"),
            (abuse_rec, "abuseipdb_flagged", "AbuseIPDB IP Reputation", "low"),
        ]

        for rec, factor_id, check_label, unconf_impact in provider_checks:
            if rec.get("cached"):
                cache_hits += 1

            status = rec.get("status")
            if status == "matched":
                feed_hits.append(f"{rec['source']} ({rec['summary']})")
                tags.extend(rec.get("tags") or [])
                target_score = float(rec.get("_score_target", 0.0))
                new_penalty = max(penalty, target_score)
                delta = new_penalty - penalty
                penalty = new_penalty
                confidence = max(confidence, float(rec.get("match_confidence", 90.0)))
                if delta > 0:
                    contributions.append(make_contribution(
                        "threat_intel",
                        factor_id,
                        f"{rec['source']} match: {rec['summary']}",
                        delta,
                        "critical" if target_score >= 85.0 else "high",
                        rec.get("provenance"),
                    ))
            elif status == "unavailable":
                missing_evidence.append(make_missing_evidence(
                    "threat_intel",
                    check_label,
                    rec.get("_error") or rec.get("summary") or f"{rec['source']} unavailable",
                    impact="medium",
                ))
            elif status == "unconfigured":
                missing_evidence.append(make_missing_evidence(
                    "threat_intel",
                    check_label,
                    rec.get("provenance") or f"{rec['source']} not configured",
                    impact=unconf_impact,
                ))

        # 3. Community consensus weighting
        net_votes = votes_malicious - votes_benign
        if net_votes > 3:
            new_penalty = max(penalty, 80.0)
            delta = new_penalty - penalty
            penalty = new_penalty
            feed_hits.append(f"Community Consensus ({votes_malicious} malicious votes)")
            if delta > 0:
                contributions.append(make_contribution(
                    "threat_intel",
                    "community_consensus_malicious",
                    f"Community consensus malicious ({votes_malicious} votes)",
                    delta,
                    "high",
                ))
        elif net_votes < -2 and penalty > 0:
            new_penalty = max(0.0, penalty - 35.0)
            delta = new_penalty - penalty
            penalty = new_penalty
            feed_hits.append("Community Dispute: Flagged as potential False Positive")
            if delta < 0:
                contributions.append(make_contribution(
                    "threat_intel",
                    "community_dispute_benign",
                    f"Community false-positive dispute ({votes_benign} benign votes)",
                    delta,
                    "info",
                ))

        # Fallback benign confidence if clean
        if not feed_hits:
            confidence = 80.0

        score = min(100.0, float(penalty))

        # Strip internal fields before returning provider telemetry
        public_providers = [
            {k: v for k, v in rec.items() if not k.startswith("_")}
            for rec in (providers + list(ext_records))
        ]

        urlhaus_status = (
            uh_rec["summary"]
            if uh_rec["status"] in ("matched", "unavailable")
            else None
        )

        abuse_meta = abuse_rec.get("_meta") or {}

        return {
            "score": round(score, 1),
            "feed_hits": list(dict.fromkeys(feed_hits)),
            "urlhaus_status": urlhaus_status,
            "openphish_status": None,
            "virustotal_status": vt_rec["summary"],
            "gsb_status": gsb_rec["summary"],
            "phishtank_status": pt_rec["summary"],
            "otx_status": otx_rec["summary"],
            "abuseipdb_status": abuse_rec["summary"],
            "community_votes_malicious": votes_malicious,
            "community_votes_benign": votes_benign,
            "confidence_score": round(confidence, 1),
            "cache_hits": cache_hits,
            "tags": list(dict.fromkeys(tags)),
            "providers": public_providers,
            "contributions": contributions,
            "missing_evidence": missing_evidence,
            "details": {
                "local_hit": bool(local_hit),
                "urlhaus_hit": uh_rec["matched"],
                "urlhaus_checked": uh_rec["status"] in ("matched", "clean"),
                "virustotal_configured": bool(self.vt_api_key),
                "virustotal_checked": vt_rec["status"] in ("matched", "clean"),
                "gsb_configured": bool(self.gsb_api_key),
                "gsb_checked": gsb_rec["status"] in ("matched", "clean"),
                "phishtank_checked": pt_rec["status"] in ("matched", "clean"),
                "otx_configured": bool(self.otx_api_key),
                "otx_checked": otx_rec["status"] in ("matched", "clean"),
                "abuseipdb_configured": bool(self.abuseipdb_api_key),
                "abuseipdb_checked": abuse_rec["status"] in ("matched", "clean"),
                "abuseipdb_isp": abuse_meta.get("isp"),
                "abuseipdb_country": abuse_meta.get("country_code"),
                "abuseipdb_usage_type": abuse_meta.get("usage_type"),
                "cache_hits": cache_hits,
                "net_community_votes": net_votes,
            },
        }
