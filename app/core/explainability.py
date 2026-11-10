from typing import Any, Dict, List, Optional, Tuple


ENGINE_LABELS: Dict[str, str] = {
    "threat_analysis": "Threat Analysis",
    "web_security": "Web Security",
    "cert_validation": "SSL/TLS Certificate",
    "threat_intel": "Threat Intelligence",
    "correlation": "Correlation Rule",
}


def make_contribution(
    engine: str,
    factor: str,
    label: str,
    raw_points: float,
    severity: str = "medium",
    evidence: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a normalized score contribution item for an analytical engine."""
    return {
        "engine": engine,
        "engine_label": ENGINE_LABELS.get(engine, engine),
        "factor": factor,
        "label": label,
        "raw_points": round(float(raw_points), 1),
        "points": 0.0,
        "severity": severity,
        "evidence": evidence,
    }


def make_missing_evidence(
    engine: str,
    check: str,
    reason: str,
    impact: str = "medium",
) -> Dict[str, Any]:
    """Create a structured missing-evidence entry explaining an uncollected signal."""
    return {
        "engine": engine,
        "check": check,
        "reason": reason,
        "impact": impact,
    }


def _scale_engine_contributions(
    raw_contributions: List[Dict[str, Any]],
    engine_score: float,
    weight: float,
) -> List[Dict[str, Any]]:
    """Convert raw engine rule points into weighted contributions toward composite score."""
    if not raw_contributions:
        return []

    raw_sum = sum(float(c.get("raw_points", 0.0)) for c in raw_contributions)
    # Engines cap raw penalties at 100.0; scale proportionally if raw sum exceeded cap
    cap_factor = 1.0 if raw_sum <= 100.0 else (100.0 / raw_sum)

    scaled: List[Dict[str, Any]] = []
    for item in raw_contributions:
        raw_pts = float(item.get("raw_points", 0.0))
        weighted_pts = raw_pts * cap_factor * weight
        entry = dict(item)
        entry["points"] = round(weighted_pts, 1)
        entry["_exact_points"] = weighted_pts
        scaled.append(entry)
    return scaled


def compute_engine_confidences(
    threat_res: Dict[str, Any],
    sec_res: Dict[str, Any],
    cert_res: Dict[str, Any],
    intel_res: Dict[str, Any],
    fetch_content: bool,
    deep_dns: bool,
) -> Dict[str, Tuple[float, str]]:
    """
    Calculate confidence (0-100) and status ('evaluated'|'partial'|'unavailable'|'skipped')
    for each analytical engine based on observed evidence vs gaps.
    """
    # 1. Threat Analysis confidence
    t_details = threat_res.get("details", {})
    t_status = "evaluated"
    t_conf = 100.0
    if not fetch_content:
        t_conf = 60.0
        t_status = "partial"
    elif t_details.get("content_fetch_failed"):
        t_conf = 55.0
        t_status = "partial"
    elif t_details.get("content_truncated") or t_details.get("content_empty"):
        t_conf = 80.0
        t_status = "partial"

    # 2. Web Security confidence
    s_details = sec_res.get("details", {})
    headers_ok = bool(s_details.get("headers_fetched", True))
    dns_has_records = any((sec_res.get("dns_records") or {}).values())
    if headers_ok and deep_dns and dns_has_records:
        s_conf = 100.0
        s_status = "evaluated"
    elif headers_ok and not deep_dns:
        s_conf = 70.0
        s_status = "partial"
    elif headers_ok and deep_dns and not dns_has_records:
        s_conf = 75.0
        s_status = "partial"
    elif not headers_ok and deep_dns and dns_has_records:
        s_conf = 55.0
        s_status = "partial"
    else:
        s_conf = 25.0
        s_status = "unavailable" if not headers_ok and not deep_dns else "partial"

    # 3. Certificate Validation confidence
    c_details = cert_res.get("details", {})
    if c_details.get("error") == "Target does not use SSL/TLS":
        c_conf = 85.0
        c_status = "partial"
    elif c_details.get("handshake_error") or cert_res.get("issuer") is None:
        c_conf = 35.0
        c_status = "unavailable"
    else:
        c_conf = 100.0
        c_status = "evaluated"

    # 4. Threat Intel confidence
    i_details = intel_res.get("details", {})
    i_conf = 45.0  # Local collaborative IoC DB is always queried
    if i_details.get("urlhaus_checked"):
        i_conf += 20.0
    if i_details.get("phishtank_checked"):
        i_conf += 10.0
    if i_details.get("virustotal_checked"):
        i_conf += 10.0
    if i_details.get("gsb_checked"):
        i_conf += 10.0
    if i_details.get("otx_checked"):
        i_conf += 10.0
    if i_details.get("abuseipdb_checked"):
        i_conf += 5.0
    i_conf = min(100.0, i_conf)
    i_status = "evaluated" if i_conf >= 65.0 else "partial"

    return {
        "threat_analysis": (round(t_conf, 1), t_status),
        "web_security": (round(s_conf, 1), s_status),
        "cert_validation": (round(c_conf, 1), c_status),
        "threat_intel": (round(i_conf, 1), i_status),
    }


def compute_overall_confidence(
    engine_meta: Dict[str, Tuple[float, str]],
    weights: Dict[str, float],
    threat_res: Dict[str, Any],
    sec_res: Dict[str, Any],
    cert_res: Dict[str, Any],
    intel_res: Dict[str, Any],
    missing_evidence: List[Dict[str, Any]],
) -> Tuple[float, str, str]:
    """Aggregate coverage-weighted confidence, cross-engine corroboration, and gap penalties."""
    weighted_conf = sum(
        engine_meta[k][0] * weights[k]
        for k in ("threat_analysis", "web_security", "cert_validation", "threat_intel")
    )

    # Corroboration boost when verified threat feed or >=2 engines strongly agree
    high_risk_engines = sum(
        1
        for res in (threat_res, sec_res, cert_res, intel_res)
        if float(res.get("score", 0.0)) >= 50.0
    )
    if intel_res.get("feed_hits"):
        weighted_conf = min(99.0, weighted_conf + 12.0)
    elif high_risk_engines >= 2:
        weighted_conf = min(96.0, weighted_conf + 6.0)

    # Cap overall confidence if multiple high-impact evidence pillars failed/skipped
    high_impact_gaps = [m for m in missing_evidence if m.get("impact") == "high"]
    if len(high_impact_gaps) >= 2:
        weighted_conf = min(weighted_conf, 60.0)
    elif len(high_impact_gaps) == 1:
        weighted_conf = min(weighted_conf, 82.0)

    confidence = round(max(15.0, min(100.0, weighted_conf)), 1)

    if confidence >= 80.0:
        level = "HIGH"
    elif confidence >= 55.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not missing_evidence:
        reason = f"High evidence coverage ({confidence}%): all primary and configured external checks completed."
    else:
        gap_names = ", ".join(m["check"] for m in missing_evidence[:3])
        extra = f" (+{len(missing_evidence) - 3} more)" if len(missing_evidence) > 3 else ""
        reason = (
            f"{level.title()} confidence ({confidence}%): "
            f"{len(missing_evidence)} check(s) unavailable or skipped ({gap_names}{extra})."
        )

    return confidence, level, reason


def build_explainable_breakdown(
    engine_specs: List[Tuple[str, str, Dict[str, Any], float, float, str]],
    amplification_hits: List[Tuple[str, float, str]],
    base_composite: float,
    final_score: float,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Reconcile weighted engine factor contributions and any correlation floor override
    so `sum(item['points'] for item in breakdown) == final_score`.
    Also returns `engine_scores` summary list.
    """
    all_items: List[Dict[str, Any]] = []
    engine_summaries: List[Dict[str, Any]] = []

    for key, name, res, weight, conf, status in engine_specs:
        raw_contribs = list(res.get("contributions") or [])
        scaled = _scale_engine_contributions(raw_contribs, float(res.get("score", 0.0)), weight)
        all_items.extend(scaled)

        clean_engine_contribs = [
            {k: v for k, v in item.items() if k != "_exact_points"}
            for item in sorted(scaled, key=lambda x: abs(x["points"]), reverse=True)
        ]

        engine_summaries.append({
            "engine": key,
            "name": name,
            "score": round(float(res.get("score", 0.0)), 1),
            "weight": round(weight, 2),
            "weighted_score": round(float(res.get("score", 0.0)) * weight, 1),
            "status": status,
            "confidence": conf,
            "contributions": clean_engine_contribs,
            "missing_evidence": list(res.get("missing_evidence") or []),
        })

    # If a correlation amplification rule elevated the score above the weighted sum, record it explicitly
    rounded_base = round(base_composite, 1)
    amp_delta = round(final_score - rounded_base, 1)
    if amp_delta > 0.0 and amplification_hits:
        top_rule_label, top_floor, top_evidence = max(amplification_hits, key=lambda x: x[1])
        amp_item = make_contribution(
            engine="correlation",
            factor="correlation_amplification",
            label=top_rule_label,
            raw_points=amp_delta,
            severity="critical",
            evidence=f"{top_evidence} (minimum risk floor {top_floor:.0f}/100)",
        )
        amp_item["points"] = amp_delta
        amp_item["_exact_points"] = float(amp_delta)
        all_items.append(amp_item)

    # Reconcile 1-decimal rounding drift so item points sum exactly to final_score
    if all_items:
        total_rounded = round(sum(float(x["points"]) for x in all_items), 1)
        drift = round(final_score - total_rounded, 1)
        if drift != 0.0 and abs(drift) <= 1.0:
            # Adjust the largest positive contributor (or first contributor) to preserve exact sum
            target_item = max(all_items, key=lambda x: x.get("_exact_points", 0.0))
            target_item["points"] = round(float(target_item["points"]) + drift, 1)

    cleaned_breakdown = [
        {k: v for k, v in item.items() if k != "_exact_points"}
        for item in sorted(all_items, key=lambda x: x["points"], reverse=True)
    ]

    return cleaned_breakdown, engine_summaries
