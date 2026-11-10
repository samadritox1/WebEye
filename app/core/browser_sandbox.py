import base64
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import esprima

from app.config import settings
from app.core.browser_worker import (
    BrowserSandboxError,
    BrowserSandboxTimeoutError,
    run_in_browser_worker,
)
from app.core.concurrency import bounded_sandbox_slot
from app.core.observability import metrics
from app.core.security_guard import SSRFBlockedError, validate_target_url
from app.core.mitre_mapper import MitreAttackMapper
from app.models.database import get_sandbox_run_by_id, save_sandbox_run


_SAFE_SANDBOX_ID_RE = re.compile(r"^SBX-[A-F0-9]{6,16}$")

# Static JS obfuscation & phishing indicators (tuned to avoid benign framework noise)
_CO_LOCATED_EVAL_RE = re.compile(
    r"\beval\s*\((?:[^;]{0,180}(?:atob|unescape|decodeURIComponent|String\.fromCharCode|function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k))",
    re.I | re.S,
)
_PACKER_RE = re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,", re.I)
_LONG_CHARCODE_RE = re.compile(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){20,}\d+\s*\)", re.I)
_HEX_OBFUSCATION_RE = re.compile(r"_0x[a-f0-9]{4,}", re.I)
_KEYLOGGER_RE = re.compile(
    r"(?:addEventListener\s*\(\s*['\"](?:keydown|keypress|keyup)['\"].{0,220}(?:fetch\s*\(|XMLHttpRequest|sendBeacon|new\s+Image)|on(?:keydown|keyup)\s*=)",
    re.I | re.S,
)
_ANTI_DEBUG_RE = re.compile(
    r"(?:\bdebugger\b.{0,80}(?:while|setInterval|setTimeout)|addEventListener\s*\(\s*['\"]contextmenu['\"].{0,150}preventDefault)",
    re.I | re.S,
)
_WALLET_DRAINER_RE = re.compile(r"(?:eth_sendTransaction|eth_signTypedData|signAndSendTransaction)", re.I)

_SUSPICIOUS_SCRIPT_TLDS = (".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".icu", ".buzz", ".top", ".click")


def _norm_host(url_or_host: str) -> str:
    if not url_or_host:
        return ""
    if "://" in url_or_host:
        return (urlparse(url_or_host).hostname or "").lower().rstrip(".")
    return url_or_host.strip().lower().rstrip(".")


def _is_cross_origin(host_a: str, host_b: str) -> bool:
    if not host_a or not host_b:
        return False
    a = host_a.lower().rstrip(".")
    b = host_b.lower().rstrip(".")
    return a != b and not a.endswith("." + b) and not b.endswith("." + a)


def resolve_screenshot_path(sandbox_id: str) -> Optional[Path]:
    """Safely validate sandbox_id and resolve screenshot PNG path inside SANDBOX_SCREENSHOTS_DIR."""
    clean_id = (sandbox_id or "").strip().upper()
    if not _SAFE_SANDBOX_ID_RE.match(clean_id):
        return None
    base_dir = settings.SANDBOX_SCREENSHOTS_DIR.resolve()
    candidate = (base_dir / f"{clean_id}.png").resolve()
    if not candidate.is_relative_to(base_dir):
        return None
    if candidate.is_file():
        return candidate
    return None


def _save_screenshot_b64(sandbox_id: str, screenshot_b64: str) -> Optional[str]:
    if not screenshot_b64 or not _SAFE_SANDBOX_ID_RE.match(sandbox_id):
        return None
    try:
        raw_bytes = base64.b64decode(screenshot_b64)
        if not raw_bytes.startswith(b"\x89PNG"):
            return None
        base_dir = settings.SANDBOX_SCREENSHOTS_DIR.resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
        out_path = (base_dir / f"{sandbox_id}.png").resolve()
        if not out_path.is_relative_to(base_dir):
            return None
        out_path.write_bytes(raw_bytes)
        return str(out_path)
    except Exception:
        return None


def _inspect_ast_stats(code: str) -> Dict[str, int]:
    """Use Esprima AST to count eval/Function calls and debugger traps cleanly when syntax is valid."""
    stats = {"eval_nodes": 0, "debugger_nodes": 0, "try_catch_nodes": 0}
    if not code or len(code) > 40000:
        return stats
    try:
        tree = esprima.parseScript(code, tolerant=True)
    except Exception:
        return stats

    stack: List[Any] = [tree]
    visited = 0
    while stack and visited < 3000:
        node = stack.pop()
        visited += 1
        ntype = getattr(node, "type", None)
        if ntype == "DebuggerStatement":
            stats["debugger_nodes"] += 1
        elif ntype == "TryStatement":
            stats["try_catch_nodes"] += 1
        elif ntype == "CallExpression":
            callee = getattr(node, "callee", None)
            if getattr(callee, "type", None) == "Identifier" and getattr(callee, "name", "") == "eval":
                stats["eval_nodes"] += 1
        elif ntype == "NewExpression":
            callee = getattr(node, "callee", None)
            if getattr(callee, "type", None) == "Identifier" and getattr(callee, "name", "") == "Function":
                stats["eval_nodes"] += 1

        if hasattr(node, "__dict__"):
            for val in node.__dict__.values():
                if isinstance(val, list):
                    stack.extend(val)
                elif hasattr(val, "type"):
                    stack.append(val)
    return stats


def analyze_sandbox_scripts_and_telemetry(
    raw: Dict[str, Any],
    final_domain: str,
    final_url: str,
) -> Dict[str, Any]:
    """Analyze inline scripts, external scripts, and runtime browser observer telemetry."""
    suspicious_scripts: List[Dict[str, Any]] = []
    runtime_exfil_targets: List[Dict[str, Any]] = []

    inline_scripts = raw.get("inline_scripts") or []
    external_scripts = raw.get("external_scripts") or []
    inline_handlers = raw.get("inline_handlers") or []
    telemetry = raw.get("telemetry") or {}

    # 1. Analyze captured inline <script> blocks via AST + heuristics
    for idx, item in enumerate(inline_scripts):
        code = str(item.get("text") or "")
        if not code.strip():
            continue
        reasons: List[str] = []
        indicators: List[str] = []
        sev = "low"

        ast_stats = _inspect_ast_stats(code)
        if _PACKER_RE.search(code):
            reasons.append("Dean Edwards JS packer signature (eval + p,a,c,k)")
            indicators.append("js_packer")
            sev = "high"
        if _CO_LOCATED_EVAL_RE.search(code):
            reasons.append("Co-located eval() with dynamic string decoder (atob/unescape/fromCharCode)")
            indicators.append("obfuscated_eval")
            sev = "high"
        if _LONG_CHARCODE_RE.search(code):
            reasons.append("Obfuscated String.fromCharCode() array (20+ char codes)")
            indicators.append("charcode_obfuscation")
            if sev != "high":
                sev = "medium"
        hex_hits = len(_HEX_OBFUSCATION_RE.findall(code))
        if hex_hits >= 8:
            reasons.append(f"Heavy hex-identifier obfuscation ({hex_hits} _0x symbols)")
            indicators.append("hex_obfuscated_identifiers")
            sev = "high"
        if _KEYLOGGER_RE.search(code):
            reasons.append("Potential keystroke/form exfiltration listener to network API")
            indicators.append("keylogger_exfil")
            sev = "critical"
        if _ANTI_DEBUG_RE.search(code) or ast_stats["debugger_nodes"] >= 2:
            reasons.append("Anti-analysis behavior (debugger loop or right-click lock)")
            indicators.append("anti_analysis")
            if sev == "low":
                sev = "medium"
        if _WALLET_DRAINER_RE.search(code):
            reasons.append("Web3 wallet transaction signing invocation detected")
            indicators.append("wallet_drainer_api")
            if sev != "critical":
                sev = "high"

        if reasons:
            suspicious_scripts.append({
                "script_id": f"inline-{item.get('index', idx + 1)}",
                "source_type": "inline",
                "url": final_url,
                "severity": sev,
                "reasons": reasons,
                "indicators": indicators,
                "eval_count": ast_stats["eval_nodes"],
                "snippet_preview": re.sub(r"\s+", " ", code).strip()[:240],
            })

    # 2. Inline DOM event blocking traps (<body oncontextmenu="return false">)
    for h in inline_handlers:
        ctx_attr = str(h.get("oncontextmenu") or "").lower()
        key_attr = str(h.get("onkeydown") or "").lower()
        if "return false" in ctx_attr or "preventdefault" in ctx_attr or "123" in key_attr:
            suspicious_scripts.append({
                "script_id": f"dom-handler-{h.get('tag', 'el')}",
                "source_type": "inline",
                "url": final_url,
                "severity": "medium",
                "reasons": [f"Inline anti-inspection DOM attribute on <{h.get('tag', 'element')}>"],
                "indicators": ["inline_anti_analysis"],
                "eval_count": 0,
                "snippet_preview": f"oncontextmenu={h.get('oncontextmenu')} onkeydown={h.get('onkeydown')}"[:200],
            })
            break

    # 3. Runtime eval() / Function() execution captured live inside browser
    eval_calls = telemetry.get("eval_calls") or []
    if eval_calls:
        previews = " | ".join(str(c.get("preview") or "")[:90] for c in eval_calls[:2])
        suspicious_scripts.append({
            "script_id": "runtime-eval-monitor",
            "source_type": "runtime_eval",
            "url": final_url,
            "severity": "high" if len(eval_calls) >= 2 else "medium",
            "reasons": [f"Runtime dynamic code execution observed ({len(eval_calls)} eval/Function call(s))"],
            "indicators": ["runtime_eval"],
            "eval_count": len(eval_calls),
            "snippet_preview": previews[:240],
        })

    # 4. Runtime event listener traps (contextmenu/keydown/copy blocking)
    event_hooks = telemetry.get("event_hooks") or []
    anti_hooks = [
        ev for ev in event_hooks
        if ev.get("event") in ("contextmenu", "keydown", "copy")
        and ("preventdefault" in str(ev.get("preview") or "").lower() or "123" in str(ev.get("preview") or ""))
    ]
    if anti_hooks:
        suspicious_scripts.append({
            "script_id": "runtime-anti-devtools",
            "source_type": "runtime_hook",
            "url": final_url,
            "severity": "medium",
            "reasons": [f"Runtime event trap registered ({anti_hooks[0].get('event')} with preventDefault/F12 check)"],
            "indicators": ["runtime_anti_analysis"],
            "eval_count": 0,
            "snippet_preview": str(anti_hooks[0].get("preview") or "")[:220],
        })

    # 5. Runtime fetch / XHR / sendBeacon / JS form submits to external endpoints
    seen_exfil: Set[str] = set()
    for nc in (telemetry.get("network_calls") or []):
        raw_target = str(nc.get("url") or "").strip()
        if not raw_target:
            continue
        resolved = urljoin(final_url, raw_target)
        target_dom = _norm_host(resolved)
        is_ext = _is_cross_origin(target_dom, final_domain)
        method = str(nc.get("method") or "GET").upper()
        api = str(nc.get("api") or "fetch")
        if is_ext or (api == "sendBeacon") or (method == "POST"):
            key = f"{api}|{method}|{resolved[:200]}"
            if key not in seen_exfil:
                seen_exfil.add(key)
                runtime_exfil_targets.append({
                    "api": api,
                    "method": method,
                    "url": resolved[:400],
                    "domain": target_dom,
                    "is_cross_origin": is_ext,
                })

    for fs in (telemetry.get("form_submits") or []):
        act = str(fs.get("action") or "").strip()
        resolved = urljoin(final_url, act) if act else final_url
        dom = _norm_host(resolved)
        is_ext = _is_cross_origin(dom, final_domain)
        runtime_exfil_targets.append({
            "api": "form.submit()",
            "method": str(fs.get("method") or "POST"),
            "url": resolved[:400],
            "domain": dom,
            "is_cross_origin": is_ext,
        })

    # 6. Suspicious external script hosts (high-abuse TLDs)
    for src_url in external_scripts:
        sdom = _norm_host(str(src_url))
        if sdom and any(sdom.endswith(tld) for tld in _SUSPICIOUS_SCRIPT_TLDS) and _is_cross_origin(sdom, final_domain):
            suspicious_scripts.append({
                "script_id": f"ext-{len(suspicious_scripts) + 1}",
                "source_type": "external",
                "url": str(src_url)[:400],
                "severity": "medium",
                "reasons": [f"External script loaded from third-party high-abuse TLD host '{sdom}'"],
                "indicators": ["suspicious_external_script"],
                "eval_count": 0,
                "snippet_preview": str(src_url)[:220],
            })

    return {
        "suspicious_scripts": suspicious_scripts,
        "runtime_exfil_targets": runtime_exfil_targets,
    }


def build_sandbox_report(
    raw: Dict[str, Any],
    sandbox_id: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], Optional[str]]:
    """Score and structure raw browser worker capture into a full SandboxReport dict."""
    sid = sandbox_id or f"SBX-{uuid.uuid4().hex[:8].upper()}"
    target_url = str(raw.get("target_url") or "")
    final_url = str(raw.get("final_url") or target_url)
    target_domain = _norm_host(target_url)
    final_domain = _norm_host(final_url) or target_domain
    timestamp = datetime.now(timezone.utc).isoformat()

    forms = list(raw.get("form_destinations") or [])
    redirects = list(raw.get("redirect_chain") or [])
    requests = list(raw.get("network_requests") or [])
    blocked = list(raw.get("blocked_requests") or [])

    script_analysis = analyze_sandbox_scripts_and_telemetry(raw, final_domain, final_url)
    suspicious_scripts = script_analysis["suspicious_scripts"]
    runtime_exfil_targets = script_analysis["runtime_exfil_targets"]

    # Score computation strictly grounded in dynamic sandbox behavior
    score = 0.0
    findings: List[str] = []

    cross_origin_forms = [f for f in forms if f.get("is_cross_origin")]
    cred_forms = [f for f in forms if f.get("has_password_input") or f.get("has_credential_fields") or f.get("has_payment_fields")]

    if cross_origin_forms:
        score += 50.0 if cred_forms else 35.0
        dests = ", ".join({str(f.get("action_domain") or "external") for f in cross_origin_forms[:3]})
        findings.append(f"cross-origin form destination ({dests})")
    elif cred_forms:
        score += 12.0

    cross_runtime = [r for r in runtime_exfil_targets if r.get("is_cross_origin") and (r.get("method") == "POST" or r.get("api") in ("sendBeacon", "form.submit()"))]
    if cross_runtime:
        score += 35.0
        findings.append(f"dynamic cross-origin POST/beacon ({cross_runtime[0].get('domain')})")

    if blocked:
        score += 25.0
        findings.append(f"{len(blocked)} SSRF/unsafe subresource request(s) blocked")

    cross_hops = [h for h in redirects if h.get("is_cross_origin")]
    if len(redirects) >= 3 and cross_hops:
        score += 18.0
        findings.append(f"{len(redirects)}-hop cross-domain redirect chain")
    elif cross_hops:
        score += 8.0

    script_pts = 0.0
    for sc in suspicious_scripts:
        sev = sc.get("severity", "low")
        if sev == "critical":
            script_pts += 32.0
        elif sev == "high":
            script_pts += 22.0
        elif sev == "medium":
            script_pts += 12.0
        else:
            script_pts += 5.0
    if script_pts > 0:
        score += min(45.0, script_pts)
        findings.append(f"{len(suspicious_scripts)} suspicious script behavior(s)")

    telemetry = raw.get("telemetry") or {}
    if telemetry.get("history_calls"):
        score += 10.0
        findings.append("history.replaceState URL bar manipulation")
    if int(telemetry.get("clipboard_ops") or 0) > 0:
        score += 10.0
        findings.append("clipboard API access")

    score = min(100.0, round(score, 1))
    if score >= settings.RISK_THRESHOLD_HIGH:
        verdict = "MALICIOUS"
    elif score >= settings.RISK_THRESHOLD_SUSPICIOUS:
        verdict = "HIGH_RISK"
    elif score >= settings.RISK_THRESHOLD_BENIGN:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    if findings:
        summary = f"Sandbox verdict {verdict} ({score}/100): observed {', '.join(findings)}."
    else:
        summary = f"Sandbox execution completed cleanly ({score}/100) across {len(requests)} network request(s)."

    screenshot_b64 = str(raw.get("screenshot_b64") or "")
    saved_path = _save_screenshot_b64(sid, screenshot_b64)

    unique_domains = sorted({r.get("domain") for r in requests if r.get("domain")})
    third_party_domains = sorted({r.get("domain") for r in requests if r.get("domain") and r.get("is_third_party")})

    report = {
        "sandbox_id": sid,
        "scan_id": scan_id,
        "target_url": target_url,
        "final_url": final_url,
        "target_domain": target_domain,
        "final_domain": final_domain,
        "page_title": str(raw.get("page_title") or ""),
        "timestamp": timestamp,
        "status": "completed",
        "sandbox_score": score,
        "verdict": verdict,
        "summary": summary,
        "browser_product": str(raw.get("browser_product") or "Headless Chromium"),
        "execution_ms": int(raw.get("execution_ms") or 0),
        "isolated_worker_pid": raw.get("isolated_worker_pid"),
        "screenshot_available": bool(saved_path),
        "screenshot_url": f"/api/sandbox/{sid}/screenshot" if saved_path else None,
        "redirect_chain": redirects,
        "network_requests": requests[:150],
        "blocked_requests": blocked[:50],
        "form_destinations": forms,
        "suspicious_scripts": suspicious_scripts,
        "runtime_exfil_targets": runtime_exfil_targets,
        "telemetry": {
            "total_requests": len(requests),
            "third_party_requests": sum(1 for r in requests if r.get("is_third_party")),
            "unique_domains": unique_domains[:40],
            "third_party_domains": third_party_domains[:30],
            "blocked_count": len(blocked),
            "eval_calls_count": len(telemetry.get("eval_calls") or []),
            "event_hooks_count": len(telemetry.get("event_hooks") or []),
            "parsed_scripts_count": int(raw.get("parsed_scripts_count") or 0),
            "external_scripts_count": len(raw.get("external_scripts") or []),
            "clipboard_ops": int(telemetry.get("clipboard_ops") or 0),
            "history_rewrites": len(telemetry.get("history_calls") or []),
        },
        "error": None,
    }
    report["mitre_attack"] = MitreAttackMapper().build_investigation_report(
        sandbox_runs=[report],
        context_label=f"Browser Sandbox: {final_domain}",
        source_id=sid,
    )
    return report, saved_path


async def execute_browser_sandbox(
    url: str,
    wait_seconds: float = settings.SANDBOX_WAIT_AFTER_LOAD_SECONDS,
    scan_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Validate target URL against SSRF policy, execute inside isolated browser worker subprocess,
    analyze dynamic DOM/script/network behavior, save screenshot, and persist report.
    """
    try:
        clean_url = validate_target_url(url)
    except SSRFBlockedError:
        metrics.record_ssrf_block()
        raise

    async with bounded_sandbox_slot():
        try:
            raw = await run_in_browser_worker(
                url=clean_url,
                wait_seconds=wait_seconds,
                timeout_seconds=settings.SANDBOX_TIMEOUT_SECONDS,
            )
        except SSRFBlockedError:
            metrics.record_ssrf_block()
            raise
        except (BrowserSandboxTimeoutError, BrowserSandboxError):
            raise

    report, saved_path = build_sandbox_report(raw, scan_id=scan_id)
    save_sandbox_run(report, screenshot_path=saved_path)
    return report


def get_sandbox_report(sandbox_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a persisted sandbox report safely."""
    clean_id = (sandbox_id or "").strip().upper()
    if not _SAFE_SANDBOX_ID_RE.match(clean_id):
        return None
    rep = get_sandbox_run_by_id(clean_id)
    if rep:
        rep.pop("_screenshot_path", None)
    return rep
