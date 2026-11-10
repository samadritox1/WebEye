import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.core.batch_manager import batch_manager
from app.core.browser_sandbox import (
    BrowserSandboxError,
    BrowserSandboxTimeoutError,
    execute_browser_sandbox,
    get_sandbox_report,
    resolve_screenshot_path,
)
from app.core.email_analyzer import (
    EmailPhishingAnalyzer,
    extract_eml_from_http_request,
)
from app.core.mitre_mapper import build_mitre_report_for_target
from app.core.observability import (
    build_liveness_report,
    build_readiness_report,
    configure_logging,
    get_logger,
    metrics,
)
from app.core.scoring_engine import ScoringEngine
from app.core.security_guard import SSRFBlockedError, validate_target_url
from app.core.security_middleware import (
    AuthManager,
    api_security_and_observability_middleware,
)
from app.core.threat_graph import build_threat_graph_from_db
from app.export.pdf_exporter import PDFIncidentReportExporter
from app.export.stix_exporter import STIX21Exporter
from app.models.database import (
    add_ioc,
    get_all_iocs,
    get_email_scan_by_id,
    get_recent_email_scans,
    get_recent_sandbox_runs,
    get_recent_scans,
    get_scan_by_id,
    get_schema_status,
    get_stats,
    init_db,
    record_vote,
)
from app.models.schemas import (
    AuthTokenRequest,
    AuthTokenResponse,
    BatchJobCreatedResponse,
    BatchJobStatusResponse,
    BatchScanRequest,
    CommunityReportRequest,
    CommunityVoteRequest,
    CompositeScanReport,
    EmailAnalysisReport,
    EmailAnalysisRequest,
    IoCItem,
    MitreInvestigationReport,
    PlatformStats,
    SandboxReport,
    SandboxRequest,
    ScanRequest,
    ThreatGraphResponse,
)

logger = get_logger("phishpulse.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    init_db()
    posture = settings.validate_security_posture()
    logger.info(
        f"Started {settings.APP_NAME} v{settings.APP_VERSION} ({settings.ENVIRONMENT})",
        extra={"event": "app_startup", "fields": posture},
    )
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Intelligence platform detecting phishing and malicious websites combining threat analysis, "
        "web security assessment, certificate validation, and collaborative threat intelligence."
    ),
    lifespan=lifespan,
)

# Register security & structured logging middleware inside CORS so error responses retain CORS headers
app.middleware("http")(api_security_and_observability_middleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

scoring_engine = ScoringEngine()
email_analyzer = EmailPhishingAnalyzer()

# Mount static assets
static_path = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")


def _validate_target_or_track(url: str) -> str:
    try:
        return validate_target_url(url)
    except SSRFBlockedError:
        metrics.record_ssrf_block()
        raise


# --- Dashboard UI & Top-Level Health / Metrics ---

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_file = static_path / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>WebEye Platform Loading...</h1>")


@app.get("/legacy", response_class=HTMLResponse)
async def serve_legacy_dashboard():
    index_file = static_path / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    raise HTTPException(status_code=404, detail="Legacy dashboard not found")


@app.get("/health")
async def liveness_probe():
    """Lightweight liveness check."""
    return build_liveness_report()


@app.get("/ready")
async def readiness_probe():
    """Readiness probe verifying database connectivity, migrations, and storage writability."""
    is_ready, report = build_readiness_report()
    return JSONResponse(status_code=200 if is_ready else 503, content=report)


@app.get("/metrics")
async def prometheus_metrics():
    """Export metrics in Prometheus 0.0.4 exposition format."""
    return PlainTextResponse(metrics.render_prometheus(), media_type="text/plain; version=0.0.4")


# --- Shared Versioned API Router ---

api_router = APIRouter()
v1_batch_router = APIRouter()
legacy_batch_router = APIRouter()


@api_router.get("/health")
async def api_liveness_probe():
    return build_liveness_report()


@api_router.get("/ready")
async def api_readiness_probe():
    is_ready, report = build_readiness_report()
    return JSONResponse(status_code=200 if is_ready else 503, content=report)


@api_router.get("/metrics")
async def api_metrics_snapshot(request: Request):
    accept = request.headers.get("accept", "")
    if "text/plain" in accept:
        return PlainTextResponse(metrics.render_prometheus(), media_type="text/plain; version=0.0.4")
    return metrics.snapshot_json()


@api_router.get("/config/security")
async def security_posture_config():
    """Return redacted configuration summary, DB migration status, and security posture warnings."""
    return {
        "settings": settings.redacted_summary(),
        "security_posture": settings.validate_security_posture(),
        "database": get_schema_status(),
    }


@api_router.get("/auth/status")
async def auth_status(request: Request):
    """Inspect whether API authentication is enforced and validate caller credentials if present."""
    ok, actor, err = AuthManager.authenticate_request(request)
    return {
        "auth_required": AuthManager.is_enforced(),
        "authenticated": ok and actor != "anonymous",
        "actor": actor if ok else "unauthenticated",
        "detail": err,
    }


@api_router.post("/auth/token", response_model=AuthTokenResponse)
async def issue_auth_token(request: Request, body: Optional[AuthTokenRequest] = None):
    """Exchange a configured API key (header X-API-Key or JSON api_key) for a short-lived Bearer JWT."""
    candidate_key = request.headers.get("X-API-Key", "").strip()
    if not candidate_key and body and body.api_key:
        candidate_key = body.api_key.strip()

    if not settings.API_KEYS:
        raise HTTPException(
            status_code=503,
            detail="API key authentication is not configured (set PHISHPULSE_API_KEYS in environment).",
        )

    matched_actor = AuthManager.verify_api_key(candidate_key)
    if not matched_actor:
        metrics.record_auth_failure()
        raise HTTPException(status_code=401, detail="Invalid API key credential")

    subject = (body.subject.strip() if body and body.subject else "") or matched_actor
    ttl = body.ttl_minutes if body else None
    return AuthManager.issue_jwt(subject=subject, ttl_minutes=ttl)


# --- Scan & Async Bounded Batch Endpoints ---

@api_router.post("/scan", response_model=CompositeScanReport)
async def run_scan(request: ScanRequest):
    """Perform comprehensive multi-engine threat assessment on target URL."""
    clean_url = _validate_target_or_track(request.url)
    try:
        return await scoring_engine.execute_scan(
            url=clean_url,
            fetch_content=request.fetch_content,
            deep_dns=request.deep_dns,
            refresh_intel=request.refresh_intel,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")


async def _handle_batch_submission(request: BatchScanRequest, raw_request: Request, default_async: bool):
    use_async = default_async if request.async_mode is None else bool(request.async_mode)
    actor = getattr(raw_request.state, "actor", "anonymous")

    if use_async:
        job = await batch_manager.enqueue_batch(
            urls=request.urls,
            scoring_engine=scoring_engine,
            concurrency=request.concurrency,
            fetch_content=request.fetch_content,
            deep_dns=request.deep_dns,
            requested_by=actor,
        )
        prefix = settings.API_V1_PREFIX
        payload = {
            **job,
            "status_url": f"{prefix}/jobs/{job['job_id']}",
        }
        return JSONResponse(status_code=202, content=payload)

    batch_out = await batch_manager.run_bounded_batch(
        urls=request.urls,
        scoring_engine=scoring_engine,
        concurrency=request.concurrency,
        fetch_content=request.fetch_content,
        deep_dns=request.deep_dns,
    )
    return batch_out


@v1_batch_router.post("/scan/batch")
async def run_v1_batch_scan(request: BatchScanRequest, raw_request: Request):
    """Submit a batch URL scan asynchronously by default (202 Accepted) or bounded-sync when async_mode=false."""
    return await _handle_batch_submission(request, raw_request, default_async=True)


@legacy_batch_router.post("/scan/batch")
async def run_legacy_batch_scan(request: BatchScanRequest, raw_request: Request):
    """Legacy batch URL scan supporting bounded concurrency sync mode (default) or async_mode=true."""
    return await _handle_batch_submission(request, raw_request, default_async=False)


@api_router.post("/jobs/batch", response_model=BatchJobCreatedResponse, status_code=202)
async def enqueue_async_batch_job(request: BatchScanRequest, raw_request: Request):
    """Queue an asynchronous bounded-concurrency batch scan job and return job tracking metadata immediately."""
    actor = getattr(raw_request.state, "actor", "anonymous")
    job = await batch_manager.enqueue_batch(
        urls=request.urls,
        scoring_engine=scoring_engine,
        concurrency=request.concurrency,
        fetch_content=request.fetch_content,
        deep_dns=request.deep_dns,
        requested_by=actor,
    )
    return {
        **job,
        "status_url": f"{settings.API_V1_PREFIX}/jobs/{job['job_id']}",
    }


@api_router.get("/jobs")
async def list_async_batch_jobs(limit: int = Query(20, ge=1, le=100)):
    """List recent asynchronous batch jobs."""
    return batch_manager.recent_jobs(limit=limit)


@api_router.get("/jobs/{job_id}", response_model=BatchJobStatusResponse)
async def get_async_batch_job_status(job_id: str):
    """Retrieve live progress, verdict summary, and per-URL results for a batch job."""
    job = batch_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Batch job ID not found")
    return job


@api_router.post("/jobs/{job_id}/cancel", response_model=BatchJobStatusResponse)
async def cancel_async_batch_job(job_id: str):
    """Cooperatively cancel an active or queued batch job."""
    job = batch_manager.cancel_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Batch job ID not found")
    return job


@api_router.get("/scans")
async def list_recent_scans(limit: int = Query(20, ge=1, le=100)):
    """Retrieve historical scan logs."""
    return get_recent_scans(limit=limit)


@api_router.get("/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    """Retrieve full audit report for a specific scan ID."""
    report = get_scan_by_id(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return report


# --- Collaborative Threat Intel Endpoints ---

@api_router.get("/iocs")
async def list_iocs(tag: Optional[str] = None, limit: int = Query(50, ge=1, le=200)):
    """Query collaborative Threat IoCs and community threat indicators."""
    return get_all_iocs(limit=limit, tag=tag)


@api_router.post("/community/report")
async def submit_community_report(report_req: CommunityReportRequest):
    """Submit suspicious indicator to the collaborative threat intelligence pool."""
    clean_url = _validate_target_or_track(report_req.url)
    ioc_id = add_ioc(
        indicator=clean_url,
        indicator_type="url",
        tags=report_req.tags or ["#community_submission"],
        source=f"Community Analyst ({report_req.reported_by})",
        confidence=85.0,
        notes=report_req.notes or "User-submitted suspicious phishing indicator",
    )
    return {"status": "success", "ioc_id": ioc_id, "message": "Threat IoC registered successfully"}


@api_router.post("/community/vote")
async def vote_on_threat(vote_req: CommunityVoteRequest, request: Request):
    """Cast a community consensus vote on an indicator (malicious or benign)."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    record_vote(
        indicator=vote_req.indicator,
        vote=vote_req.vote,
        reason=vote_req.reason or "",
        voter_ip=client_ip,
    )
    return {"status": "success", "message": f"Recorded {vote_req.vote} vote for {vote_req.indicator}"}


# --- STIX 2.1 & PDF Incident Report Export Endpoints ---

@api_router.get("/export/stix/{scan_id}")
async def export_stix_scan(scan_id: str):
    """Export a scan report into standard STIX 2.1 JSON bundle for SIEM/EDR."""
    report = get_scan_by_id(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    stix_bundle = STIX21Exporter.generate_stix_bundle(report)
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", scan_id) or "report"
    return JSONResponse(
        content=stix_bundle,
        headers={"Content-Disposition": f"attachment; filename=stix_{safe_id}.json"},
    )


@api_router.get("/export/pdf/{scan_id}")
async def export_pdf_scan(scan_id: str):
    """Generate and download an automated PDF Incident Report for a scan ID."""
    report = get_scan_by_id(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    stix_bundle = STIX21Exporter.generate_stix_bundle(report)
    pdf_bytes = PDFIncidentReportExporter.generate_pdf_report(report, stix_bundle=stix_bundle)
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", scan_id) or "report"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=incident_report_{safe_id}.pdf"},
    )


@api_router.get("/export/stix")
async def export_stix_feed():
    """Export all active community threat IoCs as a STIX 2.1 Threat Feed bundle."""
    iocs = get_all_iocs(limit=500)
    stix_bundle = STIX21Exporter.generate_feed_bundle(iocs)
    return JSONResponse(
        content=stix_bundle,
        headers={"Content-Disposition": "attachment; filename=phishpulse_threat_feed_stix21.json"},
    )


@api_router.get("/stats")
async def platform_stats():
    """Retrieve real-time platform statistics."""
    return get_stats()


@api_router.get("/graph", response_model=ThreatGraphResponse)
async def get_threat_graph(
    scan_id: Optional[str] = Query(None, description="Focus graph around a specific scan and its related infrastructure"),
    q: Optional[str] = Query(None, description="Filter graph nodes matching domain, IP, certificate, provider, or campaign"),
    threats_only: bool = Query(False, description="Only include suspicious/high-risk/malicious entities and their infrastructure"),
    limit: int = Query(120, ge=1, le=250, description="Maximum recent scan records to correlate"),
):
    """Build correlated Threat Relationship Graph connecting domains, IPs, certs, URLs, hosting providers, and campaigns."""
    return build_threat_graph_from_db(
        scan_id=scan_id,
        query=q,
        threats_only=threats_only,
        limit=limit,
    )


# --- Browser-Based Phishing Sandbox Endpoints ---

@api_router.post("/sandbox", response_model=SandboxReport)
async def run_browser_sandbox_endpoint(request: SandboxRequest):
    """Execute target URL inside an isolated headless browser sandbox and capture screenshot & telemetry."""
    clean_url = _validate_target_or_track(request.url)
    try:
        return await execute_browser_sandbox(
            url=clean_url,
            wait_seconds=request.wait_seconds,
            scan_id=request.scan_id,
        )
    except HTTPException:
        raise
    except BrowserSandboxTimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc))
    except BrowserSandboxError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Sandbox execution error: {str(exc)}")


@api_router.get("/sandbox")
async def list_sandbox_runs(limit: int = Query(20, ge=1, le=100)):
    """List recent isolated browser sandbox executions."""
    return get_recent_sandbox_runs(limit=limit)


@api_router.get("/sandbox/{sandbox_id}", response_model=SandboxReport)
async def get_sandbox_details(sandbox_id: str):
    """Retrieve full forensic report for a browser sandbox run."""
    report = get_sandbox_report(sandbox_id)
    if not report:
        raise HTTPException(status_code=404, detail="Sandbox run ID not found")
    return report


@api_router.get("/sandbox/{sandbox_id}/screenshot")
async def get_sandbox_screenshot(sandbox_id: str):
    """Serve captured sandbox screenshot PNG safely."""
    img_path = resolve_screenshot_path(sandbox_id)
    if not img_path:
        raise HTTPException(status_code=404, detail="Sandbox screenshot not found")
    return FileResponse(str(img_path), media_type="image/png")


# --- Email (.eml) Phishing Analysis Endpoints ---

@api_router.post("/email/analyze", response_model=EmailAnalysisReport)
async def analyze_email_json(request: EmailAnalysisRequest):
    """Analyze raw RFC 822 / .eml content for SPF/DKIM/DMARC, spoofing, headers, URLs, and attachments."""
    try:
        raw_bytes = request.eml_content.encode("utf-8", errors="replace")
        return await email_analyzer.analyze_eml(
            raw_bytes=raw_bytes,
            filename=request.filename or "message.eml",
            verify_dns=request.verify_dns,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Email analysis error: {str(exc)}")


@api_router.post("/email/upload", response_model=EmailAnalysisReport)
async def upload_and_analyze_eml(
    request: Request,
    verify_dns: bool = Query(True, description="Perform live DNS SPF/DKIM/DMARC verification"),
):
    """Upload a .eml file (multipart/form-data or raw message/rfc822) and inspect safely."""
    raw_body = await request.body()
    if not raw_body:
        raise HTTPException(status_code=400, detail="Empty upload payload")
    if len(raw_body) > settings.MAX_EMAIL_BYTES + 131072:
        raise HTTPException(status_code=413, detail="Uploaded email exceeds maximum allowed size")

    content_type = request.headers.get("content-type", "")
    try:
        filename, eml_bytes = extract_eml_from_http_request(content_type, raw_body)
        return await email_analyzer.analyze_eml(
            raw_bytes=eml_bytes,
            filename=filename,
            verify_dns=verify_dns,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Email upload analysis error: {str(exc)}")


@api_router.get("/email/scans")
async def list_email_scans(limit: int = Query(20, ge=1, le=100)):
    """Retrieve historical .eml email phishing analyses."""
    return get_recent_email_scans(limit=limit)


@api_router.get("/email/scans/{email_id}", response_model=EmailAnalysisReport)
async def get_email_scan_details(email_id: str):
    """Retrieve complete forensic report for a specific .eml analysis."""
    report = get_email_scan_by_id(email_id)
    if not report:
        raise HTTPException(status_code=404, detail="Email analysis ID not found")
    return report


@api_router.get("/mitre", response_model=MitreInvestigationReport)
async def get_mitre_attack_report(
    scan_id: Optional[str] = None,
    sandbox_id: Optional[str] = None,
    email_id: Optional[str] = None,
    limit: int = 50,
):
    """Build an investigation-oriented MITRE ATT&CK matrix & hunting report for a target or workspace."""
    norm_scan = (scan_id or "").strip() or None
    norm_sbx = (sandbox_id or "").strip() or None
    norm_eml = (email_id or "").strip() or None
    bounded_limit = max(1, min(int(limit), 200))

    report = build_mitre_report_for_target(
        scan_id=norm_scan,
        sandbox_id=norm_sbx,
        email_id=norm_eml,
        limit=bounded_limit,
    )
    if report.get("not_found"):
        raise HTTPException(status_code=404, detail=report["not_found"])
    return report


@api_router.get("/engine-metadata")
async def engine_metadata():
    """Retrieve internal detection heuristics, weights, seed counts, and pipeline metadata."""
    stats = get_stats()
    return {
        "pipeline": [
            {
                "id": "engine_1",
                "name": "Heuristic Threat Analyzer",
                "weight": settings.WEIGHT_THREAT_ANALYSIS,
                "weight_percent": f"{int(settings.WEIGHT_THREAT_ANALYSIS * 100)}%",
                "description": (
                    "Lexical analysis, Shannon entropy, homoglyph lookalike matching, "
                    "brand impersonation distance, and credential form inspection."
                ),
                "metrics": {
                    "monitored_brands": 15,
                    "homoglyph_rules": 114,
                    "leetspeak_rules": 11,
                    "suspicious_tlds": 20,
                },
            },
            {
                "id": "engine_2",
                "name": "Web Security Posture Assessor",
                "weight": settings.WEIGHT_WEB_SECURITY,
                "weight_percent": f"{int(settings.WEIGHT_WEB_SECURITY * 100)}%",
                "description": (
                    "HTTP security headers grading (A+ to F), HSTS enforcement, "
                    "Content Security Policy (CSP), clickjacking defenses, and DNS SPF/DMARC resolution."
                ),
                "metrics": {
                    "mandatory_headers": [
                        "HSTS",
                        "CSP",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                        "Referrer-Policy",
                    ],
                    "dns_checks": ["SPF", "DMARC", "MX", "NS"],
                },
            },
            {
                "id": "engine_3",
                "name": "SSL/TLS Certificate Validator",
                "weight": settings.WEIGHT_CERT_VALIDATION,
                "weight_percent": f"{int(settings.WEIGHT_CERT_VALIDATION * 100)}%",
                "description": (
                    "Validates cryptographic certificate chain, Issuer CA authenticity, "
                    "SAN multi-domain coverage, certificate age, and expiry."
                ),
                "metrics": {
                    "trusted_roots": [
                        "DigiCert",
                        "Google Trust Services",
                        "Let's Encrypt",
                        "Sectigo",
                        "Apple Inc.",
                    ],
                    "fresh_cert_threshold_days": 3,
                },
            },
            {
                "id": "engine_4",
                "name": "Collaborative Threat Intel Hub",
                "weight": settings.WEIGHT_THREAT_INTEL,
                "weight_percent": f"{int(settings.WEIGHT_THREAT_INTEL * 100)}%",
                "description": (
                    "Cross-references active URLs against VirusTotal, Google Safe Browsing, "
                    "PhishTank, URLhaus (abuse.ch), AlienVault OTX, AbuseIPDB, and local IoCs with persistent caching."
                ),
                "metrics": {
                    "feeds": [
                        "VirusTotal v3",
                        "Google Safe Browsing v4",
                        "PhishTank",
                        "URLhaus (abuse.ch)",
                        "AlienVault OTX",
                        "AbuseIPDB",
                        "PhishPulse IoC Community",
                    ],
                    "cache_ttl_seconds": settings.CTI_CACHE_TTL_SECONDS,
                    "active_iocs": stats.get("total_iocs", 7),
                },
            },
        ],
        "scoring": {
            "threshold_high_malicious": 75.0,
            "threshold_suspicious": 50.0,
            "threshold_benign": 25.0,
            "export_format": "STIX 2.1 JSON",
        },
        "runtime": {
            "api_version": "v1",
            "scan_max_concurrency": settings.SCAN_MAX_CONCURRENCY,
            "batch_worker_concurrency": settings.BATCH_WORKER_CONCURRENCY,
            "sandbox_max_concurrency": settings.SANDBOX_MAX_CONCURRENCY,
            "rate_limit_enabled": settings.RATE_LIMIT_ENABLED,
            "auth_required": AuthManager.is_enforced(),
        },
    }


# Mount primary versioned API (/api/v1) and optional backward-compatible alias (/api)
app.include_router(v1_batch_router, prefix=settings.API_V1_PREFIX, tags=["v1"])
app.include_router(api_router, prefix=settings.API_V1_PREFIX, tags=["v1"])

if settings.ENABLE_LEGACY_API_ALIAS:
    app.include_router(legacy_batch_router, prefix=settings.API_PREFIX, tags=["legacy-api"])
    app.include_router(api_router, prefix=settings.API_PREFIX, tags=["legacy-api"])
