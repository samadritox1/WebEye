from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class ScanRequest(BaseModel):
    url: str = Field(..., description="The target URL or domain to evaluate")
    fetch_content: bool = Field(True, description="Whether to inspect live DOM & page behavior")
    deep_dns: bool = Field(True, description="Perform deep DNS SPF/DMARC resolution")
    refresh_intel: bool = Field(False, description="Bypass cached CTI results and force live lookups")

class BatchScanRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=25, description="List of URLs to batch scan")
    async_mode: Optional[bool] = Field(None, description="Run asynchronously as background job (default true on /api/v1/scan/batch)")
    fetch_content: bool = Field(False, description="Fetch HTML content for deeper heuristics")
    deep_dns: bool = Field(True, description="Perform deep DNS SPF/DMARC resolution")
    concurrency: Optional[int] = Field(None, ge=1, le=10, description="Max concurrent workers for this batch")

class ScoreContribution(BaseModel):
    engine: str
    engine_label: str
    factor: str
    label: str
    raw_points: float
    points: float = 0.0
    severity: str = "medium"
    evidence: Optional[str] = None


class MissingEvidenceItem(BaseModel):
    engine: str
    check: str
    reason: str
    impact: str = "medium"


class EngineScoreSummary(BaseModel):
    engine: str
    name: str
    score: float = Field(..., ge=0.0, le=100.0)
    weight: float
    weighted_score: float
    status: str = "evaluated"
    confidence: float = Field(100.0, ge=0.0, le=100.0)
    contributions: List[ScoreContribution] = Field(default_factory=list)
    missing_evidence: List[MissingEvidenceItem] = Field(default_factory=list)


class ThreatAnalysisResult(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0)
    entropy: float = 0.0
    is_ip_domain: bool = False
    suspicious_tld: Optional[str] = None
    homoglyph_detected: bool = False
    impersonated_brand: Optional[str] = None
    lexical_flags: List[str] = []
    content_flags: List[str] = []
    has_password_input: bool = False
    has_cross_origin_form: bool = False
    contributions: List[ScoreContribution] = Field(default_factory=list)
    missing_evidence: List[MissingEvidenceItem] = Field(default_factory=list)
    details: Dict[str, Any] = {}

class WebSecurityResult(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0)
    headers_grade: str = "N/A"
    missing_headers: List[str] = []
    present_headers: Dict[str, str] = {}
    hsts_enabled: bool = False
    csp_enabled: bool = False
    dns_records: Dict[str, List[str]] = {}
    spf_record: Optional[str] = None
    spf_status: str = "Not Found"
    dmarc_record: Optional[str] = None
    dmarc_status: str = "Not Found"
    redirect_chain: List[Dict[str, Any]] = []
    ip_address: Optional[str] = None
    asn_info: Optional[str] = None
    contributions: List[ScoreContribution] = Field(default_factory=list)
    missing_evidence: List[MissingEvidenceItem] = Field(default_factory=list)
    details: Dict[str, Any] = {}

class CertificateResult(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0)
    valid: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    san_domains: List[str] = []
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    age_days: Optional[int] = None
    days_until_expiry: Optional[int] = None
    is_free_automated_ca: bool = False
    is_wildcard: bool = False
    san_mismatch: bool = False
    signature_algorithm: Optional[str] = None
    tls_version: Optional[str] = None
    flags: List[str] = []
    contributions: List[ScoreContribution] = Field(default_factory=list)
    missing_evidence: List[MissingEvidenceItem] = Field(default_factory=list)
    details: Dict[str, Any] = {}

class ThreatIntelProviderResult(BaseModel):
    provider: str
    source: str
    status: str = "clean"  # matched, clean, unavailable, unconfigured
    matched: bool = False
    match_confidence: float = Field(0.0, ge=0.0, le=100.0)
    last_updated: Optional[str] = None
    provenance: str = ""
    reference_url: Optional[str] = None
    summary: str = ""
    tags: List[str] = Field(default_factory=list)
    cached: bool = False
    checked_at: Optional[str] = None


class ThreatIntelResult(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0)
    feed_hits: List[str] = []
    urlhaus_status: Optional[str] = None
    openphish_status: Optional[str] = None
    virustotal_status: Optional[str] = None
    gsb_status: Optional[str] = None
    phishtank_status: Optional[str] = None
    otx_status: Optional[str] = None
    abuseipdb_status: Optional[str] = None
    community_votes_malicious: int = 0
    community_votes_benign: int = 0
    confidence_score: float = 0.0
    cache_hits: int = 0
    tags: List[str] = []
    providers: List[ThreatIntelProviderResult] = Field(default_factory=list)
    contributions: List[ScoreContribution] = Field(default_factory=list)
    missing_evidence: List[MissingEvidenceItem] = Field(default_factory=list)
    details: Dict[str, Any] = {}

class CompositeScanReport(BaseModel):
    scan_id: str
    target_url: str
    target_domain: str
    timestamp: str
    overall_score: float
    verdict: str  # BENIGN, SUSPICIOUS, HIGH_RISK, MALICIOUS
    verdict_color: str  # emerald, amber, orange, rose
    summary: str
    confidence: float = 0.0
    confidence_level: str = "MEDIUM"
    confidence_reason: str = ""
    score_breakdown: List[ScoreContribution] = Field(default_factory=list)
    engine_scores: List[EngineScoreSummary] = Field(default_factory=list)
    missing_evidence: List[MissingEvidenceItem] = Field(default_factory=list)
    threat_analysis: ThreatAnalysisResult
    web_security: WebSecurityResult
    cert_validation: CertificateResult
    threat_intel: ThreatIntelResult
    mitigations: List[str] = []
    mitre_attack: Optional[Dict[str, Any]] = None

class CommunityReportRequest(BaseModel):
    url: str
    tags: List[str] = []
    notes: Optional[str] = None
    reported_by: Optional[str] = "Analyst"

class CommunityVoteRequest(BaseModel):
    indicator: str
    vote: str  # 'malicious' or 'benign'
    reason: Optional[str] = None

class IoCItem(BaseModel):
    id: int
    indicator: str
    indicator_type: str  # 'url', 'domain', 'ip'
    tags: List[str]
    first_seen: str
    last_seen: str
    confidence: float
    source: str
    status: str
    votes_malicious: int
    votes_benign: int
    notes: Optional[str] = None

class PlatformStats(BaseModel):
    total_scans: int
    malicious_detected: int
    suspicious_detected: int
    benign_detected: int
    total_iocs: int
    active_threat_feeds: int


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    risk_level: str = "neutral"
    score: Optional[float] = None
    degree: int = 0
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: str
    label: str
    evidence: str = ""


class InfrastructureCluster(BaseModel):
    cluster_id: str
    pivot_type: str
    pivot_node_id: str
    pivot_label: str
    severity: str = "info"
    title: str
    description: str = ""
    domains: List[str] = Field(default_factory=list)
    node_ids: List[str] = Field(default_factory=list)


class ThreatGraphResponse(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    clusters: List[InfrastructureCluster] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


class SandboxRequest(BaseModel):
    url: str = Field(..., description="Target URL or domain to execute inside the isolated browser sandbox")
    wait_seconds: float = Field(1.8, ge=0.2, le=6.0, description="Seconds to observe dynamic JS after page load")
    scan_id: Optional[str] = Field(None, description="Optional parent scan ID to link telemetry")


class SandboxRedirectHop(BaseModel):
    hop: int
    url: str
    status_code: Optional[int] = None
    method: str = "GET"
    resource_type: str = "Document"
    remote_ip: Optional[str] = None
    server: Optional[str] = None
    location: Optional[str] = None
    is_cross_origin: bool = False


class SandboxNetworkRequest(BaseModel):
    request_id: str = ""
    url: str
    domain: str = ""
    method: str = "GET"
    resource_type: str = "Other"
    status_code: Optional[int] = None
    mime_type: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    is_third_party: bool = False
    blocked: bool = False
    blocked_reason: Optional[str] = None
    failed: bool = False
    error_text: Optional[str] = None
    initiator_type: Optional[str] = None


class SandboxFormDestination(BaseModel):
    form_index: int
    action_raw: str = ""
    action_url: str = ""
    action_domain: str = ""
    method: str = "GET"
    is_cross_origin: bool = False
    has_password_input: bool = False
    has_credential_fields: bool = False
    has_payment_fields: bool = False
    input_count: int = 0
    hidden_inputs_count: int = 0
    input_names: List[str] = Field(default_factory=list)
    submit_labels: List[str] = Field(default_factory=list)


class SandboxSuspiciousScript(BaseModel):
    script_id: str
    source_type: str = "inline"  # inline, external, runtime_eval, runtime_hook
    url: Optional[str] = None
    severity: str = "medium"
    reasons: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)
    eval_count: int = 0
    snippet_preview: str = ""


class SandboxReport(BaseModel):
    sandbox_id: str
    scan_id: Optional[str] = None
    target_url: str
    final_url: str
    target_domain: str
    final_domain: str = ""
    page_title: str = ""
    timestamp: str
    status: str = "completed"
    sandbox_score: float = 0.0
    verdict: str = "BENIGN"
    summary: str = ""
    browser_product: str = ""
    execution_ms: int = 0
    isolated_worker_pid: Optional[int] = None
    screenshot_available: bool = False
    screenshot_url: Optional[str] = None
    redirect_chain: List[SandboxRedirectHop] = Field(default_factory=list)
    network_requests: List[SandboxNetworkRequest] = Field(default_factory=list)
    blocked_requests: List[SandboxNetworkRequest] = Field(default_factory=list)
    form_destinations: List[SandboxFormDestination] = Field(default_factory=list)
    suspicious_scripts: List[SandboxSuspiciousScript] = Field(default_factory=list)
    runtime_exfil_targets: List[Dict[str, Any]] = Field(default_factory=list)
    telemetry: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    mitre_attack: Optional[Dict[str, Any]] = None


class EmailAnalysisRequest(BaseModel):
    filename: str = Field("message.eml", description="Original .eml filename")
    eml_content: str = Field(..., description="Raw RFC 822 / .eml email content")
    verify_dns: bool = Field(True, description="Perform live DNS SPF, DKIM selector, and DMARC lookups")


class EmailAuthenticationResult(BaseModel):
    spf_status: str
    spf_domain: Optional[str] = None
    spf_record: Optional[str] = None
    spf_aligned: Optional[bool] = None
    dkim_status: str
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    dkim_body_hash_valid: Optional[bool] = None
    dkim_signature_valid: Optional[bool] = None
    dkim_aligned: Optional[bool] = None
    dmarc_status: str
    dmarc_domain: Optional[str] = None
    dmarc_policy: Optional[str] = None
    dmarc_record: Optional[str] = None
    dmarc_result: str = "fail"
    auth_results_headers: List[str] = Field(default_factory=list)


class EmailSenderSpoofing(BaseModel):
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to_address: str = ""
    reply_to_domain: str = ""
    return_path_address: str = ""
    return_path_domain: str = ""
    spoofing_detected: bool = False
    impersonated_brand: Optional[str] = None
    indicators: List[str] = Field(default_factory=list)


class EmailEmbeddedUrl(BaseModel):
    url: str
    domain: str = ""
    anchor_text: str = ""
    anchor_mismatch: bool = False
    score: float = 0.0
    verdict: str = "BENIGN"
    ioc_match: Optional[str] = None
    flags: List[str] = Field(default_factory=list)


class EmailAttachmentFinding(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    sha256: str = ""
    md5: str = ""
    declared_extension: str = ""
    detected_magic_type: str = "unknown"
    extension_mismatch: bool = False
    is_dangerous: bool = False
    risk_score: float = 0.0
    verdict: str = "BENIGN"
    findings: List[str] = Field(default_factory=list)
    archive_entries: List[str] = Field(default_factory=list)
    extracted_urls: List[str] = Field(default_factory=list)


class EmailAnalysisReport(BaseModel):
    email_id: str
    filename: str
    timestamp: str
    subject: str = ""
    date_header: str = ""
    message_id: str = ""
    overall_score: float = 0.0
    verdict: str = "BENIGN"
    summary: str = ""
    isolated_worker_pid: Optional[int] = None
    authentication: EmailAuthenticationResult
    sender: EmailSenderSpoofing
    received_hops: List[Dict[str, Any]] = Field(default_factory=list)
    headers: List[Dict[str, str]] = Field(default_factory=list)
    header_anomalies: List[str] = Field(default_factory=list)
    embedded_urls: List[EmailEmbeddedUrl] = Field(default_factory=list)
    attachments: List[EmailAttachmentFinding] = Field(default_factory=list)
    mitigations: List[str] = Field(default_factory=list)
    mitre_attack: Optional[Dict[str, Any]] = None


class MitreTechniqueFinding(BaseModel):
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    mitre_url: Optional[str] = None
    summary: Optional[str] = None
    severity: str = "medium"
    confidence: float = 80.0
    observed_behaviors: List[str] = Field(default_factory=list)
    source_engines: List[str] = Field(default_factory=list)
    hunting_pivots: List[str] = Field(default_factory=list)
    investigation_questions: List[str] = Field(default_factory=list)
    detection_guidance: Optional[str] = None
    mitigation: Optional[str] = None

    model_config = {"extra": "allow"}


class MitreTacticColumn(BaseModel):
    tactic_id: str
    tactic_name: str
    tactic_short: Optional[str] = None
    detected_count: int = 0
    total_count: int = 0
    techniques: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = {"extra": "allow"}


class MitrePlaybookPhase(BaseModel):
    phase: str
    objective: str
    pivots: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)

    model_config = {"extra": "allow"}


class MitreInvestigationReport(BaseModel):
    context_label: str
    source_id: Optional[str] = None
    investigation_priority: str
    attack_narrative: str
    summary: Dict[str, Any] = Field(default_factory=dict)
    techniques: List[MitreTechniqueFinding] = Field(default_factory=list)
    tactic_matrix: List[MitreTacticColumn] = Field(default_factory=list)
    playbook: List[MitrePlaybookPhase] = Field(default_factory=list)

    model_config = {"extra": "allow"}


class BatchJobCreatedResponse(BaseModel):
    job_id: str
    status: str
    total_urls: int
    completed_urls: int = 0
    failed_urls: int = 0
    progress_pct: float = 0.0
    concurrency_limit: int
    status_url: str
    created_at: str

    model_config = {"extra": "allow"}


class BatchJobStatusResponse(BaseModel):
    job_id: str
    status: str
    total_urls: int
    completed_urls: int = 0
    failed_urls: int = 0
    progress_pct: float = 0.0
    concurrency_limit: int
    requested_by: Optional[str] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    results: List[Dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    model_config = {"extra": "allow"}


class AuthTokenRequest(BaseModel):
    api_key: Optional[str] = Field(None, description="API key (or provide X-API-Key header)")
    subject: str = Field("soc-analyst", description="Token subject claim")
    ttl_minutes: Optional[int] = Field(None, ge=1, le=1440, description="Token lifetime in minutes")


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    subject: str

