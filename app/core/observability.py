import contextvars
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from app.config import settings
from app.models.database import check_db_ready

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_actor_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("actor", default="anonymous")

_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+", re.IGNORECASE)
_QUERY_SECRET_RE = re.compile(
    r"([?&](?:api_key|apikey|token|secret|key|password)=)[^&\s]+",
    re.IGNORECASE,
)
_HEADER_SECRET_RE = re.compile(
    r"((?:x-api-key|authorization|api_key|jwt_secret_key)\s*[:=]\s*['\"]?)[^\s,'\";}]+",
    re.IGNORECASE,
)


def set_request_context(request_id: str, actor: str = "anonymous") -> Tuple[contextvars.Token, contextvars.Token]:
    return _request_id_ctx.set(request_id), _actor_ctx.set(actor)


def set_actor_context(actor: str) -> None:
    _actor_ctx.set(actor)


def reset_request_context(tokens: Tuple[contextvars.Token, contextvars.Token]) -> None:
    req_tok, actor_tok = tokens
    _request_id_ctx.reset(req_tok)
    _actor_ctx.reset(actor_tok)


def get_request_id() -> str:
    return _request_id_ctx.get()


def redact_sensitive_text(text: Any) -> str:
    """Mask bearer tokens, API keys, and configured credentials before emitting logs."""
    raw = str(text or "")
    if not raw:
        return ""
    masked = _BEARER_RE.sub(r"\1[REDACTED]", raw)
    masked = _QUERY_SECRET_RE.sub(r"\1[REDACTED]", masked)
    masked = _HEADER_SECRET_RE.sub(r"\1[REDACTED]", masked)

    # Also redact explicit configured secrets if present cleanly
    for secret in (
        settings.JWT_SECRET_KEY,
        *settings.API_KEYS,
        settings.VIRUSTOTAL_API_KEY,
        settings.GOOGLE_SAFE_BROWSING_API_KEY,
        settings.PHISHTANK_API_KEY,
        settings.URLHAUS_API_KEY,
        settings.ABUSEIPDB_API_KEY,
        settings.OTX_API_KEY,
    ):
        if secret and len(secret) >= 8 and secret in masked:
            masked = masked.replace(secret, "[REDACTED]")
    return masked


def _redact_obj(val: Any) -> Any:
    if isinstance(val, str):
        return redact_sensitive_text(val)
    if isinstance(val, dict):
        out = {}
        for k, v in val.items():
            low_k = str(k).lower()
            if any(s in low_k for s in ("secret", "password", "token", "api_key", "authorization")):
                out[k] = "[REDACTED]"
            else:
                out[k] = _redact_obj(v)
        return out
    if isinstance(val, (list, tuple)):
        return [_redact_obj(item) for item in val]
    return val


class StructuredJsonFormatter(logging.Formatter):
    """Single-line structured JSON formatter with request correlation & secret redaction."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", None) or _request_id_ctx.get(),
            "actor": getattr(record, "actor", None) or _actor_ctx.get(),
            "message": redact_sensitive_text(record.getMessage()),
        }
        event = getattr(record, "event", None)
        if event:
            payload["event"] = event
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict) and fields:
            payload.update(_redact_obj(fields))
        if record.exc_info:
            payload["exception"] = redact_sensitive_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging() -> logging.Logger:
    """Configure root PhishPulse logger idempotently from Settings."""
    app_logger = logging.getLogger("phishpulse")
    level = getattr(logging, settings.LOG_LEVEL, logging.INFO)
    app_logger.setLevel(level)

    if not getattr(app_logger, "_phishpulse_configured", False):
        handler = logging.StreamHandler()
        if settings.LOG_FORMAT == "json":
            handler.setFormatter(StructuredJsonFormatter())
        else:
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            ))
        app_logger.handlers.clear()
        app_logger.addHandler(handler)
        app_logger.propagate = False
        app_logger._phishpulse_configured = True  # type: ignore[attr-defined]
    return app_logger


def get_logger(name: str = "phishpulse") -> logging.Logger:
    configure_logging()
    return logging.getLogger(name if name.startswith("phishpulse") else f"phishpulse.{name}")


def normalize_path_group(path: str) -> str:
    """Collapse dynamic path parameters into low-cardinality Prometheus labels."""
    if not path:
        return "/"
    p = re.sub(r"/SCN-[A-Za-z0-9_-]+", "/{scan_id}", path)
    p = re.sub(r"/SBX-[A-Za-z0-9_-]+", "/{sandbox_id}", p)
    p = re.sub(r"/EML-[A-Za-z0-9_-]+", "/{email_id}", p)
    p = re.sub(r"/JOB-[A-Za-z0-9_-]+", "/{job_id}", p)
    return p


class MetricsRegistry:
    """Thread-safe in-process metrics collector with Prometheus & JSON export."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._http_requests: Dict[Tuple[str, str, int], int] = defaultdict(int)
            self._http_duration_sum_ms: float = 0.0
            self._http_duration_count: int = 0
            self._scans_total: Dict[str, int] = defaultdict(int)
            self._scan_duration_sum_ms: float = 0.0
            self._scan_duration_count: int = 0
            self._scan_errors_total: int = 0
            self._ssrf_blocks_total: int = 0
            self._batch_jobs_total: Dict[str, int] = defaultdict(int)
            self._auth_failures_total: int = 0
            self._rate_limited_total: int = 0
            self._active_scans: int = 0
            self._peak_active_scans: int = 0
            self._active_sandbox_runs: int = 0
            self._active_batch_jobs: int = 0

    def record_http_request(self, method: str, path: str, status_code: int, duration_ms: float) -> None:
        group = normalize_path_group(path)
        with self._lock:
            self._http_requests[(method.upper(), group, int(status_code))] += 1
            self._http_duration_sum_ms += max(0.0, float(duration_ms))
            self._http_duration_count += 1

    def record_scan(self, verdict: str, duration_ms: float) -> None:
        with self._lock:
            self._scans_total[str(verdict or "UNKNOWN").upper()] += 1
            self._scan_duration_sum_ms += max(0.0, float(duration_ms))
            self._scan_duration_count += 1

    def record_scan_error(self) -> None:
        with self._lock:
            self._scan_errors_total += 1

    def record_ssrf_block(self) -> None:
        with self._lock:
            self._ssrf_blocks_total += 1

    def record_batch_job(self, status: str) -> None:
        with self._lock:
            self._batch_jobs_total[str(status or "unknown").lower()] += 1

    def record_auth_failure(self) -> None:
        with self._lock:
            self._auth_failures_total += 1

    def record_rate_limited(self) -> None:
        with self._lock:
            self._rate_limited_total += 1

    def inc_active_scans(self, delta: int) -> None:
        with self._lock:
            self._active_scans = max(0, self._active_scans + delta)
            if self._active_scans > self._peak_active_scans:
                self._peak_active_scans = self._active_scans

    def inc_active_sandbox(self, delta: int) -> None:
        with self._lock:
            self._active_sandbox_runs = max(0, self._active_sandbox_runs + delta)

    def inc_active_batch_jobs(self, delta: int) -> None:
        with self._lock:
            self._active_batch_jobs = max(0, self._active_batch_jobs + delta)

    def snapshot_json(self) -> Dict[str, Any]:
        with self._lock:
            avg_http_ms = (
                round(self._http_duration_sum_ms / self._http_duration_count, 2)
                if self._http_duration_count else 0.0
            )
            avg_scan_ms = (
                round(self._scan_duration_sum_ms / self._scan_duration_count, 2)
                if self._scan_duration_count else 0.0
            )
            total_requests = sum(self._http_requests.values())
            by_status: Dict[str, int] = defaultdict(int)
            for (_, _, code), count in self._http_requests.items():
                by_status[f"{code // 100}xx"] += count

            return {
                "uptime_seconds": round(time.time() - settings.APP_STARTED_AT, 2),
                "http": {
                    "total_requests": total_requests,
                    "avg_latency_ms": avg_http_ms,
                    "status_classes": dict(by_status),
                },
                "scanning": {
                    "total_scans": sum(self._scans_total.values()),
                    "by_verdict": dict(self._scans_total),
                    "avg_scan_ms": avg_scan_ms,
                    "scan_errors_total": self._scan_errors_total,
                    "ssrf_blocks_total": self._ssrf_blocks_total,
                    "active_scans": self._active_scans,
                    "peak_active_scans": self._peak_active_scans,
                    "scan_max_concurrency": settings.SCAN_MAX_CONCURRENCY,
                    "active_sandbox_runs": self._active_sandbox_runs,
                    "sandbox_max_concurrency": settings.SANDBOX_MAX_CONCURRENCY,
                },
                "batch_jobs": {
                    "by_status": dict(self._batch_jobs_total),
                    "active_jobs": self._active_batch_jobs,
                    "worker_concurrency": settings.BATCH_WORKER_CONCURRENCY,
                },
                "security": {
                    "auth_failures_total": self._auth_failures_total,
                    "rate_limited_total": self._rate_limited_total,
                },
            }

    def render_prometheus(self) -> str:
        with self._lock:
            lines = [
                "# HELP phishpulse_uptime_seconds Application uptime in seconds.",
                "# TYPE phishpulse_uptime_seconds gauge",
                f"phishpulse_uptime_seconds {round(time.time() - settings.APP_STARTED_AT, 2)}",
                "# HELP phishpulse_http_requests_total Total HTTP requests processed.",
                "# TYPE phishpulse_http_requests_total counter",
            ]
            for (method, group, code), count in sorted(self._http_requests.items()):
                lines.append(
                    f'phishpulse_http_requests_total{{method="{method}",path="{group}",status="{code}"}} {count}'
                )
            lines.extend([
                "# HELP phishpulse_http_request_duration_ms_sum Cumulative HTTP request duration in ms.",
                "# TYPE phishpulse_http_request_duration_ms_sum counter",
                f"phishpulse_http_request_duration_ms_sum {round(self._http_duration_sum_ms, 2)}",
                "# HELP phishpulse_http_request_duration_ms_count Total HTTP requests timed.",
                "# TYPE phishpulse_http_request_duration_ms_count counter",
                f"phishpulse_http_request_duration_ms_count {self._http_duration_count}",
                "# HELP phishpulse_scans_total Total URL scans completed by verdict.",
                "# TYPE phishpulse_scans_total counter",
            ])
            for verdict, count in sorted(self._scans_total.items()):
                lines.append(f'phishpulse_scans_total{{verdict="{verdict}"}} {count}')
            lines.extend([
                "# HELP phishpulse_scan_errors_total Total URL scan errors.",
                "# TYPE phishpulse_scan_errors_total counter",
                f"phishpulse_scan_errors_total {self._scan_errors_total}",
                "# HELP phishpulse_ssrf_blocks_total Total SSRF targets rejected.",
                "# TYPE phishpulse_ssrf_blocks_total counter",
                f"phishpulse_ssrf_blocks_total {self._ssrf_blocks_total}",
                "# HELP phishpulse_active_scans Current active concurrent URL scans.",
                "# TYPE phishpulse_active_scans gauge",
                f"phishpulse_active_scans {self._active_scans}",
                "# HELP phishpulse_peak_active_scans Observed peak concurrent URL scans.",
                "# TYPE phishpulse_peak_active_scans gauge",
                f"phishpulse_peak_active_scans {self._peak_active_scans}",
                "# HELP phishpulse_active_sandbox_runs Current active isolated browser sandboxes.",
                "# TYPE phishpulse_active_sandbox_runs gauge",
                f"phishpulse_active_sandbox_runs {self._active_sandbox_runs}",
                "# HELP phishpulse_active_batch_jobs Current running async batch jobs.",
                "# TYPE phishpulse_active_batch_jobs gauge",
                f"phishpulse_active_batch_jobs {self._active_batch_jobs}",
                "# HELP phishpulse_rate_limited_total Requests rejected with HTTP 429.",
                "# TYPE phishpulse_rate_limited_total counter",
                f"phishpulse_rate_limited_total {self._rate_limited_total}",
                "# HELP phishpulse_auth_failures_total Requests rejected with HTTP 401.",
                "# TYPE phishpulse_auth_failures_total counter",
                f"phishpulse_auth_failures_total {self._auth_failures_total}",
            ])
            return "\n".join(lines) + "\n"


metrics = MetricsRegistry()


def build_liveness_report() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "uptime_seconds": round(time.time() - settings.APP_STARTED_AT, 2),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def build_readiness_report() -> Tuple[bool, Dict[str, Any]]:
    checks: Dict[str, Any] = {}
    overall_ok = True

    try:
        db_state = check_db_ready()
        checks["database"] = {"status": "ok" if db_state["ok"] else "degraded", **db_state}
        if not db_state["ok"]:
            overall_ok = False
    except Exception as exc:
        checks["database"] = {"status": "error", "detail": str(exc)}
        overall_ok = False

    try:
        settings.SANDBOX_SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        writable = os.access(settings.SANDBOX_SCREENSHOTS_DIR, os.W_OK)
        checks["storage"] = {"status": "ok" if writable else "error", "writable": writable}
        if not writable:
            overall_ok = False
    except Exception as exc:
        checks["storage"] = {"status": "error", "detail": str(exc)}
        overall_ok = False

    posture = settings.validate_security_posture()
    checks["security_posture"] = {
        "status": "warning" if posture["warnings"] else "ok",
        **posture,
    }

    report = {
        "status": "ready" if overall_ok else "not_ready",
        "version": settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }
    return overall_ok, report
