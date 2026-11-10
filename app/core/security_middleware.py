import hmac
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Optional, Tuple

import jwt
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from app.config import settings
from app.core.observability import (
    get_logger,
    metrics,
    reset_request_context,
    set_actor_context,
    set_request_context,
)

logger = get_logger("phishpulse.security")

_PUBLIC_PATHS = {
    "/",
    "/legacy",
    "/favicon.ico",
    "/health",
    "/ready",
    "/api/health",
    "/api/ready",
    "/api/v1/health",
    "/api/v1/ready",
    "/api/auth/token",
    "/api/v1/auth/token",
    "/api/auth/status",
    "/api/v1/auth/status",
    "/docs",
    "/openapi.json",
    "/redoc",
}

_HEAVY_SCAN_SUFFIXES = (
    "/scan",
    "/scan/batch",
    "/jobs/batch",
    "/sandbox",
    "/email/analyze",
    "/email/upload",
)


class AuthManager:
    """API Key + HMAC JWT authentication helper."""

    @staticmethod
    def is_enforced() -> bool:
        return bool(settings.AUTH_REQUIRED or settings.API_KEYS)

    @staticmethod
    def verify_api_key(candidate: str) -> Optional[str]:
        clean = (candidate or "").strip()
        if not clean or not settings.API_KEYS:
            return None
        for idx, allowed in enumerate(settings.API_KEYS, start=1):
            if hmac.compare_digest(clean.encode("utf-8"), allowed.encode("utf-8")):
                return f"apikey:{idx}:{settings.mask_secret(allowed)}"
        return None

    @staticmethod
    def issue_jwt(subject: str, scopes: Optional[list[str]] = None, ttl_minutes: Optional[int] = None) -> Dict[str, object]:
        exp_mins = int(ttl_minutes or settings.JWT_EXPIRY_MINUTES)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=exp_mins)
        payload = {
            "sub": subject,
            "iss": "phishpulse",
            "scopes": list(scopes or ["read", "scan", "admin"]),
            "iat": int(now.timestamp()),
            "exp": int(expires.timestamp()),
        }
        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": exp_mins * 60,
            "subject": subject,
        }

    @staticmethod
    def verify_jwt(token: str) -> Optional[str]:
        clean = (token or "").strip()
        if not clean:
            return None
        try:
            decoded = jwt.decode(
                clean,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
                issuer="phishpulse",
            )
            sub = str(decoded.get("sub") or "jwt-client")
            return f"jwt:{sub}"
        except jwt.PyJWTError:
            return None

    @classmethod
    def authenticate_request(cls, request: Request) -> Tuple[bool, str, Optional[str]]:
        """
        Validate request credentials when auth is enforced.
        Returns (ok, actor_label, error_detail).
        """
        api_key = request.headers.get("X-API-Key", "").strip()
        if api_key:
            actor = cls.verify_api_key(api_key)
            if actor:
                return True, actor, None
            return False, "invalid-api-key", "Invalid X-API-Key credential"

        auth_hdr = request.headers.get("Authorization", "").strip()
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
            actor = cls.verify_jwt(token)
            if actor:
                return True, actor, None
            return False, "invalid-jwt", "Invalid or expired Bearer JWT"

        if not cls.is_enforced():
            return True, "anonymous", None

        return False, "unauthenticated", "Authentication required (provide X-API-Key or Authorization: Bearer token)"


class SlidingWindowRateLimiter:
    """Thread-safe memory-bounded sliding-window rate limiter with separate scan & read buckets."""

    def __init__(self, max_clients: int = 4096) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[str, Deque[float]] = {}
        self._max_clients = max_clients

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()

    def check(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, Dict[str, str]]:
        now = time.monotonic()
        cutoff = now - float(window_seconds)

        with self._lock:
            if key not in self._buckets and len(self._buckets) >= self._max_clients:
                # Evict oldest bucket cleanly to keep memory bounded
                oldest_key = next(iter(self._buckets))
                self._buckets.pop(oldest_key, None)

            dq = self._buckets.setdefault(key, deque())
            while dq and dq[0] <= cutoff:
                dq.popleft()

            count = len(dq)
            if count >= limit:
                retry_after = max(1, int(round((dq[0] + window_seconds) - now))) if dq else window_seconds
                headers = {
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(retry_after),
                    "Retry-After": str(retry_after),
                }
                return False, headers

            dq.append(now)
            remaining = max(0, limit - len(dq))
            reset_in = max(1, int(round((dq[0] + window_seconds) - now))) if dq else window_seconds
            headers = {
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(reset_in),
            }
            return True, headers


rate_limiter = SlidingWindowRateLimiter()


def _resolve_client_ip(request: Request) -> str:
    if settings.TRUST_PROXY_HEADERS:
        xff = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if xff:
            return xff
    return request.client.host if request.client else "127.0.0.1"


def _is_scan_write_route(method: str, path: str) -> bool:
    if method.upper() != "POST":
        return False
    return any(path.endswith(suffix) for suffix in _HEAVY_SCAN_SUFFIXES)


def _is_api_or_protected_path(path: str) -> bool:
    if path in _PUBLIC_PATHS:
        return False
    if path.startswith("/static"):
        return False
    return path.startswith("/api") or path == "/metrics"


async def api_security_and_observability_middleware(request: Request, call_next):
    """Enforce API auth, sliding-window rate limits, version headers, request IDs, and JSON logging."""
    started = time.perf_counter()
    req_id = request.headers.get("X-Request-ID", "").strip()[:48] or uuid.uuid4().hex[:12]
    path = request.url.path
    method = request.method.upper()

    is_legacy_api = path.startswith("/api/") and not path.startswith("/api/v1/") and path != "/api/v1"
    actor = "anonymous"
    ctx_tokens = set_request_context(req_id, actor)

    try:
        # Enforce auth + rate limit on API routes (exempting health/ready/docs/auth/static)
        rate_headers: Dict[str, str] = {}
        if _is_api_or_protected_path(path):
            auth_ok, actor, auth_err = AuthManager.authenticate_request(request)
            set_actor_context(actor)
            request.state.actor = actor

            if not auth_ok:
                metrics.record_auth_failure()
                duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
                metrics.record_http_request(method, path, 401, duration_ms)
                logger.warning(
                    f"Unauthorized API request {method} {path}: {auth_err}",
                    extra={"event": "auth_failed", "fields": {"method": method, "path": path, "status_code": 401}},
                )
                return JSONResponse(
                    status_code=401,
                    content={"detail": auth_err, "request_id": req_id},
                    headers={"WWW-Authenticate": "Bearer", "X-Request-ID": req_id},
                )

            if settings.RATE_LIMIT_ENABLED:
                is_scan_tier = _is_scan_write_route(method, path)
                tier = "scan" if is_scan_tier else "read"
                limit = settings.RATE_LIMIT_SCAN_MAX if is_scan_tier else settings.RATE_LIMIT_READ_MAX
                client_key = f"{tier}:{actor if actor != 'anonymous' else _resolve_client_ip(request)}"
                allowed, rate_headers = rate_limiter.check(
                    key=client_key,
                    limit=limit,
                    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
                )
                if not allowed:
                    metrics.record_rate_limited()
                    duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
                    metrics.record_http_request(method, path, 429, duration_ms)
                    logger.warning(
                        f"Rate limit exceeded for {method} {path} ({tier})",
                        extra={
                            "event": "rate_limit_exceeded",
                            "fields": {"method": method, "path": path, "tier": tier, "status_code": 429},
                        },
                    )
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Rate limit exceeded. Retry later.", "request_id": req_id},
                        headers={"X-Request-ID": req_id, **rate_headers},
                    )

        response = await call_next(request)
        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        metrics.record_http_request(method, path, response.status_code, duration_ms)

        response.headers["X-Request-ID"] = req_id
        if path.startswith("/api"):
            response.headers["X-API-Version"] = "v1"
        if is_legacy_api:
            response.headers["Deprecation"] = "true"
            response.headers["Link"] = '</api/v1/>; rel="successor-version"'
        for hk, hv in rate_headers.items():
            response.headers[hk] = hv

        if not path.startswith("/static"):
            logger.info(
                f"{method} {path} -> {response.status_code} ({duration_ms}ms)",
                extra={
                    "event": "http_request",
                    "fields": {
                        "method": method,
                        "path": path,
                        "status_code": response.status_code,
                        "duration_ms": duration_ms,
                    },
                },
            )
        return response
    except Exception as exc:
        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        metrics.record_http_request(method, path, 500, duration_ms)
        logger.exception(
            f"Unhandled error in {method} {path}: {exc}",
            extra={"event": "http_exception", "fields": {"method": method, "path": path, "status_code": 500}},
        )
        raise
    finally:
        reset_request_context(ctx_tokens)
