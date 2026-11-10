import os
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables before configuring storage paths.
load_dotenv(dotenv_path=BASE_DIR / ".env", override=False)

# Keep bundled seed files inside the project.
DATA_DIR = BASE_DIR / "data"
SEEDS_DIR = DATA_DIR / "seeds"

# Store runtime data on Render's persistent disk.
PERSISTENT_DATA_DIR = Path(
    os.getenv("WEBEYE_DATA_DIR", str(DATA_DIR))
).resolve()

PERSISTENT_DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = PERSISTENT_DATA_DIR / "phishpulse.db"

SCREENSHOTS_DIR = Path(
    os.getenv(
        "WEBEYE_SCREENSHOTS_DIR",
        str(PERSISTENT_DATA_DIR / "sandbox_screenshots")
    )
).resolve()

SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("true", "1", "yes", "on")


def _env_int(name: str, default: int, minimum: Optional[int] = None) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        val = default
    else:
        try:
            val = int(raw.strip())
        except ValueError:
            val = default
    if minimum is not None and val < minimum:
        return minimum
    return val


def _env_csv(name: str) -> Tuple[str, ...]:
    raw = os.getenv(name, "")
    return tuple(item.strip() for item in raw.split(",") if item.strip())


_EPHEMERAL_DEV_JWT_SECRET = secrets.token_urlsafe(32)


class Settings:
    APP_NAME: str = "WebEye Threat Intelligence Platform"
    APP_VERSION: str = "1.1.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").strip().lower() or "development"
    API_PREFIX: str = "/api"
    API_V1_PREFIX: str = "/api/v1"
    ENABLE_LEGACY_API_ALIAS: bool = _env_bool("ENABLE_LEGACY_API_ALIAS", True)
    DEBUG: bool = _env_bool("DEBUG", False)
    APP_STARTED_AT: float = time.time()

    # Logging & Observability
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").strip().upper() or "INFO"
    LOG_FORMAT: str = os.getenv("LOG_FORMAT", "json").strip().lower() or "json"

    # Authentication & Secret Management
    API_KEYS: Tuple[str, ...] = _env_csv("PHISHPULSE_API_KEYS")
    AUTH_REQUIRED: bool = _env_bool("AUTH_REQUIRED", bool(API_KEYS))
    _RAW_JWT_SECRET: str = os.getenv("JWT_SECRET_KEY", "").strip()
    JWT_EPHEMERAL_SECRET: bool = not bool(_RAW_JWT_SECRET)
    JWT_SECRET_KEY: str = _RAW_JWT_SECRET or _EPHEMERAL_DEV_JWT_SECRET
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = _env_int("JWT_EXPIRY_MINUTES", 60, 1)

    # Rate Limiting (Sliding Window)
    RATE_LIMIT_ENABLED: bool = _env_bool("RATE_LIMIT_ENABLED", True)
    RATE_LIMIT_WINDOW_SECONDS: int = _env_int("RATE_LIMIT_WINDOW_SECONDS", 60, 1)
    RATE_LIMIT_READ_MAX: int = _env_int("RATE_LIMIT_READ_MAX", 240, 1)
    RATE_LIMIT_SCAN_MAX: int = _env_int("RATE_LIMIT_SCAN_MAX", 60, 1)
    TRUST_PROXY_HEADERS: bool = _env_bool("TRUST_PROXY_HEADERS", False)

    # Threat Scoring Weights (Must sum to 1.0)
    WEIGHT_THREAT_ANALYSIS: float = 0.35
    WEIGHT_WEB_SECURITY: float = 0.20
    WEIGHT_CERT_VALIDATION: float = 0.20
    WEIGHT_THREAT_INTEL: float = 0.25

    # Risk Thresholds
    RISK_THRESHOLD_BENIGN: int = 25
    RISK_THRESHOLD_SUSPICIOUS: int = 50
    RISK_THRESHOLD_HIGH: int = 75

    # Scanner Network, SSRF & Resource Limits + Bounded Concurrency
    CONNECT_TIMEOUT_SECONDS: float = 4.0
    READ_TIMEOUT_SECONDS: float = 5.0
    REQUEST_TIMEOUT_SECONDS: int = 8
    TOTAL_FETCH_TIMEOUT_SECONDS: float = 12.0
    WORKER_EXECUTION_TIMEOUT_SECONDS: float = 15.0
    TLS_HANDSHAKE_TIMEOUT_SECONDS: float = 6.0
    MAX_REDIRECT_HOPS: int = 6
    MAX_RESPONSE_BYTES: int = 2 * 1024 * 1024          # 2 MiB max fetched response body
    MAX_CONTENT_LENGTH_BYTES: int = 10 * 1024 * 1024   # 10 MiB hard Content-Length rejection limit
    MAX_WORKER_OUTPUT_BYTES: int = 4 * 1024 * 1024     # 4 MiB IPC stdout cap
    WORKER_MEMORY_LIMIT_MB: int = 256                  # OS worker memory cap
    ALLOW_PRIVATE_NETWORK_SCANS: bool = _env_bool("ALLOW_PRIVATE_NETWORK_SCANS", False)
    SCAN_MAX_CONCURRENCY: int = _env_int("SCAN_MAX_CONCURRENCY", 6, 1)
    BATCH_WORKER_CONCURRENCY: int = _env_int("BATCH_WORKER_CONCURRENCY", 4, 1)
    BATCH_MAX_URLS: int = _env_int("BATCH_MAX_URLS", 25, 1)
    SANDBOX_MAX_CONCURRENCY: int = _env_int("SANDBOX_MAX_CONCURRENCY", 2, 1)
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    SAFETY_USER_AGENT: str = "PhishPulse-Scanner/1.0 (+https://github.com/security/phishpulse)"

    # Browser-Based Phishing Sandbox Limits & Storage
    SANDBOX_SCREENSHOTS_DIR: Path = SCREENSHOTS_DIR
    SANDBOX_TIMEOUT_SECONDS: float = 20.0
    SANDBOX_WAIT_AFTER_LOAD_SECONDS: float = 1.8
    SANDBOX_WORKER_MEMORY_LIMIT_MB: int = 768
    SANDBOX_MAX_WORKER_OUTPUT_BYTES: int = 10 * 1024 * 1024
    SANDBOX_VIEWPORT_WIDTH: int = 1366
    SANDBOX_VIEWPORT_HEIGHT: int = 768

    # Email (.eml) Phishing & Attachment Isolation Limits
    MAX_EMAIL_BYTES: int = 10 * 1024 * 1024
    MAX_ATTACHMENT_BYTES: int = 5 * 1024 * 1024
    ATTACHMENT_WORKER_TIMEOUT_SECONDS: float = 8.0

    # Collaborative Threat Intelligence APIs & Feeds
    URLHAUS_API_URL: str = "https://urlhaus-api.abuse.ch/v1/url/"
    OPENPHISH_FEED_URL: str = "https://openphish.com/feed.txt"
    GOOGLE_SAFE_BROWSING_API_URL: str = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    PHISHTANK_API_URL: str = "https://checkurl.phishtank.com/checkurl/"
    OTX_API_BASE_URL: str = "https://otx.alienvault.com/api/v1"
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    PHISHTANK_API_KEY: str = os.getenv("PHISHTANK_API_KEY", "").strip()
    URLHAUS_API_KEY: str = os.getenv("URLHAUS_API_KEY", "").strip()
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    OTX_API_KEY: str = os.getenv("OTX_API_KEY", "").strip()
    CTI_CACHE_TTL_SECONDS: int = _env_int("CTI_CACHE_TTL_SECONDS", 3600, 10)
    CTI_ERROR_COOLDOWN_SECONDS: int = 60

    # Database Settings (SQLite default locally)
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}")

    @staticmethod
    def mask_secret(value: str) -> str:
        clean = (value or "").strip()
        if not clean:
            return "[UNSET]"
        if len(clean) <= 6:
            return "***"
        return f"***{clean[-4:]}"

    def validate_security_posture(self) -> Dict[str, Any]:
        warnings = []
        if self.ENVIRONMENT == "production":
            if not self.AUTH_REQUIRED:
                warnings.append("AUTH_REQUIRED is disabled in production environment.")
            if self.JWT_EPHEMERAL_SECRET:
                warnings.append("JWT_SECRET_KEY is not persisted; using ephemeral secret.")
            if not self.API_KEYS:
                warnings.append("PHISHPULSE_API_KEYS is empty; API key exchange is disabled.")
        if self.ALLOW_PRIVATE_NETWORK_SCANS:
            warnings.append("ALLOW_PRIVATE_NETWORK_SCANS=true relaxes SSRF IP protections.")
        return {
            "environment": self.ENVIRONMENT,
            "auth_required": self.AUTH_REQUIRED,
            "configured_api_keys": len(self.API_KEYS),
            "jwt_secret_persisted": not self.JWT_EPHEMERAL_SECRET,
            "rate_limit_enabled": self.RATE_LIMIT_ENABLED,
            "ssrf_strict_mode": not self.ALLOW_PRIVATE_NETWORK_SCANS,
            "warnings": warnings,
        }

    def redacted_summary(self) -> Dict[str, Any]:
        return {
            "app_name": self.APP_NAME,
            "app_version": self.APP_VERSION,
            "environment": self.ENVIRONMENT,
            "api_v1_prefix": self.API_V1_PREFIX,
            "legacy_api_alias": self.ENABLE_LEGACY_API_ALIAS,
            "auth_required": self.AUTH_REQUIRED,
            "api_keys": [self.mask_secret(k) for k in self.API_KEYS],
            "jwt_secret_key": "[EPHEMERAL]" if self.JWT_EPHEMERAL_SECRET else self.mask_secret(self.JWT_SECRET_KEY),
            "rate_limit_enabled": self.RATE_LIMIT_ENABLED,
            "rate_limit_read_max": self.RATE_LIMIT_READ_MAX,
            "rate_limit_scan_max": self.RATE_LIMIT_SCAN_MAX,
            "scan_max_concurrency": self.SCAN_MAX_CONCURRENCY,
            "batch_worker_concurrency": self.BATCH_WORKER_CONCURRENCY,
            "sandbox_max_concurrency": self.SANDBOX_MAX_CONCURRENCY,
            "cti_keys_configured": {
                "virustotal": bool(self.VIRUSTOTAL_API_KEY),
                "google_safe_browsing": bool(self.GOOGLE_SAFE_BROWSING_API_KEY),
                "phishtank": bool(self.PHISHTANK_API_KEY),
                "urlhaus": bool(self.URLHAUS_API_KEY),
                "abuseipdb": bool(self.ABUSEIPDB_API_KEY),
                "alienvault_otx": bool(self.OTX_API_KEY),
            },
        }


settings = Settings()
