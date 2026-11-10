import sqlite3
import json
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from pathlib import Path
from urllib.parse import urlparse
from app.config import DB_PATH

def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _migration_001_initial_tables(cursor: sqlite3.Cursor) -> None:
    """Create foundational URL scan, threat IoC, CTI cache, sandbox, and email tables."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            target_url TEXT NOT NULL,
            target_domain TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            overall_score REAL NOT NULL,
            verdict TEXT NOT NULL,
            raw_report_json TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE NOT NULL,
            indicator_type TEXT NOT NULL,
            tags TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            confidence REAL NOT NULL,
            source TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            votes_malicious INTEGER DEFAULT 0,
            votes_benign INTEGER DEFAULT 0,
            notes TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS community_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            vote TEXT NOT NULL,
            reason TEXT,
            voter_ip TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cti_cache (
            cache_key TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            indicator TEXT NOT NULL,
            status TEXT NOT NULL,
            matched INTEGER NOT NULL DEFAULT 0,
            match_confidence REAL NOT NULL DEFAULT 0.0,
            last_updated TEXT,
            provenance TEXT,
            payload_json TEXT NOT NULL,
            cached_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sandbox_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sandbox_id TEXT UNIQUE NOT NULL,
            scan_id TEXT,
            target_url TEXT NOT NULL,
            final_url TEXT,
            target_domain TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL,
            sandbox_score REAL NOT NULL DEFAULT 0.0,
            verdict TEXT NOT NULL,
            screenshot_path TEXT,
            raw_result_json TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            subject TEXT,
            from_address TEXT,
            from_domain TEXT,
            timestamp TEXT NOT NULL,
            overall_score REAL NOT NULL DEFAULT 0.0,
            verdict TEXT NOT NULL,
            raw_report_json TEXT NOT NULL
        )
    """)


def _migration_002_batch_jobs(cursor: sqlite3.Cursor) -> None:
    """Create persistent asynchronous batch scanning job table."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS batch_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            total_urls INTEGER NOT NULL DEFAULT 0,
            completed_urls INTEGER NOT NULL DEFAULT 0,
            failed_urls INTEGER NOT NULL DEFAULT 0,
            concurrency_limit INTEGER NOT NULL DEFAULT 4,
            requested_by TEXT,
            urls_json TEXT NOT NULL,
            results_json TEXT NOT NULL,
            summary_json TEXT NOT NULL,
            error TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT
        )
    """)


def _migration_003_performance_indexes(cursor: sqlite3.Cursor) -> None:
    """Create secondary indexes for scan queries, cache TTL expiration, graph correlation, and jobs."""
    index_statements = [
        "CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(target_domain)",
        "CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_type ON threat_iocs(indicator_type)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON threat_iocs(last_seen DESC)",
        "CREATE INDEX IF NOT EXISTS idx_cti_cache_expires ON cti_cache(expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_cti_cache_provider_ind ON cti_cache(provider, indicator)",
        "CREATE INDEX IF NOT EXISTS idx_sandbox_timestamp ON sandbox_runs(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_sandbox_domain ON sandbox_runs(target_domain)",
        "CREATE INDEX IF NOT EXISTS idx_sandbox_verdict ON sandbox_runs(verdict)",
        "CREATE INDEX IF NOT EXISTS idx_email_timestamp ON email_scans(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_email_verdict ON email_scans(verdict)",
        "CREATE INDEX IF NOT EXISTS idx_batch_jobs_created ON batch_jobs(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_batch_jobs_status ON batch_jobs(status)",
    ]
    for stmt in index_statements:
        cursor.execute(stmt)


_MIGRATIONS = [
    (1, "001_initial_core_tables", _migration_001_initial_tables),
    (2, "002_batch_jobs_table", _migration_002_batch_jobs),
    (3, "003_performance_indexes", _migration_003_performance_indexes),
]


def _run_migrations(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
    """)
    # Always ensure core schema DDL stays intact even if an older DB already existed
    _migration_001_initial_tables(cursor)
    cursor.execute("SELECT version FROM schema_migrations")
    applied = {int(row["version"]) for row in cursor.fetchall()}

    now = datetime.now(timezone.utc).isoformat()
    for version, name, fn in _MIGRATIONS:
        if version not in applied:
            fn(cursor)
            cursor.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, now),
            )
    conn.commit()


def init_db():
    conn = get_connection()
    try:
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            pass
        _run_migrations(conn)
        seed_initial_iocs(conn)
    finally:
        conn.close()

def seed_initial_iocs(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM threat_iocs")
    count = cursor.fetchone()["count"]
    if count == 0:
        now = datetime.now(timezone.utc).isoformat()
        sample_iocs = [
            ("http://paypal-security-update-center.com/login", "url", '["#paypal", "#credential_harvesting", "#phish"]', now, now, 98.0, "URLhaus Feed", "active", 14, 0, "Fake PayPal resolution center login page"),
            ("http://microsoft-365-password-reset.live-verify.xyz/auth", "url", '["#microsoft", "#o365", "#credential_theft"]', now, now, 99.0, "OpenPhish", "active", 21, 0, "Office 365 token harvesting trap"),
            ("http://appleid-support-icloud-lock.tk/signin", "url", '["#apple", "#icloud", "#credential_harvesting"]', now, now, 95.0, "Community Report", "active", 8, 0, "Fake Apple ID unlock notice"),
            ("http://binance-us-security-check.icu/verify", "url", '["#crypto", "#binance", "#wallet_drainer"]', now, now, 97.0, "Analyst Submission", "active", 19, 0, "Cryptocurrency wallet drainer landing page"),
            ("http://netflix-billing-account-update.buzz/pay", "url", '["#netflix", "#creditcard_stealer"]', now, now, 94.0, "URLhaus Feed", "active", 11, 0, "Credit card payment phishing for Netflix")
        ]
        cursor.executemany("""
            INSERT INTO threat_iocs (indicator, indicator_type, tags, first_seen, last_seen, confidence, source, status, votes_malicious, votes_benign, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, sample_iocs)
        conn.commit()

def save_scan(report_dict: Dict[str, Any]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO scans (scan_id, target_url, target_domain, timestamp, overall_score, verdict, raw_report_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        report_dict["scan_id"],
        report_dict["target_url"],
        report_dict["target_domain"],
        report_dict["timestamp"],
        report_dict["overall_score"],
        report_dict["verdict"],
        json.dumps(report_dict)
    ))
    conn.commit()
    conn.close()

def get_recent_scans(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_id, target_url, target_domain, timestamp, overall_score, verdict
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT raw_report_json FROM scans WHERE scan_id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return json.loads(row["raw_report_json"])
    return None


def get_full_scans(limit: int = 200, deduplicate_urls: bool = True) -> List[Dict[str, Any]]:
    """Retrieve recent full JSON scan reports ordered newest-first for correlation and graphing."""
    conn = get_connection()
    cursor = conn.cursor()
    if deduplicate_urls:
        cursor.execute(
            """
            SELECT raw_report_json
            FROM scans
            WHERE id IN (SELECT MAX(id) FROM scans GROUP BY target_url)
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
    else:
        cursor.execute(
            "SELECT raw_report_json FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        )
    rows = cursor.fetchall()
    conn.close()
    reports: List[Dict[str, Any]] = []
    for row in rows:
        try:
            parsed = json.loads(row["raw_report_json"])
            if isinstance(parsed, dict):
                reports.append(parsed)
        except Exception:
            continue
    return reports

def add_ioc(indicator: str, indicator_type: str, tags: List[str], source: str, confidence: float = 90.0, notes: str = "") -> int:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    tags_json = json.dumps(tags)
    
    cursor.execute("""
        INSERT INTO threat_iocs (indicator, indicator_type, tags, first_seen, last_seen, confidence, source, status, votes_malicious, votes_benign, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 1, 0, ?)
        ON CONFLICT(indicator) DO UPDATE SET
            last_seen = excluded.last_seen,
            confidence = MAX(confidence, excluded.confidence),
            votes_malicious = votes_malicious + 1
    """, (indicator, indicator_type, tags_json, now, now, confidence, source, notes))
    
    ioc_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return ioc_id

def _parse_ioc_row(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    try:
        d["tags"] = json.loads(d["tags"])
    except Exception:
        d["tags"] = []
    return d


def query_ioc(indicator: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    clean_ind = (indicator or "").strip()
    if not clean_ind:
        conn.close()
        return None

    # 1. Exact indicator match first
    cursor.execute("SELECT * FROM threat_iocs WHERE lower(indicator) = lower(?)", (clean_ind,))
    row = cursor.fetchone()
    if row:
        conn.close()
        return _parse_ioc_row(row)

    # 2. Host-based fallback: match by hostname, whether the query is a bare domain or a full URL
    if "://" not in clean_ind:
        query_host = clean_ind.lower().rstrip(".")
    else:
        query_host = (urlparse(clean_ind).hostname or "").lower().rstrip(".")

    if query_host:
        cursor.execute("SELECT * FROM threat_iocs WHERE indicator LIKE ?", (f"%{query_host}%",))
        rows = cursor.fetchall()
        conn.close()
        for candidate in rows:
            stored = str(candidate["indicator"] or "").strip().lower()
            stored_host = (urlparse(stored).hostname or stored.split("/")[0]).rstrip(".") if "://" in stored else stored.rstrip(".")
            if stored_host == query_host or stored_host.endswith("." + query_host):
                return _parse_ioc_row(candidate)
        return None

    conn.close()
    return None

def get_all_iocs(limit: int = 100, tag: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    if tag:
        cursor.execute("""
            SELECT * FROM threat_iocs WHERE tags LIKE ? ORDER BY id DESC LIMIT ?
        """, (f"%{tag}%", limit))
    else:
        cursor.execute("""
            SELECT * FROM threat_iocs ORDER BY id DESC LIMIT ?
        """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["tags"] = json.loads(d["tags"])
        except Exception:
            d["tags"] = []
        result.append(d)
    return result

def record_vote(indicator: str, vote: str, reason: str = "", voter_ip: str = "127.0.0.1"):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("""
        INSERT INTO community_votes (indicator, vote, reason, voter_ip, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (indicator, vote, reason, voter_ip, now))

    # Update votes in threat_iocs table if exists
    if vote.lower() == "malicious":
        cursor.execute("UPDATE threat_iocs SET votes_malicious = votes_malicious + 1, last_seen = ? WHERE indicator = ?", (now, indicator))
    elif vote.lower() == "benign":
        cursor.execute("UPDATE threat_iocs SET votes_benign = votes_benign + 1, last_seen = ? WHERE indicator = ?", (now, indicator))

    conn.commit()
    conn.close()

def get_stats() -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as count FROM scans")
    total_scans = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE verdict = 'MALICIOUS'")
    malicious_scans = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE verdict IN ('SUSPICIOUS', 'HIGH_RISK')")
    suspicious_scans = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE verdict = 'BENIGN'")
    benign_scans = cursor.fetchone()["count"]
    
    cursor.execute("SELECT COUNT(*) as count FROM threat_iocs")
    total_iocs = cursor.fetchone()["count"]
    
    conn.close()
    return {
        "total_scans": total_scans,
        "malicious_detected": malicious_scans,
        "suspicious_detected": suspicious_scans,
        "benign_detected": benign_scans,
        "total_iocs": total_iocs,
        "active_threat_feeds": 6
    }


def get_cti_cache(cache_key: str) -> Optional[Dict[str, Any]]:
    """Retrieve a non-expired cached CTI provider lookup from SQLite."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT payload_json, cached_at, expires_at FROM cti_cache WHERE cache_key = ?", (cache_key,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    now = datetime.now(timezone.utc)
    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except Exception:
        expires_at = now - timedelta(seconds=1)

    if expires_at <= now:
        cursor.execute("DELETE FROM cti_cache WHERE cache_key = ?", (cache_key,))
        conn.commit()
        conn.close()
        return None

    conn.close()
    try:
        payload = json.loads(row["payload_json"])
        payload["cached"] = True
        payload["cached_at"] = row["cached_at"]
        payload["cache_expires_at"] = row["expires_at"]
        return payload
    except Exception:
        return None


def set_cti_cache(
    cache_key: str,
    provider: str,
    indicator: str,
    payload: Dict[str, Any],
    ttl_seconds: int,
) -> None:
    """Persist a CTI provider lookup result with an explicit UTC expiration timestamp."""
    if ttl_seconds <= 0:
        return
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=int(ttl_seconds))).isoformat()
    now_iso = now.isoformat()

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO cti_cache (
            cache_key, provider, indicator, status, matched,
            match_confidence, last_updated, provenance, payload_json,
            cached_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cache_key) DO UPDATE SET
            status = excluded.status,
            matched = excluded.matched,
            match_confidence = excluded.match_confidence,
            last_updated = excluded.last_updated,
            provenance = excluded.provenance,
            payload_json = excluded.payload_json,
            cached_at = excluded.cached_at,
            expires_at = excluded.expires_at
    """, (
        cache_key,
        provider,
        indicator,
        str(payload.get("status", "clean")),
        1 if payload.get("matched") else 0,
        float(payload.get("match_confidence", 0.0)),
        payload.get("last_updated"),
        payload.get("provenance", ""),
        json.dumps(payload),
        now_iso,
        expires_at,
    ))
    conn.commit()
    conn.close()


def clear_expired_cti_cache() -> int:
    """Remove all expired CTI cache entries and return the number deleted."""
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cti_cache WHERE expires_at <= ?", (now_iso,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted


def save_sandbox_run(report_dict: Dict[str, Any], screenshot_path: Optional[str] = None) -> None:
    """Persist an isolated browser sandbox execution report into SQLite."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO sandbox_runs (
            sandbox_id, scan_id, target_url, final_url, target_domain,
            timestamp, status, sandbox_score, verdict, screenshot_path, raw_result_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report_dict["sandbox_id"],
        report_dict.get("scan_id"),
        report_dict["target_url"],
        report_dict.get("final_url"),
        report_dict["target_domain"],
        report_dict["timestamp"],
        report_dict["status"],
        float(report_dict.get("sandbox_score", 0.0)),
        report_dict.get("verdict", "BENIGN"),
        screenshot_path,
        json.dumps(report_dict),
    ))
    conn.commit()
    conn.close()


def get_recent_sandbox_runs(limit: int = 20) -> List[Dict[str, Any]]:
    """List recent browser sandbox runs ordered newest-first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sandbox_id, scan_id, target_url, final_url, target_domain,
               timestamp, status, sandbox_score, verdict, screenshot_path
        FROM sandbox_runs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_sandbox_run_by_id(sandbox_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full persisted sandbox report by sandbox_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT raw_result_json, screenshot_path FROM sandbox_runs WHERE sandbox_id = ?",
        (sandbox_id,),
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    try:
        data = json.loads(row["raw_result_json"])
        if row["screenshot_path"]:
            data["_screenshot_path"] = row["screenshot_path"]
        return data
    except Exception:
        return None


def save_email_scan(report_dict: Dict[str, Any]) -> None:
    """Persist an analyzed .eml phishing assessment into SQLite."""
    conn = get_connection()
    cursor = conn.cursor()
    sender = report_dict.get("sender") or {}
    cursor.execute("""
        INSERT OR REPLACE INTO email_scans (
            email_id, filename, subject, from_address, from_domain,
            timestamp, overall_score, verdict, raw_report_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report_dict["email_id"],
        report_dict.get("filename", "uploaded.eml"),
        report_dict.get("subject", ""),
        sender.get("from_address", ""),
        sender.get("from_domain", ""),
        report_dict["timestamp"],
        float(report_dict.get("overall_score", 0.0)),
        report_dict.get("verdict", "BENIGN"),
        json.dumps(report_dict),
    ))
    conn.commit()
    conn.close()


def get_recent_email_scans(limit: int = 20) -> List[Dict[str, Any]]:
    """List recent .eml analyses ordered newest-first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT email_id, filename, subject, from_address, from_domain,
               timestamp, overall_score, verdict
        FROM email_scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_email_scan_by_id(email_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full persisted email analysis report by email_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT raw_report_json FROM email_scans WHERE email_id = ?", (email_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    try:
        return json.loads(row["raw_report_json"])
    except Exception:
        return None


def get_schema_status() -> Dict[str, Any]:
    """Return applied schema migration versions and database index inventory."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC")
        migrations = [dict(r) for r in cursor.fetchall()]
        cursor.execute("SELECT name, tbl_name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%' ORDER BY name ASC")
        indexes = [dict(r) for r in cursor.fetchall()]
        current_version = max((int(m["version"]) for m in migrations), default=0)
        return {
            "backend": "sqlite",
            "db_path": str(DB_PATH),
            "current_version": current_version,
            "latest_version": _MIGRATIONS[-1][0],
            "migrations": migrations,
            "index_count": len(indexes),
            "indexes": [i["name"] for i in indexes],
        }
    finally:
        conn.close()


def check_db_ready() -> Dict[str, Any]:
    """Perform a lightweight database liveness/readiness query."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.execute("SELECT MAX(version) as ver FROM schema_migrations")
        row = cursor.fetchone()
        ver = int(row["ver"]) if row and row["ver"] is not None else 0
        return {
            "ok": ver >= _MIGRATIONS[-1][0],
            "schema_version": ver,
            "expected_version": _MIGRATIONS[-1][0],
        }
    finally:
        conn.close()


def create_batch_job(
    job_id: str,
    urls: List[str],
    concurrency_limit: int,
    requested_by: str = "anonymous",
    status: str = "queued",
) -> None:
    """Create a new persisted batch scan job record."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO batch_jobs (
                job_id, status, total_urls, completed_urls, failed_urls,
                concurrency_limit, requested_by, urls_json, results_json, summary_json,
                error, created_at, started_at, finished_at
            )
            VALUES (?, ?, ?, 0, 0, ?, ?, ?, ?, ?, NULL, ?, NULL, NULL)
        """, (
            job_id,
            status,
            len(urls),
            int(concurrency_limit),
            requested_by,
            json.dumps(urls),
            json.dumps([]),
            json.dumps({}),
            now,
        ))
        conn.commit()
    finally:
        conn.close()


def update_batch_job(
    job_id: str,
    *,
    status: Optional[str] = None,
    completed_urls: Optional[int] = None,
    failed_urls: Optional[int] = None,
    results: Optional[List[Dict[str, Any]]] = None,
    summary: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
) -> None:
    """Update progress, status, or results of an asynchronous batch job."""
    sets = []
    params: List[Any] = []
    if status is not None:
        sets.append("status = ?")
        params.append(status)
    if completed_urls is not None:
        sets.append("completed_urls = ?")
        params.append(int(completed_urls))
    if failed_urls is not None:
        sets.append("failed_urls = ?")
        params.append(int(failed_urls))
    if results is not None:
        sets.append("results_json = ?")
        params.append(json.dumps(results))
    if summary is not None:
        sets.append("summary_json = ?")
        params.append(json.dumps(summary))
    if error is not None:
        sets.append("error = ?")
        params.append(error)
    if started_at is not None:
        sets.append("started_at = ?")
        params.append(started_at)
    if finished_at is not None:
        sets.append("finished_at = ?")
        params.append(finished_at)

    if not sets:
        return
    params.append(job_id)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE batch_jobs SET {', '.join(sets)} WHERE job_id = ?", params)
        conn.commit()
    finally:
        conn.close()


def _parse_batch_job_row(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    try:
        urls = json.loads(d.pop("urls_json", "[]") or "[]")
    except Exception:
        urls = []
    try:
        results = json.loads(d.pop("results_json", "[]") or "[]")
    except Exception:
        results = []
    try:
        summary = json.loads(d.pop("summary_json", "{}") or "{}")
    except Exception:
        summary = {}
    total = int(d.get("total_urls") or 0)
    done = int(d.get("completed_urls") or 0)
    d["urls"] = urls
    d["results"] = results
    d["summary"] = summary
    d["progress_pct"] = round((done / total) * 100.0, 1) if total > 0 else 100.0
    return d


def get_batch_job_by_id(job_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single batch job and its current results."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM batch_jobs WHERE job_id = ?", (job_id,))
        row = cursor.fetchone()
        return _parse_batch_job_row(row) if row else None
    finally:
        conn.close()


def list_batch_jobs(limit: int = 20) -> List[Dict[str, Any]]:
    """List recent batch scan jobs newest-first (without full raw results payload)."""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT job_id, status, total_urls, completed_urls, failed_urls,
                   concurrency_limit, requested_by, summary_json, error,
                   created_at, started_at, finished_at
            FROM batch_jobs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        out = []
        for r in rows:
            item = dict(r)
            try:
                item["summary"] = json.loads(item.pop("summary_json", "{}") or "{}")
            except Exception:
                item["summary"] = {}
            total = int(item.get("total_urls") or 0)
            done = int(item.get("completed_urls") or 0)
            item["progress_pct"] = round((done / total) * 100.0, 1) if total > 0 else 100.0
            out.append(item)
        return out
    finally:
        conn.close()
