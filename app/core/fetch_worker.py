import asyncio
import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Optional

# Ensure project root is importable when worker runs under `python -I`
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.config import settings
from app.core.safe_fetcher import FetchError, FetchTimeoutError, SafeURLFetcher
from app.core.security_guard import SSRFBlockedError, validate_url_syntax_and_host


_WORKER_SCRIPT_PATH = str(Path(__file__).resolve())
_IS_WINDOWS = os.name == "nt"


class _WindowsJobSandbox:
    """Windows Job Object enforcing memory cap, no child processes, and kill-on-close."""

    def __init__(self, memory_limit_mb: int) -> None:
        self._handle = None
        if not _IS_WINDOWS:
            return
        try:
            import ctypes
            import ctypes.wintypes as wt

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_uint64),
                    ("WriteOperationCount", ctypes.c_uint64),
                    ("OtherOperationCount", ctypes.c_uint64),
                    ("ReadTransferCount", ctypes.c_uint64),
                    ("WriteTransferCount", ctypes.c_uint64),
                    ("OtherTransferCount", ctypes.c_uint64),
                ]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wt.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wt.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wt.DWORD),
                    ("SchedulingClass", wt.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._kernel32 = kernel32
            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                return

            # KILL_ON_JOB_CLOSE (0x2000) | ACTIVE_PROCESS (0x0008) | PROCESS_MEMORY (0x0100) | PRIORITY_CLASS (0x0020)
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = 0x2000 | 0x0008 | 0x0100 | 0x0020
            info.BasicLimitInformation.ActiveProcessLimit = 1
            info.BasicLimitInformation.PriorityClass = 0x00004000  # BELOW_NORMAL_PRIORITY_CLASS
            info.ProcessMemoryLimit = int(memory_limit_mb) * 1024 * 1024

            if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
                # Fallback without ACTIVE_PROCESS if nested job environment disallows it
                info.BasicLimitInformation.LimitFlags = 0x2000 | 0x0100
                info.BasicLimitInformation.ActiveProcessLimit = 0
                kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))

            self._handle = job
        except Exception:
            self._handle = None

    def assign(self, process_handle: int) -> bool:
        if not self._handle or not _IS_WINDOWS:
            return False
        try:
            return bool(self._kernel32.AssignProcessToJobObject(self._handle, int(process_handle)))
        except Exception:
            return False

    def close(self) -> None:
        if self._handle and _IS_WINDOWS:
            try:
                self._kernel32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None


def _build_posix_preexec(memory_limit_mb: int, timeout_seconds: float):
    """Build POSIX rlimit + setsid preexec function for child isolation."""
    def _preexec() -> None:
        try:
            import resource

            os.setsid()
            mem_bytes = int(memory_limit_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            cpu_limit = max(2, int(timeout_seconds) + 2)
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except Exception:
                pass
        except Exception:
            pass

    return _preexec


def _build_sanitized_env(sandbox_dir: str) -> Dict[str, str]:
    """
    Create a strictly stripped environment for the worker process.
    Removes ALL API keys, proxy variables (HTTP_PROXY/HTTPS_PROXY), cloud credentials, and app config.
    """
    if _IS_WINDOWS:
        env: Dict[str, str] = {
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
            "TEMP": sandbox_dir,
            "TMP": sandbox_dir,
            "PYTHONNOUSERSITE": "1",
        }
        windir = os.environ.get("WINDIR")
        if windir:
            env["WINDIR"] = windir
        return env

    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": sandbox_dir,
        "PYTHONNOUSERSITE": "1",
    }
    for cert_var in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        val = os.environ.get(cert_var)
        if val:
            env[cert_var] = val
    return env


def _read_stream_capped(stream, max_bytes: int, sink: list) -> None:
    """Read stream up to max_bytes + 1 in chunks without unbounded buffering."""
    total = 0
    chunks = []
    try:
        while True:
            to_read = min(65536, (max_bytes + 1) - total)
            if to_read <= 0:
                break
            chunk = stream.read(to_read)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except Exception:
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass
    sink.append(b"".join(chunks))


def run_in_restricted_worker_sync(
    url: str,
    mode: str = "bundle",
    fetch_content: bool = True,
    fetch_tls: bool = True,
    max_response_bytes: Optional[int] = None,
    max_redirects: Optional[int] = None,
    connect_timeout: Optional[float] = None,
    read_timeout: Optional[float] = None,
    total_timeout: Optional[float] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute untrusted URL/TLS fetching inside an OS-isolated restricted worker subprocess.
    Strips secrets/proxies, runs in isolated temp CWD with `python -I`, applies Job Object / rlimits,
    and enforces strict wall-clock and output-size limits.
    """
    # Pre-flight validation in parent before spawning worker
    normalized_url, _, _, _ = validate_url_syntax_and_host(url, allow_local=False)

    eff_total_timeout = float(total_timeout or settings.TOTAL_FETCH_TIMEOUT_SECONDS)
    worker_timeout = max(eff_total_timeout + 4.0, float(settings.WORKER_EXECUTION_TIMEOUT_SECONDS))

    payload = {
        "url": normalized_url,
        "mode": mode,
        "fetch_content": bool(fetch_content),
        "fetch_tls": bool(fetch_tls),
        "max_response_bytes": min(
            int(max_response_bytes or settings.MAX_RESPONSE_BYTES),
            settings.MAX_RESPONSE_BYTES,
        ),
        "max_redirects": min(
            int(max_redirects if max_redirects is not None else settings.MAX_REDIRECT_HOPS),
            settings.MAX_REDIRECT_HOPS,
        ),
        "connect_timeout": min(float(connect_timeout or settings.CONNECT_TIMEOUT_SECONDS), 30.0),
        "read_timeout": min(float(read_timeout or settings.READ_TIMEOUT_SECONDS), 30.0),
        "total_timeout": min(eff_total_timeout, 60.0),
        "user_agent": user_agent or settings.USER_AGENT,
    }
    input_bytes = json.dumps(payload, ensure_ascii=True).encode("utf-8")

    with tempfile.TemporaryDirectory(prefix="phishpulse_worker_") as sandbox_dir:
        clean_env = _build_sanitized_env(sandbox_dir)
        job = _WindowsJobSandbox(memory_limit_mb=settings.WORKER_MEMORY_LIMIT_MB)

        popen_kwargs: Dict[str, Any] = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "cwd": sandbox_dir,
            "env": clean_env,
            "close_fds": True,
        }
        if _IS_WINDOWS:
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        else:
            popen_kwargs["preexec_fn"] = _build_posix_preexec(
                memory_limit_mb=settings.WORKER_MEMORY_LIMIT_MB,
                timeout_seconds=worker_timeout,
            )

        proc = subprocess.Popen(
            [sys.executable, "-I", _WORKER_SCRIPT_PATH],
            **popen_kwargs,
        )

        try:
            if _IS_WINDOWS:
                job.assign(int(proc._handle))

            if proc.stdin is not None:
                try:
                    proc.stdin.write(input_bytes)
                    proc.stdin.flush()
                finally:
                    proc.stdin.close()

            stdout_sink: list = []
            stderr_sink: list = []
            t_out = threading.Thread(
                target=_read_stream_capped,
                args=(proc.stdout, settings.MAX_WORKER_OUTPUT_BYTES, stdout_sink),
                daemon=True,
            )
            t_err = threading.Thread(
                target=_read_stream_capped,
                args=(proc.stderr, 65536, stderr_sink),
                daemon=True,
            )
            t_out.start()
            t_err.start()

            try:
                returncode = proc.wait(timeout=worker_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                raise FetchTimeoutError(
                    f"Restricted worker execution exceeded timeout ({worker_timeout:.1f}s)"
                )

            t_out.join(timeout=2)
            t_err.join(timeout=2)

            raw_out = stdout_sink[0] if stdout_sink else b""
            raw_err = stderr_sink[0] if stderr_sink else b""

            if len(raw_out) > settings.MAX_WORKER_OUTPUT_BYTES:
                raise FetchError("Restricted worker output exceeded maximum IPC limit")

            if returncode != 0 and not raw_out:
                err_msg = raw_err.decode("utf-8", errors="replace").strip()[:200]
                raise FetchError(f"Restricted worker exited with code {returncode}: {err_msg}")

            try:
                worker_resp = json.loads(raw_out.decode("utf-8"))
            except Exception as exc:
                err_msg = raw_err.decode("utf-8", errors="replace").strip()[:200]
                raise FetchError(f"Invalid restricted worker response: {exc} ({err_msg})") from exc

            if worker_resp.get("ssrf_blocked"):
                raise SSRFBlockedError(
                    worker_resp.get("error") or "Security Policy Violation (SSRF Defense)."
                )

            if not worker_resp.get("ok"):
                raise FetchError(worker_resp.get("error") or "Restricted worker failed")

            return worker_resp["data"]
        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except Exception:
                    pass
            job.close()


async def run_in_restricted_worker(
    url: str,
    mode: str = "bundle",
    fetch_content: bool = True,
    fetch_tls: bool = True,
    max_response_bytes: Optional[int] = None,
    max_redirects: Optional[int] = None,
    connect_timeout: Optional[float] = None,
    read_timeout: Optional[float] = None,
    total_timeout: Optional[float] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """Async wrapper running the OS-isolated restricted worker in a thread."""
    return await asyncio.to_thread(
        run_in_restricted_worker_sync,
        url=url,
        mode=mode,
        fetch_content=fetch_content,
        fetch_tls=fetch_tls,
        max_response_bytes=max_response_bytes,
        max_redirects=max_redirects,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        total_timeout=total_timeout,
        user_agent=user_agent,
    )


def _install_worker_audit_hook() -> None:
    """
    Defense-in-depth Python audit hook inside the worker process.
    Blocks subprocess execution, filesystem mutations, registry/DB access, and dynamic library loads.
    """
    blocked_exact = frozenset({
        "subprocess.Popen",
        "os.system",
        "os.fork",
        "os.forkpty",
        "os.posix_spawn",
        "os.startfile",
        "webbrowser.open",
        "ctypes.dlopen",
        "ctypes.dlsym",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.rename",
        "os.replace",
        "os.mkdir",
        "os.makedirs",
        "os.chmod",
        "os.chown",
    })
    blocked_prefixes = (
        "os.spawn",
        "os.exec",
        "winreg.",
        "sqlite3.",
    )
    write_open_flags = (
        getattr(os, "O_WRONLY", 1)
        | getattr(os, "O_RDWR", 2)
        | getattr(os, "O_CREAT", 0)
        | getattr(os, "O_TRUNC", 0)
        | getattr(os, "O_APPEND", 0)
    )

    def _audit_hook(event: str, args: tuple) -> None:
        if event in blocked_exact or any(event.startswith(p) for p in blocked_prefixes):
            raise PermissionError(f"Operation '{event}' is prohibited in restricted fetch worker")

        if event == "open" and len(args) >= 3:
            mode = args[1]
            flags = args[2]
            if isinstance(mode, str) and any(ch in mode for ch in ("w", "a", "x", "+")):
                raise PermissionError("Write file access is prohibited in restricted fetch worker")
            if isinstance(flags, int) and (flags & write_open_flags):
                raise PermissionError("Write file flags are prohibited in restricted fetch worker")

    sys.addaudithook(_audit_hook)


def _worker_main() -> int:
    _install_worker_audit_hook()

    try:
        raw_input = sys.stdin.buffer.read(65536).decode("utf-8")
        req = json.loads(raw_input)
    except Exception as exc:
        sys.stdout.buffer.write(
            json.dumps({"ok": False, "error": f"Invalid worker input: {exc}"}, ensure_ascii=False).encode("utf-8")
        )
        sys.stdout.buffer.flush()
        return 1

    url = str(req.get("url", ""))
    mode = str(req.get("mode", "bundle"))
    fetch_content = bool(req.get("fetch_content", True))
    fetch_tls = bool(req.get("fetch_tls", True))

    # Strict caps enforced inside the worker regardless of caller payload
    max_response_bytes = min(int(req.get("max_response_bytes", settings.MAX_RESPONSE_BYTES)), settings.MAX_RESPONSE_BYTES)
    max_redirects = min(int(req.get("max_redirects", settings.MAX_REDIRECT_HOPS)), settings.MAX_REDIRECT_HOPS)
    connect_timeout = min(float(req.get("connect_timeout", settings.CONNECT_TIMEOUT_SECONDS)), 30.0)
    read_timeout = min(float(req.get("read_timeout", settings.READ_TIMEOUT_SECONDS)), 30.0)
    total_timeout = min(float(req.get("total_timeout", settings.TOTAL_FETCH_TIMEOUT_SECONDS)), 60.0)
    user_agent = str(req.get("user_agent", settings.USER_AGENT))[:512]

    # Worker ALWAYS enforces allow_local=False
    fetcher = SafeURLFetcher(
        allow_local=False,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        total_timeout=total_timeout,
        tls_timeout=min(settings.TLS_HANDSHAKE_TIMEOUT_SECONDS, total_timeout),
        max_redirects=max_redirects,
        max_response_bytes=max_response_bytes,
        max_content_length_bytes=settings.MAX_CONTENT_LENGTH_BYTES,
        user_agent=user_agent,
    )

    try:
        if mode == "tls":
            data = fetcher.fetch_tls_certificate(url)
        elif mode == "http":
            res = asyncio.run(fetcher.fetch_http(url, fetch_content=fetch_content, user_agent=user_agent))
            data = res.to_dict()
        else:
            res = asyncio.run(
                fetcher.fetch_scan_bundle(
                    url,
                    fetch_http=True,
                    fetch_content=fetch_content,
                    fetch_tls=fetch_tls,
                )
            )
            data = res.to_dict()

        out = json.dumps({"ok": True, "data": data}, ensure_ascii=False).encode("utf-8")
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        return 0
    except SSRFBlockedError as exc:
        out = json.dumps({"ok": False, "ssrf_blocked": True, "error": exc.detail}, ensure_ascii=False).encode("utf-8")
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        return 0
    except Exception as exc:
        out = json.dumps({"ok": False, "error": str(exc)[:300]}, ensure_ascii=False).encode("utf-8")
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        return 1


if __name__ == "__main__":
    raise SystemExit(_worker_main())
