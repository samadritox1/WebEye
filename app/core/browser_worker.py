import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

# Ensure project root is importable when worker runs under `python -I`
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.config import settings
from app.core.security_guard import (
    DNSResolutionError,
    SSRFBlockedError,
    is_public_ip,
    resolve_and_validate_host,
    validate_url_syntax_and_host,
)


_WORKER_SCRIPT_PATH = str(Path(__file__).resolve())
_IS_WINDOWS = os.name == "nt"


class BrowserSandboxError(Exception):
    """Raised when the isolated browser sandbox cannot run or fails."""


class BrowserSandboxTimeoutError(BrowserSandboxError):
    """Raised when isolated browser execution exceeds its wall-clock deadline."""


class BrowserJobSandbox:
    """Windows Job Object without single-process cap so Chromium + child renderers terminate together."""

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

            # KILL_ON_JOB_CLOSE (0x2000) | JOB_MEMORY (0x0200) | PRIORITY_CLASS (0x0020)
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = 0x2000 | 0x0200 | 0x0020
            info.BasicLimitInformation.PriorityClass = 0x00004000
            info.JobMemoryLimit = int(memory_limit_mb) * 1024 * 1024

            if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
                info.BasicLimitInformation.LimitFlags = 0x2000
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
                self._kernel32.TerminateJobObject(self._handle, 1)
            except Exception:
                pass
            try:
                self._kernel32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None


def find_headless_browser() -> Optional[str]:
    """Locate an installed Chromium, Google Chrome, or Microsoft Edge executable."""
    env_override = os.environ.get("PHISHPULSE_BROWSER_PATH", "").strip()
    if env_override and os.path.isfile(env_override):
        return env_override

    candidates: List[str] = []
    if _IS_WINDOWS:
        local_app = os.environ.get("LOCALAPPDATA", "")
        candidates.extend([
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ])
        if local_app:
            candidates.extend([
                os.path.join(local_app, r"Google\Chrome\Application\chrome.exe"),
                os.path.join(local_app, r"Microsoft\Edge\Application\msedge.exe"),
                os.path.join(local_app, r"Chromium\Application\chrome.exe"),
            ])
        for name in ("chrome", "msedge", "chromium"):
            found = shutil.which(name)
            if found:
                candidates.append(found)
    else:
        for name in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge"):
            found = shutil.which(name)
            if found:
                candidates.append(found)
        candidates.extend([
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ])

    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def _build_sanitized_env(sandbox_dir: str) -> Dict[str, str]:
    """Strip API keys, proxy variables, and host credentials from browser sandbox process."""
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
        "HOME": sandbox_dir,
        "TMPDIR": sandbox_dir,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
    }
    for cert_var in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        val = os.environ.get(cert_var)
        if val:
            env[cert_var] = val
    return env


def _read_stream_capped(stream, max_bytes: int, sink: list) -> None:
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


_OBSERVER_INIT_SCRIPT = r"""
(() => {
    const MAX_LOG = 60;
    const state = {
        eval_calls: [],
        network_calls: [],
        form_submits: [],
        event_hooks: [],
        history_calls: [],
        clipboard_ops: 0
    };
    const push = (arr, item) => {
        if (arr.length < MAX_LOG) arr.push(item);
    };

    try {
        const origEval = window.eval;
        window.eval = function(code) {
            push(state.eval_calls, {
                api: "eval",
                preview: String(code || "").slice(0, 220)
            });
            return origEval.apply(this, arguments);
        };
    } catch (_) {}

    try {
        const OrigFunc = window.Function;
        window.Function = function() {
            const body = arguments.length ? String(arguments[arguments.length - 1] || "") : "";
            push(state.eval_calls, {
                api: "Function",
                preview: body.slice(0, 220)
            });
            return OrigFunc.apply(this, arguments);
        };
        window.Function.prototype = OrigFunc.prototype;
    } catch (_) {}

    try {
        const origFetch = window.fetch;
        if (origFetch) {
            window.fetch = function(input, init) {
                const targetUrl = typeof input === "string" ? input : (input && input.url ? input.url : "");
                const method = (init && init.method) ? String(init.method).toUpperCase() : "GET";
                push(state.network_calls, { api: "fetch", method, url: String(targetUrl).slice(0, 500) });
                return origFetch.apply(this, arguments);
            };
        }
    } catch (_) {}

    try {
        const origOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
            push(state.network_calls, {
                api: "xhr",
                method: String(method || "GET").toUpperCase(),
                url: String(url || "").slice(0, 500)
            });
            return origOpen.apply(this, arguments);
        };
    } catch (_) {}

    try {
        if (navigator.sendBeacon) {
            const origBeacon = navigator.sendBeacon.bind(navigator);
            navigator.sendBeacon = function(url, data) {
                push(state.network_calls, {
                    api: "sendBeacon",
                    method: "POST",
                    url: String(url || "").slice(0, 500)
                });
                return origBeacon(url, data);
            };
        }
    } catch (_) {}

    try {
        const origSubmit = HTMLFormElement.prototype.submit;
        HTMLFormElement.prototype.submit = function() {
            push(state.form_submits, {
                action: String(this.action || "").slice(0, 500),
                method: String(this.method || "GET").toUpperCase()
            });
            return origSubmit.apply(this, arguments);
        };
    } catch (_) {}

    try {
        const origAdd = EventTarget.prototype.addEventListener;
        const watched = new Set(["contextmenu", "keydown", "keyup", "keypress", "beforeunload", "copy", "paste"]);
        EventTarget.prototype.addEventListener = function(type, listener, options) {
            const t = String(type || "").toLowerCase();
            if (watched.has(t)) {
                push(state.event_hooks, {
                    event: t,
                    target: (this && this.tagName) ? this.tagName.toLowerCase() : (this === window ? "window" : "document"),
                    preview: listener ? String(listener).slice(0, 180) : ""
                });
            }
            return origAdd.apply(this, arguments);
        };
    } catch (_) {}

    try {
        const origReplace = history.replaceState;
        history.replaceState = function(s, title, url) {
            push(state.history_calls, { api: "replaceState", url: String(url || "").slice(0, 300) });
            return origReplace.apply(this, arguments);
        };
    } catch (_) {}

    try {
        if (navigator.clipboard) {
            ["readText", "writeText"].forEach((m) => {
                if (typeof navigator.clipboard[m] === "function") {
                    const orig = navigator.clipboard[m].bind(navigator.clipboard);
                    navigator.clipboard[m] = function() {
                        state.clipboard_ops += 1;
                        return orig.apply(this, arguments);
                    };
                }
            });
        }
    } catch (_) {}

    Object.defineProperty(window, "__ppCollectSnapshot", {
        value: () => {
            const pageUrl = window.location.href;
            let pageOrigin = "";
            try { pageOrigin = new URL(pageUrl).origin; } catch (_) {}

            const forms = Array.from(document.querySelectorAll("form")).slice(0, 40).map((form, idx) => {
                const rawAction = (form.getAttribute("action") || "").trim();
                let resolvedAction = form.action || pageUrl;
                let actionDomain = "";
                let isCrossOrigin = false;
                try {
                    const u = new URL(resolvedAction, pageUrl);
                    resolvedAction = u.href;
                    actionDomain = u.hostname.toLowerCase();
                    if (pageOrigin && u.origin !== pageOrigin) {
                        isCrossOrigin = true;
                    }
                } catch (_) {}

                const inputs = Array.from(form.querySelectorAll("input, select, textarea, button"));
                const passwordCount = inputs.filter(el => (el.type || "").toLowerCase() === "password").length;
                const hiddenCount = inputs.filter(el => (el.type || "").toLowerCase() === "hidden").length;
                const inputNames = inputs
                    .map(el => (el.name || el.id || el.type || "").trim())
                    .filter(Boolean)
                    .slice(0, 16);
                const joinedMeta = inputNames.join(" ").toLowerCase();
                const hasCred = passwordCount > 0 || /(pass|pwd|otp|pin|token|login|user|email)/i.test(joinedMeta);
                const hasPay = /(card|cvv|cvc|ccnum|exp|iban|routing|ssn)/i.test(joinedMeta);
                const submitLabels = Array.from(form.querySelectorAll("button, input[type='submit']"))
                    .map(el => (el.innerText || el.value || "").trim())
                    .filter(Boolean)
                    .slice(0, 5);

                return {
                    form_index: idx + 1,
                    action_raw: rawAction,
                    action_url: resolvedAction,
                    action_domain: actionDomain,
                    method: (form.getAttribute("method") || "GET").toUpperCase(),
                    is_cross_origin: isCrossOrigin,
                    has_password_input: passwordCount > 0,
                    has_credential_fields: hasCred,
                    has_payment_fields: hasPay,
                    input_count: inputs.length,
                    hidden_inputs_count: hiddenCount,
                    input_names: inputNames,
                    submit_labels: submitLabels
                };
            });

            // Capture orphan password fields rendered outside <form> (JS credential kits)
            const totalPwdInputs = document.querySelectorAll("input[type='password']").length;
            const formPwdCount = forms.reduce((acc, f) => acc + (f.has_password_input ? 1 : 0), 0);
            if (totalPwdInputs > 0 && formPwdCount === 0) {
                forms.push({
                    form_index: forms.length + 1,
                    action_raw: "(dynamic-js-formless)",
                    action_url: pageUrl,
                    action_domain: location.hostname.toLowerCase(),
                    method: "JS_HANDLER",
                    is_cross_origin: false,
                    has_password_input: true,
                    has_credential_fields: true,
                    has_payment_fields: false,
                    input_count: totalPwdInputs,
                    hidden_inputs_count: 0,
                    input_names: ["password"],
                    submit_labels: []
                });
            }

            const inlineScripts = Array.from(document.querySelectorAll("script"))
                .filter(s => !s.src && (s.textContent || "").trim().length > 0)
                .slice(0, 25)
                .map((s, idx) => ({
                    index: idx + 1,
                    text: (s.textContent || "").slice(0, 12000)
                }));

            const externalScripts = Array.from(document.querySelectorAll("script[src]"))
                .map(s => s.src)
                .filter(Boolean)
                .slice(0, 50);

            const inlineHandlers = Array.from(document.querySelectorAll("[oncontextmenu],[onkeydown]"))
                .slice(0, 15)
                .map(el => ({
                    tag: el.tagName.toLowerCase(),
                    oncontextmenu: el.getAttribute("oncontextmenu") || "",
                    onkeydown: el.getAttribute("onkeydown") || ""
                }));

            return {
                final_url: pageUrl,
                page_title: document.title || "",
                forms,
                inline_scripts: inlineScripts,
                external_scripts: externalScripts,
                inline_handlers: inlineHandlers,
                telemetry: state
            };
        },
        configurable: false,
        enumerable: false
    });
})();
"""


def validate_browser_subrequest(
    req_url: str,
    dns_cache: Optional[Dict[Tuple[str, int], bool]] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Enforce strict SSRF & scheme policy for every URL/subresource requested by Chrome.
    Returns (allowed, blocked_reason).
    """
    low = (req_url or "").strip().lower()
    if not low:
        return False, "Empty request URL"

    if low == "about:blank" or low.startswith(("data:", "blob:")):
        return True, None

    if not low.startswith(("http://", "https://")):
        scheme = low.split(":", 1)[0] if ":" in low else "unknown"
        return False, f"Unsupported scheme blocked in sandbox: {scheme}"

    try:
        _, _, ascii_host, port = validate_url_syntax_and_host(req_url, allow_local=False)
    except Exception as exc:
        detail = getattr(exc, "detail", str(exc))
        return False, f"SSRFBlocked: {detail}"

    cache_key = (ascii_host, port)
    if dns_cache is not None and cache_key in dns_cache:
        if not dns_cache[cache_key]:
            return False, f"SSRFBlocked: Cached DNS rejection for '{ascii_host}'"
        return True, None

    try:
        resolve_and_validate_host(
            ascii_host,
            port,
            allow_local=False,
            require_resolution=False,
        )
        if dns_cache is not None:
            dns_cache[cache_key] = True
        return True, None
    except SSRFBlockedError as exc:
        if dns_cache is not None:
            dns_cache[cache_key] = False
        return False, f"SSRFBlocked: {exc.detail}"
    except DNSResolutionError as exc:
        return False, f"DNS resolution error: {exc}"


class _CDPSession:
    """Minimal concurrent Chrome DevTools Protocol client over aiohttp WebSocket."""

    def __init__(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        self.ws = ws
        self.session_id: Optional[str] = None
        self._msg_id = 0
        self._pending: Dict[int, asyncio.Future] = {}
        self._handlers: Dict[str, Any] = {}
        self._recv_task: Optional[asyncio.Task] = None

    def on(self, method: str, handler) -> None:
        self._handlers[method] = handler

    def start(self) -> None:
        self._recv_task = asyncio.create_task(self._recv_loop())

    async def stop(self) -> None:
        if self._recv_task:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    async def _recv_loop(self) -> None:
        async for msg in self.ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                continue
            try:
                payload = json.loads(msg.data)
            except Exception:
                continue

            if "id" in payload:
                fut = self._pending.pop(payload["id"], None)
                if fut and not fut.done():
                    fut.set_result(payload)
            elif "method" in payload:
                handler = self._handlers.get(payload["method"])
                if handler:
                    res = handler(payload.get("params") or {}, payload.get("sessionId"))
                    if asyncio.iscoroutine(res):
                        asyncio.create_task(res)

    async def send(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        use_session: bool = True,
        timeout: float = 8.0,
    ) -> Dict[str, Any]:
        self._msg_id += 1
        cid = self._msg_id
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[cid] = fut

        frame: Dict[str, Any] = {"id": cid, "method": method}
        if params is not None:
            frame["params"] = params
        if use_session and self.session_id:
            frame["sessionId"] = self.session_id

        await self.ws.send_json(frame)
        try:
            resp = await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._pending.pop(cid, None)

        if "error" in resp:
            err = resp["error"]
            raise BrowserSandboxError(f"CDP {method} failed: {err.get('message', err)}")
        return resp.get("result") or {}


def _spawn_browser_and_get_ws(
    browser_exe: str,
    user_data_dir: str,
    width: int,
    height: int,
) -> Tuple[subprocess.Popen, str, BrowserJobSandbox]:
    """Launch headless Chrome/Edge cleanly on an ephemeral loopback CDP port."""
    cmd = [
        browser_exe,
        "--headless=new",
        "--incognito",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-default-apps",
        "--disable-popup-blocking",
        "--mute-audio",
        "--disk-cache-size=1",
        "--media-cache-size=1",
        "--disable-features=Translate,OptimizationHints",
        f"--window-size={width},{height}",
        f"--user-data-dir={user_data_dir}",
        "--remote-debugging-port=0",
        "about:blank",
    ]
    if not _IS_WINDOWS and os.geteuid() == 0:
        cmd.append("--no-sandbox")

    job = BrowserJobSandbox(memory_limit_mb=settings.SANDBOX_WORKER_MEMORY_LIMIT_MB)
    popen_kwargs: Dict[str, Any] = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.DEVNULL,
        "cwd": user_data_dir,
        "close_fds": True,
    }
    if _IS_WINDOWS:
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    else:
        popen_kwargs["preexec_fn"] = os.setsid

    proc = subprocess.Popen(cmd, **popen_kwargs)
    if _IS_WINDOWS:
        job.assign(int(proc._handle))

    ws_url = None
    deadline = time.monotonic() + 10.0
    stderr_lines: List[str] = []

    def _read_stderr() -> None:
        nonlocal ws_url
        if proc.stderr is None:
            return
        try:
            for raw_line in iter(proc.stderr.readline, b""):
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if line:
                    stderr_lines.append(line)
                match = re.search(r"DevTools listening on (ws://127\.0\.0\.1:\d+/devtools/browser/\S+)", line)
                if match:
                    ws_url = match.group(1)
                    break
        except Exception:
            pass

    reader_thread = threading.Thread(target=_read_stderr, daemon=True)
    reader_thread.start()
    while time.monotonic() < deadline and ws_url is None and proc.poll() is None:
        time.sleep(0.05)

    if not ws_url:
        proc.kill()
        job.close()
        tail = " | ".join(stderr_lines[-3:])[:220]
        raise BrowserSandboxError(f"Failed to start headless browser CDP endpoint ({tail or 'no stderr'})")

    return proc, ws_url, job


async def _detonate_in_cdp(req: Dict[str, Any]) -> Dict[str, Any]:
    target_url = str(req["url"])
    wait_seconds = min(6.0, max(0.2, float(req.get("wait_seconds", settings.SANDBOX_WAIT_AFTER_LOAD_SECONDS))))
    timeout_seconds = min(30.0, max(5.0, float(req.get("timeout_seconds", settings.SANDBOX_TIMEOUT_SECONDS))))
    width = int(req.get("viewport_width", settings.SANDBOX_VIEWPORT_WIDTH))
    height = int(req.get("viewport_height", settings.SANDBOX_VIEWPORT_HEIGHT))
    user_agent = str(req.get("user_agent", settings.USER_AGENT))[:512]

    # Strict pre-flight SSRF check inside worker
    normalized_url, _, ascii_host, port = validate_url_syntax_and_host(target_url, allow_local=False)
    resolve_and_validate_host(ascii_host, port, allow_local=False, require_resolution=False)

    browser_exe = find_headless_browser()
    if not browser_exe:
        raise BrowserSandboxError(
            "No headless Chromium/Chrome/Edge browser executable found on system."
        )

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="pp_browser_profile_", ignore_cleanup_errors=True) as profile_dir:
        proc, ws_url, job = _spawn_browser_and_get_ws(browser_exe, profile_dir, width, height)

        request_map: Dict[str, Dict[str, Any]] = {}
        redirect_chain: List[Dict[str, Any]] = []
        blocked_requests: List[Dict[str, Any]] = []
        parsed_scripts: List[Dict[str, Any]] = []
        dns_cache: Dict[Tuple[str, int], bool] = {}
        load_event = asyncio.Event()
        browser_product = ""
        target_host = ascii_host

        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(ws_url, max_msg_size=16 * 1024 * 1024) as ws:
                    cdp = _CDPSession(ws)
                    cdp.start()

                    async def _on_fetch_paused(params: Dict[str, Any], sess_id: Optional[str]) -> None:
                        rid = params.get("requestId")
                        req_obj = params.get("request") or {}
                        req_url = str(req_obj.get("url") or "")
                        res_type = str(params.get("resourceType") or "Other")
                        allowed, reason = await asyncio.to_thread(
                            validate_browser_subrequest, req_url, dns_cache
                        )
                        if allowed:
                            try:
                                await cdp.send("Fetch.continueRequest", {"requestId": rid}, timeout=3.0)
                            except Exception:
                                pass
                        else:
                            parsed_u = urlparse(req_url)
                            net_id = str(params.get("networkId") or "")
                            if net_id and net_id in request_map:
                                request_map[net_id]["blocked"] = True
                                request_map[net_id]["blocked_reason"] = reason
                                request_map[net_id]["failed"] = True
                            blocked_requests.append({
                                "request_id": str(net_id or rid or ""),
                                "url": req_url[:600],
                                "domain": (parsed_u.hostname or "").lower(),
                                "method": str(req_obj.get("method") or "GET"),
                                "resource_type": res_type,
                                "is_third_party": (parsed_u.hostname or "").lower() != target_host,
                                "blocked": True,
                                "blocked_reason": reason,
                                "failed": True,
                            })
                            try:
                                await cdp.send(
                                    "Fetch.failRequest",
                                    {"requestId": rid, "errorReason": "AccessDenied"},
                                    timeout=3.0,
                                )
                            except Exception:
                                pass

                    async def _on_dialog(params: Dict[str, Any], sess_id: Optional[str]) -> None:
                        try:
                            await cdp.send(
                                "Page.handleJavaScriptDialog",
                                {"accept": False},
                                timeout=2.0,
                            )
                        except Exception:
                            pass

                    def _on_request_sent(params: Dict[str, Any], sess_id: Optional[str]) -> None:
                        rid = str(params.get("requestId") or "")
                        req_obj = params.get("request") or {}
                        req_url = str(req_obj.get("url") or "")
                        res_type = str(params.get("type") or "Other")
                        init_type = str((params.get("initiator") or {}).get("type") or "other")
                        redir_resp = params.get("redirectResponse")

                        if redir_resp:
                            prev_url = str(redir_resp.get("url") or "")
                            prev_host = (urlparse(prev_url).hostname or "").lower()
                            redirect_chain.append({
                                "hop": len(redirect_chain) + 1,
                                "url": prev_url[:600],
                                "status_code": int(redir_resp.get("status") or 302),
                                "method": str(req_obj.get("method") or "GET"),
                                "resource_type": res_type,
                                "remote_ip": redir_resp.get("remoteIPAddress"),
                                "server": (redir_resp.get("headers") or {}).get("server"),
                                "location": req_url[:600],
                                "is_cross_origin": bool(prev_host and prev_host != target_host),
                            })

                        if len(request_map) < 150 and req_url.startswith(("http://", "https://")):
                            dom = (urlparse(req_url).hostname or "").lower()
                            request_map[rid] = {
                                "request_id": rid,
                                "url": req_url[:600],
                                "domain": dom,
                                "method": str(req_obj.get("method") or "GET"),
                                "resource_type": res_type,
                                "status_code": None,
                                "mime_type": None,
                                "remote_ip": None,
                                "remote_port": None,
                                "is_third_party": bool(dom and dom != target_host and not dom.endswith("." + target_host)),
                                "blocked": False,
                                "blocked_reason": None,
                                "failed": False,
                                "error_text": None,
                                "initiator_type": init_type,
                            }

                    def _on_response_received(params: Dict[str, Any], sess_id: Optional[str]) -> None:
                        rid = str(params.get("requestId") or "")
                        resp = params.get("response") or {}
                        remote_ip = resp.get("remoteIPAddress")
                        entry = request_map.get(rid)
                        if entry:
                            entry["status_code"] = resp.get("status")
                            entry["mime_type"] = resp.get("mimeType")
                            entry["remote_ip"] = remote_ip
                            entry["remote_port"] = resp.get("remotePort")

                        # Defense-in-depth remote peer check
                        if remote_ip and not is_public_ip(str(remote_ip)):
                            if entry:
                                entry["blocked"] = True
                                entry["blocked_reason"] = f"SSRFBlocked: non-public remote peer '{remote_ip}'"
                                blocked_requests.append(dict(entry))

                    def _on_loading_failed(params: Dict[str, Any], sess_id: Optional[str]) -> None:
                        rid = str(params.get("requestId") or "")
                        entry = request_map.get(rid)
                        if entry:
                            entry["failed"] = True
                            entry["error_text"] = str(params.get("errorText") or "Failed")[:120]

                    def _on_script_parsed(params: Dict[str, Any], sess_id: Optional[str]) -> None:
                        if len(parsed_scripts) < 80:
                            s_url = str(params.get("url") or "")
                            if not s_url.startswith("__puppeteer") and not s_url.startswith("inspector://"):
                                parsed_scripts.append({
                                    "scriptId": str(params.get("scriptId") or ""),
                                    "url": s_url[:500],
                                    "length": int(params.get("length") or 0),
                                    "is_module": bool(params.get("isModule")),
                                    "has_source_url": bool(params.get("hasSourceURL")),
                                })

                    def _on_load_event(params: Dict[str, Any], sess_id: Optional[str]) -> None:
                        load_event.set()

                    try:
                        ver = await cdp.send("Browser.getVersion", use_session=False)
                        browser_product = str(ver.get("product") or "Chromium")

                        ctx_res = await cdp.send("Target.createBrowserContext", {"disposeOnDetach": True}, use_session=False)
                        ctx_id = ctx_res["browserContextId"]

                        await cdp.send(
                            "Browser.setDownloadBehavior",
                            {"behavior": "deny", "browserContextId": ctx_id},
                            use_session=False,
                        )

                        tgt_res = await cdp.send(
                            "Target.createTarget",
                            {"url": "about:blank", "browserContextId": ctx_id, "width": width, "height": height},
                            use_session=False,
                        )
                        target_id = tgt_res["targetId"]

                        att_res = await cdp.send(
                            "Target.attachToTarget",
                            {"targetId": target_id, "flatten": True},
                            use_session=False,
                        )
                        cdp.session_id = att_res["sessionId"]

                        cdp.on("Fetch.requestPaused", _on_fetch_paused)
                        cdp.on("Page.javascriptDialogOpening", _on_dialog)
                        cdp.on("Network.requestWillBeSent", _on_request_sent)
                        cdp.on("Network.responseReceived", _on_response_received)
                        cdp.on("Network.loadingFailed", _on_loading_failed)
                        cdp.on("Debugger.scriptParsed", _on_script_parsed)
                        cdp.on("Page.loadEventFired", _on_load_event)

                        await cdp.send("Page.enable")
                        await cdp.send("Network.enable", {"maxTotalBufferSize": 4 * 1024 * 1024})
                        await cdp.send("Network.setUserAgentOverride", {"userAgent": user_agent})
                        await cdp.send("Runtime.enable")
                        await cdp.send("Debugger.enable")
                        await cdp.send(
                            "Emulation.setDeviceMetricsOverride",
                            {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": False},
                        )
                        await cdp.send("Page.addScriptToEvaluateOnNewDocument", {"source": _OBSERVER_INIT_SCRIPT})
                        await cdp.send(
                            "Fetch.enable",
                            {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
                        )

                        nav_res = await cdp.send("Page.navigate", {"url": normalized_url}, timeout=12.0)
                        if nav_res.get("errorText") and not redirect_chain:
                            raise BrowserSandboxError(f"Navigation failed: {nav_res['errorText']}")

                        # Wait for load event, then settle to observe dynamic JS forms/redirects
                        nav_budget = max(2.0, timeout_seconds - (time.monotonic() - started) - wait_seconds - 2.0)
                        try:
                            await asyncio.wait_for(load_event.wait(), timeout=nav_budget)
                        except asyncio.TimeoutError:
                            pass

                        await asyncio.sleep(wait_seconds)

                        # Collect screenshot & DOM + runtime telemetry
                        shot_res = await cdp.send(
                            "Page.captureScreenshot",
                            {"format": "png", "fromSurface": True},
                            timeout=8.0,
                        )
                        screenshot_b64 = shot_res.get("data") or ""

                        eval_res = await cdp.send(
                            "Runtime.evaluate",
                            {
                                "expression": "window.__ppCollectSnapshot ? window.__ppCollectSnapshot() : {}",
                                "returnByValue": True,
                            },
                            timeout=5.0,
                        )
                        snapshot = ((eval_res.get("result") or {}).get("value")) or {}

                        final_url = str(snapshot.get("final_url") or normalized_url)
                        # Include any subsequent client-side/JS Document hops plus terminal page state
                        doc_reqs = [r for r in request_map.values() if r["resource_type"] == "Document"]
                        seen_hop_urls = {h["url"] for h in redirect_chain}
                        for doc in doc_reqs:
                            if doc["url"] not in seen_hop_urls and doc["url"] != final_url:
                                doc_host = (urlparse(doc["url"]).hostname or target_host).lower()
                                redirect_chain.append({
                                    "hop": len(redirect_chain) + 1,
                                    "url": doc["url"][:600],
                                    "status_code": doc.get("status_code"),
                                    "method": doc.get("method") or "GET",
                                    "resource_type": "Document",
                                    "remote_ip": doc.get("remote_ip"),
                                    "server": None,
                                    "location": None,
                                    "is_cross_origin": bool(doc_host != target_host),
                                })
                                seen_hop_urls.add(doc["url"])

                        last_doc = doc_reqs[-1] if doc_reqs else {}
                        final_host = (urlparse(final_url).hostname or target_host).lower()
                        if not seen_hop_urls or final_url not in seen_hop_urls:
                            redirect_chain.append({
                                "hop": len(redirect_chain) + 1,
                                "url": final_url[:600],
                                "status_code": last_doc.get("status_code"),
                                "method": last_doc.get("method") or "GET",
                                "resource_type": "Document",
                                "remote_ip": last_doc.get("remote_ip"),
                                "server": None,
                                "location": None,
                                "is_cross_origin": bool(final_host != target_host),
                            })

                        return {
                            "target_url": normalized_url,
                            "final_url": final_url,
                            "page_title": str(snapshot.get("page_title") or ""),
                            "browser_product": browser_product,
                            "execution_ms": int((time.monotonic() - started) * 1000),
                            "screenshot_b64": screenshot_b64,
                            "redirect_chain": redirect_chain,
                            "network_requests": list(request_map.values()),
                            "blocked_requests": blocked_requests,
                            "form_destinations": list(snapshot.get("forms") or []),
                            "inline_scripts": list(snapshot.get("inline_scripts") or []),
                            "external_scripts": list(snapshot.get("external_scripts") or []),
                            "inline_handlers": list(snapshot.get("inline_handlers") or []),
                            "parsed_scripts_count": len(parsed_scripts),
                            "telemetry": snapshot.get("telemetry") or {},
                        }
                    finally:
                        try:
                            await cdp.send("Browser.close", use_session=False, timeout=2.0)
                        except Exception:
                            pass
                        await cdp.stop()
        finally:
            job.close()
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=4)
                except Exception:
                    pass
            if proc.stderr is not None:
                try:
                    proc.stderr.close()
                except Exception:
                    pass
            if not _IS_WINDOWS:
                try:
                    os.killpg(os.getpgid(proc.pid), 9)
                except Exception:
                    pass


def run_in_browser_worker_sync(
    url: str,
    wait_seconds: float = settings.SANDBOX_WAIT_AFTER_LOAD_SECONDS,
    timeout_seconds: float = settings.SANDBOX_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """
    Execute URL inside an OS-isolated browser sandbox subprocess.
    Never executes untrusted web content directly inside the main FastAPI server process.
    """
    normalized_url, _, _, _ = validate_url_syntax_and_host(url, allow_local=False)
    browser_exe = find_headless_browser()
    if not browser_exe:
        raise BrowserSandboxError(
            "No headless Chrome/Chromium/Edge browser installed for sandbox execution."
        )

    eff_timeout = min(30.0, max(5.0, float(timeout_seconds)))
    wait_sec = min(6.0, max(0.2, float(wait_seconds)))
    subprocess_timeout = eff_timeout + 5.0

    payload = {
        "url": normalized_url,
        "wait_seconds": wait_sec,
        "timeout_seconds": eff_timeout,
        "viewport_width": settings.SANDBOX_VIEWPORT_WIDTH,
        "viewport_height": settings.SANDBOX_VIEWPORT_HEIGHT,
        "user_agent": settings.USER_AGENT,
    }
    input_bytes = json.dumps(payload, ensure_ascii=True).encode("utf-8")

    with tempfile.TemporaryDirectory(prefix="phishpulse_browser_worker_", ignore_cleanup_errors=True) as sandbox_dir:
        clean_env = _build_sanitized_env(sandbox_dir)
        clean_env["PHISHPULSE_BROWSER_PATH"] = browser_exe
        job = BrowserJobSandbox(memory_limit_mb=settings.SANDBOX_WORKER_MEMORY_LIMIT_MB + 256)

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
            popen_kwargs["preexec_fn"] = os.setsid

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
                args=(proc.stdout, settings.SANDBOX_MAX_WORKER_OUTPUT_BYTES, stdout_sink),
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
                returncode = proc.wait(timeout=subprocess_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                raise BrowserSandboxTimeoutError(
                    f"Browser sandbox execution exceeded timeout ({subprocess_timeout:.1f}s)"
                )

            t_out.join(timeout=2)
            t_err.join(timeout=2)

            raw_out = stdout_sink[0] if stdout_sink else b""
            raw_err = stderr_sink[0] if stderr_sink else b""

            if len(raw_out) > settings.SANDBOX_MAX_WORKER_OUTPUT_BYTES:
                raise BrowserSandboxError("Browser sandbox output exceeded maximum IPC limit")

            if returncode != 0 and not raw_out:
                err_msg = raw_err.decode("utf-8", errors="replace").strip()[:200]
                raise BrowserSandboxError(f"Browser sandbox exited with code {returncode}: {err_msg}")

            try:
                worker_resp = json.loads(raw_out.decode("utf-8"))
            except Exception as exc:
                err_msg = raw_err.decode("utf-8", errors="replace").strip()[:200]
                raise BrowserSandboxError(f"Invalid browser sandbox response: {exc} ({err_msg})") from exc

            if worker_resp.get("ssrf_blocked"):
                raise SSRFBlockedError(
                    worker_resp.get("error") or "Security Policy Violation (SSRF Defense)."
                )
            if not worker_resp.get("ok"):
                raise BrowserSandboxError(worker_resp.get("error") or "Browser sandbox failed")

            result = worker_resp["data"]
            result["isolated_worker_pid"] = proc.pid
            return result
        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except Exception:
                    pass
            job.close()


async def run_in_browser_worker(
    url: str,
    wait_seconds: float = settings.SANDBOX_WAIT_AFTER_LOAD_SECONDS,
    timeout_seconds: float = settings.SANDBOX_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Run isolated Chromium detonation asynchronously without blocking the FastAPI event loop."""
    return await asyncio.to_thread(
        run_in_browser_worker_sync,
        url=url,
        wait_seconds=wait_seconds,
        timeout_seconds=timeout_seconds,
    )


def _worker_main() -> int:
    try:
        raw_input = sys.stdin.buffer.read(65536).decode("utf-8")
        req = json.loads(raw_input)
    except Exception as exc:
        sys.stdout.buffer.write(
            json.dumps({"ok": False, "error": f"Invalid sandbox input: {exc}"}, ensure_ascii=False).encode("utf-8")
        )
        sys.stdout.buffer.flush()
        return 1

    try:
        data = asyncio.run(_detonate_in_cdp(req))
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
