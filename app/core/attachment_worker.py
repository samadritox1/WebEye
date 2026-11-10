import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from lxml import html as lxml_html

# Ensure project root is importable when worker runs under `python -I`
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.config import settings


_WORKER_SCRIPT_PATH = str(Path(__file__).resolve())
_IS_WINDOWS = os.name == "nt"

_MAX_ARCHIVE_ENTRIES = 64
_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 10 * 1024 * 1024  # 10 MiB decompression bomb guard

_EXECUTABLE_EXTS = frozenset({
    ".exe", ".dll", ".scr", ".cpl", ".msi", ".msp", ".com", ".pif", ".bat", ".cmd",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar",
    ".lnk", ".iso", ".img", ".vhd", ".vhdx", ".reg", ".inf",
})
_MACRO_OFFICE_EXTS = frozenset({".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".doc", ".xls", ".ppt"})
_HTML_SVG_EXTS = frozenset({".html", ".htm", ".shtml", ".xhtml", ".svg"})

_BENIGN_DOC_EXTS = frozenset({".pdf", ".txt", ".csv", ".png", ".jpg", ".jpeg", ".gif", ".docx", ".xlsx", ".pptx"})
_URL_RE = re.compile(r"https?://[^\s<>'\"\)\]]+", re.I)


class AttachmentWorkerError(Exception):
    """Raised when isolated attachment inspection fails or exceeds resource bounds."""


class _WorkerJobSandbox:
    """OS job/memory containment for isolated attachment analysis."""

    def __init__(self, memory_limit_mb: int = 128) -> None:
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
                    ("SchedulingClass", ctypes.c_DWORD if hasattr(ctypes, "c_DWORD") else wt.DWORD),
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
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = 0x2000 | 0x0008 | 0x0100 | 0x0020
            info.BasicLimitInformation.ActiveProcessLimit = 1
            info.BasicLimitInformation.PriorityClass = 0x00004000
            info.ProcessMemoryLimit = int(memory_limit_mb) * 1024 * 1024
            if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
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
    def _preexec() -> None:
        try:
            import resource

            os.setsid()
            mem_bytes = int(memory_limit_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
            resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
            cpu_limit = max(2, int(timeout_seconds) + 1)
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except Exception:
                pass
        except Exception:
            pass

    return _preexec


def _build_sanitized_env(sandbox_dir: str) -> Dict[str, str]:
    if _IS_WINDOWS:
        return {
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
            "TEMP": sandbox_dir,
            "TMP": sandbox_dir,
            "PYTHONNOUSERSITE": "1",
        }
    return {
        "PATH": "/usr/bin:/bin",
        "TMPDIR": sandbox_dir,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
    }


def _install_strict_offline_audit_hook() -> None:
    """Block all network sockets, subprocess creation, dynamic libraries, and filesystem writes."""
    blocked_exact = frozenset({
        "subprocess.Popen",
        "os.system",
        "os.fork",
        "os.forkpty",
        "os.posix_spawn",
        "os.startfile",
        "ctypes.dlopen",
        "ctypes.dlsym",
        "socket.connect",
        "socket.bind",
        "socket.getaddrinfo",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.rename",
        "os.mkdir",
    })
    blocked_prefixes = ("os.spawn", "os.exec", "winreg.", "sqlite3.")
    write_open_flags = (
        getattr(os, "O_WRONLY", 1)
        | getattr(os, "O_RDWR", 2)
        | getattr(os, "O_CREAT", 0)
        | getattr(os, "O_TRUNC", 0)
        | getattr(os, "O_APPEND", 0)
    )

    def _hook(event: str, args: tuple) -> None:
        if event in blocked_exact or any(event.startswith(p) for p in blocked_prefixes):
            raise PermissionError(f"Prohibited operation '{event}' inside isolated attachment analyzer")
        if event == "open" and len(args) >= 3:
            mode = args[1]
            flags = args[2]
            if isinstance(mode, str) and any(ch in mode for ch in ("w", "a", "x", "+")):
                raise PermissionError("File write access prohibited in isolated attachment analyzer")
            if isinstance(flags, int) and (flags & write_open_flags):
                raise PermissionError("Write flags prohibited in isolated attachment analyzer")

    sys.addaudithook(_hook)


def _detect_magic_type(raw: bytes) -> str:
    if raw.startswith(b"MZ"):
        return "pe_executable"
    if raw.startswith(b"\x7fELF"):
        return "elf_executable"
    if raw.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")):
        return "macho_executable"
    if raw.startswith(b"%PDF-"):
        return "pdf"
    if raw.startswith(b"PK\x03\x04"):
        return "zip_container"
    if raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole2_office"
    if raw.startswith(b"Rar!\x1a\x07"):
        return "rar_archive"
    if raw.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z_archive"
    if raw.startswith(b"\x1f\x8b\x08"):
        return "gzip_archive"
    if raw.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "windows_shortcut_lnk"
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png_image"
    if raw.startswith(b"\xff\xd8\xff"):
        return "jpeg_image"
    if raw.startswith((b"GIF87a", b"GIF89a")):
        return "gif_image"
    head = raw[:512].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html", b"<script", b"<meta")):
        return "html_document"
    if b"<svg" in head:
        return "svg_image"
    return "text_or_binary"


def _inspect_single_attachment(item: Dict[str, Any]) -> Dict[str, Any]:
    filename = str(item.get("filename") or "attachment.bin")
    content_type = str(item.get("content_type") or "application/octet-stream").lower()
    raw_b64 = str(item.get("data_b64") or "")
    raw = base64.b64decode(raw_b64) if raw_b64 else b""

    sha256 = hashlib.sha256(raw).hexdigest()
    md5 = hashlib.md5(raw).hexdigest()
    size_bytes = len(raw)

    clean_name = filename.strip()
    lower_name = clean_name.lower()
    ext = Path(lower_name).suffix
    magic = _detect_magic_type(raw)

    findings: List[str] = []
    archive_entries: List[str] = []
    extracted_urls: List[str] = []
    score = 0.0
    ext_mismatch = False
    is_dangerous = False

    # 1. RLO Unicode Spoofing & Double-Extension Deception
    if "\u202e" in clean_name or "\u202d" in clean_name:
        findings.append("Right-to-Left Override (RLO) Unicode filename spoofing detected")
        score += 60.0
        is_dangerous = True

    parts = [p for p in lower_name.split(".") if p]
    if len(parts) >= 3 and f".{parts[-1]}" in _EXECUTABLE_EXTS and f".{parts[-2]}" in _BENIGN_DOC_EXTS:
        findings.append(f"Double-extension masquerading detected ('.{parts[-2]}.{parts[-1]}')")
        score += 55.0
        is_dangerous = True

    # 2. Magic-byte vs Declared Extension Mismatch
    if magic in ("pe_executable", "elf_executable", "macho_executable", "windows_shortcut_lnk"):
        is_dangerous = True
        if ext not in _EXECUTABLE_EXTS:
            ext_mismatch = True
            findings.append(f"Executable binary magic ({magic}) disguised with extension '{ext or 'none'}'")
            score += 75.0
        else:
            findings.append(f"Executable / system payload attached ({ext}, {magic})")
            score += 65.0
    elif ext in _EXECUTABLE_EXTS:
        is_dangerous = True
        findings.append(f"High-risk executable/script file extension '{ext}'")
        score += 60.0

    # 3. ZIP / OOXML Safe In-Memory Inspection (Decompression-Bomb Bounded)
    if magic == "zip_container" or ext in (".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw), "r") as zf:
                infos = zf.infolist()
                total_uncomp = 0
                if len(infos) > _MAX_ARCHIVE_ENTRIES:
                    findings.append(f"Archive contains excessive entries ({len(infos)}); truncated inspection")
                    score += 15.0

                for zi in infos[:_MAX_ARCHIVE_ENTRIES]:
                    archive_entries.append(zi.filename[:180])
                    zlow = zi.filename.lower()
                    zext = Path(zlow).suffix
                    total_uncomp += max(0, zi.file_size)

                    if zi.flag_bits & 0x1:
                        findings.append(f"Password-encrypted archive entry '{zi.filename}' (sandbox evasion tactic)")
                        score += 35.0
                        is_dangerous = True

                    if zext in _EXECUTABLE_EXTS:
                        findings.append(f"Archive embeds dangerous executable/script '{zi.filename}'")
                        score += 65.0
                        is_dangerous = True

                    if zlow.endswith("vbaproject.bin"):
                        findings.append(f"Office document contains VBA Macro payload ('{zi.filename}')")
                        score += 50.0
                        is_dangerous = True

                    if "oleobject" in zlow or zlow.endswith(".bin"):
                        findings.append(f"Embedded OLE/binary object inside document ('{zi.filename}')")
                        score += 25.0

                    # Inspect OOXML relationship XMLs for external template injection
                    if zlow.endswith(".rels") and zi.file_size <= 262144 and total_uncomp <= _MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        try:
                            rel_text = zf.read(zi.filename).decode("utf-8", errors="ignore")
                            if "TargetMode=\"External\"" in rel_text or "TargetMode='External'" in rel_text:
                                urls = _URL_RE.findall(rel_text)
                                for u in urls[:5]:
                                    if u not in extracted_urls and not u.lower().startswith("http://schemas."):
                                        extracted_urls.append(u)
                                if urls:
                                    findings.append(f"OOXML external relationship/template link in '{zi.filename}'")
                                    score += 45.0
                                    is_dangerous = True
                        except Exception:
                            pass

                if total_uncomp > _MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                    findings.append(f"Archive uncompressed size ({total_uncomp} bytes) exceeds 10 MiB threshold (zip bomb risk)")
                    score += 40.0
                    is_dangerous = True
        except zipfile.BadZipFile:
            if magic == "zip_container":
                findings.append("Corrupted or malformed ZIP/OOXML container")
                score += 20.0

    # 4. Legacy OLE2 Binary Macro Check (.doc / .xls / .ppt)
    if magic == "ole2_office":
        if b"VBA" in raw or b"vbaProject" in raw or b"AutoOpen" in raw or b"Workbook_Open" in raw:
            findings.append("Legacy OLE2 Office file contains VBA Macro / AutoOpen markers")
            score += 50.0
            is_dangerous = True
        for u in _URL_RE.findall(raw.decode("latin-1", errors="ignore"))[:8]:
            if u not in extracted_urls:
                extracted_urls.append(u)

    # 5. PDF Static Token & URI Inspection (No rendering/execution)
    if magic == "pdf" or ext == ".pdf":
        if magic != "pdf" and ext == ".pdf" and not ext_mismatch:
            ext_mismatch = True
            findings.append(f"File declared as .pdf does not match PDF header (magic={magic})")
            score += 35.0
        pdf_text = raw.decode("latin-1", errors="ignore")
        if re.search(r"/(?:JavaScript|JS)\b", pdf_text):
            findings.append("PDF embeds active /JavaScript actions")
            score += 45.0
            is_dangerous = True
        if re.search(r"/(?:OpenAction|AA)\b", pdf_text):
            findings.append("PDF uses automatic trigger (/OpenAction or /AA)")
            score += 25.0
        if re.search(r"/Launch\b", pdf_text):
            findings.append("PDF requests external program /Launch command")
            score += 60.0
            is_dangerous = True
        if re.search(r"/EmbeddedFile\b", pdf_text):
            findings.append("PDF carries /EmbeddedFile payload")
            score += 25.0
        for u in _URL_RE.findall(pdf_text)[:10]:
            if u not in extracted_urls:
                extracted_urls.append(u)

    # 6. HTML / SVG Attachment Smuggling & Phishing Form Inspection
    if magic in ("html_document", "svg_image") or ext in _HTML_SVG_EXTS or "text/html" in content_type or "image/svg" in content_type:
        text_body = raw.decode("utf-8", errors="replace")
        low_body = text_body.lower()
        try:
            parser = lxml_html.HTMLParser(recover=True, collect_ids=False, no_network=True)
            tree = lxml_html.fromstring(text_body, parser=parser)
            pwd_count = len(tree.xpath("//input[@type='password']"))
            forms = tree.xpath("//form")
            if pwd_count > 0:
                findings.append(f"HTML attachment renders credential password form ({pwd_count} password input(s))")
                score += 45.0
                is_dangerous = True
            for form in forms:
                act = (form.get("action") or "").strip()
                if act.startswith(("http://", "https://")) and act not in extracted_urls:
                    extracted_urls.append(act)
                    findings.append(f"HTML attachment <form> posts directly to external URL '{act[:80]}'")
                    score += 35.0
                    is_dangerous = True
            for link in tree.xpath("//a[@href]"):
                href = (link.get("href") or "").strip()
                if href.startswith(("http://", "https://")) and href not in extracted_urls and len(extracted_urls) < 12:
                    extracted_urls.append(href)
        except Exception:
            pass

        if ("createobjecturl" in low_body or "mssaveoropenblob" in low_body) and ("atob" in low_body or "base64" in low_body):
            findings.append("HTML smuggling detected (Blob/Base64 payload assembly via JavaScript)")
            score += 55.0
            is_dangerous = True
        if "<script" in low_body and (magic == "svg_image" or ext == ".svg"):
            findings.append("SVG attachment contains executable <script> payload")
            score += 50.0
            is_dangerous = True
        elif "eval(" in low_body and ("atob(" in low_body or "unescape(" in low_body):
            findings.append("HTML attachment executes obfuscated JavaScript (eval + decoder)")
            score += 40.0
            is_dangerous = True

    score = min(100.0, round(score, 1))
    if score >= settings.RISK_THRESHOLD_HIGH:
        verdict = "MALICIOUS"
    elif score >= settings.RISK_THRESHOLD_SUSPICIOUS:
        verdict = "HIGH_RISK"
    elif score >= settings.RISK_THRESHOLD_BENIGN:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    return {
        "filename": clean_name,
        "content_type": content_type,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "md5": md5,
        "declared_extension": ext or "(none)",
        "detected_magic_type": magic,
        "extension_mismatch": ext_mismatch,
        "is_dangerous": is_dangerous,
        "risk_score": score,
        "verdict": verdict,
        "findings": findings,
        "archive_entries": archive_entries[:30],
        "extracted_urls": extracted_urls[:15],
    }


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


def inspect_attachments_isolated_sync(
    attachments_payload: List[Dict[str, Any]],
    timeout_seconds: float = settings.ATTACHMENT_WORKER_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """
    Analyze untrusted email attachments inside an OS-isolated offline worker subprocess.
    """
    if not attachments_payload:
        return {"results": [], "worker_pid": None}

    req_bytes = json.dumps({"attachments": attachments_payload}, ensure_ascii=True).encode("utf-8")
    max_wait = max(3.0, min(20.0, float(timeout_seconds)))

    with tempfile.TemporaryDirectory(prefix="pp_attach_worker_", ignore_cleanup_errors=True) as sandbox_dir:
        clean_env = _build_sanitized_env(sandbox_dir)
        job = _WorkerJobSandbox(memory_limit_mb=128)
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
            popen_kwargs["preexec_fn"] = _build_posix_preexec(128, max_wait)

        proc = subprocess.Popen([sys.executable, "-I", _WORKER_SCRIPT_PATH], **popen_kwargs)
        try:
            if _IS_WINDOWS:
                job.assign(int(proc._handle))

            if proc.stdin is not None:
                try:
                    proc.stdin.write(req_bytes)
                    proc.stdin.flush()
                finally:
                    proc.stdin.close()

            out_sink: list = []
            err_sink: list = []
            t_out = threading.Thread(target=_read_stream_capped, args=(proc.stdout, 2 * 1024 * 1024, out_sink), daemon=True)
            t_err = threading.Thread(target=_read_stream_capped, args=(proc.stderr, 65536, err_sink), daemon=True)
            t_out.start()
            t_err.start()

            try:
                returncode = proc.wait(timeout=max_wait)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
                raise AttachmentWorkerError(f"Isolated attachment analysis timed out after {max_wait}s")

            t_out.join(timeout=2)
            t_err.join(timeout=2)
            raw_out = out_sink[0] if out_sink else b""
            raw_err = err_sink[0] if err_sink else b""

            if returncode != 0 and not raw_out:
                err_msg = raw_err.decode("utf-8", errors="replace").strip()[:200]
                raise AttachmentWorkerError(f"Attachment worker exited {returncode}: {err_msg}")

            resp = json.loads(raw_out.decode("utf-8"))
            if not resp.get("ok"):
                raise AttachmentWorkerError(resp.get("error") or "Attachment worker failed")
            return {"results": resp["results"], "worker_pid": proc.pid}
        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except Exception:
                    pass
            job.close()


def _worker_main() -> int:
    _install_strict_offline_audit_hook()
    try:
        raw_input = sys.stdin.buffer.read(16 * 1024 * 1024).decode("utf-8")
        req = json.loads(raw_input)
        attachments = req.get("attachments") or []
        results = [_inspect_single_attachment(item) for item in attachments]
        out = json.dumps({"ok": True, "results": results}, ensure_ascii=False).encode("utf-8")
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
