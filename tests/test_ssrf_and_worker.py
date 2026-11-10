import asyncio
import gzip
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, MagicMock, patch

import anyio
import httpx
from fastapi.testclient import TestClient

from app.core.fetch_worker import (
    _build_sanitized_env,
    run_in_restricted_worker_sync,
)
from app.core.safe_fetcher import (
    FetchTimeoutError,
    SSRFSafeNetworkBackend,
    SafeURLFetcher,
)
from app.core.security_guard import SSRFBlockedError
from app.main import app


class _MockSocketHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass  # Silence test server access logs

    def do_GET(self):
        if self.path == "/ok":
            body = b"<html><title>OK</title><body>hello</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/large":
            body = b"A" * (256 * 1024)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        elif self.path == "/chunked-infinite":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            chunk = b"B" * 2048
            chunk_hdr = f"{len(chunk):x}\r\n".encode("ascii")
            for _ in range(100):
                try:
                    self.wfile.write(chunk_hdr + chunk + b"\r\n")
                    self.wfile.flush()
                except OSError:
                    break
            try:
                self.wfile.write(b"0\r\n\r\n")
            except OSError:
                pass

        elif self.path == "/huge-content-length":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(100 * 1024 * 1024))
            self.end_headers()

        elif self.path == "/gzip-bomb":
            raw = b"Z" * (512 * 1024)
            compressed = gzip.compress(raw)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(compressed)))
            self.end_headers()
            try:
                self.wfile.write(compressed)
            except OSError:
                pass

        elif self.path == "/slow-read":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "100")
            self.end_headers()
            try:
                self.wfile.write(b"part1")
                self.wfile.flush()
                time.sleep(2.5)
                self.wfile.write(b"part2")
            except OSError:
                pass

        elif self.path == "/slow-trickle":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "50")
            self.end_headers()
            for _ in range(10):
                try:
                    self.wfile.write(b"abcde")
                    self.wfile.flush()
                    time.sleep(0.25)
                except OSError:
                    break

        elif self.path == "/redirect-to-metadata":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif self.path == "/redirect-to-localhost":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:8000/api/scans")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif self.path == "/redirect-to-file":
            self.send_response(302)
            self.send_header("Location", "file:///etc/passwd")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif self.path == "/redirect-to-rebind-domain":
            self.send_response(302)
            self.send_header("Location", "http://internal-after-redirect.example/secret")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif self.path.startswith("/hop/"):
            idx = int(self.path.split("/")[-1])
            self.send_response(302)
            self.send_header("Location", f"/hop/{idx + 1}")
            self.send_header("Content-Length", "0")
            self.end_headers()

        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


class TestSSRFAndWorker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _MockSocketHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_response_size_limit_truncation(self):
        fetcher = SafeURLFetcher(
            allow_local=True,
            max_response_bytes=4096,
            max_content_length_bytes=1024 * 1024,
        )
        res = asyncio.run(fetcher.fetch_http(f"http://127.0.0.1:{self.port}/large"))
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.truncated)
        self.assertEqual(res.bytes_read, 4096)
        self.assertLessEqual(len(res.body_text), 4096)

    def test_chunked_stream_size_limit(self):
        fetcher = SafeURLFetcher(
            allow_local=True,
            max_response_bytes=3000,
            max_content_length_bytes=1024 * 1024,
        )
        res = asyncio.run(fetcher.fetch_http(f"http://127.0.0.1:{self.port}/chunked-infinite"))
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.truncated)
        self.assertLessEqual(res.bytes_read, 3000)

    def test_huge_content_length_rejected_early(self):
        fetcher = SafeURLFetcher(
            allow_local=True,
            max_response_bytes=4096,
            max_content_length_bytes=65536,
        )
        res = asyncio.run(fetcher.fetch_http(f"http://127.0.0.1:{self.port}/huge-content-length"))
        self.assertEqual(res.error_type, "size_limit")
        self.assertTrue(res.truncated)
        self.assertEqual(res.bytes_read, 0)

    def test_gzip_decompression_bomb_bounded(self):
        fetcher = SafeURLFetcher(
            allow_local=True,
            max_response_bytes=4096,
            max_content_length_bytes=65536,
        )
        res = asyncio.run(fetcher.fetch_http(f"http://127.0.0.1:{self.port}/gzip-bomb"))
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.truncated)
        self.assertLessEqual(res.bytes_read, 4096)
        self.assertLessEqual(len(res.body_text), 4096)

    def test_read_timeout_enforced(self):
        fetcher = SafeURLFetcher(
            allow_local=True,
            connect_timeout=2.0,
            read_timeout=0.4,
            total_timeout=1.0,
        )
        t0 = time.monotonic()
        res = asyncio.run(fetcher.fetch_http(f"http://127.0.0.1:{self.port}/slow-read"))
        elapsed = time.monotonic() - t0
        self.assertEqual(res.error_type, "timeout")
        self.assertLess(elapsed, 2.0)

    def test_total_deadline_stops_slow_trickle(self):
        fetcher = SafeURLFetcher(
            allow_local=True,
            connect_timeout=2.0,
            read_timeout=1.5,
            total_timeout=0.6,
        )
        t0 = time.monotonic()
        res = asyncio.run(fetcher.fetch_http(f"http://127.0.0.1:{self.port}/slow-trickle"))
        elapsed = time.monotonic() - t0
        self.assertEqual(res.error_type, "timeout")
        self.assertLess(elapsed, 1.5)

    def test_max_redirect_hops_enforced(self):
        fetcher = SafeURLFetcher(allow_local=True, max_redirects=3)
        res = asyncio.run(fetcher.fetch_http(f"http://127.0.0.1:{self.port}/hop/0"))
        self.assertEqual(res.error_type, "max_redirects")
        self.assertEqual(len(res.redirect_chain), 4)

    def test_redirect_revalidates_and_blocks_ssrf_targets(self):
        # Simulate public initial hop that redirects to internal/metadata/file/rebound destinations
        for redirect_location in (
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8000/api/scans",
            "http://[::1]:8000/admin",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "http://0x7f000001/",
        ):
            with self.subTest(location=redirect_location):
                fetcher = SafeURLFetcher(allow_local=False)

                call_count = 0

                def fake_getaddrinfo(host, port, *args, **kwargs):
                    nonlocal call_count
                    call_count += 1
                    if host == "public-redirector.example":
                        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
                    raise AssertionError(f"DNS resolution should not have reached blocked redirect host '{host}'")

                mock_resp = MagicMock()
                mock_resp.status_code = 302
                mock_resp.url = httpx.URL("https://public-redirector.example/start")
                mock_resp.headers = httpx.Headers({"location": redirect_location})

                mock_stream_ctx = AsyncMock()
                mock_stream_ctx.__aenter__.return_value = mock_resp
                mock_stream_ctx.__aexit__.return_value = None

                mock_client = MagicMock()
                mock_client.stream.return_value = mock_stream_ctx

                mock_client_ctx = AsyncMock()
                mock_client_ctx.__aenter__.return_value = mock_client
                mock_client_ctx.__aexit__.return_value = None

                with patch("app.core.security_guard.socket.getaddrinfo", side_effect=fake_getaddrinfo):
                    with patch("app.core.safe_fetcher.httpx.AsyncClient", return_value=mock_client_ctx):
                        with self.assertRaises(SSRFBlockedError):
                            asyncio.run(fetcher.fetch_http("https://public-redirector.example/start"))

                # Ensure only the initial public host was resolved & requested
                self.assertEqual(call_count, 1)
                self.assertEqual(mock_client.stream.call_count, 1)

    def test_redirect_revalidates_dns_of_redirect_hostname(self):
        fetcher = SafeURLFetcher(allow_local=False)
        resolved_hosts = []

        def fake_getaddrinfo(host, port, *args, **kwargs):
            resolved_hosts.append(host)
            if host == "hop1.example":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
            if host == "internal-hop2.example":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.42", port))]
            raise AssertionError(f"Unexpected host {host}")

        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.url = httpx.URL("https://hop1.example/go")
        mock_resp.headers = httpx.Headers({"location": "https://internal-hop2.example/admin"})

        mock_stream_ctx = AsyncMock()
        mock_stream_ctx.__aenter__.return_value = mock_resp
        mock_stream_ctx.__aexit__.return_value = None

        mock_client = MagicMock()
        mock_client.stream.return_value = mock_stream_ctx

        mock_client_ctx = AsyncMock()
        mock_client_ctx.__aenter__.return_value = mock_client
        mock_client_ctx.__aexit__.return_value = None

        with patch("app.core.security_guard.socket.getaddrinfo", side_effect=fake_getaddrinfo):
            with patch("app.core.safe_fetcher.httpx.AsyncClient", return_value=mock_client_ctx):
                with self.assertRaises(SSRFBlockedError) as ctx:
                    asyncio.run(fetcher.fetch_http("https://hop1.example/go"))

        self.assertIn("10.0.0.42", ctx.exception.detail)
        self.assertEqual(resolved_hosts, ["hop1.example", "internal-hop2.example"])
        # Crucial: NEVER connected to internal-hop2.example!
        self.assertEqual(mock_client.stream.call_count, 1)

    def test_dns_rebinding_prevented_by_ip_pinning(self):
        # Simulate TTL=0 DNS rebinding server:
        # 1st lookup returns public IP 93.184.216.34;
        # 2nd lookup (if TOCTOU existed) would return 127.0.0.1!
        dns_calls = 0

        def rebinding_getaddrinfo(host, port, *args, **kwargs):
            nonlocal dns_calls
            dns_calls += 1
            if dns_calls == 1:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

        connected_targets = []

        async def fake_anyio_connect_tcp(remote_host, remote_port, local_host=None):
            connected_targets.append((remote_host, remote_port))
            raw_sock = MagicMock()
            raw_sock.getpeername.return_value = (remote_host, remote_port)
            fake_stream = MagicMock()
            fake_stream.extra.return_value = raw_sock
            fake_stream.aclose = AsyncMock()
            return fake_stream

        backend = SSRFSafeNetworkBackend(allow_local=False)
        with patch("app.core.security_guard.socket.getaddrinfo", side_effect=rebinding_getaddrinfo):
            with patch("app.core.safe_fetcher.anyio.connect_tcp", side_effect=fake_anyio_connect_tcp):
                from app.core.security_guard import resolve_and_validate_host

                pinned = resolve_and_validate_host("rebinding-victim.example", 443, allow_local=False)
                backend.pin_host("rebinding-victim.example", 443, pinned)
                asyncio.run(backend.connect_tcp("rebinding-victim.example", 443, timeout=2.0))

        # Only 1 DNS resolution occurred, and TCP connected strictly to the pinned public IP!
        self.assertEqual(dns_calls, 1)
        self.assertEqual(connected_targets, [("93.184.216.34", 443)])

    def test_peer_ip_verification_blocks_spoofed_non_public_socket(self):
        async def spoofed_connect_tcp(remote_host, remote_port, local_host=None):
            raw_sock = MagicMock()
            # Simulate OS/socket resolving/connecting to private IP unexpectedly
            raw_sock.getpeername.return_value = ("127.0.0.1", remote_port)
            fake_stream = MagicMock()
            fake_stream.extra.return_value = raw_sock
            fake_stream.aclose = AsyncMock()
            return fake_stream

        backend = SSRFSafeNetworkBackend(allow_local=False)
        backend.pin_host("victim.example", 443, ["93.184.216.34"])
        with patch("app.core.safe_fetcher.anyio.connect_tcp", side_effect=spoofed_connect_tcp):
            with self.assertRaises(SSRFBlockedError):
                asyncio.run(backend.connect_tcp("victim.example", 443, timeout=2.0))

    def test_restricted_worker_blocks_ssrf_and_strips_secrets(self):
        with patch.dict(
            os.environ,
            {
                "VIRUSTOTAL_API_KEY": "secret-vt-token",
                "ABUSEIPDB_API_KEY": "secret-abuse-token",
                "HTTP_PROXY": "http://127.0.0.1:8888",
                "HTTPS_PROXY": "http://127.0.0.1:8888",
            },
        ):
            with tempfile.TemporaryDirectory() as tmp:
                clean_env = _build_sanitized_env(tmp)
                self.assertNotIn("VIRUSTOTAL_API_KEY", clean_env)
                self.assertNotIn("ABUSEIPDB_API_KEY", clean_env)
                self.assertNotIn("HTTP_PROXY", clean_env)
                self.assertNotIn("HTTPS_PROXY", clean_env)

            # Real subprocess execution rejects SSRF targets
            for target in (
                "http://127.0.0.1:8000",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]:8000",
            ):
                with self.subTest(target=target):
                    with self.assertRaises(SSRFBlockedError):
                        run_in_restricted_worker_sync(target)

    def test_restricted_worker_audit_hook_blocks_exec_and_writes(self):
        # Launch an isolated python -I subprocess running the worker's audit hook + Windows Job sandbox
        # and verify secrets are absent, child spawning is blocked, and file writes are blocked.
        repo_root = os.getcwd()
        script = f"""
import os, subprocess, sys
sys.path.insert(0, {repo_root!r})
from app.core.fetch_worker import _install_worker_audit_hook
_install_worker_audit_hook()
assert 'VIRUSTOTAL_API_KEY' not in os.environ
assert 'HTTP_PROXY' not in os.environ
blocked_spawn = False
blocked_write = False
try:
    subprocess.Popen([sys.executable, '-c', 'pass'])
except PermissionError:
    blocked_spawn = True
try:
    open('evil.txt', 'w')
except PermissionError:
    blocked_write = True
assert blocked_spawn and blocked_write, (blocked_spawn, blocked_write)
print('SANDBOX_OK')
"""
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "secret", "HTTP_PROXY": "http://127.0.0.1:9"}):
            with tempfile.TemporaryDirectory() as tmp:
                clean_env = _build_sanitized_env(tmp)
                proc = subprocess.run(
                    [sys.executable, "-I", "-c", script],
                    cwd=tmp,
                    env=clean_env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("SANDBOX_OK", proc.stdout)

    def test_restricted_worker_kills_hanging_subprocess_on_timeout(self):
        # Simulate a worker process that hangs beyond timeout -> launcher kills it cleanly
        with patch("app.core.fetch_worker.settings.WORKER_EXECUTION_TIMEOUT_SECONDS", 0.5):
            with patch(
                "app.core.fetch_worker.subprocess.Popen"
            ) as mock_popen_cls:
                fake_proc = MagicMock()
                fake_proc._handle = 0
                fake_proc.stdin = MagicMock()
                fake_proc.stdout = MagicMock()
                fake_proc.stdout.read.return_value = b""
                fake_proc.stderr = MagicMock()
                fake_proc.stderr.read.return_value = b""
                fake_proc.poll.return_value = None
                fake_proc.wait.side_effect = [subprocess.TimeoutExpired("python", 0.5), 0]
                mock_popen_cls.return_value = fake_proc

                with self.assertRaises(FetchTimeoutError):
                    run_in_restricted_worker_sync("https://example.com", total_timeout=0.2)

                fake_proc.kill.assert_called()

    def test_api_endpoints_block_ssrf_and_redirect_ssrf(self):
        client = TestClient(app)

        # Direct SSRF scan requests
        for target in (
            "http://127.0.0.1:8000/api/scans",
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:8000/",
            "http://0x7f000001/",
            "http://metadata.google.internal/",
        ):
            resp = client.post("/api/scan", json={"url": target, "fetch_content": True, "deep_dns": False})
            self.assertEqual(resp.status_code, 400, f"Expected 400 for {target}, got {resp.status_code}")
            self.assertIn("SSRF", resp.json()["detail"])

        # Community report endpoint also enforces SSRF defense
        resp_comm = client.post("/api/community/report", json={
            "url": "http://169.254.169.254/latest/meta-data/",
            "tags": ["#test"],
        })
        self.assertEqual(resp_comm.status_code, 400)

        # Batch endpoint reports per-item SSRF errors cleanly without 500
        resp_batch = client.post("/api/scan/batch", json={
            "urls": [
                "http://169.254.169.254/latest/meta-data/",
                "http://paypa1-update-center.xyz/auth",
            ]
        })
        self.assertEqual(resp_batch.status_code, 200)
        batch_data = resp_batch.json()
        self.assertIn("error", batch_data["results"][0])
        self.assertIn("SSRF", batch_data["results"][0]["error"])
        self.assertIn("verdict", batch_data["results"][1])

        # Redirect SSRF propagated from restricted worker returns HTTP 400
        with patch(
            "app.core.scoring_engine.run_in_restricted_worker",
            side_effect=SSRFBlockedError("Security Policy Violation: Redirect to 169.254.169.254 blocked (SSRF Defense)."),
        ):
            resp_redir = client.post("/api/scan", json={
                "url": "https://public-redirector.example/trap",
                "fetch_content": True,
                "deep_dns": False,
            })
            self.assertEqual(resp_redir.status_code, 400)
            self.assertIn("SSRF Defense", resp_redir.json()["detail"])


if __name__ == "__main__":
    unittest.main()
