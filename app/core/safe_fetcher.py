import asyncio
import base64
import ipaddress
import socket
import ssl
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

import anyio
import httpcore
import httpx
from httpcore._backends.anyio import AnyIOStream
from httpcore._exceptions import ConnectError, ConnectTimeout, map_exceptions

from app.config import settings
from app.core.security_guard import (
    DNSResolutionError,
    SSRFBlockedError,
    is_public_ip,
    resolve_and_validate_host,
    validate_url_syntax_and_host,
)


class FetchError(Exception):
    """Base error for safe URL fetching failures."""


class FetchTimeoutError(FetchError):
    """Raised when a connect, read, or total fetch deadline is exceeded."""


class ResponseSizeLimitError(FetchError):
    """Raised when an HTTP response exceeds configured size limits."""


@dataclass
class SafeFetchResult:
    target_url: str
    final_url: str
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    bytes_read: int = 0
    truncated: bool = False
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    redirect_downgrade: bool = False
    resolved_ip: Optional[str] = None
    error: Optional[str] = None
    error_type: Optional[str] = None
    tls_cert_der_b64: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    tls_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "headers": self.headers,
            "body_text": self.body_text,
            "bytes_read": self.bytes_read,
            "truncated": self.truncated,
            "redirect_chain": self.redirect_chain,
            "redirect_downgrade": self.redirect_downgrade,
            "resolved_ip": self.resolved_ip,
            "error": self.error,
            "error_type": self.error_type,
            "tls_cert_der_b64": self.tls_cert_der_b64,
            "tls_version": self.tls_version,
            "tls_cipher": self.tls_cipher,
            "tls_error": self.tls_error,
        }


def _normalize_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip_obj = ipaddress.ip_address(ip_str.split("%", 1)[0])
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    return ip_obj


class SSRFSafeNetworkBackend(httpcore.AsyncNetworkBackend):
    """
    Custom httpcore network backend that prevents DNS rebinding (TOCTOU) attacks.
    Connects directly to pre-validated pinned IP literals while preserving hostname
    for HTTP Host headers and TLS SNI.
    """

    def __init__(self, allow_local: bool = False) -> None:
        self.allow_local = allow_local
        self.pinned_hosts: Dict[Tuple[str, int], List[str]] = {}

    def pin_host(self, hostname: str, port: int, ips: List[str]) -> None:
        if not ips:
            raise DNSResolutionError(f"No validated IPs provided for '{hostname}'")
        if not self.allow_local:
            for ip in ips:
                if not is_public_ip(ip):
                    raise SSRFBlockedError(
                        f"Security Policy Violation: Refusing to pin non-public IP '{ip}' for '{hostname}' (SSRF Defense)."
                    )
        self.pinned_hosts[(hostname.lower().rstrip("."), port)] = list(ips)

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable[Any]] = None,
    ) -> httpcore.AsyncNetworkStream:
        clean_host = host.lower().rstrip(".")
        key = (clean_host, port)

        # Retrieve pre-pinned IPs, or resolve & validate strictly on demand
        candidate_ips = self.pinned_hosts.get(key)
        if not candidate_ips:
            candidate_ips = resolve_and_validate_host(
                clean_host,
                port,
                allow_local=self.allow_local,
                require_resolution=True,
            )
            self.pinned_hosts[key] = candidate_ips

        if not self.allow_local:
            for ip in candidate_ips:
                if not is_public_ip(ip):
                    raise SSRFBlockedError(
                        f"Security Policy Violation: Blocked connection to non-public IP '{ip}' (SSRF Defense)."
                    )

        if socket_options is None:
            socket_options = []

        exc_map = {
            TimeoutError: ConnectTimeout,
            OSError: ConnectError,
            anyio.BrokenResourceError: ConnectError,
        }

        last_exc: Optional[BaseException] = None
        for pinned_ip in candidate_ips:
            try:
                with map_exceptions(exc_map):
                    with anyio.fail_after(timeout):
                        # Connect directly to the validated IP literal (no second DNS lookup!)
                        stream: anyio.abc.ByteStream = await anyio.connect_tcp(
                            remote_host=pinned_ip,
                            remote_port=port,
                            local_host=local_address,
                        )
                        raw_sock = stream.extra(anyio.abc.SocketAttribute.raw_socket, None)
                        if raw_sock is not None:
                            peer_addr = raw_sock.getpeername()
                            peer_ip = str(peer_addr[0]) if peer_addr else ""
                            if not self.allow_local and not is_public_ip(peer_ip):
                                await stream.aclose()
                                raise SSRFBlockedError(
                                    f"Security Policy Violation: Connected peer IP '{peer_ip}' is not public (SSRF Defense)."
                                )
                            if _normalize_ip(peer_ip) != _normalize_ip(pinned_ip):
                                await stream.aclose()
                                raise SSRFBlockedError(
                                    f"Security Policy Violation: Peer IP '{peer_ip}' mismatched pinned IP '{pinned_ip}' (SSRF Defense)."
                                )
                            for option in socket_options:
                                raw_sock.setsockopt(*option)
                return AnyIOStream(stream)
            except (SSRFBlockedError, DNSResolutionError):
                raise
            except (ConnectTimeout, ConnectError) as exc:
                last_exc = exc
                continue

        if last_exc is not None:
            raise last_exc
        raise ConnectError(f"Failed to establish TCP connection to '{clean_host}'")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: Optional[float] = None,
        socket_options: Optional[Iterable[Any]] = None,
    ) -> httpcore.AsyncNetworkStream:
        raise SSRFBlockedError("Security Policy Violation: Unix domain sockets are prohibited (SSRF Defense).")

    async def sleep(self, seconds: float) -> None:
        await anyio.sleep(seconds)


class SSRFSafeHTTPTransport(httpx.AsyncHTTPTransport):
    """httpx AsyncHTTPTransport wired with SSRFSafeNetworkBackend and no env/keepalive leakage."""

    def __init__(
        self,
        backend: SSRFSafeNetworkBackend,
        verify: bool = False,
    ) -> None:
        limits = httpx.Limits(max_connections=4, max_keepalive_connections=0, keepalive_expiry=0.0)
        super().__init__(verify=verify, trust_env=False, limits=limits, retries=0)
        ssl_context = httpx.create_ssl_context(verify=verify, trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=0,
            keepalive_expiry=0.0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=backend,
        )


def _is_text_or_html_content_type(content_type: str) -> bool:
    if not content_type:
        return True
    ct = content_type.split(";", 1)[0].strip().lower()
    if not ct:
        return True
    if ct.startswith("text/"):
        return True
    return ct in (
        "application/xhtml+xml",
        "application/xml",
        "application/json",
        "application/javascript",
        "application/x-javascript",
    ) or ct.endswith("+xml") or ct.endswith("+json")


async def _read_bounded_body(
    resp: httpx.Response,
    max_response_bytes: int,
    max_content_length_bytes: int,
    deadline: float,
) -> Tuple[bytes, int, bool]:
    """
    Stream response body safely with strict wire-byte limit, decompression bomb protection,
    and wall-clock deadline enforcement.
    """
    content_length_hdr = resp.headers.get("content-length")
    if content_length_hdr is not None:
        try:
            declared_len = int(content_length_hdr.strip())
            if declared_len > max_content_length_bytes:
                raise ResponseSizeLimitError(
                    f"Response Content-Length ({declared_len} bytes) exceeds limit ({max_content_length_bytes} bytes)"
                )
        except ValueError:
            pass

    encoding = resp.headers.get("content-encoding", "").strip().lower()
    decomp = None
    if encoding == "gzip":
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        decomp = zlib.decompressobj(zlib.MAX_WBITS)

    chunks: List[bytes] = []
    wire_read = 0
    decoded_read = 0
    truncated = False

    async for raw_chunk in resp.aiter_raw():
        if time.monotonic() > deadline:
            raise FetchTimeoutError("Total fetch timeout exceeded while reading response body")

        if not raw_chunk:
            continue

        remaining_wire = max_response_bytes - wire_read
        if remaining_wire <= 0:
            truncated = True
            break

        if len(raw_chunk) > remaining_wire:
            raw_chunk = raw_chunk[:remaining_wire]
            truncated = True

        wire_read += len(raw_chunk)

        if decomp is not None:
            remaining_decoded = max_response_bytes - decoded_read
            if remaining_decoded <= 0:
                truncated = True
                break
            try:
                decoded_part = decomp.decompress(raw_chunk, max_length=remaining_decoded)
            except zlib.error:
                # Fallback if server sent raw deflate without zlib header
                if encoding == "deflate" and decoded_read == 0:
                    decomp = zlib.decompressobj(-zlib.MAX_WBITS)
                    decoded_part = decomp.decompress(raw_chunk, max_length=remaining_decoded)
                else:
                    raise
            if decoded_part:
                chunks.append(decoded_part)
                decoded_read += len(decoded_part)
            if decomp.unconsumed_tail or decoded_read >= max_response_bytes:
                truncated = True
                break
        else:
            chunks.append(raw_chunk)
            decoded_read += len(raw_chunk)

        if truncated:
            break

    if decomp is not None and not truncated:
        remaining_decoded = max_response_bytes - decoded_read
        if remaining_decoded > 0:
            try:
                tail = decomp.flush(remaining_decoded)
                if tail:
                    chunks.append(tail[:remaining_decoded])
                    decoded_read += min(len(tail), remaining_decoded)
                    if len(tail) > remaining_decoded or decomp.unconsumed_tail:
                        truncated = True
            except zlib.error:
                pass

    return b"".join(chunks), decoded_read, truncated


class SafeURLFetcher:
    """
    SSRF-hardened URL & TLS fetcher:
    - Validates URL syntax, scheme, credentials, port, and host policy
    - Resolves DNS per hop and rejects ANY private/loopback/metadata/reserved IP
    - Pins resolved public IP at TCP socket layer to prevent DNS rebinding (TOCTOU)
    - Manually traces redirects and revalidates URL & DNS on every redirect hop
    - Enforces granular connect/read/total deadlines and bounded response sizes
    """

    def __init__(
        self,
        allow_local: bool = False,
        connect_timeout: float = settings.CONNECT_TIMEOUT_SECONDS,
        read_timeout: float = settings.READ_TIMEOUT_SECONDS,
        total_timeout: float = settings.TOTAL_FETCH_TIMEOUT_SECONDS,
        tls_timeout: float = settings.TLS_HANDSHAKE_TIMEOUT_SECONDS,
        max_redirects: int = settings.MAX_REDIRECT_HOPS,
        max_response_bytes: int = settings.MAX_RESPONSE_BYTES,
        max_content_length_bytes: int = settings.MAX_CONTENT_LENGTH_BYTES,
        user_agent: str = settings.USER_AGENT,
    ) -> None:
        self.allow_local = allow_local
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.total_timeout = total_timeout
        self.tls_timeout = tls_timeout
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes
        self.max_content_length_bytes = max_content_length_bytes
        self.user_agent = user_agent

    async def fetch_http(
        self,
        url: str,
        fetch_content: bool = True,
        user_agent: Optional[str] = None,
    ) -> SafeFetchResult:
        normalized_url, _, _, _ = validate_url_syntax_and_host(url, allow_local=self.allow_local)
        result = SafeFetchResult(target_url=normalized_url, final_url=normalized_url)
        ua = user_agent or self.user_agent

        deadline = time.monotonic() + self.total_timeout
        current_url = normalized_url
        backend = SSRFSafeNetworkBackend(allow_local=self.allow_local)

        try:
            for hop in range(self.max_redirects + 1):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FetchTimeoutError("Total fetch timeout exceeded")

                # Revalidate URL syntax, scheme, credentials, port, and host on EVERY hop
                current_url, _, ascii_host, port = validate_url_syntax_and_host(
                    current_url, allow_local=self.allow_local
                )

                # Fresh DNS resolution & validation on EVERY hop (redirect revalidation)
                pinned_ips = resolve_and_validate_host(
                    ascii_host,
                    port,
                    allow_local=self.allow_local,
                    require_resolution=True,
                )
                backend.pin_host(ascii_host, port, pinned_ips)
                if result.resolved_ip is None:
                    result.resolved_ip = pinned_ips[0]

                timeout_cfg = httpx.Timeout(
                    connect=min(self.connect_timeout, remaining),
                    read=min(self.read_timeout, remaining),
                    write=min(self.read_timeout, remaining),
                    pool=min(self.connect_timeout, remaining),
                )

                transport = SSRFSafeHTTPTransport(backend=backend, verify=False)
                async with httpx.AsyncClient(
                    transport=transport,
                    timeout=timeout_cfg,
                    follow_redirects=False,
                    trust_env=False,
                    headers={
                        "User-Agent": ua,
                        "Accept-Encoding": "gzip, deflate, identity",
                        "Connection": "close",
                    },
                ) as client:
                    async with asyncio.timeout(remaining):
                        async with client.stream("GET", current_url) as resp:
                            result.status_code = resp.status_code
                            result.final_url = str(resp.url)
                            result.headers = {
                                k.lower(): v[:4096] for k, v in resp.headers.items()
                            }
                            result.redirect_chain.append({
                                "hop": hop + 1,
                                "status_code": resp.status_code,
                                "url": str(resp.url),
                                "resolved_ip": pinned_ips[0],
                                "server": resp.headers.get("server", "unknown"),
                            })

                            is_redirect = resp.status_code in (301, 302, 303, 307, 308) and "location" in resp.headers
                            if is_redirect:
                                raw_location = resp.headers["location"].strip()
                                next_url = urljoin(str(resp.url), raw_location)

                                # Immediately validate redirect target BEFORE next iteration
                                next_url, _, _, _ = validate_url_syntax_and_host(
                                    next_url, allow_local=self.allow_local
                                )

                                if current_url.startswith("https://") and next_url.startswith("http://"):
                                    result.redirect_downgrade = True

                                if hop >= self.max_redirects:
                                    result.error_type = "max_redirects"
                                    result.error = f"Maximum redirect hops ({self.max_redirects}) exceeded"
                                    break

                                current_url = next_url
                                continue

                            # Final non-redirect response
                            if fetch_content:
                                content_type = resp.headers.get("content-type", "")
                                if _is_text_or_html_content_type(content_type):
                                    body_bytes, bytes_read, truncated = await _read_bounded_body(
                                        resp,
                                        max_response_bytes=self.max_response_bytes,
                                        max_content_length_bytes=self.max_content_length_bytes,
                                        deadline=deadline,
                                    )
                                    result.bytes_read = bytes_read
                                    result.truncated = truncated
                                    charset = resp.charset_encoding or "utf-8"
                                    result.body_text = body_bytes.decode(charset, errors="replace")
                            break

        except SSRFBlockedError:
            raise
        except DNSResolutionError as exc:
            result.error_type = "dns_error"
            result.error = str(exc)
        except (FetchTimeoutError, TimeoutError, httpx.TimeoutException) as exc:
            result.error_type = "timeout"
            result.error = f"Request timed out: {str(exc) or 'deadline exceeded'}"
        except ResponseSizeLimitError as exc:
            result.error_type = "size_limit"
            result.error = str(exc)
            result.truncated = True
        except Exception as exc:
            result.error_type = "network_error"
            result.error = str(exc)[:200]

        return result

    def fetch_tls_certificate(self, target_url: str) -> Dict[str, Any]:
        """
        Perform IP-pinned TLS handshake with SNI preserved and extract X.509 DER certificate.
        Prevents DNS rebinding by connecting directly to the validated pinned IP.
        """
        normalized_url, scheme, ascii_host, port = validate_url_syntax_and_host(
            target_url, allow_local=self.allow_local
        )

        if scheme == "http" and port == 80:
            return {"plain_http": True}

        try:
            pinned_ips = resolve_and_validate_host(
                ascii_host,
                port,
                allow_local=self.allow_local,
                require_resolution=True,
            )
        except SSRFBlockedError:
            raise
        except DNSResolutionError as exc:
            return {"tls_error": str(exc)}

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Extract cert for risk scoring even if self-signed/expired

        last_err: Optional[Exception] = None
        for pinned_ip in pinned_ips:
            sock = None
            try:
                sock = socket.create_connection((pinned_ip, port), timeout=self.tls_timeout)
                sock.settimeout(self.tls_timeout)
                peer_addr = sock.getpeername()
                peer_ip = str(peer_addr[0]) if peer_addr else ""
                if not self.allow_local and not is_public_ip(peer_ip):
                    raise SSRFBlockedError(
                        f"Security Policy Violation: TLS peer IP '{peer_ip}' is not public (SSRF Defense)."
                    )
                if _normalize_ip(peer_ip) != _normalize_ip(pinned_ip):
                    raise SSRFBlockedError(
                        f"Security Policy Violation: TLS peer IP '{peer_ip}' mismatched pinned IP '{pinned_ip}' (SSRF Defense)."
                    )
                with ctx.wrap_socket(sock, server_hostname=ascii_host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    tls_version = ssock.version()
                    cipher_info = ssock.cipher()
                    cipher_name = cipher_info[0] if cipher_info else None
                    if not der_cert:
                        return {
                            "tls_version": tls_version,
                            "tls_cipher": cipher_name,
                            "resolved_ip": pinned_ip,
                            "tls_error": "No peer certificate presented",
                        }
                    if len(der_cert) > 256 * 1024:
                        return {
                            "tls_version": tls_version,
                            "tls_cipher": cipher_name,
                            "resolved_ip": pinned_ip,
                            "tls_error": "Peer certificate exceeded maximum size limit",
                        }
                    return {
                        "der_cert_b64": base64.b64encode(der_cert).decode("ascii"),
                        "tls_version": tls_version,
                        "tls_cipher": cipher_name,
                        "resolved_ip": pinned_ip,
                    }
            except SSRFBlockedError:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                raise
            except Exception as exc:
                last_err = exc
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
                continue

        return {"tls_error": str(last_err) if last_err else "TLS handshake failed"}

    async def fetch_scan_bundle(
        self,
        url: str,
        fetch_http: bool = True,
        fetch_content: bool = True,
        fetch_tls: bool = True,
    ) -> SafeFetchResult:
        """Execute bounded HTTP fetch (if enabled) and TLS cert fetch (if enabled)."""
        normalized_url, scheme, _, port = validate_url_syntax_and_host(
            url, allow_local=self.allow_local
        )
        if fetch_http:
            result = await self.fetch_http(normalized_url, fetch_content=fetch_content)
        else:
            result = SafeFetchResult(target_url=normalized_url, final_url=normalized_url)

        if fetch_tls and not (scheme == "http" and port == 80):
            tls_info = await asyncio.to_thread(self.fetch_tls_certificate, normalized_url)
            result.tls_cert_der_b64 = tls_info.get("der_cert_b64")
            result.tls_version = tls_info.get("tls_version")
            result.tls_cipher = tls_info.get("tls_cipher")
            result.tls_error = tls_info.get("tls_error")
            if result.resolved_ip is None:
                result.resolved_ip = tls_info.get("resolved_ip")

        return result
