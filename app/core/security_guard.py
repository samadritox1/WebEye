import ipaddress
import re
import socket
from typing import List, Optional, Tuple, Union
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException


IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class SSRFBlockedError(HTTPException):
    """Raised when a URL, hostname, IP, port, or redirect target violates SSRF policy."""

    def __init__(self, detail: str):
        super().__init__(status_code=400, detail=detail)


class DNSResolutionError(Exception):
    """Raised when DNS resolution fails for a target hostname."""


# Special-use, private, loopback, link-local, CGNAT, cloud metadata, and multicast networks
_BLOCKED_CIDRS = (
    # IPv4
    "0.0.0.0/8",          # "This network"
    "10.0.0.0/8",         # RFC 1918 Private
    "100.64.0.0/10",      # RFC 6598 CGNAT & Alibaba Cloud metadata (100.100.100.200)
    "127.0.0.0/8",        # Loopback
    "169.254.0.0/16",     # Link-local & AWS/GCP/Azure/DO/Oracle metadata (169.254.169.254, 169.254.170.2)
    "172.16.0.0/12",      # RFC 1918 Private
    "192.0.0.0/24",       # IETF Protocol Assignments & Oracle metadata (192.0.0.192)
    "192.0.2.0/24",       # TEST-NET-1
    "192.88.99.0/24",     # Deprecated 6to4 Relay Anycast
    "192.168.0.0/16",     # RFC 1918 Private
    "198.18.0.0/15",      # Benchmarking
    "198.51.100.0/24",    # TEST-NET-2
    "203.0.113.0/24",     # TEST-NET-3
    "224.0.0.0/4",        # Multicast
    "240.0.0.0/4",        # Reserved / Future Use
    "255.255.255.255/32", # Broadcast
    # IPv6
    "::/128",             # Unspecified
    "::1/128",            # Loopback
    "::/96",              # Deprecated IPv4-compatible IPv6
    "::ffff:0:0/96",      # IPv4-mapped IPv6
    "64:ff9b::/96",       # NAT64
    "64:ff9b:1::/48",     # Local-use NAT64
    "100::/64",           # Discard-Only
    "2001::/32",          # Teredo
    "2001:2::/48",        # Benchmarking
    "2001:db8::/32",      # Documentation
    "2002::/16",          # 6to4
    "fc00::/7",           # Unique Local Addresses (includes AWS IPv6 IMDS fd00:ec2::254)
    "fe80::/10",          # Link-Local
    "ff00::/8",           # Multicast
)

BLOCKED_IP_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in _BLOCKED_CIDRS)

BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "local",
    "ip6-localhost",
    "ip6-loopback",
    "loopback",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "metadata.azure.internal",
    "metadata.nic.internal",
    "metadata.packet.net",
    "metadata.platformequinix.com",
    "instance-data",
    "instance-data.ec2.internal",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
    "wpad",
    "isatap",
})

BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".home.arpa",
    ".arpa",
    ".intranet",
    ".corp",
    ".lan",
    ".home",
    ".svc",
    ".cluster.local",
    ".ec2.internal",
)

# Non-HTTP / sensitive internal service ports blocked to prevent protocol-smuggling SSRF
BLOCKED_PORTS = frozenset({
    21, 22, 23, 25, 53, 69, 110, 111, 135, 137, 138, 139, 143, 161, 389,
    445, 465, 512, 513, 514, 587, 636, 873, 993, 995, 1433, 1521, 2049,
    2375, 2376, 2379, 2380, 3306, 3389, 5432, 5672, 5900, 6379, 6443,
    9200, 9300, 10250, 10255, 11211, 27017, 27018,
})

_EXPLICIT_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):")
_MAX_URL_LENGTH = 4096


def _parse_ip_literal(ip_str: str) -> Tuple[Optional[IPAddress], bool, bool]:
    """
    Parse an IP literal (IPv4, IPv6, or obfuscated BSD inet_aton IPv4).
    Returns (ip_obj, has_zone_id, is_obfuscated).
    """
    if not ip_str or not isinstance(ip_str, str):
        return None, False, False

    candidate = ip_str.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    candidate = candidate.rstrip(".")

    has_zone = "%" in candidate
    if has_zone:
        candidate = candidate.split("%", 1)[0]

    try:
        return ipaddress.ip_address(candidate), has_zone, False
    except ValueError:
        pass

    # Detect obfuscated IPv4 forms (octal 0177.0.0.1, hex 0x7f000001, integer 2130706433, short 127.1)
    if not has_zone and ":" not in candidate:
        try:
            packed = socket.inet_aton(candidate)
            return ipaddress.IPv4Address(packed), False, True
        except OSError:
            pass

    return None, has_zone, False


def _is_ip_disallowed(ip: IPAddress) -> bool:
    """Return True if an IP (or any IPv4 tunnel/mapping wrapped inside it) is non-public."""
    if (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True

    for network in BLOCKED_IP_NETWORKS:
        if ip in network:
            return True

    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None and _is_ip_disallowed(ip.ipv4_mapped):
            return True
        if ip.sixtofour is not None and _is_ip_disallowed(ip.sixtofour):
            return True
        if ip.teredo is not None:
            server_ip, client_ip = ip.teredo
            if _is_ip_disallowed(server_ip) or _is_ip_disallowed(client_ip):
                return True
        # NAT64 prefix 64:ff9b::/96 embeds IPv4 in lowest 32 bits
        nat64_net = ipaddress.IPv6Network("64:ff9b::/96")
        if ip in nat64_net:
            embedded_v4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            if _is_ip_disallowed(embedded_v4):
                return True

    return False


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Check if an IP string (canonical or obfuscated) is private, loopback, link-local, metadata, or reserved."""
    ip, has_zone, _ = _parse_ip_literal(ip_str)
    if ip is None:
        return False
    if has_zone:
        return True
    return _is_ip_disallowed(ip)


def is_public_ip(ip_str: str) -> bool:
    """Return True strictly if ip_str is a canonical, global, non-reserved IP address."""
    if not ip_str or "%" in ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    return not _is_ip_disallowed(ip)


def _check_hostname_policy(hostname: str, allow_local: bool = False) -> Tuple[str, Optional[str]]:
    """
    Validate hostname against SSRF blocklists, obfuscated IP literals, and private IP ranges.
    Returns (ascii_hostname, canonical_ip_if_literal).
    """
    if not hostname:
        raise SSRFBlockedError("Invalid target hostname")

    if "%" in hostname:
        raise SSRFBlockedError(
            f"Security Policy Violation: IPv6 zone identifier in host '{hostname}' is prohibited (SSRF Defense)."
        )

    clean_host = hostname.strip().lower()
    if clean_host.endswith(".."):
        raise SSRFBlockedError("Malformed target hostname")
    clean_host = clean_host.rstrip(".")
    if not clean_host:
        raise SSRFBlockedError("Invalid target hostname")

    try:
        ascii_host = clean_host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        raise SSRFBlockedError(f"Malformed IDN hostname '{hostname}'")

    if not ascii_host or any(label == "" for label in ascii_host.split(".")):
        raise SSRFBlockedError("Malformed target hostname")

    # Check both raw unicode form and IDNA-normalized ASCII form (catches fullwidth １２７.０.０.１ / ⓛⓞⓒⓐⓛⓗⓞⓢⓣ)
    for candidate in (clean_host, ascii_host):
        if not allow_local:
            if candidate in BLOCKED_HOSTNAMES or any(candidate.endswith(sfx) for sfx in BLOCKED_HOST_SUFFIXES):
                raise SSRFBlockedError(
                    f"Security Policy Violation: Scanning internal or loopback host '{hostname}' is prohibited (SSRF Defense)."
                )

        ip_obj, has_zone, is_obfuscated = _parse_ip_literal(candidate)
        if ip_obj is not None:
            if has_zone and not allow_local:
                raise SSRFBlockedError(
                    f"Security Policy Violation: IPv6 zone identifier in '{hostname}' is prohibited (SSRF Defense)."
                )
            if not allow_local and _is_ip_disallowed(ip_obj):
                raise SSRFBlockedError(
                    f"Security Policy Violation: Scanning private/reserved IP '{ip_obj}' is prohibited (SSRF Defense)."
                )
            if is_obfuscated and not allow_local:
                raise SSRFBlockedError(
                    f"Security Policy Violation: Obfuscated IP literal '{hostname}' is prohibited (SSRF Defense)."
                )
            return ascii_host, str(ip_obj)

    return ascii_host, None


def validate_url_syntax_and_host(url: str, allow_local: bool = False) -> Tuple[str, str, str, int]:
    """
    Strictly validate URL syntax, scheme, credentials, port, and host without making network calls.
    Cross-validates urllib.parse.urlparse and httpx.URL to prevent parser-differential SSRF.
    Returns (normalized_url, scheme, ascii_hostname, port).
    """
    if not url or not isinstance(url, str):
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")

    url = url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")

    if len(url) > _MAX_URL_LENGTH:
        raise HTTPException(status_code=400, detail="Target URL exceeds maximum allowed length")

    if any(ord(ch) < 32 or ord(ch) == 127 or ch.isspace() for ch in url):
        raise HTTPException(status_code=400, detail="Malformed URL: whitespace or control characters are prohibited")

    # Inspect scheme before prepending https://
    if "://" in url:
        scheme_part = url.split("://", 1)[0].lower()
        if scheme_part not in ("http", "https"):
            raise SSRFBlockedError(
                f"Security Policy Violation: Unsupported URL scheme '{scheme_part}' (SSRF Defense)."
            )
    else:
        scheme_match = _EXPLICIT_SCHEME_RE.match(url)
        if scheme_match:
            candidate_scheme = scheme_match.group(1).lower()
            # Allow host:port (digits after ':') without scheme, reject explicit non-HTTP schemes like file:/javascript:/data:
            after_colon = url[len(candidate_scheme) + 1:]
            if candidate_scheme not in ("http", "https") and not re.match(r"^\d+([/?#]|$)", after_colon):
                raise SSRFBlockedError(
                    f"Security Policy Violation: Unsupported URL scheme '{candidate_scheme}' (SSRF Defense)."
                )
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed URL format")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SSRFBlockedError(
            f"Security Policy Violation: Unsupported URL scheme '{scheme}' (SSRF Defense)."
        )

    if not parsed.netloc or "\\" in parsed.netloc:
        raise HTTPException(status_code=400, detail="Malformed URL authority")

    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise SSRFBlockedError(
            "Security Policy Violation: Embedded URL credentials ('@' in authority) are prohibited (SSRF Defense)."
        )

    try:
        explicit_port = parsed.port
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid target port")

    port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
    if not (1 <= port <= 65535):
        raise HTTPException(status_code=400, detail="Invalid target port range")

    if not allow_local and port in BLOCKED_PORTS:
        raise SSRFBlockedError(
            f"Security Policy Violation: Target port {port} is prohibited by scanning policy (SSRF Defense)."
        )

    raw_hostname = parsed.hostname
    if not raw_hostname:
        raise HTTPException(status_code=400, detail="Invalid target hostname")

    # Enforce host policy (also catches fullwidth/IDN localhost or obfuscated IPs before httpx.URL)
    ascii_host, ip_literal = _check_hostname_policy(raw_hostname, allow_local=allow_local)

    # Cross-validate with httpx.URL to eliminate parser-differential SSRF
    try:
        hx_url = httpx.URL(url)
    except httpx.InvalidURL:
        raise HTTPException(status_code=400, detail="Malformed URL format")

    if hx_url.scheme.lower() != scheme or hx_url.username or hx_url.password:
        raise SSRFBlockedError("Security Policy Violation: URL parser validation mismatch (SSRF Defense).")

    hx_host_ascii = hx_url.raw_host.decode("ascii", errors="ignore").lower().rstrip(".")
    expected_host = ip_literal if ip_literal else ascii_host
    if ":" in expected_host:
        # IPv6 literal comparison
        try:
            if ipaddress.ip_address(hx_host_ascii) != ipaddress.ip_address(expected_host):
                raise SSRFBlockedError("Security Policy Violation: IPv6 host parser mismatch (SSRF Defense).")
        except ValueError:
            raise SSRFBlockedError("Security Policy Violation: Invalid IPv6 host (SSRF Defense).")
    elif hx_host_ascii != expected_host:
        raise SSRFBlockedError("Security Policy Violation: Hostname parser mismatch (SSRF Defense).")

    return url, scheme, ascii_host, port


def resolve_and_validate_host(
    hostname: str,
    port: int,
    allow_local: bool = False,
    require_resolution: bool = True,
) -> List[str]:
    """
    Resolve hostname via DNS and validate EVERY returned IP address.
    If ANY returned address is private, loopback, link-local, metadata, or reserved,
    reject the entire host to prevent dual-record and DNS rebinding bypasses.
    Returns ordered list of validated canonical IP strings (IPv4 first, then IPv6).
    """
    ascii_host, ip_literal = _check_hostname_policy(hostname, allow_local=allow_local)

    if ip_literal is not None:
        if not allow_local and not is_public_ip(ip_literal):
            raise SSRFBlockedError(
                f"Security Policy Violation: Scanning private/reserved IP '{ip_literal}' is prohibited (SSRF Defense)."
            )
        return [ip_literal]

    try:
        addr_info = socket.getaddrinfo(
            ascii_host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        if require_resolution:
            raise DNSResolutionError(f"DNS resolution failed for '{ascii_host}': {exc}") from exc
        return []
    except Exception as exc:
        if require_resolution:
            raise DNSResolutionError(f"DNS resolution error for '{ascii_host}': {exc}") from exc
        return []

    v4_ips: List[str] = []
    v6_ips: List[str] = []
    seen = set()

    for item in addr_info:
        sockaddr = item[4]
        if not sockaddr:
            continue
        raw_ip = str(sockaddr[0])
        if "%" in raw_ip:
            if not allow_local:
                raise SSRFBlockedError(
                    f"Security Policy Violation: Host '{ascii_host}' resolves to scoped/link-local IP '{raw_ip}' (SSRF Defense)."
                )
            raw_ip = raw_ip.split("%", 1)[0]

        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue

        canonical_ip = str(ip_obj)
        if not allow_local and _is_ip_disallowed(ip_obj):
            raise SSRFBlockedError(
                f"Security Policy Violation: Host '{ascii_host}' resolves to private/internal IP '{canonical_ip}' (SSRF Defense)."
            )

        if canonical_ip not in seen:
            seen.add(canonical_ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                v4_ips.append(canonical_ip)
            else:
                v6_ips.append(canonical_ip)

    ordered_ips = v4_ips + v6_ips
    if require_resolution and not ordered_ips:
        raise DNSResolutionError(f"No usable IP addresses resolved for '{ascii_host}'")

    return ordered_ips


def validate_target_url(url: str, allow_local: Optional[bool] = None) -> str:
    """
    Validate target URL and prevent Server-Side Request Forgery (SSRF).
    Blocks requests to localhost, loopback, cloud metadata endpoints,
    RFC1918/CGNAT/link-local private subnets, obfuscated IPs, unsafe schemes,
    and hostnames resolving to non-public IPs.
    """
    if allow_local is None:
        allow_local = False  # Strict by default

    normalized_url, _, ascii_host, port = validate_url_syntax_and_host(url, allow_local=allow_local)

    if not allow_local:
        # Check DNS if resolvable; NXDOMAIN is allowed at pre-flight so lexical/CTI-only
        # scans or reporting on offline domains still work without making connections.
        resolve_and_validate_host(
            ascii_host,
            port,
            allow_local=False,
            require_resolution=False,
        )

    return normalized_url
