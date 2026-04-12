"""URL safety utilities for SSRF protection on metadata fetches."""

import ipaddress
import socket
import ssl
import urllib.request
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse

import settings

# 5 MB limit for metadata responses
MAX_METADATA_BYTES = 5 * 1024 * 1024

# IP networks that must never be contacted by metadata fetches
_BLOCKED_NETWORKS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_ip_blocked(ip_str: str) -> bool:
    """Check whether an IP address falls in a blocked network."""
    addr = ipaddress.ip_address(ip_str)

    # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1): check the inner IPv4 address
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped

    for net in _BLOCKED_NETWORKS:
        if addr in net:
            return True
    return False


def validate_metadata_url(url: str) -> str:
    """Validate a metadata URL for safe fetching.

    Checks the URL scheme and resolves the hostname to ensure the target is
    not a private/internal IP address.

    Args:
        url: The URL to validate.

    Returns:
        The resolved IP address string (first result from getaddrinfo).

    Raises:
        ValueError: If the URL is unsafe (bad scheme, private IP, or
            unresolvable hostname).
    """
    parsed = urlparse(url)

    # Scheme validation
    allowed_schemes = {"https"}
    if settings.IS_DEV:
        allowed_schemes.add("http")
    if parsed.scheme not in allowed_schemes:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL missing hostname")

    # Resolve hostname and check IP
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve hostname: {hostname}") from e

    if not results:
        raise ValueError(f"Cannot resolve hostname: {hostname}")

    ip_str = str(results[0][4][0])
    if _is_ip_blocked(ip_str):
        raise ValueError("URL targets a private or reserved address")

    return ip_str


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that re-validates each hop against the IP blocklist."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None
        # Validate the redirect destination IP
        validate_metadata_url(newurl)
        return new_req


def read_response_with_limit(response: Any, max_bytes: int) -> bytes:
    """Read an HTTP response body with a size cap.

    Args:
        response: The urllib response object.
        max_bytes: Maximum number of bytes to accept.

    Returns:
        The response body bytes.

    Raises:
        ValueError: If the response exceeds max_bytes.
    """
    # Check Content-Length header first (fast rejection)
    content_length = response.headers.get("Content-Length")
    if content_length and int(content_length) > max_bytes:
        raise ValueError(f"Response too large ({content_length} bytes, max {max_bytes})")

    data: bytes = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"Response too large (>{max_bytes} bytes)")
    return data


def fetch_metadata_xml(url: str, timeout: int = 10) -> str:
    """Fetch metadata XML from a URL with SSRF protection.

    Validates the URL scheme and target IP, enforces a response size limit,
    and checks that the response looks like XML.

    In dev mode, URLs targeting *.BASE_DOMAIN are routed through the
    reverse-proxy Docker container (hostname rewrite, TLS verification
    skipped). For these URLs, IP validation is skipped because the
    hostname will be rewritten to the container name.

    Args:
        url: Metadata URL (https required in production).
        timeout: Request timeout in seconds.

    Returns:
        Raw XML metadata string.

    Raises:
        ValueError: If the URL is unsafe, the fetch fails, the response
            is too large, or the response is not XML.
    """
    parsed = urlparse(url)
    headers: dict[str, str] = {
        "Accept": "application/xml, text/xml, application/samlmetadata+xml",
    }
    ssl_ctx = None

    # Dev-mode reverse-proxy handling for *.BASE_DOMAIN
    base = settings.BASE_DOMAIN
    is_dev_internal = (
        settings.IS_DEV and base and parsed.hostname and parsed.hostname.endswith(base)
    )

    if is_dev_internal:
        # Still validate the scheme
        allowed_schemes = {"https", "http"}
        if parsed.scheme not in allowed_schemes:
            raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")

        # Rewrite to reverse-proxy container
        original_host = parsed.hostname  # guaranteed non-None by is_dev_internal check
        assert original_host is not None
        port = parsed.port or 443
        parsed = parsed._replace(netloc=f"reverse-proxy:{port}")
        headers["Host"] = original_host
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    else:
        # Full SSRF validation for all other URLs
        validate_metadata_url(url)

    try:
        req = urllib.request.Request(urlunparse(parsed), headers=headers)
        handlers: list[urllib.request.BaseHandler] = [_SafeRedirectHandler()]
        if ssl_ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
        opener = urllib.request.build_opener(*handlers)
        with opener.open(req, timeout=timeout) as response:  # noqa: S310
            data = read_response_with_limit(response, MAX_METADATA_BYTES)
            content = data.decode("utf-8")

            # Basic XML validation
            stripped = content.strip()
            if not stripped.startswith("<?xml") and not stripped.startswith("<"):
                raise ValueError("Response does not appear to be XML")

            return content

    except HTTPError as e:
        raise ValueError(f"HTTP error fetching metadata: {e.code} {e.reason}") from e
    except URLError as e:
        raise ValueError(f"Failed to fetch metadata: {e.reason}") from e
    except TimeoutError:
        raise ValueError(f"Timeout fetching metadata (>{timeout}s)") from None
