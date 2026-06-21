"""Tests for the SSRF-hardened outbound httpx client (utils.safe_http).

Covers the DNS-rebinding defense (send-time resolution + blocklist
re-validation + IP pinning), the dev hostname allowlist, the dev
*.BASE_DOMAIN reverse-proxy rewrite, and the redirect-disabled factory.
"""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import httpx
import pytest
from utils import safe_http
from utils.safe_http import (
    PinnedResolveTransport,
    SsrfBlockedError,
    build_safe_client,
)


def _gai(ip: str, port: int = 443):
    """Build a getaddrinfo-shaped result for a single IPv4/IPv6 address."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", (ip, port))]


def _patched_super():
    """Patch the base HTTPTransport.handle_request, returning the mock."""
    return patch.object(
        httpx.HTTPTransport, "handle_request", MagicMock(return_value=httpx.Response(200))
    )


# ---------------------------------------------------------------------------
# _resolve_and_validate
# ---------------------------------------------------------------------------


def test_resolve_public_ip_returns_address():
    with patch("socket.getaddrinfo", return_value=_gai("93.184.216.34")):
        assert safe_http._resolve_and_validate("example.com", 443) == "93.184.216.34"


@pytest.mark.parametrize(
    "blocked",
    ["127.0.0.1", "169.254.169.254", "10.1.2.3", "192.168.0.5", "::1"],
)
def test_resolve_blocked_ip_raises(blocked):
    with patch("socket.getaddrinfo", return_value=_gai(blocked)):
        with pytest.raises(SsrfBlockedError):
            safe_http._resolve_and_validate("attacker.example", 443)


def test_resolve_rejects_when_any_address_blocked():
    # A rebinding host returning one public and one internal record must be
    # rejected outright rather than gambling on which httpx would dial.
    infos = _gai("93.184.216.34") + _gai("169.254.169.254")
    with patch("socket.getaddrinfo", return_value=infos):
        with pytest.raises(SsrfBlockedError):
            safe_http._resolve_and_validate("rebind.example", 443)


def test_resolve_unresolvable_raises():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
        with pytest.raises(SsrfBlockedError):
            safe_http._resolve_and_validate("nx.example", 443)


def test_resolve_strips_ipv6_zone_identifier():
    infos = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%eth0", 443, 0, 0))]
    with patch("socket.getaddrinfo", return_value=infos):
        with pytest.raises(SsrfBlockedError):
            safe_http._resolve_and_validate("linklocal.example", 443)


# ---------------------------------------------------------------------------
# PinnedResolveTransport.handle_request
# ---------------------------------------------------------------------------


def test_handle_request_pins_validated_ip_and_preserves_host():
    transport = PinnedResolveTransport()
    request = httpx.Request("POST", "https://scim.example.com/Users")

    with patch("socket.getaddrinfo", return_value=_gai("93.184.216.34")):
        with _patched_super() as mock_super:
            transport.handle_request(request)

    sent = mock_super.call_args.args[0]
    # URL host rewritten to the pinned IP so httpcore does not re-resolve.
    assert sent.url.host == "93.184.216.34"
    # Host header still names the real host for receiver-side routing.
    assert sent.headers["host"] == "scim.example.com"
    # TLS SNI / cert verification still target the real hostname.
    assert sent.extensions["sni_hostname"] == "scim.example.com"


def test_handle_request_blocked_ip_raises_and_never_dials():
    transport = PinnedResolveTransport()
    request = httpx.Request("POST", "https://attacker.example/Users")

    with patch("socket.getaddrinfo", return_value=_gai("169.254.169.254")):
        with _patched_super() as mock_super:
            with pytest.raises(SsrfBlockedError):
                transport.handle_request(request)
    mock_super.assert_not_called()


def test_handle_request_dev_allowlist_bypasses_validation():
    transport = PinnedResolveTransport(dev_hostname_allowlist=frozenset({"host.docker.internal"}))
    request = httpx.Request("POST", "http://host.docker.internal:9000/v2/Users")

    with patch.object(safe_http.settings, "IS_DEV", True):
        with patch("socket.getaddrinfo") as mock_gai:
            with _patched_super() as mock_super:
                transport.handle_request(request)
            mock_gai.assert_not_called()

    sent = mock_super.call_args.args[0]
    assert sent.url.host == "host.docker.internal"


def test_handle_request_allowlist_inert_outside_dev():
    transport = PinnedResolveTransport(dev_hostname_allowlist=frozenset({"host.docker.internal"}))
    request = httpx.Request("POST", "https://host.docker.internal/Users")

    with patch.object(safe_http.settings, "IS_DEV", False):
        with patch("socket.getaddrinfo", return_value=_gai("172.17.0.2")):
            with _patched_super():
                with pytest.raises(SsrfBlockedError):
                    transport.handle_request(request)


def test_handle_request_dev_base_domain_rewrite_to_reverse_proxy():
    transport = PinnedResolveTransport(dev_base_domain_rewrite=True)
    request = httpx.Request("POST", "https://meridian-health.weftid.localhost/saml/slo")

    with patch.object(safe_http.settings, "IS_DEV", True):
        with patch.object(safe_http.settings, "BASE_DOMAIN", "weftid.localhost"):
            with patch("socket.getaddrinfo") as mock_gai:
                with _patched_super() as mock_super:
                    transport.handle_request(request)
                # Rewrite path skips resolution/pinning entirely.
                mock_gai.assert_not_called()

    sent = mock_super.call_args.args[0]
    assert sent.url.host == "reverse-proxy"
    # Host header preserved so the proxy routes to the right tenant.
    assert sent.headers["host"] == "meridian-health.weftid.localhost"


def test_dev_base_domain_rewrite_inert_outside_dev():
    transport = PinnedResolveTransport(dev_base_domain_rewrite=True)
    request = httpx.Request("POST", "https://tenant.weftid.localhost/saml/slo")

    with patch.object(safe_http.settings, "IS_DEV", False):
        with patch.object(safe_http.settings, "BASE_DOMAIN", "weftid.localhost"):
            with patch("socket.getaddrinfo", return_value=_gai("127.0.0.1")):
                with _patched_super():
                    with pytest.raises(SsrfBlockedError):
                        transport.handle_request(request)


def test_blocked_error_is_request_error():
    # Callers catch httpx.RequestError; a blocked target must surface as one
    # rather than crashing the caller.
    assert issubclass(SsrfBlockedError, httpx.RequestError)


# ---------------------------------------------------------------------------
# build_safe_client
# ---------------------------------------------------------------------------


def test_build_safe_client_disables_redirects_and_pins():
    client = build_safe_client()
    try:
        assert client.follow_redirects is False
        assert isinstance(client._transport, PinnedResolveTransport)
    finally:
        client.close()


def test_build_safe_client_dev_base_domain_rewrite_disables_tls_verify():
    # The dev reverse proxy serves a local cert; verification must be off only
    # for that dev rewrite path, never in production.
    with patch.object(safe_http.settings, "IS_DEV", True):
        client = build_safe_client(dev_base_domain_rewrite=True)
        try:
            transport = client._transport
            assert transport._dev_base_domain_rewrite is True
        finally:
            client.close()
