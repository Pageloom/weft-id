"""Tests for URL safety utilities (SSRF protection)."""

import socket
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from app.utils.url_safety import (
    MAX_METADATA_BYTES,
    _is_ip_blocked,
    _SafeRedirectHandler,
    fetch_metadata_xml,
    read_response_with_limit,
    validate_metadata_url,
)


def _mock_opener(mock_response=None, side_effect=None):
    """Create a mock opener that replaces build_opener in tests."""
    opener = MagicMock()
    if side_effect:
        opener.open.side_effect = side_effect
    else:
        opener.open.return_value.__enter__.return_value = mock_response
    return opener


# =============================================================================
# _is_ip_blocked tests
# =============================================================================


class TestIsIpBlocked:
    """Tests for the IP blocklist checker."""

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.255",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "169.254.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "0.255.255.255",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.1",
            "224.0.0.1",
            "240.0.0.1",
        ],
        ids=[
            "loopback",
            "loopback-2",
            "loopback-max",
            "rfc1918-10",
            "rfc1918-10-max",
            "rfc1918-172",
            "rfc1918-172-max",
            "rfc1918-192",
            "rfc1918-192-max",
            "link-local",
            "cloud-metadata",
            "zero-net",
            "zero-net-max",
            "cgnat",
            "cgnat-max",
            "ietf-protocol",
            "multicast",
            "reserved",
        ],
    )
    def test_blocked_ipv4(self, ip: str):
        assert _is_ip_blocked(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "::1",
            "fc00::1",
            "fdff::1",
            "fe80::1",
        ],
        ids=["ipv6-loopback", "ipv6-unique-local", "ipv6-unique-local-fd", "ipv6-link-local"],
    )
    def test_blocked_ipv6(self, ip: str):
        assert _is_ip_blocked(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:192.168.1.1",
        ],
        ids=["mapped-loopback", "mapped-rfc1918", "mapped-cloud-meta", "mapped-private"],
    )
    def test_blocked_ipv4_mapped_ipv6(self, ip: str):
        assert _is_ip_blocked(ip) is True

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.1",
            "2607:f8b0:4004:800::200e",
        ],
        ids=["google-dns", "cloudflare-dns", "public-doc", "google-ipv6"],
    )
    def test_allowed_public_ip(self, ip: str):
        assert _is_ip_blocked(ip) is False


# =============================================================================
# validate_metadata_url tests
# =============================================================================


class TestValidateMetadataUrl:
    """Tests for URL validation with SSRF protection."""

    @patch("app.utils.url_safety.settings")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_https_passes_in_prod(self, mock_getaddrinfo, mock_settings):
        mock_settings.IS_DEV = False
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

        result = validate_metadata_url("https://example.com/metadata")
        assert result == "93.184.216.34"

    @patch("app.utils.url_safety.settings")
    def test_http_rejected_in_prod(self, mock_settings):
        mock_settings.IS_DEV = False

        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            validate_metadata_url("http://example.com/metadata")

    @patch("app.utils.url_safety.settings")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_http_allowed_in_dev(self, mock_getaddrinfo, mock_settings):
        mock_settings.IS_DEV = True
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

        result = validate_metadata_url("http://example.com/metadata")
        assert result == "93.184.216.34"

    @pytest.mark.parametrize("scheme", ["file", "ftp", "gopher", "data"])
    @patch("app.utils.url_safety.settings")
    def test_non_http_schemes_rejected(self, mock_settings, scheme: str):
        mock_settings.IS_DEV = True  # Even in dev, only http/https allowed

        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            validate_metadata_url(f"{scheme}:///etc/passwd")

    @patch("app.utils.url_safety.settings")
    def test_missing_hostname(self, mock_settings):
        mock_settings.IS_DEV = False

        with pytest.raises(ValueError, match="URL missing hostname"):
            validate_metadata_url("https:///path/only")

    @patch("app.utils.url_safety.settings")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_dns_resolution_failure(self, mock_getaddrinfo, mock_settings):
        mock_settings.IS_DEV = False
        mock_getaddrinfo.side_effect = socket.gaierror("Name resolution failed")

        with pytest.raises(ValueError, match="Cannot resolve hostname"):
            validate_metadata_url("https://nonexistent.invalid/metadata")

    @patch("app.utils.url_safety.settings")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_empty_dns_result(self, mock_getaddrinfo, mock_settings):
        mock_settings.IS_DEV = False
        mock_getaddrinfo.return_value = []

        with pytest.raises(ValueError, match="Cannot resolve hostname"):
            validate_metadata_url("https://example.com/metadata")

    @pytest.mark.parametrize(
        "ip",
        ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1"],
        ids=["loopback", "rfc1918", "cloud-metadata", "private"],
    )
    @patch("app.utils.url_safety.settings")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_private_ip_rejected(self, mock_getaddrinfo, mock_settings, ip: str):
        mock_settings.IS_DEV = False
        mock_getaddrinfo.return_value = [(2, 1, 6, "", (ip, 0))]

        with pytest.raises(ValueError, match="private or reserved"):
            validate_metadata_url("https://evil.example.com/metadata")

    @patch("app.utils.url_safety.settings")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_public_ip_passes(self, mock_getaddrinfo, mock_settings):
        mock_settings.IS_DEV = False
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

        result = validate_metadata_url("https://example.com/metadata")
        assert result == "93.184.216.34"


# =============================================================================
# read_response_with_limit tests
# =============================================================================


class TestReadResponseWithLimit:
    """Tests for response size limiting."""

    def test_under_limit(self):
        response = MagicMock()
        response.headers = {}
        response.read.return_value = b"<xml>small</xml>"

        result = read_response_with_limit(response, 1024)
        assert result == b"<xml>small</xml>"

    def test_at_limit(self):
        data = b"x" * 1024
        response = MagicMock()
        response.headers = {}
        response.read.return_value = data

        result = read_response_with_limit(response, 1024)
        assert result == data

    def test_over_limit_via_read(self):
        data = b"x" * 1025
        response = MagicMock()
        response.headers = {}
        response.read.return_value = data

        with pytest.raises(ValueError, match="Response too large"):
            read_response_with_limit(response, 1024)

    def test_over_limit_via_content_length(self):
        response = MagicMock()
        response.headers = {"Content-Length": "2000"}
        response.read.return_value = b""

        with pytest.raises(ValueError, match="Response too large"):
            read_response_with_limit(response, 1024)


# =============================================================================
# fetch_metadata_xml integration tests (with mocked HTTP)
# =============================================================================

SAMPLE_XML = '<?xml version="1.0"?><EntityDescriptor>test</EntityDescriptor>'


class TestFetchMetadataXml:
    """Integration tests for the full fetch_metadata_xml function."""

    @patch("app.utils.url_safety.urllib.request.build_opener")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_successful_fetch(self, mock_settings, mock_getaddrinfo, mock_build):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.read.return_value = SAMPLE_XML.encode("utf-8")
        mock_build.return_value = _mock_opener(mock_response)

        result = fetch_metadata_xml("https://idp.example.com/metadata")
        assert "EntityDescriptor" in result

    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_ssrf_blocked(self, mock_settings, mock_getaddrinfo):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("169.254.169.254", 0))]

        with pytest.raises(ValueError, match="private or reserved"):
            fetch_metadata_xml("https://evil.example.com/latest/meta-data/")

    @patch("app.utils.url_safety.settings")
    def test_file_scheme_blocked(self, mock_settings):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""

        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            fetch_metadata_xml("file:///etc/passwd")

    @patch("app.utils.url_safety.urllib.request.build_opener")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_http_error(self, mock_settings, mock_getaddrinfo, mock_build):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        mock_build.return_value = _mock_opener(
            side_effect=HTTPError(
                url="https://example.com", code=404, msg="Not Found", hdrs={}, fp=None
            )
        )

        with pytest.raises(ValueError, match="HTTP error"):
            fetch_metadata_xml("https://example.com/metadata")

    @patch("app.utils.url_safety.urllib.request.build_opener")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_network_error(self, mock_settings, mock_getaddrinfo, mock_build):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        mock_build.return_value = _mock_opener(side_effect=URLError("Connection refused"))

        with pytest.raises(ValueError, match="fetch metadata"):
            fetch_metadata_xml("https://example.com/metadata")

    @patch("app.utils.url_safety.urllib.request.build_opener")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_timeout(self, mock_settings, mock_getaddrinfo, mock_build):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        mock_build.return_value = _mock_opener(side_effect=TimeoutError())

        with pytest.raises(ValueError, match="Timeout"):
            fetch_metadata_xml("https://example.com/metadata")

    @patch("app.utils.url_safety.urllib.request.build_opener")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_non_xml_response(self, mock_settings, mock_getaddrinfo, mock_build):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.read.return_value = b"This is not XML content"
        mock_build.return_value = _mock_opener(mock_response)

        with pytest.raises(ValueError, match="XML"):
            fetch_metadata_xml("https://example.com/metadata")

    @patch("app.utils.url_safety.urllib.request.build_opener")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_oversized_response(self, mock_settings, mock_getaddrinfo, mock_build):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.read.return_value = b"x" * (MAX_METADATA_BYTES + 1)
        mock_build.return_value = _mock_opener(mock_response)

        with pytest.raises(ValueError, match="Response too large"):
            fetch_metadata_xml("https://example.com/metadata")


# =============================================================================
# Dev-mode reverse-proxy tests
# =============================================================================


class TestDevModeReverseProxy:
    """Tests for dev-mode *.BASE_DOMAIN handling."""

    @patch("app.utils.url_safety.urllib.request.build_opener")
    @patch("app.utils.url_safety.settings")
    def test_base_domain_skips_ip_validation(self, mock_settings, mock_build):
        """URLs matching *.BASE_DOMAIN skip IP validation in dev mode."""
        mock_settings.IS_DEV = True
        mock_settings.BASE_DOMAIN = "weftid.localhost"

        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.read.return_value = SAMPLE_XML.encode("utf-8")
        mock_build.return_value = _mock_opener(mock_response)

        # This URL targets BASE_DOMAIN, so IP validation is skipped.
        # No socket.getaddrinfo mock needed.
        result = fetch_metadata_xml("https://tenant.weftid.localhost/metadata")
        assert "EntityDescriptor" in result

    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_non_base_domain_still_validated_in_dev(self, mock_settings, mock_getaddrinfo):
        """Non-BASE_DOMAIN URLs in dev mode still get full IP validation."""
        mock_settings.IS_DEV = True
        mock_settings.BASE_DOMAIN = "weftid.localhost"
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 0))]

        with pytest.raises(ValueError, match="private or reserved"):
            fetch_metadata_xml("http://localhost:8080/metadata")

    @patch("app.utils.url_safety.settings")
    def test_base_domain_still_validates_scheme(self, mock_settings):
        """Even *.BASE_DOMAIN URLs must use http or https."""
        mock_settings.IS_DEV = True
        mock_settings.BASE_DOMAIN = "weftid.localhost"

        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            fetch_metadata_xml("ftp://tenant.weftid.localhost/metadata")

    @patch("app.utils.url_safety.urllib.request.build_opener")
    @patch("app.utils.url_safety.settings")
    def test_dev_proxy_sets_host_header(self, mock_settings, mock_build):
        """Reverse-proxy rewrite preserves original hostname via Host header."""
        mock_settings.IS_DEV = True
        mock_settings.BASE_DOMAIN = "weftid.localhost"

        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.read.return_value = SAMPLE_XML.encode("utf-8")
        mock_build.return_value = _mock_opener(mock_response)

        fetch_metadata_xml("https://tenant.weftid.localhost/metadata")

        # The opener was called with a Request object that has the Host header
        call_args = mock_build.return_value.open.call_args
        req = call_args[0][0]
        assert req.get_header("Host") == "tenant.weftid.localhost"


# =============================================================================
# Redirect SSRF protection tests
# =============================================================================


class TestSafeRedirectHandler:
    """Tests for redirect validation against IP blocklist."""

    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_redirect_to_private_ip_blocked(self, mock_settings, mock_getaddrinfo):
        """Redirect to a private/internal IP is rejected."""
        import urllib.request

        mock_settings.IS_DEV = False
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("169.254.169.254", 0))]

        handler = _SafeRedirectHandler()
        req = urllib.request.Request("https://example.com/metadata")
        with pytest.raises(ValueError, match="private or reserved"):
            handler.redirect_request(req, None, 301, "Moved", {}, "https://evil.com/redirect")

    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_redirect_to_public_ip_allowed(self, mock_settings, mock_getaddrinfo):
        """Redirect to a public IP is allowed."""
        import urllib.request

        mock_settings.IS_DEV = False
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

        handler = _SafeRedirectHandler()
        req = urllib.request.Request("https://example.com/metadata")

        result = handler.redirect_request(
            req, None, 301, "Moved", {}, "https://new.example.com/metadata"
        )
        assert result is not None
