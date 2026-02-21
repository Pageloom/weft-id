"""Tests for SAML AuthnRequest parsing and validation."""

import base64
import zlib

import pytest
from utils.saml_authn_request import parse_authn_request, validate_authn_request


def _build_authn_request_xml(
    request_id: str = "_abc123",
    issuer: str = "https://sp.example.com",
    acs_url: str | None = None,
    name_id_format: str | None = None,
) -> str:
    """Build a minimal AuthnRequest XML string for testing."""
    acs_attr = f' AssertionConsumerServiceURL="{acs_url}"' if acs_url else ""
    name_id_policy = ""
    if name_id_format:
        name_id_policy = f'  <samlp:NameIDPolicy Format="{name_id_format}" AllowCreate="true"/>\n'

    return (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        f' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="{request_id}"'
        f' Version="2.0"'
        f' IssueInstant="2026-01-01T00:00:00Z"'
        f"{acs_attr}>\n"
        f"  <saml:Issuer>{issuer}</saml:Issuer>\n"
        f"{name_id_policy}"
        f"</samlp:AuthnRequest>"
    )


def _encode_redirect(xml: str) -> str:
    """Encode an AuthnRequest as HTTP-Redirect binding (deflate + base64)."""
    compressed = zlib.compress(xml.encode("utf-8"))[2:-4]  # raw deflate (no header/checksum)
    return base64.b64encode(compressed).decode("utf-8")


def _encode_post(xml: str) -> str:
    """Encode an AuthnRequest as HTTP-POST binding (base64 only)."""
    return base64.b64encode(xml.encode("utf-8")).decode("utf-8")


# ============================================================================
# parse_authn_request - Redirect Binding
# ============================================================================


class TestParseRedirectBinding:
    def test_parse_basic_request(self):
        xml = _build_authn_request_xml()
        encoded = _encode_redirect(xml)
        result = parse_authn_request(encoded, binding="redirect")

        assert result["id"] == "_abc123"
        assert result["issuer"] == "https://sp.example.com"
        assert result["acs_url"] is None
        assert result["name_id_policy_format"] is None

    def test_parse_with_acs_url(self):
        xml = _build_authn_request_xml(acs_url="https://sp.example.com/acs")
        encoded = _encode_redirect(xml)
        result = parse_authn_request(encoded, binding="redirect")

        assert result["acs_url"] == "https://sp.example.com/acs"

    def test_parse_with_name_id_policy(self):
        xml = _build_authn_request_xml(
            name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        )
        encoded = _encode_redirect(xml)
        result = parse_authn_request(encoded, binding="redirect")

        assert (
            result["name_id_policy_format"]
            == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        )


# ============================================================================
# parse_authn_request - POST Binding
# ============================================================================


class TestParsePostBinding:
    def test_parse_basic_request(self):
        xml = _build_authn_request_xml(request_id="_post789", issuer="https://other-sp.com")
        encoded = _encode_post(xml)
        result = parse_authn_request(encoded, binding="post")

        assert result["id"] == "_post789"
        assert result["issuer"] == "https://other-sp.com"

    def test_parse_with_all_fields(self):
        xml = _build_authn_request_xml(
            request_id="_full",
            issuer="https://full-sp.com",
            acs_url="https://full-sp.com/acs",
            name_id_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        )
        encoded = _encode_post(xml)
        result = parse_authn_request(encoded, binding="post")

        assert result["id"] == "_full"
        assert result["issuer"] == "https://full-sp.com"
        assert result["acs_url"] == "https://full-sp.com/acs"
        assert (
            result["name_id_policy_format"]
            == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        )


# ============================================================================
# parse_authn_request - Error Cases
# ============================================================================


class TestParseErrors:
    def test_empty_input(self):
        with pytest.raises(ValueError, match="empty"):
            parse_authn_request("", binding="redirect")

    def test_whitespace_only(self):
        with pytest.raises(ValueError, match="empty"):
            parse_authn_request("   ", binding="redirect")

    def test_invalid_base64(self):
        with pytest.raises(ValueError, match="Invalid base64"):
            parse_authn_request("not-valid-base64!!!", binding="post")

    def test_invalid_deflate(self):
        # Valid base64 but not a deflated stream
        encoded = base64.b64encode(b"not compressed xml").decode()
        with pytest.raises(ValueError, match="decompress"):
            parse_authn_request(encoded, binding="redirect")

    def test_invalid_xml(self):
        bad_xml = b"<not valid xml"
        encoded = base64.b64encode(bad_xml).decode()
        with pytest.raises(ValueError, match="parse"):
            parse_authn_request(encoded, binding="post")

    def test_wrong_root_element(self):
        xml = '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x"/>'
        encoded = _encode_post(xml)
        with pytest.raises(ValueError, match="Expected AuthnRequest"):
            parse_authn_request(encoded, binding="post")

    def test_missing_id(self):
        xml = (
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            "<saml:Issuer>https://sp.example.com</saml:Issuer>"
            "</samlp:AuthnRequest>"
        )
        encoded = _encode_post(xml)
        with pytest.raises(ValueError, match="missing ID"):
            parse_authn_request(encoded, binding="post")

    def test_missing_issuer(self):
        xml = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_test"/>'
        encoded = _encode_post(xml)
        with pytest.raises(ValueError, match="missing Issuer"):
            parse_authn_request(encoded, binding="post")


# ============================================================================
# validate_authn_request
# ============================================================================


class TestValidateAuthnRequest:
    def test_valid_request_matches_sp(self):
        parsed = {
            "id": "_test",
            "issuer": "https://sp.example.com",
            "acs_url": None,
            "name_id_policy_format": None,
        }
        sp = {"entity_id": "https://sp.example.com", "acs_url": "https://sp.example.com/acs"}

        # Should not raise
        validate_authn_request(parsed, sp)

    def test_valid_request_with_matching_acs_url(self):
        parsed = {
            "id": "_test",
            "issuer": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "name_id_policy_format": None,
        }
        sp = {"entity_id": "https://sp.example.com", "acs_url": "https://sp.example.com/acs"}

        validate_authn_request(parsed, sp)

    def test_reject_unknown_issuer(self):
        parsed = {
            "id": "_test",
            "issuer": "https://unknown-sp.com",
            "acs_url": None,
            "name_id_policy_format": None,
        }
        sp = {"entity_id": "https://sp.example.com", "acs_url": "https://sp.example.com/acs"}

        with pytest.raises(ValueError, match="does not match"):
            validate_authn_request(parsed, sp)

    def test_reject_mismatched_acs_url(self):
        parsed = {
            "id": "_test",
            "issuer": "https://sp.example.com",
            "acs_url": "https://evil.com/acs",
            "name_id_policy_format": None,
        }
        sp = {"entity_id": "https://sp.example.com", "acs_url": "https://sp.example.com/acs"}

        with pytest.raises(ValueError, match="ACS URL"):
            validate_authn_request(parsed, sp)
