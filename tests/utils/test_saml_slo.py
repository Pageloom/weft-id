"""Tests for SAML SLO (Single Logout) XML construction and parsing."""

import base64
import zlib

import pytest
import xmlsec
from lxml import etree
from utils.saml import generate_sp_certificate
from utils.saml_slo import (
    build_idp_logout_request,
    build_idp_logout_response,
    parse_sp_logout_request,
)

# SAML namespaces for xpath queries
_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_NS = {
    "saml": _SAML_NS,
    "samlp": _SAMLP_NS,
    "ds": _DS_NS,
}

_IDP_ENTITY_ID = "https://idp.example.com/saml/idp/metadata/sp-1"
_SP_SLO_URL = "https://sp.example.com/slo"


@pytest.fixture(scope="module")
def signing_keys():
    """Generate a test signing certificate and private key."""
    cert_pem, key_pem = generate_sp_certificate("test-tenant")
    return cert_pem, key_pem


def _make_logout_request_xml(
    issuer: str = "https://sp.example.com",
    request_id: str = "_req_slo_123",
    name_id: str = "user@example.com",
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    session_index: str | None = "_session_abc",
) -> str:
    parts = [
        f'<samlp:LogoutRequest xmlns:samlp="{_SAMLP_NS}"'
        f' xmlns:saml="{_SAML_NS}"'
        f' ID="{request_id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">',
        f"<saml:Issuer>{issuer}</saml:Issuer>",
        f'<saml:NameID Format="{name_id_format}">{name_id}</saml:NameID>',
    ]
    if session_index:
        parts.append(f"<samlp:SessionIndex>{session_index}</samlp:SessionIndex>")
    parts.append("</samlp:LogoutRequest>")
    return "".join(parts)


def _encode_post(xml: str) -> str:
    return base64.b64encode(xml.encode("utf-8")).decode("utf-8")


def _encode_redirect(xml: str) -> str:
    compressed = zlib.compress(xml.encode("utf-8"))[2:-4]
    return base64.b64encode(compressed).decode("utf-8")


def _decode_b64_xml(b64: str) -> etree._Element:
    return etree.fromstring(base64.b64decode(b64))


# ============================================================================
# parse_sp_logout_request
# ============================================================================


class TestParseSpLogoutRequest:
    def test_parses_post_binding(self):
        xml = _make_logout_request_xml()
        encoded = _encode_post(xml)

        result = parse_sp_logout_request(encoded, "post")

        assert result["id"] == "_req_slo_123"
        assert result["issuer"] == "https://sp.example.com"
        assert result["name_id"] == "user@example.com"
        assert result["name_id_format"] == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        assert result["session_index"] == "_session_abc"

    def test_parses_redirect_binding(self):
        xml = _make_logout_request_xml()
        encoded = _encode_redirect(xml)

        result = parse_sp_logout_request(encoded, "redirect")

        assert result["id"] == "_req_slo_123"
        assert result["issuer"] == "https://sp.example.com"
        assert result["name_id"] == "user@example.com"

    def test_handles_missing_session_index(self):
        xml = _make_logout_request_xml(session_index=None)
        encoded = _encode_post(xml)

        result = parse_sp_logout_request(encoded, "post")

        assert result["session_index"] is None

    def test_invalid_base64_raises(self):
        with pytest.raises(ValueError, match="Failed to decode"):
            parse_sp_logout_request("!!!not-base64!!!", "post")

    def test_invalid_xml_raises(self):
        encoded = base64.b64encode(b"not xml at all").decode()
        with pytest.raises(ValueError, match="Failed to parse"):
            parse_sp_logout_request(encoded, "post")

    def test_wrong_root_element_raises(self):
        xml = (
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' ID="_x" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"/>'
        )
        encoded = _encode_post(xml)
        with pytest.raises(ValueError, match="Expected LogoutRequest"):
            parse_sp_logout_request(encoded, "post")

    def test_missing_id_raises(self):
        xml = (
            f'<samlp:LogoutRequest xmlns:samlp="{_SAMLP_NS}"'
            f' xmlns:saml="{_SAML_NS}"'
            f' Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            f"<saml:Issuer>https://sp.example.com</saml:Issuer>"
            f"</samlp:LogoutRequest>"
        )
        encoded = _encode_post(xml)
        with pytest.raises(ValueError, match="missing ID"):
            parse_sp_logout_request(encoded, "post")

    def test_parse_missing_issuer_element(self):
        """LogoutRequest without <saml:Issuer> yields issuer=None."""
        xml = (
            f'<samlp:LogoutRequest xmlns:samlp="{_SAMLP_NS}"'
            f' xmlns:saml="{_SAML_NS}"'
            f' ID="_req_no_issuer" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
            f"user@example.com</saml:NameID>"
            f"</samlp:LogoutRequest>"
        )
        encoded = _encode_post(xml)
        result = parse_sp_logout_request(encoded, "post")
        assert result["issuer"] is None
        assert result["name_id"] == "user@example.com"

    def test_parse_missing_name_id_element(self):
        """LogoutRequest without <saml:NameID> yields name_id=None and name_id_format=None."""
        xml = (
            f'<samlp:LogoutRequest xmlns:samlp="{_SAMLP_NS}"'
            f' xmlns:saml="{_SAML_NS}"'
            f' ID="_req_no_nameid" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            f"<saml:Issuer>https://sp.example.com</saml:Issuer>"
            f"</samlp:LogoutRequest>"
        )
        encoded = _encode_post(xml)
        result = parse_sp_logout_request(encoded, "post")
        assert result["name_id"] is None
        assert result["name_id_format"] is None
        assert result["issuer"] == "https://sp.example.com"

    def test_parse_whitespace_only_issuer(self):
        """Issuer element with only whitespace text yields empty string after strip."""
        xml = (
            f'<samlp:LogoutRequest xmlns:samlp="{_SAMLP_NS}"'
            f' xmlns:saml="{_SAML_NS}"'
            f' ID="_req_ws_issuer" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            f"<saml:Issuer>   </saml:Issuer>"
            f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
            f"user@example.com</saml:NameID>"
            f"</samlp:LogoutRequest>"
        )
        encoded = _encode_post(xml)
        result = parse_sp_logout_request(encoded, "post")
        assert result["issuer"] == ""

    def test_parse_whitespace_only_name_id(self):
        """NameID element with only whitespace text yields empty string after strip."""
        xml = (
            f'<samlp:LogoutRequest xmlns:samlp="{_SAMLP_NS}"'
            f' xmlns:saml="{_SAML_NS}"'
            f' ID="_req_ws_nameid" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
            f"<saml:Issuer>https://sp.example.com</saml:Issuer>"
            f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
            f"   </saml:NameID>"
            f"</samlp:LogoutRequest>"
        )
        encoded = _encode_post(xml)
        result = parse_sp_logout_request(encoded, "post")
        assert result["name_id"] == ""


# ============================================================================
# build_idp_logout_response
# ============================================================================


class TestBuildIdpLogoutResponse:
    def test_returns_valid_base64(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_response(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            in_response_to="_req_slo_123",
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        xml_bytes = base64.b64decode(result)
        assert xml_bytes.startswith(b"<?xml")

    def test_response_structure(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_response(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            in_response_to="_req_slo_123",
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_b64_xml(result)

        assert root.tag == f"{{{_SAMLP_NS}}}LogoutResponse"
        assert root.get("Destination") == _SP_SLO_URL
        assert root.get("InResponseTo") == "_req_slo_123"
        assert root.get("Version") == "2.0"
        assert root.get("ID") is not None
        assert root.get("IssueInstant") is not None

    def test_issuer_element(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_response(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            in_response_to="_req_slo_123",
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_b64_xml(result)
        issuer = root.find("saml:Issuer", _NS)
        assert issuer is not None
        assert issuer.text == _IDP_ENTITY_ID

    def test_status_success(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_response(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            in_response_to="_req_slo_123",
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_b64_xml(result)
        status_code = root.find("samlp:Status/samlp:StatusCode", _NS)
        assert status_code is not None
        assert "Success" in status_code.get("Value")

    def test_signature_is_valid(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_response(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            in_response_to="_req_slo_123",
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_b64_xml(result)
        signature = root.find("ds:Signature", _NS)
        assert signature is not None

        xmlsec.tree.add_ids(root, ["ID"])
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_memory(cert_pem.encode(), xmlsec.KeyFormat.CERT_PEM)
        ctx.key = key
        ctx.verify(signature)  # Raises on failure


# ============================================================================
# build_idp_logout_request
# ============================================================================


class TestBuildIdpLogoutRequest:
    def test_returns_valid_base64(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_request(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            name_id="user@example.com",
            name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index="_session_abc",
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        xml_bytes = base64.b64decode(result)
        assert xml_bytes.startswith(b"<?xml")

    def test_request_structure(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_request(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            name_id="user@example.com",
            name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index="_session_abc",
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_b64_xml(result)

        assert root.tag == f"{{{_SAMLP_NS}}}LogoutRequest"
        assert root.get("Destination") == _SP_SLO_URL
        assert root.get("Version") == "2.0"
        assert root.get("ID") is not None
        assert root.get("NotOnOrAfter") is not None

    def test_name_id_element(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_request(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            name_id="user@example.com",
            name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            session_index=None,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_b64_xml(result)
        name_id = root.find("saml:NameID", _NS)
        assert name_id is not None
        assert name_id.text == "user@example.com"
        assert name_id.get("Format") == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    def test_session_index_included(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_request(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            name_id="user@example.com",
            name_id_format=None,
            session_index="_session_xyz",
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_b64_xml(result)
        session_idx = root.find("samlp:SessionIndex", _NS)
        assert session_idx is not None
        assert session_idx.text == "_session_xyz"

    def test_session_index_omitted_when_none(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_request(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            name_id="user@example.com",
            name_id_format=None,
            session_index=None,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_b64_xml(result)
        session_idx = root.find("samlp:SessionIndex", _NS)
        assert session_idx is None

    def test_signature_is_valid(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_request(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            name_id="user@example.com",
            name_id_format=None,
            session_index="_session_abc",
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_b64_xml(result)
        signature = root.find("ds:Signature", _NS)
        assert signature is not None

        xmlsec.tree.add_ids(root, ["ID"])
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_memory(cert_pem.encode(), xmlsec.KeyFormat.CERT_PEM)
        ctx.key = key
        ctx.verify(signature)

    def test_name_id_without_format(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_idp_logout_request(
            issuer_entity_id=_IDP_ENTITY_ID,
            destination=_SP_SLO_URL,
            name_id="user@example.com",
            name_id_format=None,
            session_index=None,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_b64_xml(result)
        name_id = root.find("saml:NameID", _NS)
        assert name_id is not None
        assert name_id.get("Format") is None
