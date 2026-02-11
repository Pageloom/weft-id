"""Tests for SAML Response and Assertion generation."""

import base64
import datetime

import pytest
import xmlsec
from lxml import etree
from utils.saml import generate_sp_certificate
from utils.saml_assertion import (
    SAML_ATTRIBUTE_URIS,
    build_saml_response,
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

# Test fixtures
_ISSUER = "https://idp.example.com/saml/idp/metadata"
_SP_ENTITY_ID = "https://sp.example.com"
_SP_ACS_URL = "https://sp.example.com/acs"
_NAME_ID = "user@example.com"
_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
_USER_ATTRS = {
    "email": "user@example.com",
    "firstName": "Alice",
    "lastName": "Smith",
}


@pytest.fixture(scope="module")
def signing_keys():
    """Generate a test signing certificate and private key."""
    cert_pem, key_pem = generate_sp_certificate("test-tenant")
    return cert_pem, key_pem


def _decode_response(b64_response: str) -> etree._Element:
    """Decode a base64 SAML Response to an lxml Element."""
    xml_bytes = base64.b64decode(b64_response)
    return etree.fromstring(xml_bytes)


# ============================================================================
# build_saml_response - Integration Tests
# ============================================================================


class TestBuildSamlResponse:
    def test_returns_valid_base64(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id="_req123",
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        # Should be valid base64
        xml_bytes = base64.b64decode(result)
        assert xml_bytes.startswith(b"<?xml")

    def test_response_structure(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id="_req123",
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)

        # Check outer Response element
        assert root.tag == f"{{{_SAMLP_NS}}}Response"
        assert root.get("Destination") == _SP_ACS_URL
        assert root.get("InResponseTo") == "_req123"
        assert root.get("Version") == "2.0"

        # Response Issuer
        issuer = root.find("saml:Issuer", _NS)
        assert issuer is not None
        assert issuer.text == _ISSUER

        # Status
        status_code = root.find("samlp:Status/samlp:StatusCode", _NS)
        assert status_code is not None
        assert "Success" in status_code.get("Value")

    def test_assertion_issuer(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        assertion = root.find("saml:Assertion", _NS)
        assert assertion is not None

        assertion_issuer = assertion.find("saml:Issuer", _NS)
        assert assertion_issuer is not None
        assert assertion_issuer.text == _ISSUER

    def test_name_id(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        name_id = root.find(".//saml:Subject/saml:NameID", _NS)
        assert name_id is not None
        assert name_id.text == _NAME_ID
        assert name_id.get("Format") == _NAME_ID_FORMAT
        assert name_id.get("SPNameQualifier") == _SP_ENTITY_ID

    def test_audience_restriction(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        audience = root.find(".//saml:Conditions/saml:AudienceRestriction/saml:Audience", _NS)
        assert audience is not None
        assert audience.text == _SP_ENTITY_ID

    def test_authn_statement_exists(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        authn_stmt = root.find(".//saml:AuthnStatement", _NS)
        assert authn_stmt is not None
        assert authn_stmt.get("AuthnInstant") is not None
        assert authn_stmt.get("SessionNotOnOrAfter") is not None

    def test_attribute_values(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        attrs = root.findall(".//saml:AttributeStatement/saml:Attribute", _NS)
        assert len(attrs) == 3

        attr_map = {}
        for attr in attrs:
            friendly = attr.get("FriendlyName")
            name = attr.get("Name")
            value = attr.find("saml:AttributeValue", _NS).text
            attr_map[friendly] = (name, value)

        assert attr_map["email"] == (SAML_ATTRIBUTE_URIS["email"], "user@example.com")
        assert attr_map["firstName"] == (SAML_ATTRIBUTE_URIS["firstName"], "Alice")
        assert attr_map["lastName"] == (SAML_ATTRIBUTE_URIS["lastName"], "Smith")

    def test_in_response_to_present_when_provided(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id="_request_abc",
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)

        # Both Response and SubjectConfirmationData should have InResponseTo
        assert root.get("InResponseTo") == "_request_abc"
        conf_data = root.find(".//saml:SubjectConfirmationData", _NS)
        assert conf_data.get("InResponseTo") == "_request_abc"

    def test_in_response_to_absent_when_none(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)

        assert root.get("InResponseTo") is None
        conf_data = root.find(".//saml:SubjectConfirmationData", _NS)
        assert conf_data.get("InResponseTo") is None

    def test_not_on_or_after_is_in_future(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        conditions = root.find(".//saml:Conditions", _NS)
        not_on_or_after = conditions.get("NotOnOrAfter")
        expiry = datetime.datetime.strptime(not_on_or_after, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.UTC
        )
        assert expiry > datetime.datetime.now(datetime.UTC)

    def test_issue_instant_is_utc(self, signing_keys):
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        issue_instant = root.get("IssueInstant")
        assert issue_instant.endswith("Z")

        # Should parse as a valid datetime
        dt = datetime.datetime.strptime(issue_instant, "%Y-%m-%dT%H:%M:%SZ").replace(  # noqa: DTZ007
            tzinfo=datetime.UTC
        )
        assert dt is not None


# ============================================================================
# Signature Verification (Round-trip: sign then verify)
# ============================================================================


class TestSignatureVerification:
    def test_signature_is_valid(self, signing_keys):
        """Verify the Assertion signature round-trips correctly."""
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        assertion = root.find("saml:Assertion", _NS)
        assert assertion is not None

        # Find the Signature node
        signature = assertion.find("ds:Signature", _NS)
        assert signature is not None

        # Register IDs for verification
        xmlsec.tree.add_ids(assertion, ["ID"])

        # Verify signature
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_memory(cert_pem.encode(), xmlsec.KeyFormat.CERT_PEM)
        ctx.key = key
        # This should not raise
        ctx.verify(signature)

    def test_uses_rsa_sha256(self, signing_keys):
        """Verify that RSA-SHA256 is used for signing."""
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        sig_method = root.find(".//ds:Signature/ds:SignedInfo/ds:SignatureMethod", _NS)
        assert sig_method is not None
        assert "rsa-sha256" in sig_method.get("Algorithm")

    def test_uses_enveloped_transform(self, signing_keys):
        """Verify enveloped signature transform is used."""
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        transforms = root.findall(
            ".//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform",
            _NS,
        )
        algorithms = [t.get("Algorithm") for t in transforms]
        assert any("enveloped" in a for a in algorithms)

    def test_uses_exclusive_c14n(self, signing_keys):
        """Verify Exclusive C14N canonicalization is used."""
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)

        # Check C14N method in SignedInfo
        c14n_method = root.find(".//ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod", _NS)
        assert c14n_method is not None
        assert "exc-c14n" in c14n_method.get("Algorithm")

    def test_x509_certificate_included(self, signing_keys):
        """Verify the signing certificate is included in the Signature."""
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        x509_cert = root.find(".//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate", _NS)
        assert x509_cert is not None
        assert x509_cert.text is not None
        assert len(x509_cert.text.strip()) > 0

    def test_signature_position_after_issuer(self, signing_keys):
        """Signature should be the second child of Assertion (after Issuer)."""
        cert_pem, key_pem = signing_keys
        result = build_saml_response(
            issuer_entity_id=_ISSUER,
            sp_entity_id=_SP_ENTITY_ID,
            sp_acs_url=_SP_ACS_URL,
            name_id=_NAME_ID,
            name_id_format=_NAME_ID_FORMAT,
            authn_request_id=None,
            user_attributes=_USER_ATTRS,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
        )
        root = _decode_response(result)
        assertion = root.find("saml:Assertion", _NS)
        children = list(assertion)

        # First child: Issuer, Second child: Signature
        assert children[0].tag == f"{{{_SAML_NS}}}Issuer"
        assert children[1].tag == f"{{{_DS_NS}}}Signature"
        assert children[2].tag == f"{{{_SAML_NS}}}Subject"
