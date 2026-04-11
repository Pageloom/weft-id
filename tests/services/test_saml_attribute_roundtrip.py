"""Integration test: SAML attribute mapping round-trip.

Exercises the real IdP assertion builder and SP attribute extractor
end-to-end. The IdP side writes attributes with configurable URIs,
signs the assertion, and the SP side parses it with python3-saml
(real signature validation) and extracts attributes via the mapping.

No database, no mocking, no browser. Catches regressions in either
the attribute builder or the extractor.
"""

from datetime import UTC, datetime

import pytest
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from app.schemas.saml import DEFAULT_ATTRIBUTE_MAPPING, PROVIDER_ATTRIBUTE_PRESETS, IdPConfig
from app.services.saml.auth import _extract_mapped_attributes
from app.utils.saml import build_saml_settings, generate_sp_certificate
from app.utils.saml_assertion import build_saml_response

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IDP_ENTITY_ID = "https://idp.example.com/saml/metadata"
_SP_ENTITY_ID = "https://sp.example.com/saml/metadata"
_SP_ACS_URL = "https://sp.example.com/saml/acs"
_NAME_ID = "jane.doe@example.com"
_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

# SP-side key → IdP-side key (translates first_name → firstName, etc.)
_SP_TO_IDP_KEY = {
    "first_name": "firstName",
    "last_name": "lastName",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def signing_keys() -> tuple[str, str]:
    """Generate a self-signed cert/key pair for both signing and validation."""
    cert_pem, key_pem = generate_sp_certificate(tenant_id="test-roundtrip")
    return cert_pem, key_pem


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _build_and_parse_roundtrip(
    cert_pem: str,
    key_pem: str,
    user_attributes: dict[str, str | list[str]],
    sp_attribute_mapping: dict[str, str],
) -> dict:
    """Build a signed SAML response and parse it back.

    Translates the SP-side attribute mapping to IdP-side keys, builds a signed
    assertion, feeds it to python3-saml for real signature validation, and
    extracts attributes using the production _extract_mapped_attributes function.

    Returns the extracted attributes dict.
    """
    # Translate SP-side mapping to IdP-side mapping
    idp_attribute_mapping: dict[str, str] = {}
    for sp_key, uri in sp_attribute_mapping.items():
        idp_key = _SP_TO_IDP_KEY.get(sp_key, sp_key)
        idp_attribute_mapping[idp_key] = uri

    # --- IdP side: build signed assertion ---
    base64_response, _session_index = build_saml_response(
        issuer_entity_id=_IDP_ENTITY_ID,
        sp_entity_id=_SP_ENTITY_ID,
        sp_acs_url=_SP_ACS_URL,
        name_id=_NAME_ID,
        name_id_format=_NAME_ID_FORMAT,
        authn_request_id=None,  # IdP-initiated, skip InResponseTo check
        user_attributes=user_attributes,
        certificate_pem=cert_pem,
        private_key_pem=key_pem,
        attribute_mapping=idp_attribute_mapping,
    )

    # --- SP side: parse and validate ---
    settings = build_saml_settings(
        sp_entity_id=_SP_ENTITY_ID,
        sp_acs_url=_SP_ACS_URL,
        sp_certificate_pem=cert_pem,
        sp_private_key_pem=key_pem,
        idp_entity_id=_IDP_ENTITY_ID,
        idp_sso_url="https://idp.example.com/saml/sso",
        idp_certificate_pem=cert_pem,  # same cert validates the signature
    )

    request_data = {
        "https": "on",
        "http_host": "sp.example.com",
        "script_name": "/saml/acs",
        "get_data": {},
        "post_data": {"SAMLResponse": base64_response},
    }

    auth = OneLogin_Saml2_Auth(request_data, settings)
    auth.process_response()  # no request_id → skip InResponseTo check

    errors = auth.get_errors()
    assert not errors, f"python3-saml validation failed: {errors} — {auth.get_last_error_reason()}"
    assert auth.is_authenticated()

    # Build IdPConfig with the SP-side mapping
    now = datetime.now(UTC)
    idp_config = IdPConfig(
        id="test-idp",
        name="Test IdP",
        provider_type="generic",
        entity_id=_IDP_ENTITY_ID,
        sso_url="https://idp.example.com/saml/sso",
        slo_url=None,
        certificate_pem=cert_pem,
        metadata_url=None,
        metadata_xml=None,
        metadata_last_fetched_at=None,
        metadata_fetch_error=None,
        sp_entity_id=_SP_ENTITY_ID,
        sp_acs_url=_SP_ACS_URL,
        attribute_mapping=sp_attribute_mapping,
        is_enabled=True,
        is_default=False,
        require_platform_mfa=False,
        jit_provisioning=False,
        trust_established=True,
        created_at=now,
        updated_at=now,
    )

    return _extract_mapped_attributes(auth, idp_config)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSAMLAttributeRoundTrip:
    """Integration tests for SAML attribute mapping round-trip."""

    def test_default_mapping_roundtrip(self, signing_keys):
        """Default URIs (email, firstName, lastName) work end-to-end."""
        cert_pem, key_pem = signing_keys

        attrs = _build_and_parse_roundtrip(
            cert_pem=cert_pem,
            key_pem=key_pem,
            user_attributes={
                "email": "jane@example.com",
                "firstName": "Jane",
                "lastName": "Doe",
            },
            sp_attribute_mapping=DEFAULT_ATTRIBUTE_MAPPING,
        )

        assert attrs["email"] == "jane@example.com"
        assert attrs["first_name"] == "Jane"
        assert attrs["last_name"] == "Doe"
        assert attrs["name_id"] == _NAME_ID
        assert attrs["missing_optional_attributes"] == ["groups"]

    def test_full_custom_mapping_azure_ad_style(self, signing_keys):
        """Azure AD long URIs round-trip correctly."""
        cert_pem, key_pem = signing_keys

        attrs = _build_and_parse_roundtrip(
            cert_pem=cert_pem,
            key_pem=key_pem,
            user_attributes={
                "email": "jane@contoso.com",
                "firstName": "Jane",
                "lastName": "Doe",
            },
            sp_attribute_mapping=PROVIDER_ATTRIBUTE_PRESETS["azure_ad"],
        )

        assert attrs["email"] == "jane@contoso.com"
        assert attrs["first_name"] == "Jane"
        assert attrs["last_name"] == "Doe"

    def test_partial_custom_mapping(self, signing_keys):
        """Mix of custom and default URIs works."""
        cert_pem, key_pem = signing_keys

        partial_mapping = {
            "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "first_name": "firstName",  # default
            "last_name": "lastName",  # default
            "groups": "groups",
        }

        attrs = _build_and_parse_roundtrip(
            cert_pem=cert_pem,
            key_pem=key_pem,
            user_attributes={
                "email": "jane@example.com",
                "firstName": "Jane",
                "lastName": "Doe",
            },
            sp_attribute_mapping=partial_mapping,
        )

        assert attrs["email"] == "jane@example.com"
        assert attrs["first_name"] == "Jane"
        assert attrs["last_name"] == "Doe"

    def test_custom_mapping_with_groups(self, signing_keys):
        """Multi-valued group claims with custom URI."""
        cert_pem, key_pem = signing_keys

        attrs = _build_and_parse_roundtrip(
            cert_pem=cert_pem,
            key_pem=key_pem,
            user_attributes={
                "email": "jane@contoso.com",
                "firstName": "Jane",
                "lastName": "Doe",
                "groups": ["Engineering", "Platform Team", "Admins"],
            },
            sp_attribute_mapping=PROVIDER_ATTRIBUTE_PRESETS["azure_ad"],
        )

        assert attrs["email"] == "jane@contoso.com"
        assert attrs["groups"] == ["Engineering", "Platform Team", "Admins"]

    def test_default_mapping_with_groups(self, signing_keys):
        """Multi-valued group claims with default URI."""
        cert_pem, key_pem = signing_keys

        attrs = _build_and_parse_roundtrip(
            cert_pem=cert_pem,
            key_pem=key_pem,
            user_attributes={
                "email": "jane@example.com",
                "firstName": "Jane",
                "lastName": "Doe",
                "groups": ["Developers", "QA"],
            },
            sp_attribute_mapping=DEFAULT_ATTRIBUTE_MAPPING,
        )

        assert attrs["email"] == "jane@example.com"
        assert attrs["first_name"] == "Jane"
        assert attrs["last_name"] == "Doe"
        assert attrs["groups"] == ["Developers", "QA"]
        assert attrs["missing_optional_attributes"] == []

    def test_missing_optional_attributes_tracked(self, signing_keys):
        """Missing optional attributes are reported but don't cause failure."""
        cert_pem, key_pem = signing_keys

        attrs = _build_and_parse_roundtrip(
            cert_pem=cert_pem,
            key_pem=key_pem,
            user_attributes={
                "email": "jane@example.com",
            },
            sp_attribute_mapping=DEFAULT_ATTRIBUTE_MAPPING,
        )

        assert attrs["email"] == "jane@example.com"
        assert attrs["first_name"] is None
        assert attrs["last_name"] is None
        assert attrs["groups"] == []
        assert sorted(attrs["missing_optional_attributes"]) == [
            "first_name",
            "groups",
            "last_name",
        ]

    def test_partial_optional_attributes_tracked(self, signing_keys):
        """Only actually missing optional attributes are reported."""
        cert_pem, key_pem = signing_keys

        attrs = _build_and_parse_roundtrip(
            cert_pem=cert_pem,
            key_pem=key_pem,
            user_attributes={
                "email": "jane@example.com",
                "firstName": "Jane",
            },
            sp_attribute_mapping=DEFAULT_ATTRIBUTE_MAPPING,
        )

        assert attrs["email"] == "jane@example.com"
        assert attrs["first_name"] == "Jane"
        assert attrs["missing_optional_attributes"] == ["last_name", "groups"]
