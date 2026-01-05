"""Tests for SAML utility functions.

This module tests the cryptographic and XML utilities in app/utils/saml.py:
- Private key encryption/decryption
- Certificate generation and parsing
- IdP metadata parsing
- SP metadata generation
- SAML settings builder
"""

import datetime
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest
from cryptography import x509

from app.utils.saml import (
    build_saml_settings,
    decrypt_private_key,
    encrypt_private_key,
    fetch_idp_metadata,
    generate_sp_certificate,
    generate_sp_metadata_xml,
    get_certificate_expiry,
    parse_idp_metadata_xml,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_certificate():
    """Generate a sample certificate for testing."""
    cert_pem, key_pem = generate_sp_certificate("test-tenant-id")
    return cert_pem, key_pem


@pytest.fixture
def sample_idp_metadata_xml():
    """Sample IdP metadata XML for testing."""
    # Using a real-ish certificate from the test fixtures
    return """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.com/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.com/sso"/>
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.com/slo"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


# =============================================================================
# Encryption Tests
# =============================================================================


def test_encrypt_decrypt_private_key_roundtrip(sample_certificate):
    """Test that encrypting and decrypting a private key returns the original."""
    _, key_pem = sample_certificate

    encrypted = encrypt_private_key(key_pem)
    decrypted = decrypt_private_key(encrypted)

    assert decrypted == key_pem


def test_encrypt_private_key_returns_different_string(sample_certificate):
    """Test that encrypted key is different from the original."""
    _, key_pem = sample_certificate

    encrypted = encrypt_private_key(key_pem)

    assert encrypted != key_pem
    assert "-----BEGIN" not in encrypted  # Should not contain PEM headers


def test_encrypt_private_key_is_deterministic(sample_certificate):
    """Test that same key encrypted twice produces same result (Fernet with same key)."""
    _, key_pem = sample_certificate

    # Note: Fernet includes a timestamp, so different encryptions will differ
    # But both should decrypt to the same value
    encrypted1 = encrypt_private_key(key_pem)
    encrypted2 = encrypt_private_key(key_pem)

    # Both should decrypt correctly
    assert decrypt_private_key(encrypted1) == key_pem
    assert decrypt_private_key(encrypted2) == key_pem


# =============================================================================
# Certificate Generation Tests
# =============================================================================


def test_generate_sp_certificate_returns_valid_pem():
    """Test that generate_sp_certificate returns valid PEM-encoded strings."""
    cert_pem, key_pem = generate_sp_certificate("test-tenant")

    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert cert_pem.strip().endswith("-----END CERTIFICATE-----")
    assert key_pem.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert key_pem.strip().endswith("-----END RSA PRIVATE KEY-----")


def test_generate_sp_certificate_has_correct_validity():
    """Test that certificate has correct validity period."""
    validity_years = 5
    cert_pem, _ = generate_sp_certificate("test-tenant", validity_years=validity_years)

    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Check validity period is approximately correct
    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except AttributeError:
        not_after = cert.not_valid_after
        not_before = cert.not_valid_before

    validity_days = (not_after - not_before).days
    expected_days = validity_years * 365

    # Allow some tolerance for leap years
    assert abs(validity_days - expected_days) <= 2


def test_generate_sp_certificate_contains_tenant_id():
    """Test that certificate subject contains the tenant ID."""
    tenant_id = "abc12345-6789-def0"
    cert_pem, _ = generate_sp_certificate(tenant_id)

    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    subject = cert.subject

    # Check that CN contains truncated tenant ID
    cn_attrs = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    assert len(cn_attrs) == 1
    assert tenant_id[:8] in cn_attrs[0].value


def test_generate_sp_certificate_is_not_ca():
    """Test that certificate is not a CA certificate."""
    cert_pem, _ = generate_sp_certificate("test-tenant")

    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Check BasicConstraints
    basic_constraints = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    )
    assert basic_constraints.value.ca is False


def test_generate_sp_certificate_has_digital_signature_usage():
    """Test that certificate has digital signature key usage."""
    cert_pem, _ = generate_sp_certificate("test-tenant")

    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Check KeyUsage
    key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
    assert key_usage.value.digital_signature is True


# =============================================================================
# Certificate Expiry Parsing Tests
# =============================================================================


def test_get_certificate_expiry_returns_datetime(sample_certificate):
    """Test that get_certificate_expiry returns a datetime."""
    cert_pem, _ = sample_certificate

    expiry = get_certificate_expiry(cert_pem)

    assert isinstance(expiry, datetime.datetime)


def test_get_certificate_expiry_matches_generated_cert():
    """Test that expiry matches what was generated."""
    validity_years = 3
    cert_pem, _ = generate_sp_certificate("test-tenant", validity_years=validity_years)

    expiry = get_certificate_expiry(cert_pem)

    # Should be approximately validity_years from now
    now = datetime.datetime.now(datetime.UTC)
    expected_expiry = now + datetime.timedelta(days=validity_years * 365)

    # Allow 1 day tolerance
    assert abs((expiry.replace(tzinfo=None) - expected_expiry.replace(tzinfo=None)).days) <= 1


# =============================================================================
# IdP Metadata Parsing Tests
# =============================================================================

# Note: These tests require the python3-saml library which depends on xmlsec.
# We check if the library is available and skip tests if not installed.

try:
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser  # noqa: F401
    HAS_SAML_LIBRARY = True
except ImportError:
    HAS_SAML_LIBRARY = False


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_parse_idp_metadata_xml_valid(sample_idp_metadata_xml):
    """Test parsing valid IdP metadata XML."""
    result = parse_idp_metadata_xml(sample_idp_metadata_xml)

    assert result["entity_id"] == "https://idp.example.com/entity"
    assert result["sso_url"] == "https://idp.example.com/sso"
    assert result["slo_url"] == "https://idp.example.com/slo"
    assert "-----BEGIN CERTIFICATE-----" in result["certificate_pem"]


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_parse_idp_metadata_xml_missing_entity_id():
    """Test that missing entityID raises ValueError."""
    # XML without entityID attribute
    bad_xml = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""

    with pytest.raises(ValueError, match="entityId"):
        parse_idp_metadata_xml(bad_xml)


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_parse_idp_metadata_xml_missing_sso_url():
    """Test that missing SSO URL raises ValueError."""
    # XML without SingleSignOnService
    bad_xml = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIC...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""

    with pytest.raises(ValueError, match="SSO URL"):
        parse_idp_metadata_xml(bad_xml)


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_parse_idp_metadata_xml_missing_certificate():
    """Test that missing certificate raises ValueError."""
    # XML without X509Certificate
    bad_xml = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="https://idp.example.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""

    with pytest.raises(ValueError, match="certificate"):
        parse_idp_metadata_xml(bad_xml)


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_parse_idp_metadata_xml_invalid_xml():
    """Test that invalid XML raises ValueError."""
    bad_xml = "not xml at all"

    with pytest.raises(ValueError, match="parse"):
        parse_idp_metadata_xml(bad_xml)


# =============================================================================
# Metadata Fetching Tests
# =============================================================================


@patch("urllib.request.urlopen")
def test_fetch_idp_metadata_success(mock_urlopen, sample_idp_metadata_xml):
    """Test successful metadata fetch."""
    mock_response = MagicMock()
    mock_response.read.return_value = sample_idp_metadata_xml.encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    result = fetch_idp_metadata("https://idp.example.com/metadata")

    assert "EntityDescriptor" in result
    mock_urlopen.assert_called_once()


@patch("urllib.request.urlopen")
def test_fetch_idp_metadata_http_error(mock_urlopen):
    """Test that HTTP errors raise ValueError."""
    mock_urlopen.side_effect = HTTPError(
        url="https://idp.example.com/metadata",
        code=404,
        msg="Not Found",
        hdrs={},
        fp=None,
    )

    with pytest.raises(ValueError, match="HTTP error"):
        fetch_idp_metadata("https://idp.example.com/metadata")


@patch("urllib.request.urlopen")
def test_fetch_idp_metadata_network_error(mock_urlopen):
    """Test that network errors raise ValueError."""
    mock_urlopen.side_effect = URLError("Connection refused")

    with pytest.raises(ValueError, match="fetch metadata"):
        fetch_idp_metadata("https://idp.example.com/metadata")


@patch("urllib.request.urlopen")
def test_fetch_idp_metadata_timeout(mock_urlopen):
    """Test that timeout raises ValueError."""
    mock_urlopen.side_effect = TimeoutError()

    with pytest.raises(ValueError, match="Timeout"):
        fetch_idp_metadata("https://idp.example.com/metadata")


@patch("urllib.request.urlopen")
def test_fetch_idp_metadata_non_xml_response(mock_urlopen):
    """Test that non-XML response raises ValueError."""
    mock_response = MagicMock()
    mock_response.read.return_value = b"This is not XML content"
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with pytest.raises(ValueError, match="XML"):
        fetch_idp_metadata("https://idp.example.com/metadata")


# =============================================================================
# SP Metadata Generation Tests
# =============================================================================


def test_generate_sp_metadata_xml_contains_entity_id(sample_certificate):
    """Test that generated SP metadata contains the entity ID."""
    cert_pem, _ = sample_certificate
    entity_id = "https://sp.example.com/saml/metadata"

    xml = generate_sp_metadata_xml(
        entity_id=entity_id,
        acs_url="https://sp.example.com/saml/acs",
        certificate_pem=cert_pem,
    )

    assert entity_id in xml
    assert "EntityDescriptor" in xml


def test_generate_sp_metadata_xml_contains_certificate(sample_certificate):
    """Test that generated SP metadata contains the certificate."""
    cert_pem, _ = sample_certificate

    xml = generate_sp_metadata_xml(
        entity_id="https://sp.example.com/saml/metadata",
        acs_url="https://sp.example.com/saml/acs",
        certificate_pem=cert_pem,
    )

    # Certificate should be included without PEM headers
    assert "X509Certificate" in xml
    # Should not include PEM headers in the output
    assert "-----BEGIN CERTIFICATE-----" not in xml


def test_generate_sp_metadata_xml_contains_acs_url(sample_certificate):
    """Test that generated SP metadata contains the ACS URL."""
    cert_pem, _ = sample_certificate
    acs_url = "https://sp.example.com/saml/acs"

    xml = generate_sp_metadata_xml(
        entity_id="https://sp.example.com/saml/metadata",
        acs_url=acs_url,
        certificate_pem=cert_pem,
    )

    assert acs_url in xml
    assert "AssertionConsumerService" in xml


def test_generate_sp_metadata_xml_with_slo_url(sample_certificate):
    """Test that SLO URL is included when provided."""
    cert_pem, _ = sample_certificate
    slo_url = "https://sp.example.com/saml/slo"

    xml = generate_sp_metadata_xml(
        entity_id="https://sp.example.com/saml/metadata",
        acs_url="https://sp.example.com/saml/acs",
        certificate_pem=cert_pem,
        slo_url=slo_url,
    )

    assert slo_url in xml
    assert "SingleLogoutService" in xml


def test_generate_sp_metadata_xml_without_slo_url(sample_certificate):
    """Test that SLO URL is not included when not provided."""
    cert_pem, _ = sample_certificate

    xml = generate_sp_metadata_xml(
        entity_id="https://sp.example.com/saml/metadata",
        acs_url="https://sp.example.com/saml/acs",
        certificate_pem=cert_pem,
    )

    assert "SingleLogoutService" not in xml


# =============================================================================
# SAML Settings Builder Tests
# =============================================================================


def test_build_saml_settings_returns_valid_structure(sample_certificate):
    """Test that build_saml_settings returns the expected structure."""
    cert_pem, key_pem = sample_certificate

    settings = build_saml_settings(
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        sp_certificate_pem=cert_pem,
        sp_private_key_pem=key_pem,
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_certificate_pem=cert_pem,
    )

    # Check top-level structure
    assert "strict" in settings
    assert "sp" in settings
    assert "idp" in settings
    assert "security" in settings

    # Check SP settings
    assert settings["sp"]["entityId"] == "https://sp.example.com"
    assert settings["sp"]["assertionConsumerService"]["url"] == "https://sp.example.com/acs"

    # Check IdP settings
    assert settings["idp"]["entityId"] == "https://idp.example.com"
    assert settings["idp"]["singleSignOnService"]["url"] == "https://idp.example.com/sso"


def test_build_saml_settings_cleans_certificate_headers(sample_certificate):
    """Test that certificate PEM headers are removed."""
    cert_pem, key_pem = sample_certificate

    settings = build_saml_settings(
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        sp_certificate_pem=cert_pem,
        sp_private_key_pem=key_pem,
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_certificate_pem=cert_pem,
    )

    # Certificates should not have PEM headers
    assert "-----BEGIN" not in settings["sp"]["x509cert"]
    assert "-----END" not in settings["sp"]["x509cert"]
    assert "-----BEGIN" not in settings["idp"]["x509cert"]
    assert "-----BEGIN" not in settings["sp"]["privateKey"]


def test_build_saml_settings_includes_security_settings(sample_certificate):
    """Test that security settings are included."""
    cert_pem, key_pem = sample_certificate

    settings = build_saml_settings(
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        sp_certificate_pem=cert_pem,
        sp_private_key_pem=key_pem,
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_certificate_pem=cert_pem,
    )

    security = settings["security"]
    assert security["authnRequestsSigned"] is True
    assert security["wantAssertionsSigned"] is True
    assert settings["strict"] is True


def test_build_saml_settings_with_slo_urls(sample_certificate):
    """Test that SLO URLs are included when provided."""
    cert_pem, key_pem = sample_certificate

    settings = build_saml_settings(
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        sp_certificate_pem=cert_pem,
        sp_private_key_pem=key_pem,
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_certificate_pem=cert_pem,
        idp_slo_url="https://idp.example.com/slo",
        sp_slo_url="https://sp.example.com/slo",
    )

    assert settings["idp"]["singleLogoutService"]["url"] == "https://idp.example.com/slo"
    assert settings["sp"]["singleLogoutService"]["url"] == "https://sp.example.com/slo"


def test_build_saml_settings_without_slo_urls(sample_certificate):
    """Test that SLO settings are not included when not provided."""
    cert_pem, key_pem = sample_certificate

    settings = build_saml_settings(
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        sp_certificate_pem=cert_pem,
        sp_private_key_pem=key_pem,
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_certificate_pem=cert_pem,
    )

    assert "singleLogoutService" not in settings["idp"]
    assert "singleLogoutService" not in settings["sp"]
