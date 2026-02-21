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


@patch("app.utils.url_safety.urllib.request.urlopen")
@patch("app.utils.url_safety.socket.getaddrinfo")
@patch("app.utils.url_safety.settings")
def test_fetch_idp_metadata_success(
    mock_settings, mock_getaddrinfo, mock_urlopen, sample_idp_metadata_xml
):
    """Test successful metadata fetch."""
    mock_settings.IS_DEV = False
    mock_settings.BASE_DOMAIN = ""
    mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

    mock_response = MagicMock()
    mock_response.headers = {}
    mock_response.read.return_value = sample_idp_metadata_xml.encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    result = fetch_idp_metadata("https://idp.example.com/metadata")

    assert "EntityDescriptor" in result
    mock_urlopen.assert_called_once()


@pytest.mark.parametrize(
    "exception,match",
    [
        (
            HTTPError(
                url="https://idp.example.com/metadata", code=404, msg="Not Found", hdrs={}, fp=None
            ),
            "HTTP error",
        ),
        (URLError("Connection refused"), "fetch metadata"),
        (TimeoutError(), "Timeout"),
    ],
    ids=["http_error", "network_error", "timeout"],
)
@patch("app.utils.url_safety.urllib.request.urlopen")
@patch("app.utils.url_safety.socket.getaddrinfo")
@patch("app.utils.url_safety.settings")
def test_fetch_idp_metadata_error(mock_settings, mock_getaddrinfo, mock_urlopen, exception, match):
    """Test that fetch errors raise ValueError."""
    mock_settings.IS_DEV = False
    mock_settings.BASE_DOMAIN = ""
    mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
    mock_urlopen.side_effect = exception

    with pytest.raises(ValueError, match=match):
        fetch_idp_metadata("https://idp.example.com/metadata")


@patch("app.utils.url_safety.urllib.request.urlopen")
@patch("app.utils.url_safety.socket.getaddrinfo")
@patch("app.utils.url_safety.settings")
def test_fetch_idp_metadata_non_xml_response(mock_settings, mock_getaddrinfo, mock_urlopen):
    """Test that non-XML response raises ValueError."""
    mock_settings.IS_DEV = False
    mock_settings.BASE_DOMAIN = ""
    mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

    mock_response = MagicMock()
    mock_response.headers = {}
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


def test_generate_sp_metadata_xml_custom_attribute_mapping(sample_certificate):
    """Custom attribute mapping overrides default RequestedAttribute elements."""
    from defusedxml import ElementTree as DefusedET

    cert_pem, _ = sample_certificate
    custom_mapping = {
        "urn:oid:0.9.2342.19200300.100.1.3": "email",
        "urn:oid:2.5.4.42": "firstName",
    }

    xml = generate_sp_metadata_xml(
        entity_id="https://sp.example.com/saml/metadata",
        acs_url="https://sp.example.com/saml/acs",
        certificate_pem=cert_pem,
        attribute_mapping=custom_mapping,
    )

    root = DefusedET.fromstring(xml)
    md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
    sp_desc = root.find(f"{{{md_ns}}}SPSSODescriptor")
    acs_elem = sp_desc.find(f"{{{md_ns}}}AttributeConsumingService")
    req_attrs = acs_elem.findall(f"{{{md_ns}}}RequestedAttribute")

    assert len(req_attrs) == 2
    attr_map = {a.attrib["Name"]: a.attrib["FriendlyName"] for a in req_attrs}
    assert attr_map == custom_mapping

    # email field should be required
    for a in req_attrs:
        if a.attrib["FriendlyName"] == "email":
            assert a.attrib["isRequired"] == "true"
        else:
            assert a.attrib["isRequired"] == "false"


def test_generate_sp_metadata_xml_default_attributes(sample_certificate):
    """No mapping uses default SAML_ATTRIBUTE_URIS for RequestedAttribute."""
    from defusedxml import ElementTree as DefusedET

    from app.utils.saml_assertion import SAML_ATTRIBUTE_URIS

    cert_pem, _ = sample_certificate

    xml = generate_sp_metadata_xml(
        entity_id="https://sp.example.com/saml/metadata",
        acs_url="https://sp.example.com/saml/acs",
        certificate_pem=cert_pem,
    )

    root = DefusedET.fromstring(xml)
    md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
    sp_desc = root.find(f"{{{md_ns}}}SPSSODescriptor")
    acs_elem = sp_desc.find(f"{{{md_ns}}}AttributeConsumingService")
    req_attrs = acs_elem.findall(f"{{{md_ns}}}RequestedAttribute")

    assert len(req_attrs) == len(SAML_ATTRIBUTE_URIS)
    names = {a.attrib["Name"] for a in req_attrs}
    for uri in SAML_ATTRIBUTE_URIS.values():
        assert uri in names


def test_generate_sp_metadata_xml_escapes_xml_injection_in_mapping_name(
    sample_certificate,
):
    """Attribute mapping keys with XML special chars are escaped."""
    from defusedxml import ElementTree as DefusedET

    cert_pem, _ = sample_certificate
    malicious_mapping = {
        'foo"/><Evil xmlns="http://evil': "email",
    }

    xml = generate_sp_metadata_xml(
        entity_id="https://sp.example.com/saml/metadata",
        acs_url="https://sp.example.com/saml/acs",
        certificate_pem=cert_pem,
        attribute_mapping=malicious_mapping,
    )

    # Must still be valid XML
    root = DefusedET.fromstring(xml)

    # Injected element must NOT exist
    evil = root.findall(".//{http://evil}*")
    assert len(evil) == 0, "XML injection succeeded: injected element found"

    # Value should round-trip correctly
    md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
    sp_desc = root.find(f"{{{md_ns}}}SPSSODescriptor")
    acs_elem = sp_desc.find(f"{{{md_ns}}}AttributeConsumingService")
    req_attrs = acs_elem.findall(f"{{{md_ns}}}RequestedAttribute")
    assert len(req_attrs) == 1
    assert req_attrs[0].attrib["Name"] == 'foo"/><Evil xmlns="http://evil'


def test_generate_sp_metadata_xml_escapes_xml_injection_in_mapping_value(
    sample_certificate,
):
    """Attribute mapping values with XML special chars are escaped."""
    from defusedxml import ElementTree as DefusedET

    cert_pem, _ = sample_certificate
    malicious_mapping = {
        "urn:oid:1.2.3": '<script>alert("xss")</script>',
    }

    xml = generate_sp_metadata_xml(
        entity_id="https://sp.example.com/saml/metadata",
        acs_url="https://sp.example.com/saml/acs",
        certificate_pem=cert_pem,
        attribute_mapping=malicious_mapping,
    )

    root = DefusedET.fromstring(xml)
    assert "<script>" not in xml

    md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
    sp_desc = root.find(f"{{{md_ns}}}SPSSODescriptor")
    acs_elem = sp_desc.find(f"{{{md_ns}}}AttributeConsumingService")
    req_attrs = acs_elem.findall(f"{{{md_ns}}}RequestedAttribute")
    assert len(req_attrs) == 1
    assert req_attrs[0].attrib["FriendlyName"] == '<script>alert("xss")</script>'


def test_generate_sp_metadata_xml_escapes_entity_id_and_urls(sample_certificate):
    """Entity ID and URLs with ampersands are properly escaped."""
    from defusedxml import ElementTree as DefusedET

    cert_pem, _ = sample_certificate

    xml = generate_sp_metadata_xml(
        entity_id='https://sp.example.com/saml?a=1&b=2"',
        acs_url="https://sp.example.com/saml/acs?x=1&y=2",
        certificate_pem=cert_pem,
        slo_url="https://sp.example.com/saml/slo?p=1&q=2",
    )

    root = DefusedET.fromstring(xml)
    assert root.attrib["entityID"] == 'https://sp.example.com/saml?a=1&b=2"'

    md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
    sp_desc = root.find(f"{{{md_ns}}}SPSSODescriptor")
    acs_elem = sp_desc.find(f"{{{md_ns}}}AssertionConsumerService")
    assert acs_elem.attrib["Location"] == "https://sp.example.com/saml/acs?x=1&y=2"

    slo_elem = sp_desc.find(f"{{{md_ns}}}SingleLogoutService")
    assert slo_elem.attrib["Location"] == "https://sp.example.com/saml/slo?p=1&q=2"


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


# =============================================================================
# Extract Issuer from Response Tests
# =============================================================================


def test_extract_issuer_from_response_valid():
    """Test extracting issuer from valid SAML response."""
    import base64

    from app.utils.saml import extract_issuer_from_response

    # Create a sample SAML response with issuer in Response element
    saml_response = """<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>"""

    encoded = base64.b64encode(saml_response.encode("utf-8")).decode("utf-8")
    result = extract_issuer_from_response(encoded)

    assert result == "https://idp.example.com"


def test_extract_issuer_from_response_in_assertion():
    """Test extracting issuer from SAML assertion element."""
    import base64

    from app.utils.saml import extract_issuer_from_response

    # SAML response with issuer only in Assertion
    saml_response = """<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Issuer>https://assertion-issuer.example.com</saml:Issuer>
  </saml:Assertion>
</samlp:Response>"""

    encoded = base64.b64encode(saml_response.encode("utf-8")).decode("utf-8")
    result = extract_issuer_from_response(encoded)

    assert result == "https://assertion-issuer.example.com"


def test_extract_issuer_from_response_without_namespace():
    """Test extracting issuer when no namespace prefix is used."""
    import base64

    from app.utils.saml import extract_issuer_from_response

    # SAML-like response without proper namespace prefixes
    saml_response = """<?xml version="1.0"?>
<Response>
  <Issuer>https://no-namespace.example.com</Issuer>
</Response>"""

    encoded = base64.b64encode(saml_response.encode("utf-8")).decode("utf-8")
    result = extract_issuer_from_response(encoded)

    assert result == "https://no-namespace.example.com"


def test_extract_issuer_from_response_no_issuer():
    """Test extracting issuer when no issuer is present."""
    import base64

    from app.utils.saml import extract_issuer_from_response

    saml_response = """<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>"""

    encoded = base64.b64encode(saml_response.encode("utf-8")).decode("utf-8")
    result = extract_issuer_from_response(encoded)

    assert result is None


def test_extract_issuer_from_response_invalid_base64():
    """Test extracting issuer with invalid base64 input."""
    from app.utils.saml import extract_issuer_from_response

    result = extract_issuer_from_response("not-valid-base64!!!")

    assert result is None


def test_extract_issuer_from_response_invalid_xml():
    """Test extracting issuer with invalid XML."""
    import base64

    from app.utils.saml import extract_issuer_from_response

    invalid_xml = "not valid xml <unclosed"
    encoded = base64.b64encode(invalid_xml.encode("utf-8")).decode("utf-8")
    result = extract_issuer_from_response(encoded)

    assert result is None


def test_extract_issuer_from_response_whitespace_trimmed():
    """Test that issuer text is trimmed of whitespace."""
    import base64

    from app.utils.saml import extract_issuer_from_response

    saml_response = """<?xml version="1.0"?>
<Response>
  <Issuer>  https://whitespace.example.com  </Issuer>
</Response>"""

    encoded = base64.b64encode(saml_response.encode("utf-8")).decode("utf-8")
    result = extract_issuer_from_response(encoded)

    assert result == "https://whitespace.example.com"


# =============================================================================
# Single Logout (SLO) Utility Tests
# =============================================================================


@pytest.fixture
def saml_settings_with_slo(sample_certificate):
    """Build SAML settings with SLO configured for testing."""
    cert_pem, key_pem = sample_certificate

    return build_saml_settings(
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


def test_build_logout_request_basic(saml_settings_with_slo):
    """Test building a basic logout request."""
    from app.utils.saml import build_logout_request

    redirect_url, request_id = build_logout_request(
        settings=saml_settings_with_slo,
        name_id="user@example.com",
    )

    # Should return a redirect URL to the IdP's SLO endpoint
    assert redirect_url.startswith("https://idp.example.com/slo")
    assert "SAMLRequest=" in redirect_url
    assert request_id is not None


def test_build_logout_request_with_session_index(saml_settings_with_slo):
    """Test building logout request with session index."""
    from app.utils.saml import build_logout_request

    redirect_url, request_id = build_logout_request(
        settings=saml_settings_with_slo,
        name_id="user@example.com",
        name_id_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        session_index="session-12345",
    )

    assert redirect_url.startswith("https://idp.example.com/slo")
    assert request_id is not None


def test_build_logout_request_uses_email_format_by_default(saml_settings_with_slo):
    """Test that email NameID format is used by default."""
    from app.utils.saml import build_logout_request

    # The function uses email format by default when name_id_format is None
    redirect_url, _ = build_logout_request(
        settings=saml_settings_with_slo,
        name_id="user@example.com",
        name_id_format=None,
    )

    # Should succeed with default format
    assert redirect_url.startswith("https://idp.example.com/slo")


def test_process_logout_response_success(saml_settings_with_slo):
    """Test processing successful logout response."""
    from app.utils.saml import process_logout_response

    with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth") as mock_auth_cls:
        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth_cls.return_value = mock_auth

        success, error = process_logout_response(
            settings=saml_settings_with_slo,
            get_data={"SAMLResponse": "encoded-response"},
        )

        assert success is True
        assert error is None
        mock_auth.process_slo.assert_called_once()


def test_process_logout_response_with_errors(saml_settings_with_slo):
    """Test processing logout response with errors."""
    from app.utils.saml import process_logout_response

    with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth") as mock_auth_cls:
        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = ["Invalid signature", "Response expired"]
        mock_auth_cls.return_value = mock_auth

        success, error = process_logout_response(
            settings=saml_settings_with_slo,
            get_data={"SAMLResponse": "encoded-response"},
        )

        assert success is False
        assert "Invalid signature" in error
        assert "Response expired" in error


def test_process_logout_response_exception(saml_settings_with_slo):
    """Test processing logout response when exception is raised."""
    from app.utils.saml import process_logout_response

    with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth") as mock_auth_cls:
        mock_auth = MagicMock()
        mock_auth.process_slo.side_effect = Exception("SLO processing failed")
        mock_auth_cls.return_value = mock_auth

        success, error = process_logout_response(
            settings=saml_settings_with_slo,
            get_data={"SAMLResponse": "encoded-response"},
        )

        assert success is False
        assert "SLO processing failed" in error


def test_process_logout_response_with_request_id(saml_settings_with_slo):
    """Test processing logout response with request ID validation."""
    from app.utils.saml import process_logout_response

    with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth") as mock_auth_cls:
        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth_cls.return_value = mock_auth

        success, error = process_logout_response(
            settings=saml_settings_with_slo,
            get_data={"SAMLResponse": "encoded-response"},
            request_id="original-request-id",
        )

        assert success is True
        # Verify request_id was passed to process_slo
        call_kwargs = mock_auth.process_slo.call_args[1]
        assert call_kwargs["request_id"] == "original-request-id"


def test_process_logout_request_success(saml_settings_with_slo):
    """Test processing IdP-initiated logout request."""
    from app.utils.saml import process_logout_request

    with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth") as mock_auth_cls:
        mock_auth = MagicMock()
        mock_auth.get_nameid.return_value = "user@example.com"
        mock_auth.get_session_index.return_value = "session-123"
        mock_auth.get_last_request_id.return_value = "request-456"
        mock_auth_cls.return_value = mock_auth

        request_data = {
            "http_host": "sp.example.com",
            "script_name": "/slo",
            "get_data": {"SAMLRequest": "encoded-request"},
            "post_data": {},
        }

        name_id, session_index, request_id = process_logout_request(
            settings=saml_settings_with_slo,
            request_data=request_data,
        )

        assert name_id == "user@example.com"
        assert session_index == "session-123"
        assert request_id == "request-456"


def test_process_logout_request_exception(saml_settings_with_slo):
    """Test processing logout request when exception is raised."""
    from app.utils.saml import process_logout_request

    with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth") as mock_auth_cls:
        mock_auth = MagicMock()
        mock_auth.process_slo.side_effect = Exception("Invalid request")
        mock_auth_cls.return_value = mock_auth

        request_data = {
            "http_host": "sp.example.com",
            "script_name": "/slo",
            "get_data": {"SAMLRequest": "encoded-request"},
            "post_data": {},
        }

        name_id, session_index, request_id = process_logout_request(
            settings=saml_settings_with_slo,
            request_data=request_data,
        )

        assert name_id is None
        assert session_index is None
        assert request_id is None


def test_build_logout_response_success(saml_settings_with_slo):
    """Test building logout response."""
    from app.utils.saml import build_logout_response

    redirect_url = build_logout_response(
        settings=saml_settings_with_slo,
        in_response_to="original-request-id",
    )

    assert redirect_url.startswith("https://idp.example.com/slo")
    assert "SAMLResponse=" in redirect_url


def test_build_logout_response_without_in_response_to(saml_settings_with_slo):
    """Test building logout response without InResponseTo."""
    from app.utils.saml import build_logout_response

    redirect_url = build_logout_response(
        settings=saml_settings_with_slo,
        in_response_to=None,
    )

    assert redirect_url.startswith("https://idp.example.com/slo")
    assert "SAMLResponse=" in redirect_url


def test_build_logout_response_no_slo_url(sample_certificate):
    """Test building logout response when IdP has no SLO URL."""
    from app.utils.saml import build_logout_response

    cert_pem, key_pem = sample_certificate

    # Build settings without SLO URL
    settings = build_saml_settings(
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        sp_certificate_pem=cert_pem,
        sp_private_key_pem=key_pem,
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_certificate_pem=cert_pem,
        # No idp_slo_url
    )

    with pytest.raises(ValueError, match="IdP has no SLO URL configured"):
        build_logout_response(settings=settings, in_response_to="request-id")


def test_build_logout_response_slo_url_with_query_string(sample_certificate):
    """Test building logout response when SLO URL already has query params."""
    from app.utils.saml import build_logout_response

    cert_pem, key_pem = sample_certificate

    # Build settings with SLO URL that has query params
    settings = build_saml_settings(
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        sp_certificate_pem=cert_pem,
        sp_private_key_pem=key_pem,
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_certificate_pem=cert_pem,
        idp_slo_url="https://idp.example.com/slo?param=value",
        sp_slo_url="https://sp.example.com/slo",
    )

    redirect_url = build_logout_response(settings=settings, in_response_to="request-id")

    # Should use & instead of ? since URL already has query params
    assert "idp.example.com/slo?param=value&SAMLResponse=" in redirect_url


# =============================================================================
# Edge Case Tests (for complete coverage)
# =============================================================================


def test_get_encryption_key_with_valid_32_byte_key():
    """Test encryption key generation when key is exactly 32 bytes."""
    import base64

    # Create a valid 32-byte key (base64 encoded)
    valid_key = base64.urlsafe_b64encode(b"a" * 32).decode()

    with patch("app.utils.saml.settings") as mock_settings:
        mock_settings.SAML_KEY_ENCRYPTION_KEY = valid_key

        # Reimport to pick up mocked settings
        from importlib import reload

        import app.utils.saml

        reload(app.utils.saml)
        from app.utils.saml import _get_encryption_key

        result = _get_encryption_key()

        # Should return base64-encoded version of the key
        assert len(base64.urlsafe_b64decode(result)) == 32


def test_get_encryption_key_with_invalid_key_falls_back_to_hkdf():
    """Test encryption key generation falls back to HKDF derivation for invalid keys."""
    import base64

    with patch("app.utils.saml.settings") as mock_settings:
        mock_settings.SAML_KEY_ENCRYPTION_KEY = "not-valid-base64!"

        from importlib import reload

        import app.utils.saml

        reload(app.utils.saml)
        from app.utils.saml import _get_encryption_key

        result = _get_encryption_key()

        # Should still return a valid 32-byte key (base64 encoded)
        assert len(base64.urlsafe_b64decode(result)) == 32


def test_get_certificate_expiry_fallback_for_older_cryptography():
    """Test certificate expiry uses not_valid_after when not_valid_after_utc not available."""
    cert_pem, _ = generate_sp_certificate("test-tenant")

    # Create a mock cert that raises AttributeError for not_valid_after_utc
    class MockCert:
        @property
        def not_valid_after_utc(self):
            raise AttributeError("not_valid_after_utc not available")

        @property
        def not_valid_after(self):
            return datetime.datetime(2030, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)

    with patch("app.utils.saml.x509.load_pem_x509_certificate", return_value=MockCert()):
        result = get_certificate_expiry(cert_pem)
        assert result == datetime.datetime(2030, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)


def test_parse_idp_metadata_with_certificate_as_list():
    """Test parsing IdP metadata when certificate is returned as a list."""
    with patch(
        "onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.parse"
    ) as mock_parse:
        # Simulate metadata where certificate is returned as a list
        mock_parse.return_value = {
            "idp": {
                "entityId": "https://idp.example.com",
                "singleSignOnService": {"url": "https://idp.example.com/sso"},
                "singleLogoutService": {"url": "https://idp.example.com/slo"},
                "x509cert": [
                    "MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADA",  # First cert
                    "MIICqDCCAZACCQC6SOM/9zQJgTANBgkqhkiG9w0BAQsFADA",  # Second cert
                ],
            }
        }

        result = parse_idp_metadata_xml("<fake-xml>")

        # Should take the first certificate
        assert "-----BEGIN CERTIFICATE-----" in result["certificate_pem"]
        assert "MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADA" in result["certificate_pem"]


def test_parse_idp_metadata_with_empty_certificate_list():
    """Test parsing IdP metadata when certificate list is empty."""
    with patch(
        "onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.parse"
    ) as mock_parse:
        # Simulate metadata where certificate list is empty
        mock_parse.return_value = {
            "idp": {
                "entityId": "https://idp.example.com",
                "singleSignOnService": {"url": "https://idp.example.com/sso"},
                "x509cert": [],  # Empty list
            }
        }

        with pytest.raises(ValueError, match="missing X.509 certificate"):
            parse_idp_metadata_xml("<fake-xml>")
