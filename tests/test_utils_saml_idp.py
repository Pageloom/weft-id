"""Tests for SAML IdP SP metadata parsing and IdP metadata generation utilities."""

import pytest
from defusedxml import ElementTree as DefusedET
from utils.saml_idp import generate_idp_metadata_xml, parse_sp_metadata_xml

# =============================================================================
# Sample Metadata
# =============================================================================

SAMPLE_SP_METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://app.example.com/saml/metadata">
  <md:SPSSODescriptor
      AuthnRequestsSigned="true"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIICsDCCAZigAwIBAgIJALwzrJEIQ9UHMA0=</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://app.example.com/saml/acs"
        index="0"
        isDefault="true" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""

SAMPLE_SP_METADATA_MINIMAL = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://minimal.example.com">
  <md:SPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://minimal.example.com/acs"
        index="0" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""

SAMPLE_SP_METADATA_PERSISTENT_NAMEID = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://persistent.example.com">
  <md:SPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://persistent.example.com/acs"
        index="0" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""


# =============================================================================
# parse_sp_metadata_xml Tests
# =============================================================================


class TestParseSPMetadataXML:
    """Tests for parse_sp_metadata_xml."""

    def test_full_metadata(self):
        """Parse full SP metadata with certificate and NameID format."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA)

        assert result["entity_id"] == "https://app.example.com/saml/metadata"
        assert result["acs_url"] == "https://app.example.com/saml/acs"
        assert result["certificate_pem"] is not None
        assert "BEGIN CERTIFICATE" in result["certificate_pem"]
        assert result["nameid_format"] == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    def test_minimal_metadata(self):
        """Parse minimal SP metadata (no cert, no NameID format)."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_MINIMAL)

        assert result["entity_id"] == "https://minimal.example.com"
        assert result["acs_url"] == "https://minimal.example.com/acs"
        assert result["certificate_pem"] is None
        # Default NameID format
        assert result["nameid_format"] == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    def test_persistent_nameid_format(self):
        """Parse metadata with persistent NameID format."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_PERSISTENT_NAMEID)

        assert result["entity_id"] == "https://persistent.example.com"
        assert result["nameid_format"] == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

    def test_invalid_xml(self):
        """Raise ValueError for invalid XML."""
        with pytest.raises(ValueError, match="Failed to parse SP metadata XML"):
            parse_sp_metadata_xml("not xml at all")

    def test_missing_entity_id(self):
        """Raise ValueError if entityID is missing."""
        xml = """<?xml version="1.0"?>
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
          <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:AssertionConsumerService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                Location="https://example.com/acs" index="0" />
          </md:SPSSODescriptor>
        </md:EntityDescriptor>"""

        with pytest.raises(ValueError, match="missing entityID"):
            parse_sp_metadata_xml(xml)

    def test_missing_sp_descriptor(self):
        """Raise ValueError if SPSSODescriptor is missing."""
        xml = """<?xml version="1.0"?>
        <md:EntityDescriptor
            xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            entityID="https://example.com">
        </md:EntityDescriptor>"""

        with pytest.raises(ValueError, match="missing SPSSODescriptor"):
            parse_sp_metadata_xml(xml)

    def test_missing_acs_url(self):
        """Raise ValueError if ACS URL is missing."""
        xml = """<?xml version="1.0"?>
        <md:EntityDescriptor
            xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            entityID="https://example.com">
          <md:SPSSODescriptor
              protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          </md:SPSSODescriptor>
        </md:EntityDescriptor>"""

        with pytest.raises(ValueError, match="missing AssertionConsumerService URL"):
            parse_sp_metadata_xml(xml)

    def test_certificate_pem_formatting(self):
        """Certificate should be wrapped in PEM headers."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA)

        cert = result["certificate_pem"]
        assert cert.startswith("-----BEGIN CERTIFICATE-----")
        assert cert.endswith("-----END CERTIFICATE-----")


# =============================================================================
# generate_idp_metadata_xml Tests
# =============================================================================

SAMPLE_CERT_PEM = (
    "-----BEGIN CERTIFICATE-----\nMIICsDCCAZigAwIBAgIJALwzrJEIQ9UHMA0=\n-----END CERTIFICATE-----"
)


class TestGenerateIdPMetadataXML:
    """Tests for generate_idp_metadata_xml."""

    def test_valid_xml_output(self):
        """Generated output is valid XML."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        # Should not raise
        DefusedET.fromstring(xml)

    def test_entity_id(self):
        """EntityDescriptor has correct entityID."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        root = DefusedET.fromstring(xml)
        assert root.attrib["entityID"] == "https://idp.example.com/saml/idp/metadata"

    def test_idp_sso_descriptor(self):
        """Contains IDPSSODescriptor (not SPSSODescriptor)."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        root = DefusedET.fromstring(xml)
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        sp_desc = root.find(f"{{{md_ns}}}SPSSODescriptor")

        assert idp_desc is not None
        assert sp_desc is None

    def test_want_authn_requests_signed_false(self):
        """IDPSSODescriptor has WantAuthnRequestsSigned=false."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        root = DefusedET.fromstring(xml)
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        assert idp_desc.attrib["WantAuthnRequestsSigned"] == "false"

    def test_signing_certificate(self):
        """Contains signing KeyDescriptor with certificate data."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        root = DefusedET.fromstring(xml)
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        ds_ns = "http://www.w3.org/2000/09/xmldsig#"

        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        key_desc = idp_desc.find(f"{{{md_ns}}}KeyDescriptor")
        assert key_desc is not None
        assert key_desc.attrib["use"] == "signing"

        x509_cert = key_desc.find(f".//{{{ds_ns}}}X509Certificate")
        assert x509_cert is not None
        assert "MIICsDCCAZigAwIBAgIJALwzrJEIQ9UHMA0=" in x509_cert.text

    def test_strips_pem_headers(self):
        """Certificate PEM headers are stripped from the XML."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        assert "-----BEGIN CERTIFICATE-----" not in xml
        assert "-----END CERTIFICATE-----" not in xml

    def test_two_nameid_formats(self):
        """Contains both emailAddress and unspecified NameID formats."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        root = DefusedET.fromstring(xml)
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        nameid_formats = [elem.text for elem in idp_desc.findall(f"{{{md_ns}}}NameIDFormat")]

        assert len(nameid_formats) == 2
        assert "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" in nameid_formats
        assert "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" in nameid_formats

    def test_two_sso_bindings(self):
        """Contains both HTTP-Redirect and HTTP-POST SSO bindings."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        root = DefusedET.fromstring(xml)
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        sso_services = idp_desc.findall(f"{{{md_ns}}}SingleSignOnService")

        assert len(sso_services) == 2
        bindings = [svc.attrib["Binding"] for svc in sso_services]
        assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" in bindings
        assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" in bindings

    def test_sso_url_in_bindings(self):
        """Both SSO bindings point to the correct SSO URL."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        root = DefusedET.fromstring(xml)
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        sso_services = idp_desc.findall(f"{{{md_ns}}}SingleSignOnService")

        for svc in sso_services:
            assert svc.attrib["Location"] == "https://idp.example.com/saml/idp/sso"


# =============================================================================
# parse_sp_metadata_xml: fallback ACS and PEM header edge cases
# =============================================================================


class TestParseSPMetadataFallbackACS:
    """Test ACS URL extraction when no HTTP-POST binding is found."""

    def test_falls_back_to_first_acs(self):
        """When no HTTP-POST ACS exists, uses the first ACS URL found."""
        xml = """<?xml version="1.0"?>
        <md:EntityDescriptor
            xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            entityID="https://redirect-only.example.com">
          <md:SPSSODescriptor
              protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:AssertionConsumerService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                Location="https://redirect-only.example.com/acs"
                index="0" />
          </md:SPSSODescriptor>
        </md:EntityDescriptor>"""

        result = parse_sp_metadata_xml(xml)
        assert result["acs_url"] == "https://redirect-only.example.com/acs"

    def test_prefers_http_post_over_redirect(self):
        """When both bindings exist, HTTP-POST is preferred."""
        xml = """<?xml version="1.0"?>
        <md:EntityDescriptor
            xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            entityID="https://both.example.com">
          <md:SPSSODescriptor
              protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:AssertionConsumerService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                Location="https://both.example.com/acs-redirect"
                index="0" />
            <md:AssertionConsumerService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                Location="https://both.example.com/acs-post"
                index="1" />
          </md:SPSSODescriptor>
        </md:EntityDescriptor>"""

        result = parse_sp_metadata_xml(xml)
        assert result["acs_url"] == "https://both.example.com/acs-post"


class TestParseSPMetadataCertificateWithPEMHeaders:
    """Test certificate extraction when XML already includes PEM headers."""

    def test_preserves_existing_pem_headers(self):
        """Certificate data with PEM headers passes through unchanged."""
        xml = """<?xml version="1.0"?>
        <md:EntityDescriptor
            xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            entityID="https://pem.example.com">
          <md:SPSSODescriptor
              protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:KeyDescriptor use="signing">
              <ds:KeyInfo>
                <ds:X509Data>
                  <ds:X509Certificate>-----BEGIN CERTIFICATE-----
MIICsDCCAZigAwIBAgIJALwzrJEIQ9UHMA0=
-----END CERTIFICATE-----</ds:X509Certificate>
                </ds:X509Data>
              </ds:KeyInfo>
            </md:KeyDescriptor>
            <md:AssertionConsumerService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                Location="https://pem.example.com/acs"
                index="0" />
          </md:SPSSODescriptor>
        </md:EntityDescriptor>"""

        result = parse_sp_metadata_xml(xml)
        cert = result["certificate_pem"]
        assert cert.startswith("-----BEGIN CERTIFICATE-----")
        assert cert.endswith("-----END CERTIFICATE-----")
        # Should not double-wrap
        assert cert.count("-----BEGIN CERTIFICATE-----") == 1
