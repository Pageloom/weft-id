"""Tests for SAML IdP SP metadata parsing utilities."""

import pytest
from utils.saml_idp import parse_sp_metadata_xml

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
