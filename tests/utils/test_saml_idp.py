"""Tests for SAML IdP SP metadata parsing and IdP metadata generation utilities."""

from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest
from defusedxml import ElementTree as DefusedET
from utils.saml_idp import (
    auto_detect_attribute_mapping,
    fetch_sp_metadata,
    generate_idp_metadata_xml,
    parse_sp_metadata_xml,
)

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

    def test_no_slo_elements_by_default(self):
        """No SLO elements when slo_url is not provided."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        root = DefusedET.fromstring(xml)
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        slo_services = idp_desc.findall(f"{{{md_ns}}}SingleLogoutService")
        assert len(slo_services) == 0

    def test_slo_elements_when_url_provided(self):
        """SLO elements included when slo_url is provided."""
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
            slo_url="https://idp.example.com/saml/idp/slo",
        )
        root = DefusedET.fromstring(xml)
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        slo_services = idp_desc.findall(f"{{{md_ns}}}SingleLogoutService")

        assert len(slo_services) == 2
        bindings = [svc.attrib["Binding"] for svc in slo_services]
        assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" in bindings
        assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" in bindings
        for svc in slo_services:
            assert svc.attrib["Location"] == "https://idp.example.com/saml/idp/slo"

    def test_default_attributes_when_no_mapping(self):
        """Default SAML_ATTRIBUTE_URIS attributes appear when no mapping provided."""
        from utils.saml_assertion import SAML_ATTRIBUTE_URIS

        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
        )
        root = DefusedET.fromstring(xml)
        saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion"
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        attrs = idp_desc.findall(f"{{{saml_ns}}}Attribute")

        assert len(attrs) == len(SAML_ATTRIBUTE_URIS)
        names = {a.attrib["Name"] for a in attrs}
        friendly_names = {a.attrib["FriendlyName"] for a in attrs}
        for friendly_name, uri in SAML_ATTRIBUTE_URIS.items():
            assert uri in names
            assert friendly_name in friendly_names

    def test_custom_attribute_mapping(self):
        """Custom mapping overrides default attributes in metadata."""
        custom_mapping = {
            "email": "urn:oid:0.9.2342.19200300.100.1.3",
            "firstName": "urn:oid:2.5.4.42",
        }
        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
            attribute_mapping=custom_mapping,
        )
        root = DefusedET.fromstring(xml)
        saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion"
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        attrs = idp_desc.findall(f"{{{saml_ns}}}Attribute")

        assert len(attrs) == 2
        attr_map = {a.attrib["FriendlyName"]: a.attrib["Name"] for a in attrs}
        assert attr_map == custom_mapping

    def test_none_attribute_mapping_uses_defaults(self):
        """Explicitly passing None uses default attributes."""
        from utils.saml_assertion import SAML_ATTRIBUTE_URIS

        xml = generate_idp_metadata_xml(
            entity_id="https://idp.example.com/saml/idp/metadata",
            sso_url="https://idp.example.com/saml/idp/sso",
            certificate_pem=SAMPLE_CERT_PEM,
            attribute_mapping=None,
        )
        root = DefusedET.fromstring(xml)
        saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion"
        md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
        idp_desc = root.find(f"{{{md_ns}}}IDPSSODescriptor")
        attrs = idp_desc.findall(f"{{{saml_ns}}}Attribute")

        assert len(attrs) == len(SAML_ATTRIBUTE_URIS)


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


# =============================================================================
# parse_sp_metadata_xml: SLO URL extraction
# =============================================================================


SAMPLE_SP_METADATA_WITH_SLO_POST = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://slo-post.example.com">
  <md:SPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://slo-post.example.com/saml/slo" />
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://slo-post.example.com/acs"
        index="0" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""

SAMPLE_SP_METADATA_WITH_SLO_REDIRECT = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://slo-redirect.example.com">
  <md:SPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://slo-redirect.example.com/saml/slo" />
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://slo-redirect.example.com/acs"
        index="0" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""

SAMPLE_SP_METADATA_WITH_SLO_BOTH = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://slo-both.example.com">
  <md:SPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://slo-both.example.com/saml/slo-redirect" />
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://slo-both.example.com/saml/slo-post" />
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://slo-both.example.com/acs"
        index="0" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""


class TestParseSPMetadataSLOURL:
    """Tests for SLO URL extraction from SP metadata."""

    def test_extracts_slo_url_http_post(self):
        """Extracts SLO URL with HTTP-POST binding."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_WITH_SLO_POST)
        assert result["slo_url"] == "https://slo-post.example.com/saml/slo"

    def test_extracts_slo_url_http_redirect_fallback(self):
        """Falls back to HTTP-Redirect binding when no HTTP-POST."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_WITH_SLO_REDIRECT)
        assert result["slo_url"] == "https://slo-redirect.example.com/saml/slo"

    def test_prefers_http_post_over_redirect(self):
        """When both bindings exist, HTTP-POST is preferred."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_WITH_SLO_BOTH)
        assert result["slo_url"] == "https://slo-both.example.com/saml/slo-post"

    def test_no_slo_url_returns_none(self):
        """Returns None when no SingleLogoutService element exists."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_MINIMAL)
        assert result["slo_url"] is None

    def test_full_metadata_no_slo(self):
        """Full metadata without SLO returns None for slo_url."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA)
        assert result["slo_url"] is None


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


# =============================================================================
# parse_sp_metadata_xml: RequestedAttribute extraction
# =============================================================================

SAMPLE_SP_METADATA_WITH_ATTRS = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://attrs.example.com">
  <md:SPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://attrs.example.com/acs"
        index="0" />
    <md:AttributeConsumingService index="0">
      <md:ServiceName xml:lang="en">Test Service</md:ServiceName>
      <md:RequestedAttribute
          Name="urn:oid:0.9.2342.19200300.100.1.3"
          FriendlyName="mail"
          isRequired="true" />
      <md:RequestedAttribute
          Name="urn:oid:2.5.4.42"
          FriendlyName="givenName"
          isRequired="false" />
      <md:RequestedAttribute
          Name="urn:oid:2.5.4.4"
          isRequired="true" />
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""


class TestParseSPMetadataRequestedAttributes:
    """Tests for RequestedAttribute extraction from SP metadata."""

    def test_extracts_requested_attributes(self):
        """Parses multiple RequestedAttribute elements."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_WITH_ATTRS)
        attrs = result["requested_attributes"]

        assert attrs is not None
        assert len(attrs) == 3

    def test_attribute_name_and_friendly_name(self):
        """Extracts Name and FriendlyName correctly."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_WITH_ATTRS)
        attrs = result["requested_attributes"]

        assert attrs[0]["name"] == "urn:oid:0.9.2342.19200300.100.1.3"
        assert attrs[0]["friendly_name"] == "mail"

    def test_is_required_flag(self):
        """Parses isRequired flag correctly."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_WITH_ATTRS)
        attrs = result["requested_attributes"]

        assert attrs[0]["is_required"] is True
        assert attrs[1]["is_required"] is False
        assert attrs[2]["is_required"] is True

    def test_missing_friendly_name(self):
        """FriendlyName is None when not present."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_WITH_ATTRS)
        attrs = result["requested_attributes"]

        assert attrs[2]["friendly_name"] is None

    def test_no_attribute_consuming_service(self):
        """Returns None when no AttributeConsumingService exists."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA_MINIMAL)

        assert result["requested_attributes"] is None

    def test_full_metadata_without_attrs(self):
        """Full metadata without AttributeConsumingService returns None."""
        result = parse_sp_metadata_xml(SAMPLE_SP_METADATA)

        assert result["requested_attributes"] is None


# =============================================================================
# auto_detect_attribute_mapping
# =============================================================================


class TestAutoDetectAttributeMapping:
    """Tests for auto_detect_attribute_mapping."""

    def test_standard_oid_matching(self):
        """Matches standard OID URIs to IdP attributes."""
        attrs = [
            {
                "name": "urn:oid:0.9.2342.19200300.100.1.3",
                "friendly_name": "mail",
                "is_required": True,
            },
            {"name": "urn:oid:2.5.4.42", "friendly_name": "givenName", "is_required": False},
            {"name": "urn:oid:2.5.4.4", "friendly_name": "sn", "is_required": False},
        ]
        result = auto_detect_attribute_mapping(attrs)

        assert result == {
            "email": "urn:oid:0.9.2342.19200300.100.1.3",
            "firstName": "urn:oid:2.5.4.42",
            "lastName": "urn:oid:2.5.4.4",
        }

    def test_azure_claims_matching(self):
        """Matches Azure AD / WS-Federation claim URIs."""
        attrs = [
            {
                "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "friendly_name": None,
                "is_required": True,
            },
            {
                "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
                "friendly_name": None,
                "is_required": False,
            },
            {
                "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
                "friendly_name": None,
                "is_required": False,
            },
        ]
        result = auto_detect_attribute_mapping(attrs)

        assert (
            result["email"] == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        )
        assert (
            result["firstName"] == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
        )
        assert result["lastName"] == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"

    def test_friendly_name_fallback(self):
        """Falls back to friendly name when URI is not recognized."""
        attrs = [
            {
                "name": "https://custom.example.com/email",
                "friendly_name": "mail",
                "is_required": True,
            },
        ]
        result = auto_detect_attribute_mapping(attrs)

        assert result == {"email": "https://custom.example.com/email"}

    def test_case_insensitive_friendly_name(self):
        """Friendly name matching is case-insensitive."""
        attrs = [
            {
                "name": "https://custom.example.com/mail",
                "friendly_name": "Mail",
                "is_required": True,
            },
            {
                "name": "https://custom.example.com/gn",
                "friendly_name": "GivenName",
                "is_required": False,
            },
        ]
        result = auto_detect_attribute_mapping(attrs)

        assert result["email"] == "https://custom.example.com/mail"
        assert result["firstName"] == "https://custom.example.com/gn"

    def test_no_matches_returns_empty(self):
        """Returns empty dict when nothing matches."""
        attrs = [
            {
                "name": "https://unknown.example.com/foo",
                "friendly_name": "unknown",
                "is_required": True,
            },
        ]
        result = auto_detect_attribute_mapping(attrs)

        assert result == {}

    def test_empty_input(self):
        """Returns empty dict for empty input."""
        result = auto_detect_attribute_mapping([])

        assert result == {}

    def test_first_match_wins(self):
        """If two SP attrs map to the same IdP key, first wins."""
        attrs = [
            {
                "name": "urn:oid:0.9.2342.19200300.100.1.3",
                "friendly_name": "mail",
                "is_required": True,
            },
            {
                "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "friendly_name": None,
                "is_required": False,
            },
        ]
        result = auto_detect_attribute_mapping(attrs)

        # First match (OID) should win
        assert result["email"] == "urn:oid:0.9.2342.19200300.100.1.3"

    def test_groups_oid_matching(self):
        """Matches eduPersonEntitlement OID to groups."""
        attrs = [
            {
                "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
                "friendly_name": "eduPersonEntitlement",
                "is_required": False,
            },
        ]
        result = auto_detect_attribute_mapping(attrs)

        assert result == {"groups": "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"}


# =============================================================================
# fetch_sp_metadata tests
# =============================================================================

SAMPLE_SP_XML = '<?xml version="1.0"?><EntityDescriptor>sp-metadata</EntityDescriptor>'


class TestFetchSPMetadata:
    """Tests for fetch_sp_metadata (delegates to url_safety)."""

    @patch("app.utils.url_safety.urllib.request.urlopen")
    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_successful_fetch(self, mock_settings, mock_getaddrinfo, mock_urlopen):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]

        mock_response = MagicMock()
        mock_response.headers = {}
        mock_response.read.return_value = SAMPLE_SP_XML.encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = fetch_sp_metadata("https://sp.example.com/metadata")
        assert "EntityDescriptor" in result

    @patch("app.utils.url_safety.socket.getaddrinfo")
    @patch("app.utils.url_safety.settings")
    def test_ssrf_blocked(self, mock_settings, mock_getaddrinfo):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("169.254.169.254", 0))]

        with pytest.raises(ValueError, match="private or reserved"):
            fetch_sp_metadata("https://evil.example.com/metadata")

    @patch("app.utils.url_safety.settings")
    def test_file_scheme_blocked(self, mock_settings):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""

        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            fetch_sp_metadata("file:///etc/passwd")

    @pytest.mark.parametrize(
        "exception,match",
        [
            (
                HTTPError(
                    url="https://sp.example.com", code=500, msg="Server Error", hdrs={}, fp=None
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
    def test_fetch_errors(self, mock_settings, mock_getaddrinfo, mock_urlopen, exception, match):
        mock_settings.IS_DEV = False
        mock_settings.BASE_DOMAIN = ""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        mock_urlopen.side_effect = exception

        with pytest.raises(ValueError, match=match):
            fetch_sp_metadata("https://sp.example.com/metadata")
