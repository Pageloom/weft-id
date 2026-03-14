"""SAML IdP utilities for SP metadata parsing, fetching, and entity IDs."""

from typing import Any
from xml.sax.saxutils import escape as _xml_escape

from defusedxml import ElementTree as DefusedET

# Escape entities for XML attribute values (extends default &, <, > with quotes)
_XML_ATTR_ENTITIES = {'"': "&quot;", "'": "&apos;"}

# SAML metadata namespace
_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"


def _wrap_pem(cert_data: str) -> str:
    """Wrap raw certificate data in PEM headers if not already present."""
    if cert_data.startswith("-----BEGIN"):
        return cert_data
    return f"-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"


def make_idp_entity_id(tenant_id: str, sp_registration_id: str) -> str:
    """Stable URN-based IdP entity ID, one per SP connection.

    Used as the entityID in IdP metadata and as the Issuer in SAML responses.
    Each downstream SP registration gets its own entity ID so the same SP
    can be registered multiple times at a single tenant without collisions.
    """
    return f"urn:weftid:{tenant_id}:idp:{sp_registration_id}"


def parse_sp_metadata_xml(metadata_xml: str) -> dict[str, Any]:
    """Parse SAML SP metadata XML and extract configuration.

    Args:
        metadata_xml: Raw XML metadata string

    Returns:
        Dict with entity_id, acs_url, certificate_pem, nameid_format

    Raises:
        ValueError: If metadata is invalid or missing required fields
    """
    try:
        root = DefusedET.fromstring(metadata_xml)
    except Exception as e:
        raise ValueError(f"Failed to parse SP metadata XML: {e}") from e

    # Extract entity ID from EntityDescriptor
    entity_id = root.attrib.get("entityID")
    if not entity_id:
        raise ValueError("SP metadata missing entityID")

    # Find SPSSODescriptor
    sp_descriptor = root.find(f"{{{_MD_NS}}}SPSSODescriptor")
    if sp_descriptor is None:
        raise ValueError("SP metadata missing SPSSODescriptor element")

    # Extract ACS URL (required)
    acs_url = None
    for acs in sp_descriptor.findall(f"{{{_MD_NS}}}AssertionConsumerService"):
        binding = acs.attrib.get("Binding", "")
        if "HTTP-POST" in binding:
            acs_url = acs.attrib.get("Location")
            break
    # Fall back to first ACS if no HTTP-POST binding found
    if not acs_url:
        first_acs = sp_descriptor.find(f"{{{_MD_NS}}}AssertionConsumerService")
        if first_acs is not None:
            acs_url = first_acs.attrib.get("Location")
    if not acs_url:
        raise ValueError("SP metadata missing AssertionConsumerService URL")

    # Extract SP certificates (optional)
    # Iterate all KeyDescriptor elements:
    #   use="signing" -> signing cert
    #   use="encryption" -> encryption cert
    #   no use attr -> both (per SAML spec)
    # First match per category wins.
    certificate_pem = None
    encryption_certificate_pem = None
    for kd in sp_descriptor.findall(f"{{{_MD_NS}}}KeyDescriptor"):
        x509_cert = kd.find(f".//{{{_DS_NS}}}X509Certificate")
        if x509_cert is None or not x509_cert.text:
            continue
        pem = _wrap_pem(x509_cert.text.strip())
        use = kd.attrib.get("use")
        if use == "signing":
            if certificate_pem is None:
                certificate_pem = pem
        elif use == "encryption":
            if encryption_certificate_pem is None:
                encryption_certificate_pem = pem
        else:
            # No use attribute: applies to both
            if certificate_pem is None:
                certificate_pem = pem
            if encryption_certificate_pem is None:
                encryption_certificate_pem = pem

    # Extract NameID format (optional, default to emailAddress)
    nameid_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    nameid_elem = sp_descriptor.find(f"{{{_MD_NS}}}NameIDFormat")
    if nameid_elem is not None and nameid_elem.text:
        nameid_format = nameid_elem.text.strip()

    # Extract SingleLogoutService URL (optional)
    # Prefer HTTP-POST binding, fall back to HTTP-Redirect
    slo_url = None
    for sls in sp_descriptor.findall(f"{{{_MD_NS}}}SingleLogoutService"):
        binding = sls.attrib.get("Binding", "")
        location = sls.attrib.get("Location")
        if location and "HTTP-POST" in binding:
            slo_url = location
            break
    if not slo_url:
        for sls in sp_descriptor.findall(f"{{{_MD_NS}}}SingleLogoutService"):
            location = sls.attrib.get("Location")
            if location:
                slo_url = location
                break

    # Extract requested attributes from AttributeConsumingService (optional)
    requested_attributes: list[dict[str, Any]] = []
    attr_consuming = sp_descriptor.find(f"{{{_MD_NS}}}AttributeConsumingService")
    if attr_consuming is not None:
        for req_attr in attr_consuming.findall(f"{{{_MD_NS}}}RequestedAttribute"):
            attr_name = req_attr.attrib.get("Name", "")
            if not attr_name:
                continue
            friendly_name = req_attr.attrib.get("FriendlyName")
            is_required_str = req_attr.attrib.get("isRequired", "false")
            is_required = is_required_str.lower() == "true"
            entry: dict[str, Any] = {
                "name": attr_name,
                "friendly_name": friendly_name,
                "is_required": is_required,
            }
            requested_attributes.append(entry)

    return {
        "entity_id": entity_id,
        "acs_url": acs_url,
        "certificate_pem": certificate_pem,
        "encryption_certificate_pem": encryption_certificate_pem,
        "nameid_format": nameid_format,
        "slo_url": slo_url,
        "requested_attributes": requested_attributes or None,
    }


# Lookup tables for auto-detecting attribute mappings from SP metadata.
# Maps known OIDs, URIs, and friendly names to IdP attribute keys.
_OID_TO_IDP_ATTR: dict[str, str] = {
    # Standard OIDs (backward compatibility)
    "urn:oid:0.9.2342.19200300.100.1.3": "email",  # mail
    "urn:oid:2.5.4.42": "firstName",  # givenName
    "urn:oid:2.5.4.4": "lastName",  # surname
    "urn:oid:2.16.840.1.113730.3.1.241": "displayName",  # displayName
    "urn:oid:2.5.4.3": "displayName",  # cn (commonName)
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.7": "groups",  # eduPersonEntitlement
    # Friendly names (new default format)
    "email": "email",
    "firstName": "firstName",
    "lastName": "lastName",
    "displayName": "displayName",
    "groups": "groups",
    # Azure AD / WS-Federation claims
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "firstName",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "lastName",
    # Common SAML claims
    "http://schemas.xmlsoap.org/claims/EmailAddress": "email",
    "http://schemas.xmlsoap.org/claims/Group": "groups",
}

_FRIENDLY_NAME_TO_IDP_ATTR: dict[str, str] = {
    "mail": "email",
    "email": "email",
    "emailaddress": "email",
    "givenname": "firstName",
    "firstname": "firstName",
    "sn": "lastName",
    "surname": "lastName",
    "lastname": "lastName",
    "groups": "groups",
    "edupersonentitlement": "groups",
}


def auto_detect_attribute_mapping(
    requested_attributes: list[dict[str, Any]],
) -> dict[str, str]:
    """Auto-detect IdP-to-SP attribute mapping from SP requested attributes.

    Tries to match each SP requested attribute to a known IdP attribute key
    using OID/URI lookup first, then friendly name lookup.

    Args:
        requested_attributes: List of dicts with "name", "friendly_name", "is_required"

    Returns:
        Dict mapping IdP attribute keys to SP URIs, e.g. {"email": "urn:oid:..."}
    """
    mapping: dict[str, str] = {}
    for attr in requested_attributes:
        sp_uri = attr.get("name", "")
        if not sp_uri:
            continue

        # Try OID/URI match first
        idp_key = _OID_TO_IDP_ATTR.get(sp_uri)

        # Fall back to friendly name match
        if idp_key is None:
            friendly = attr.get("friendly_name") or ""
            idp_key = _FRIENDLY_NAME_TO_IDP_ATTR.get(friendly.lower())

        if idp_key and idp_key not in mapping:
            mapping[idp_key] = sp_uri

    return mapping


def generate_idp_metadata_xml(
    entity_id: str,
    sso_url: str,
    certificate_pem: str,
    slo_url: str | None = None,
    attribute_mapping: dict[str, str] | None = None,
) -> str:
    """Generate SAML IdP metadata XML for downstream SPs to consume.

    Args:
        entity_id: IdP entity ID (metadata URL)
        sso_url: Single Sign-On service URL
        certificate_pem: PEM-encoded IdP signing certificate
        slo_url: Optional Single Logout service URL
        attribute_mapping: Optional {friendlyName: URI} mapping. Uses defaults if None.

    Returns:
        XML metadata string
    """
    from utils.saml_assertion import SAML_ATTRIBUTE_URIS

    # Extract the raw certificate data (without PEM headers)
    cert_lines = certificate_pem.strip().split("\n")
    cert_data = "".join(line for line in cert_lines if not line.startswith("-----"))

    def esc(v: str) -> str:
        return _xml_escape(v, _XML_ATTR_ENTITIES)

    slo_elements = ""
    if slo_url:
        slo_url_esc = esc(slo_url)
        slo_elements = f"""
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{slo_url_esc}" />
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{slo_url_esc}" />"""

    # Build attribute declarations so SPs know what to expect
    attr_format = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    attr_elements = ""
    for friendly_name, uri in (attribute_mapping or SAML_ATTRIBUTE_URIS).items():
        attr_elements += f"""
    <saml:Attribute
        Name="{esc(uri)}"
        NameFormat="{attr_format}"
        FriendlyName="{esc(friendly_name)}" />"""

    entity_id_esc = esc(entity_id)
    sso_url_esc = esc(sso_url)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    entityID="{entity_id_esc}">
  <md:IDPSSODescriptor
      WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{cert_data}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>{slo_elements}
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{sso_url_esc}" />
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{sso_url_esc}" />{attr_elements}
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


def fetch_sp_metadata(url: str, timeout: int = 10) -> str:
    """Fetch SP metadata XML from a URL.

    Validates the URL for SSRF safety (scheme, resolved IP) and enforces a
    response size limit before returning the raw XML.

    Args:
        url: Metadata URL (https required in production)
        timeout: Request timeout in seconds

    Returns:
        Raw XML metadata string

    Raises:
        ValueError: If fetch fails, URL is unsafe, or returns non-XML content
    """
    from utils.url_safety import fetch_metadata_xml

    return fetch_metadata_xml(url, timeout=timeout)
