"""SAML IdP utilities for SP metadata parsing and fetching."""

from typing import Any

from defusedxml import ElementTree as DefusedET

# SAML metadata namespace
_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"


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

    # Extract SP certificate (optional)
    certificate_pem = None
    key_descriptor = sp_descriptor.find(f"{{{_MD_NS}}}KeyDescriptor")
    if key_descriptor is not None:
        x509_cert = key_descriptor.find(f".//{{{_DS_NS}}}X509Certificate")
        if x509_cert is not None and x509_cert.text:
            cert_data = x509_cert.text.strip()
            if not cert_data.startswith("-----BEGIN"):
                certificate_pem = (
                    f"-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"
                )
            else:
                certificate_pem = cert_data

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

    return {
        "entity_id": entity_id,
        "acs_url": acs_url,
        "certificate_pem": certificate_pem,
        "nameid_format": nameid_format,
        "slo_url": slo_url,
    }


def generate_idp_metadata_xml(
    entity_id: str,
    sso_url: str,
    certificate_pem: str,
    slo_url: str | None = None,
) -> str:
    """Generate SAML IdP metadata XML for downstream SPs to consume.

    Args:
        entity_id: IdP entity ID (metadata URL)
        sso_url: Single Sign-On service URL
        certificate_pem: PEM-encoded IdP signing certificate
        slo_url: Optional Single Logout service URL

    Returns:
        XML metadata string
    """
    from utils.saml_assertion import SAML_ATTRIBUTE_URIS

    # Extract the raw certificate data (without PEM headers)
    cert_lines = certificate_pem.strip().split("\n")
    cert_data = "".join(line for line in cert_lines if not line.startswith("-----"))

    slo_elements = ""
    if slo_url:
        slo_elements = f"""
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{slo_url}" />
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{slo_url}" />"""

    # Build attribute declarations so SPs know what to expect
    attr_format = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    attr_elements = ""
    for friendly_name, uri in SAML_ATTRIBUTE_URIS.items():
        attr_elements += f"""
    <saml:Attribute
        Name="{uri}"
        NameFormat="{attr_format}"
        FriendlyName="{friendly_name}" />"""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    entityID="{entity_id}">
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
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>{attr_elements}
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{sso_url}" />
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{sso_url}" />
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


def fetch_sp_metadata(url: str, timeout: int = 10) -> str:
    """Fetch SP metadata XML from a URL.

    Mirrors the existing fetch_idp_metadata() pattern.

    Args:
        url: Metadata URL
        timeout: Request timeout in seconds

    Returns:
        Raw XML metadata string

    Raises:
        ValueError: If fetch fails or returns non-XML content
    """
    import ssl
    import urllib.request
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlparse, urlunparse

    import settings

    try:
        headers = {"Accept": "application/xml, text/xml, application/samlmetadata+xml"}
        ssl_ctx = None

        # Route internal URLs through the reverse-proxy container so that
        # *.BASE_DOMAIN hostnames (unresolvable inside Docker) reach nginx.
        parsed = urlparse(url)
        base = settings.BASE_DOMAIN
        if base and parsed.hostname and parsed.hostname.endswith(base):
            original_host = parsed.hostname
            port = parsed.port or 443
            parsed = parsed._replace(netloc=f"reverse-proxy:{port}")
            headers["Host"] = original_host
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(urlunparse(parsed), headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as response:  # noqa: S310
            content: str = response.read().decode("utf-8")

            # Basic validation that it looks like XML
            if not content.strip().startswith("<?xml") and not content.strip().startswith("<"):
                raise ValueError("Response does not appear to be XML")

            return content

    except HTTPError as e:
        raise ValueError(f"HTTP error fetching metadata: {e.code} {e.reason}") from e
    except URLError as e:
        raise ValueError(f"Failed to fetch metadata: {e.reason}") from e
    except TimeoutError:
        raise ValueError(f"Timeout fetching metadata (>{timeout}s)") from None
