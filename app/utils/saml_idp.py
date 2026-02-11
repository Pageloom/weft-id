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

    return {
        "entity_id": entity_id,
        "acs_url": acs_url,
        "certificate_pem": certificate_pem,
        "nameid_format": nameid_format,
    }


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
    import urllib.request
    from urllib.error import HTTPError, URLError

    try:
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/xml, text/xml, application/samlmetadata+xml"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310
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
