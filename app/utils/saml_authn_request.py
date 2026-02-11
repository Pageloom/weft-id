"""SAML AuthnRequest parsing and validation for IdP SSO flow."""

import base64
import zlib

from defusedxml import ElementTree as DefusedET

# SAML namespaces
_SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"


def parse_authn_request(saml_request: str, binding: str) -> dict[str, str | None]:
    """Parse a SAMLRequest parameter from an SP.

    Args:
        saml_request: Base64-encoded (and optionally deflated) SAMLRequest
        binding: "redirect" for HTTP-Redirect (deflate + base64),
                 "post" for HTTP-POST (base64 only)

    Returns:
        Dict with keys: id, issuer, acs_url (optional), name_id_policy_format (optional)

    Raises:
        ValueError: If the request is malformed or missing required fields
    """
    if not saml_request or not saml_request.strip():
        raise ValueError("SAMLRequest is empty")

    # Decode
    try:
        raw = base64.b64decode(saml_request)
    except Exception as e:
        raise ValueError(f"Invalid base64 in SAMLRequest: {e}") from e

    # Inflate if redirect binding (deflate + base64)
    if binding == "redirect":
        try:
            xml_bytes = zlib.decompress(raw, -15)
        except zlib.error as e:
            raise ValueError(f"Failed to decompress SAMLRequest: {e}") from e
    else:
        xml_bytes = raw

    # Parse XML
    try:
        root = DefusedET.fromstring(xml_bytes)
    except Exception as e:
        raise ValueError(f"Failed to parse AuthnRequest XML: {e}") from e

    # Verify root element is AuthnRequest
    tag = root.tag
    if not tag.endswith("AuthnRequest"):
        raise ValueError(f"Expected AuthnRequest element, got {tag}")

    # Extract required fields
    request_id = root.attrib.get("ID")
    if not request_id:
        raise ValueError("AuthnRequest missing ID attribute")

    # Extract Issuer (required)
    issuer_elem = root.find(f"{{{_SAML_NS}}}Issuer")
    if issuer_elem is None or not issuer_elem.text:
        raise ValueError("AuthnRequest missing Issuer element")
    issuer = issuer_elem.text.strip()

    # Extract optional ACS URL
    acs_url = root.attrib.get("AssertionConsumerServiceURL")

    # Extract optional NameIDPolicy Format
    name_id_policy_format = None
    name_id_policy = root.find(f"{{{_SAMLP_NS}}}NameIDPolicy")
    if name_id_policy is not None:
        name_id_policy_format = name_id_policy.attrib.get("Format")

    return {
        "id": request_id,
        "issuer": issuer,
        "acs_url": acs_url,
        "name_id_policy_format": name_id_policy_format,
    }


def validate_authn_request(parsed: dict[str, str | None], registered_sp: dict) -> None:
    """Validate a parsed AuthnRequest against a registered SP.

    Args:
        parsed: Dict from parse_authn_request()
        registered_sp: SP database row with entity_id, acs_url fields

    Raises:
        ValueError: If validation fails
    """
    # Issuer must match the registered SP's entity_id
    if parsed["issuer"] != registered_sp["entity_id"]:
        raise ValueError(
            f"AuthnRequest Issuer '{parsed['issuer']}' does not match "
            f"registered SP entity_id '{registered_sp['entity_id']}'"
        )

    # If ACS URL is provided in the request, it must match the registered SP
    if parsed["acs_url"] and parsed["acs_url"] != registered_sp["acs_url"]:
        raise ValueError(
            f"AuthnRequest ACS URL '{parsed['acs_url']}' does not match "
            f"registered SP ACS URL '{registered_sp['acs_url']}'"
        )
