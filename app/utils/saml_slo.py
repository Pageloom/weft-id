"""SAML SLO (Single Logout) XML construction for the IdP side.

Builds and parses LogoutRequest/LogoutResponse XML for downstream SP SLO.
Uses lxml + xmlsec directly (consistent with saml_assertion.py).
"""

import base64
import datetime
import uuid
import zlib

import xmlsec
from defusedxml import ElementTree as DefusedET
from lxml import etree

# SAML namespaces
_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"

_NS_MAP = {
    "saml": _SAML_NS,
    "samlp": _SAMLP_NS,
}


def _generate_id() -> str:
    """Generate a SAML-safe ID (must not start with a digit)."""
    return f"_{uuid.uuid4().hex}"


def parse_sp_logout_request(
    saml_request: str,
    binding: str,
) -> dict:
    """Parse a LogoutRequest from a downstream SP.

    Args:
        saml_request: Base64-encoded (and possibly deflated) SAMLRequest
        binding: "redirect" or "post"

    Returns:
        Dict with id, issuer, name_id, session_index

    Raises:
        ValueError: If the request is malformed
    """
    try:
        raw = base64.b64decode(saml_request)
        if binding == "redirect":
            raw = zlib.decompress(raw, -15)
        xml_str = raw.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decode LogoutRequest: {e}") from e

    try:
        root = DefusedET.fromstring(xml_str)
    except Exception as e:
        raise ValueError(f"Failed to parse LogoutRequest XML: {e}") from e

    # Validate root element
    tag = root.tag
    if not tag.endswith("}LogoutRequest") and tag != "LogoutRequest":
        raise ValueError(f"Expected LogoutRequest, got {tag}")

    request_id = root.attrib.get("ID")
    if not request_id:
        raise ValueError("LogoutRequest missing ID attribute")

    # Extract Issuer
    issuer_elem = root.find(f"{{{_SAML_NS}}}Issuer")
    issuer = issuer_elem.text.strip() if issuer_elem is not None and issuer_elem.text else None

    # Extract NameID
    name_id_elem = root.find(f"{{{_SAML_NS}}}NameID")
    name_id = name_id_elem.text.strip() if name_id_elem is not None and name_id_elem.text else None
    name_id_format = name_id_elem.attrib.get("Format") if name_id_elem is not None else None

    # Extract SessionIndex
    session_index_elem = root.find(f"{{{_SAMLP_NS}}}SessionIndex")
    session_index = (
        session_index_elem.text.strip()
        if session_index_elem is not None and session_index_elem.text
        else None
    )

    return {
        "id": request_id,
        "issuer": issuer,
        "name_id": name_id,
        "name_id_format": name_id_format,
        "session_index": session_index,
    }


def build_idp_logout_response(
    issuer_entity_id: str,
    destination: str,
    in_response_to: str,
    certificate_pem: str,
    private_key_pem: str,
) -> str:
    """Build and sign a LogoutResponse from the IdP.

    Args:
        issuer_entity_id: Our IdP entity ID
        destination: SP's SLO URL
        in_response_to: ID from the LogoutRequest
        certificate_pem: PEM-encoded signing certificate
        private_key_pem: PEM-encoded private key (decrypted)

    Returns:
        Base64-encoded signed LogoutResponse XML
    """
    now = datetime.datetime.now(datetime.UTC)
    response_id = _generate_id()
    issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build LogoutResponse
    response = etree.Element(
        f"{{{_SAMLP_NS}}}LogoutResponse",
        attrib={
            "ID": response_id,
            "Version": "2.0",
            "IssueInstant": issue_instant,
            "Destination": destination,
            "InResponseTo": in_response_to,
        },
        nsmap=_NS_MAP,
    )

    # Issuer
    issuer = etree.SubElement(response, f"{{{_SAML_NS}}}Issuer")
    issuer.text = issuer_entity_id

    # Status (Success)
    status = etree.SubElement(response, f"{{{_SAMLP_NS}}}Status")
    status_code = etree.SubElement(status, f"{{{_SAMLP_NS}}}StatusCode")
    status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    # Sign the response
    _sign_element(response, certificate_pem, private_key_pem)

    # Serialize and base64-encode
    xml_bytes = etree.tostring(response, xml_declaration=True, encoding="UTF-8")
    return base64.b64encode(xml_bytes).decode("utf-8")


def build_idp_logout_request(
    issuer_entity_id: str,
    destination: str,
    name_id: str,
    name_id_format: str | None,
    session_index: str | None,
    certificate_pem: str,
    private_key_pem: str,
) -> str:
    """Build and sign a LogoutRequest from the IdP to a downstream SP.

    Args:
        issuer_entity_id: Our IdP entity ID
        destination: SP's SLO URL
        name_id: User identifier sent in the original assertion
        name_id_format: NameID format URI (optional)
        session_index: SessionIndex from the original assertion (optional)
        certificate_pem: PEM-encoded signing certificate
        private_key_pem: PEM-encoded private key (decrypted)

    Returns:
        Base64-encoded signed LogoutRequest XML
    """
    now = datetime.datetime.now(datetime.UTC)
    request_id = _generate_id()
    issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_on_or_after = (now + datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build LogoutRequest
    request = etree.Element(
        f"{{{_SAMLP_NS}}}LogoutRequest",
        attrib={
            "ID": request_id,
            "Version": "2.0",
            "IssueInstant": issue_instant,
            "Destination": destination,
            "NotOnOrAfter": not_on_or_after,
        },
        nsmap=_NS_MAP,
    )

    # Issuer
    issuer = etree.SubElement(request, f"{{{_SAML_NS}}}Issuer")
    issuer.text = issuer_entity_id

    # NameID
    name_id_attribs: dict[str, str] = {}
    if name_id_format:
        name_id_attribs["Format"] = name_id_format
    name_id_elem = etree.SubElement(request, f"{{{_SAML_NS}}}NameID", attrib=name_id_attribs)
    name_id_elem.text = name_id

    # SessionIndex (optional)
    if session_index:
        session_index_elem = etree.SubElement(request, f"{{{_SAMLP_NS}}}SessionIndex")
        session_index_elem.text = session_index

    # Sign the request
    _sign_element(request, certificate_pem, private_key_pem)

    # Serialize and base64-encode
    xml_bytes = etree.tostring(request, xml_declaration=True, encoding="UTF-8")
    return base64.b64encode(xml_bytes).decode("utf-8")


def _sign_element(
    element: etree._Element,
    certificate_pem: str,
    private_key_pem: str,
) -> None:
    """Sign a SAML XML element using enveloped XML Digital Signature.

    The signature is placed after the Issuer element (second child).
    """
    element_id = element.get("ID")

    # Create Signature template
    signature_node = xmlsec.template.create(
        element,
        c14n_method=xmlsec.Transform.EXCL_C14N,  # type: ignore[attr-defined]
        sign_method=xmlsec.Transform.RSA_SHA256,  # type: ignore[attr-defined]
    )
    # Insert after Issuer (which is the first child)
    element.insert(1, signature_node)

    # Add reference
    ref = xmlsec.template.add_reference(
        signature_node,
        digest_method=xmlsec.Transform.SHA256,  # type: ignore[attr-defined]
        uri=f"#{element_id}",
    )
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)  # type: ignore[attr-defined]
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)  # type: ignore[attr-defined]

    # Add KeyInfo with X509 certificate
    key_info = xmlsec.template.ensure_key_info(signature_node)
    x509_data = xmlsec.template.add_x509_data(key_info)
    xmlsec.template.x509_data_add_certificate(x509_data)

    # Load key and certificate
    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_memory(
        private_key_pem.encode("utf-8"),
        format=xmlsec.KeyFormat.PEM,  # type: ignore[attr-defined]
    )
    key.load_cert_from_memory(certificate_pem.encode("utf-8"), xmlsec.KeyFormat.CERT_PEM)  # type: ignore[attr-defined]
    ctx.key = key

    # Register the ID attribute
    xmlsec.tree.add_ids(element, ["ID"])

    # Sign
    ctx.sign(signature_node)
