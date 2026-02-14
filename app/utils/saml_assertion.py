"""SAML Response and Assertion generation with XML Digital Signatures.

Builds signed SAML 2.0 Responses for the IdP SSO flow. Uses lxml for
XML construction and xmlsec for enveloped RSA-SHA256 signatures.
"""

import base64
import datetime
import uuid

import xmlsec
from lxml import etree

# SAML namespaces
_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"

_NS_MAP = {
    "saml": _SAML_NS,
    "samlp": _SAMLP_NS,
}

# Standard SAML attribute URIs (OID-based)
SAML_ATTRIBUTE_URIS = {
    "email": "urn:oid:0.9.2342.19200300.100.1.3",  # mail
    "firstName": "urn:oid:2.5.4.42",  # givenName
    "lastName": "urn:oid:2.5.4.4",  # surname
    "groups": "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",  # eduPersonEntitlement
}

# SAML attribute name format
_ATTRIBUTE_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"


def _generate_id() -> str:
    """Generate a SAML-safe ID (must not start with a digit)."""
    return f"_{uuid.uuid4().hex}"


def build_saml_response(
    issuer_entity_id: str,
    sp_entity_id: str,
    sp_acs_url: str,
    name_id: str,
    name_id_format: str,
    authn_request_id: str | None,
    user_attributes: dict[str, str | list[str]],
    certificate_pem: str,
    private_key_pem: str,
    session_index: str | None = None,
) -> tuple[str, str]:
    """Build and sign a SAML 2.0 Response containing a signed Assertion.

    Args:
        issuer_entity_id: Our IdP entity ID
        sp_entity_id: The SP's entity ID (for AudienceRestriction)
        sp_acs_url: SP's ACS URL (Destination)
        name_id: User identifier (typically email)
        name_id_format: NameID format URI
        authn_request_id: ID from the AuthnRequest (for InResponseTo), or None
        user_attributes: Dict of user attributes. Values can be strings or lists
            of strings (for multi-valued attributes like groups).
        certificate_pem: PEM-encoded signing certificate
        private_key_pem: PEM-encoded private key (decrypted)
        session_index: Optional session index for SLO correlation

    Returns:
        Tuple of (base64_encoded_response, session_index)
    """
    now = datetime.datetime.now(datetime.UTC)
    response_id = _generate_id()
    assertion_id = _generate_id()

    # Generate session index if not provided
    if session_index is None:
        session_index = _generate_id()

    # Build Assertion element
    assertion = _build_assertion_element(
        assertion_id=assertion_id,
        issuer_entity_id=issuer_entity_id,
        sp_entity_id=sp_entity_id,
        sp_acs_url=sp_acs_url,
        name_id=name_id,
        name_id_format=name_id_format,
        authn_request_id=authn_request_id,
        user_attributes=user_attributes,
        now=now,
        session_index=session_index,
    )

    # Sign the Assertion
    signed_assertion = _sign_assertion(assertion, certificate_pem, private_key_pem)

    # Build the outer Response
    response = _build_response_element(
        response_id=response_id,
        sp_acs_url=sp_acs_url,
        authn_request_id=authn_request_id,
        issuer_entity_id=issuer_entity_id,
        signed_assertion=signed_assertion,
        now=now,
    )

    # Serialize to XML and base64-encode
    xml_bytes = etree.tostring(response, xml_declaration=True, encoding="UTF-8")
    return base64.b64encode(xml_bytes).decode("utf-8"), session_index


def _build_response_element(
    response_id: str,
    sp_acs_url: str,
    authn_request_id: str | None,
    issuer_entity_id: str,
    signed_assertion: etree._Element,
    now: datetime.datetime,
) -> etree._Element:
    """Build the outer SAML Response element wrapping the signed Assertion."""
    issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    attribs = {
        "ID": response_id,
        "Version": "2.0",
        "IssueInstant": issue_instant,
        "Destination": sp_acs_url,
    }
    if authn_request_id:
        attribs["InResponseTo"] = authn_request_id

    response = etree.Element(f"{{{_SAMLP_NS}}}Response", attrib=attribs, nsmap=_NS_MAP)

    # Issuer
    issuer = etree.SubElement(response, f"{{{_SAML_NS}}}Issuer")
    issuer.text = issuer_entity_id

    # Status
    status = etree.SubElement(response, f"{{{_SAMLP_NS}}}Status")
    status_code = etree.SubElement(status, f"{{{_SAMLP_NS}}}StatusCode")
    status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    # Append the signed Assertion
    response.append(signed_assertion)

    return response


def _build_assertion_element(
    assertion_id: str,
    issuer_entity_id: str,
    sp_entity_id: str,
    sp_acs_url: str,
    name_id: str,
    name_id_format: str,
    authn_request_id: str | None,
    user_attributes: dict[str, str | list[str]],
    now: datetime.datetime,
    session_index: str | None = None,
) -> etree._Element:
    """Build an unsigned SAML Assertion element."""
    issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_on_or_after = (now + datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    session_not_on_or_after = (now + datetime.timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Root Assertion element
    assertion = etree.Element(
        f"{{{_SAML_NS}}}Assertion",
        attrib={
            "ID": assertion_id,
            "Version": "2.0",
            "IssueInstant": issue_instant,
        },
        nsmap={"saml": _SAML_NS},
    )

    # 1. Issuer
    issuer = etree.SubElement(assertion, f"{{{_SAML_NS}}}Issuer")
    issuer.text = issuer_entity_id

    # 2. Signature placeholder (will be inserted by xmlsec during signing)
    # xmlsec expects the Signature template as the second child of the signed element

    # 3. Subject
    subject = etree.SubElement(assertion, f"{{{_SAML_NS}}}Subject")
    name_id_elem = etree.SubElement(
        subject,
        f"{{{_SAML_NS}}}NameID",
        attrib={
            "Format": name_id_format,
            "SPNameQualifier": sp_entity_id,
        },
    )
    name_id_elem.text = name_id

    confirmation = etree.SubElement(
        subject,
        f"{{{_SAML_NS}}}SubjectConfirmation",
        attrib={"Method": "urn:oasis:names:tc:SAML:2.0:cm:bearer"},
    )
    conf_data_attribs: dict[str, str] = {
        "NotOnOrAfter": not_on_or_after,
        "Recipient": sp_acs_url,
    }
    if authn_request_id:
        conf_data_attribs["InResponseTo"] = authn_request_id
    etree.SubElement(
        confirmation,
        f"{{{_SAML_NS}}}SubjectConfirmationData",
        attrib=conf_data_attribs,
    )

    # 4. Conditions
    conditions = etree.SubElement(
        assertion,
        f"{{{_SAML_NS}}}Conditions",
        attrib={
            "NotBefore": issue_instant,
            "NotOnOrAfter": not_on_or_after,
        },
    )
    audience_restriction = etree.SubElement(conditions, f"{{{_SAML_NS}}}AudienceRestriction")
    audience = etree.SubElement(audience_restriction, f"{{{_SAML_NS}}}Audience")
    audience.text = sp_entity_id

    # 5. AuthnStatement (AuthnContext is required by saml-schema-assertion-2.0.xsd)
    authn_attribs: dict[str, str] = {
        "AuthnInstant": issue_instant,
        "SessionNotOnOrAfter": session_not_on_or_after,
    }
    if session_index:
        authn_attribs["SessionIndex"] = session_index
    authn_statement = etree.SubElement(
        assertion,
        f"{{{_SAML_NS}}}AuthnStatement",
        attrib=authn_attribs,
    )
    authn_context = etree.SubElement(authn_statement, f"{{{_SAML_NS}}}AuthnContext")
    authn_context_class_ref = etree.SubElement(authn_context, f"{{{_SAML_NS}}}AuthnContextClassRef")
    authn_context_class_ref.text = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    )

    # 6. AttributeStatement
    if user_attributes:
        attr_stmt = etree.SubElement(assertion, f"{{{_SAML_NS}}}AttributeStatement")
        for attr_name, attr_value in user_attributes.items():
            uri = SAML_ATTRIBUTE_URIS.get(attr_name, attr_name)
            attr = etree.SubElement(
                attr_stmt,
                f"{{{_SAML_NS}}}Attribute",
                attrib={
                    "Name": uri,
                    "NameFormat": _ATTRIBUTE_NAME_FORMAT,
                    "FriendlyName": attr_name,
                },
            )
            # Support multi-valued attributes (e.g. group memberships)
            values = attr_value if isinstance(attr_value, list) else [attr_value]
            for v in values:
                attr_val = etree.SubElement(
                    attr,
                    f"{{{_SAML_NS}}}AttributeValue",
                )
                attr_val.text = v

    return assertion


def _sign_assertion(
    assertion: etree._Element,
    certificate_pem: str,
    private_key_pem: str,
) -> etree._Element:
    """Sign a SAML Assertion using enveloped XML Digital Signature.

    Uses RSA-SHA256 with Exclusive C14N canonicalization.
    The Signature is placed as the second child of the Assertion (after Issuer).
    """
    # Get the Assertion ID for the reference URI
    assertion_id = assertion.get("ID")

    # Create Signature template as child of Assertion
    # Position: after Issuer (index 1)
    signature_node = xmlsec.template.create(
        assertion,
        c14n_method=xmlsec.Transform.EXCL_C14N,  # type: ignore[attr-defined]
        sign_method=xmlsec.Transform.RSA_SHA256,  # type: ignore[attr-defined]
    )
    # Insert after Issuer (which is the first child)
    assertion.insert(1, signature_node)

    # Add reference to the Assertion itself
    ref = xmlsec.template.add_reference(
        signature_node,
        digest_method=xmlsec.Transform.SHA256,  # type: ignore[attr-defined]
        uri=f"#{assertion_id}",
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

    # Register the ID attribute so xmlsec can resolve the #ID reference
    xmlsec.tree.add_ids(assertion, ["ID"])

    # Sign
    ctx.sign(signature_node)

    return assertion
