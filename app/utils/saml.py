"""SAML utilities for certificate generation, encryption, and entity IDs."""

import base64
import datetime
from typing import Any
from xml.sax.saxutils import escape as _xml_escape

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from defusedxml import ElementTree as DefusedET
from utils.crypto import derive_fernet_key

_cipher = Fernet(derive_fernet_key(b"saml-key-encryption"))


def make_sp_entity_id(tenant_id: str, idp_registration_id: str) -> str:
    """Stable URN-based SP entity ID, one per IdP connection.

    Used as the entityID in SP metadata and as the Issuer in AuthnRequests.
    Each upstream IdP registration gets its own entity ID so the same IdP
    can be registered multiple times at a single tenant without collisions.
    """
    return f"urn:weftid:{tenant_id}:sp:{idp_registration_id}"


def encrypt_private_key(private_key_pem: str) -> str:
    """Encrypt a PEM-encoded private key for storage."""
    return _cipher.encrypt(private_key_pem.encode()).decode()


def decrypt_private_key(encrypted_key: str) -> str:
    """Decrypt a PEM-encoded private key from storage."""
    return _cipher.decrypt(encrypted_key.encode()).decode()


def generate_sp_certificate(
    tenant_id: str,
    validity_years: int = 10,
) -> tuple[str, str]:
    """
    Generate a self-signed SP certificate for SAML signing.

    Args:
        tenant_id: Tenant ID for certificate subject
        validity_years: Certificate validity in years (default 10)

    Returns:
        Tuple of (certificate_pem, private_key_pem)
    """
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Build certificate subject and issuer (self-signed, so same)
    tenant_str = str(tenant_id)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WeftID"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"SP-{tenant_str[:8]}"),
        ]
    )

    # Build the certificate
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * validity_years))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Serialize to PEM format
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    return cert_pem, key_pem


def get_certificate_fingerprint(certificate_pem: str) -> str:
    """
    Get the SHA-256 fingerprint of a PEM-encoded certificate.

    Args:
        certificate_pem: PEM-encoded X.509 certificate

    Returns:
        Colon-separated hex fingerprint (e.g. "AB:CD:EF:...")
    """
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def get_certificate_expiry(certificate_pem: str) -> datetime.datetime:
    """
    Get the expiry date from a PEM-encoded certificate.

    Args:
        certificate_pem: PEM-encoded X.509 certificate

    Returns:
        Certificate expiry datetime (UTC)
    """
    cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    # Use not_valid_after (older versions) or not_valid_after_utc (newer versions)
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after


def extract_idp_advertised_attributes(metadata_xml: str) -> list[dict[str, str]]:
    """Extract attribute declarations from IdP metadata XML.

    Parses <saml:Attribute> elements from the IDPSSODescriptor to find
    what attributes the IdP advertises. Returns an empty list if no
    attributes are declared (common for many IdPs).

    Args:
        metadata_xml: Raw XML metadata string

    Returns:
        List of dicts with 'name' and 'friendly_name' keys.
    """
    saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion"
    md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"

    try:
        root = DefusedET.fromstring(metadata_xml)
    except Exception:
        return []

    # Find IDPSSODescriptor, then its <saml:Attribute> children
    idp_descriptor = root.find(f"{{{md_ns}}}IDPSSODescriptor")
    if idp_descriptor is None:
        return []

    attributes = []
    for attr_elem in idp_descriptor.findall(f"{{{saml_ns}}}Attribute"):
        name = attr_elem.attrib.get("Name", "")
        friendly_name = attr_elem.attrib.get("FriendlyName", "")
        if name:
            attributes.append({"name": name, "friendly_name": friendly_name})

    return attributes


def parse_idp_metadata_xml(metadata_xml: str) -> dict[str, Any]:
    """
    Parse SAML IdP metadata XML and extract configuration.

    Args:
        metadata_xml: Raw XML metadata string

    Returns:
        Dict with entity_id, sso_url, slo_url, certificate_pem

    Raises:
        ValueError: If metadata is invalid or missing required fields
    """
    # Import here to avoid loading xmlsec at module level
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

    try:
        parsed = OneLogin_Saml2_IdPMetadataParser.parse(metadata_xml)
    except Exception as e:
        raise ValueError(f"Failed to parse IdP metadata XML: {e}") from e

    idp_data = parsed.get("idp", {})

    entity_id = idp_data.get("entityId")
    if not entity_id:
        raise ValueError("IdP metadata missing entityId")

    sso_service = idp_data.get("singleSignOnService", {})
    sso_url = sso_service.get("url")
    if not sso_url:
        raise ValueError("IdP metadata missing SSO URL")

    # SLO is optional
    slo_service = idp_data.get("singleLogoutService", {})
    slo_url = slo_service.get("url")

    # Certificate - could be a string or list
    cert = idp_data.get("x509cert")
    raw_certs: list[str] = []
    if isinstance(cert, list):
        raw_certs = list(cert)
        cert = cert[0] if cert else None
    elif cert:
        raw_certs = [cert]

    # Also check x509certMulti for additional signing certs
    cert_multi = idp_data.get("x509certMulti", {})
    if isinstance(cert_multi, dict):
        signing_certs = cert_multi.get("signing", [])
        if isinstance(signing_certs, list):
            for sc in signing_certs:
                if sc and sc not in raw_certs:
                    raw_certs.append(sc)

    if not cert:
        raise ValueError("IdP metadata missing X.509 certificate")

    def _format_pem(c: str) -> str:
        if not c.startswith("-----BEGIN"):
            return f"-----BEGIN CERTIFICATE-----\n{c}\n-----END CERTIFICATE-----"
        return c

    # Format certificate as PEM if needed
    cert = _format_pem(cert)

    # Format all certificates as PEM
    certificates = [_format_pem(c) for c in raw_certs if c]

    return {
        "entity_id": entity_id,
        "sso_url": sso_url,
        "slo_url": slo_url,
        "certificate_pem": cert,
        "certificates": certificates,
    }


def fetch_idp_metadata(url: str, timeout: int = 10) -> str:
    """Fetch IdP metadata XML from a URL.

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


def generate_sp_metadata_xml(
    entity_id: str,
    acs_url: str,
    certificate_pem: str,
    slo_url: str | None = None,
    previous_certificate_pem: str | None = None,
    attribute_mapping: dict[str, str] | None = None,
    encryption_certificate_pem: str | None = None,
) -> str:
    """
    Generate SP metadata XML for IdPs to consume.

    Args:
        entity_id: SP entity ID (usually the metadata URL)
        acs_url: Assertion Consumer Service URL
        certificate_pem: PEM-encoded SP signing certificate
        slo_url: Optional Single Logout URL
        previous_certificate_pem: Optional previous cert during rotation grace period
        attribute_mapping: Optional IdP attribute mapping {idp_attr_name: platform_field}.
            Uses defaults if None.
        encryption_certificate_pem: Optional PEM-encoded encryption certificate.
            When provided, an encryption KeyDescriptor is included so IdPs can
            encrypt assertions for this SP.

    Returns:
        XML metadata string
    """
    # Escape entities for XML attribute values
    _entities = {'"': "&quot;", "'": "&apos;"}

    def esc(v: str) -> str:
        return _xml_escape(v, _entities)

    # Extract the raw certificate data (without PEM headers)
    cert_lines = certificate_pem.strip().split("\n")
    cert_data = "".join(line for line in cert_lines if not line.startswith("-----"))

    from utils.saml_assertion import SAML_ATTRIBUTE_URIS

    slo_section = ""
    if slo_url:
        slo_section = f"""
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{esc(slo_url)}" />"""

    # Build requested attributes for AttributeConsumingService
    attr_format = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    attr_elements = ""
    if attribute_mapping:
        # IdP mapping: key = IdP attribute name (Name), value = platform field (FriendlyName)
        for idp_attr_name, platform_field in attribute_mapping.items():
            is_required = "true" if platform_field == "email" else "false"
            attr_elements += f"""
      <md:RequestedAttribute
          Name="{esc(idp_attr_name)}"
          NameFormat="{attr_format}"
          FriendlyName="{esc(platform_field)}"
          isRequired="{is_required}" />"""
    else:
        # Default: SAML_ATTRIBUTE_URIS key = friendlyName, value = URI
        required_attrs = {"email"}
        for friendly_name, uri in SAML_ATTRIBUTE_URIS.items():
            is_required = "true" if friendly_name in required_attrs else "false"
            attr_elements += f"""
      <md:RequestedAttribute
          Name="{esc(uri)}"
          NameFormat="{attr_format}"
          FriendlyName="{esc(friendly_name)}"
          isRequired="{is_required}" />"""

    # Build previous certificate KeyDescriptor for rotation grace period
    prev_cert_section = ""
    if previous_certificate_pem:
        prev_lines = previous_certificate_pem.strip().split("\n")
        prev_data = "".join(line for line in prev_lines if not line.startswith("-----"))
        prev_cert_section = f"""
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{prev_data}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>"""

    # Build encryption certificate KeyDescriptor
    enc_cert_section = ""
    if encryption_certificate_pem:
        enc_lines = encryption_certificate_pem.strip().split("\n")
        enc_data = "".join(line for line in enc_lines if not line.startswith("-----"))
        enc_cert_section = f"""
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{enc_data}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>"""

    entity_id_esc = esc(entity_id)
    acs_url_esc = esc(acs_url)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="{entity_id_esc}">
  <md:SPSSODescriptor
      AuthnRequestsSigned="true"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{cert_data}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>{prev_cert_section}{enc_cert_section}
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{acs_url_esc}"
        index="0"
        isDefault="true" />{slo_section}
    <md:AttributeConsumingService index="0" isDefault="true">
      <md:ServiceName xml:lang="en">WeftID</md:ServiceName>{attr_elements}
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""


def build_saml_settings(
    sp_entity_id: str,
    sp_acs_url: str,
    sp_certificate_pem: str,
    sp_private_key_pem: str,
    idp_entity_id: str,
    idp_sso_url: str,
    idp_certificate_pem: str,
    idp_slo_url: str | None = None,
    sp_slo_url: str | None = None,
    idp_certificate_pems: list[str] | None = None,
) -> dict[str, Any]:
    """
    Build python3-saml settings dict for a SAML operation.

    Args:
        sp_entity_id: Service Provider entity ID
        sp_acs_url: Assertion Consumer Service URL
        sp_certificate_pem: SP signing certificate (PEM)
        sp_private_key_pem: SP private key (PEM, decrypted)
        idp_entity_id: Identity Provider entity ID
        idp_sso_url: IdP SSO endpoint URL
        idp_certificate_pem: IdP signing certificate (PEM)
        idp_slo_url: Optional IdP Single Logout URL
        sp_slo_url: Optional SP Single Logout URL
        idp_certificate_pems: Optional list of all IdP signing certificates (PEM).
            When provided with >1 cert, enables multi-cert validation via x509certMulti.

    Returns:
        Settings dict compatible with OneLogin_Saml2_Auth
    """

    # Clean certificate strings (remove headers for the library)
    def clean_cert(pem: str) -> str:
        lines = pem.strip().split("\n")
        return "".join(line for line in lines if not line.startswith("-----"))

    def clean_key(pem: str) -> str:
        lines = pem.strip().split("\n")
        return "".join(line for line in lines if not line.startswith("-----"))

    idp_settings: dict[str, Any] = {
        "entityId": idp_entity_id,
        "singleSignOnService": {
            "url": idp_sso_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "x509cert": clean_cert(idp_certificate_pem),
    }

    # When multiple IdP certificates are provided, use x509certMulti
    # so python3-saml tries all signing certs during validation
    if idp_certificate_pems and len(idp_certificate_pems) > 1:
        idp_settings["x509certMulti"] = {
            "signing": [clean_cert(c) for c in idp_certificate_pems],
        }

    if idp_slo_url:
        idp_settings["singleLogoutService"] = {
            "url": idp_slo_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        }

    sp_settings: dict[str, Any] = {
        "entityId": sp_entity_id,
        "assertionConsumerService": {
            "url": sp_acs_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        "x509cert": clean_cert(sp_certificate_pem),
        "privateKey": clean_key(sp_private_key_pem),
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    }

    if sp_slo_url:
        sp_settings["singleLogoutService"] = {
            "url": sp_slo_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        }

    return {
        "strict": True,
        "debug": False,
        "sp": sp_settings,
        "idp": idp_settings,
        "security": {
            "authnRequestsSigned": True,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            # Single Logout messages are signed both ways (SAML Profiles
            # 4.4.3.1 / 4.4.4.1); inbound LogoutRequests are verified in
            # validate_logout_request.
            "logoutRequestSigned": True,
            "logoutResponseSigned": True,
            "wantAssertionsEncrypted": False,
            "signMetadata": False,
            "requestedAuthnContext": False,
        },
    }


def extract_issuer_from_response(saml_response_b64: str) -> str | None:
    """
    Extract the Issuer entity ID from a base64-encoded SAML response.

    This performs lightweight XML parsing to extract the Issuer without
    full SAML validation. Used to look up the IdP configuration before
    processing the full response.

    Args:
        saml_response_b64: Base64-encoded SAML response from the IdP

    Returns:
        The Issuer entity ID string, or None if extraction fails
    """
    try:
        # Decode the base64 SAML response
        xml_bytes = base64.b64decode(saml_response_b64)
        xml_str = xml_bytes.decode("utf-8")

        # Parse the XML
        root = DefusedET.fromstring(xml_str)

        # SAML namespace
        namespaces = {
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        }

        # Try to find Issuer in the Response element (top level)
        issuer = root.find("saml:Issuer", namespaces)
        if issuer is not None and issuer.text:
            return issuer.text.strip()

        # Try without namespace prefix (some IdPs may not use namespaces properly)
        issuer = root.find("Issuer")
        if issuer is not None and issuer.text:
            return issuer.text.strip()

        # Try to find it in the Assertion element
        assertion = root.find(".//saml:Assertion", namespaces)
        if assertion is not None:
            issuer = assertion.find("saml:Issuer", namespaces)
            if issuer is not None and issuer.text:
                return issuer.text.strip()

        return None

    except Exception:
        # If anything fails, return None - the full SAML validation will
        # catch any real errors
        return None


# ============================================================================
# Single Logout (SLO) Utilities (Phase 4)
# ============================================================================


def build_logout_request(
    settings: dict[str, Any],
    name_id: str,
    name_id_format: str | None = None,
    session_index: str | None = None,
) -> tuple[str, str]:
    """
    Build a SAML LogoutRequest and return the redirect URL.

    Args:
        settings: python3-saml settings dict (from build_saml_settings)
        name_id: The NameID from the original SAML assertion
        name_id_format: NameID format (default: emailAddress)
        session_index: Session index from the original assertion (optional)

    Returns:
        Tuple of (redirect_url, request_id)
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    # Create a minimal request dict for python3-saml
    request_data = {
        "http_host": "",
        "script_name": "",
        "get_data": {},
        "post_data": {},
    }

    auth = OneLogin_Saml2_Auth(request_data, settings)

    # Build the logout request
    redirect_url = auth.logout(
        name_id=name_id,
        name_id_format=name_id_format or "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        session_index=session_index,
        return_to=None,  # We'll handle redirect after SLO completes
    )

    # Get the request ID for validation later (optional)
    request_id = auth.get_last_request_id()

    return redirect_url, request_id


def process_logout_response(
    settings: dict[str, Any],
    get_data: dict[str, str],
    request_id: str | None = None,
) -> tuple[bool, str | None]:
    """
    Process a SAML LogoutResponse from the IdP.

    Args:
        settings: python3-saml settings dict
        get_data: GET parameters from the redirect (SAMLResponse, etc.)
        request_id: Optional request ID to validate against

    Returns:
        Tuple of (success, error_message)
        - success: True if logout was successful
        - error_message: Error description if failed, None otherwise
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    # Create a minimal request dict for python3-saml
    request_data = {
        "http_host": "",
        "script_name": "",
        "get_data": get_data,
        "post_data": {},
    }

    auth = OneLogin_Saml2_Auth(request_data, settings)

    try:
        # Process the logout response
        auth.process_slo(
            keep_local_session=True,  # We handle session ourselves
            request_id=request_id,
            delete_session_cb=lambda: None,  # No-op, we handle session
        )

        errors = auth.get_errors()
        if errors:
            return False, ", ".join(errors)

        return True, None

    except Exception as e:
        return False, str(e)


class LogoutRequestError(Exception):
    """An IdP's LogoutRequest failed validation (``reason`` is a short code)."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def decode_logout_request(saml_request: str) -> str:
    """Decode a SAMLRequest (base64, deflated or not) into LogoutRequest XML.

    Raises:
        LogoutRequestError: ``malformed`` when it does not decode.
    """
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

    try:
        xml = OneLogin_Saml2_Utils.decode_base64_and_inflate(saml_request, ignore_zip=True)
    except Exception as exc:  # noqa: BLE001 - any decoding failure is "malformed"
        raise LogoutRequestError("malformed", str(exc)) from exc
    return xml.decode("utf-8") if isinstance(xml, bytes) else str(xml)


def logout_request_issuer(xml: str) -> str | None:
    """The ``<saml:Issuer>`` of a LogoutRequest, or None (unparseable too)."""
    from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request

    try:
        issuer = OneLogin_Saml2_Logout_Request.get_issuer(xml)
    except Exception:  # noqa: BLE001 - an unparseable request has no issuer
        return None
    return issuer if isinstance(issuer, str) else None


def _verify_enveloped_logout_request_signature(xml: str, settings: dict[str, Any]) -> None:
    """Verify the XML signature of a POST-binding LogoutRequest.

    The signature must be a direct child of the root and reference the root
    by its ``ID`` (exactly one element carries it), so a signature over some
    other element cannot vouch for the request (signature wrapping).
    """
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

    root = OneLogin_Saml2_XML.to_etree(xml)
    root_id = root.get("ID")
    signatures = OneLogin_Saml2_XML.query(root, "/samlp:LogoutRequest/ds:Signature")
    if not root_id or len(signatures) != 1:
        raise LogoutRequestError("unsigned")
    references = OneLogin_Saml2_XML.query(signatures[0], "./ds:SignedInfo/ds:Reference")
    if len(references) != 1 or references[0].get("URI") != f"#{root_id}":
        raise LogoutRequestError("signature_reference")
    if len(root.xpath("//*[@ID=$id]", id=root_id)) != 1:
        raise LogoutRequestError("signature_reference")

    # The settings hold bare base64 certificates; xmlsec needs PEM.
    idp = settings["idp"]
    certs = [
        OneLogin_Saml2_Utils.format_cert(cert)
        for cert in idp.get("x509certMulti", {}).get("signing") or [idp["x509cert"]]
    ]
    try:
        verified = OneLogin_Saml2_Utils.validate_sign(
            xml,
            xpath="/samlp:LogoutRequest/ds:Signature",
            multicerts=certs,
        )
    except Exception as exc:  # noqa: BLE001 - the library raises on a bad signature
        raise LogoutRequestError("signature", str(exc)) from exc
    if not verified:
        raise LogoutRequestError("signature")


def validate_logout_request(
    settings: dict[str, Any],
    saml_request: str,
    *,
    request_data: dict[str, Any],
) -> tuple[str | None, str, list[str]]:
    """Validate an IdP's LogoutRequest and read who it signs out.

    SAML Profiles 4.4.4.1: the request must be signed. The HTTP-Redirect
    binding carries the signature in the query (``Signature``/``SigAlg``,
    checked against the raw query string); the HTTP-POST binding carries an
    enveloped XML signature. Either is checked against the IdP's signing
    certificates. Then python3-saml's strict checks: schema, ``Issuer`` is
    the IdP, ``Destination`` is this endpoint, ``NotOnOrAfter`` not passed.

    Args:
        settings: python3-saml settings for the IdP (``build_saml_settings``).
        saml_request: The SAMLRequest parameter as received.
        request_data: python3-saml request data for this endpoint:
            ``https``, ``http_host``, ``script_name``, ``get_data`` (the
            query parameters for the redirect binding, else empty) and, for
            the redirect binding, ``query_string``.

    Returns:
        ``(request_id, name_id, session_indexes)``.

    Raises:
        LogoutRequestError: with the reason the request was refused.
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    xml = decode_logout_request(saml_request)
    get_data = request_data.get("get_data") or {}

    if get_data.get("SAMLRequest"):
        if not get_data.get("Signature") or not get_data.get("SigAlg"):
            raise LogoutRequestError("unsigned")
        auth = OneLogin_Saml2_Auth({**request_data, "validate_signature_from_qs": True}, settings)
        if not auth.validate_request_signature(get_data):
            raise LogoutRequestError("signature")
    else:
        _verify_enveloped_logout_request_signature(xml, settings)

    logout_request = OneLogin_Saml2_Logout_Request(OneLogin_Saml2_Settings(settings), saml_request)
    try:
        logout_request.is_valid(request_data, raise_exceptions=True)
    except Exception as exc:  # noqa: BLE001 - python3-saml validation errors
        raise LogoutRequestError("invalid", str(exc)) from exc

    try:
        name_id = OneLogin_Saml2_Logout_Request.get_nameid(xml, key=settings["sp"]["privateKey"])
    except Exception as exc:  # noqa: BLE001 - missing or undecryptable NameID
        raise LogoutRequestError("name_id", str(exc)) from exc
    if not name_id:
        raise LogoutRequestError("name_id")

    return (
        OneLogin_Saml2_Logout_Request.get_id(xml),
        name_id,
        OneLogin_Saml2_Logout_Request.get_session_indexes(xml),
    )


def build_logout_response(
    settings: dict[str, Any],
    in_response_to: str | None = None,
    relay_state: str | None = None,
) -> str:
    """Build the signed HTTP-Redirect URL answering an IdP's LogoutRequest.

    Args:
        settings: python3-saml settings dict (from build_saml_settings)
        in_response_to: The ID of the LogoutRequest we're responding to
        relay_state: The request's RelayState, echoed back (Bindings 3.4.3)

    Returns:
        The IdP's SLO URL with ``SAMLResponse``, ``RelayState`` (when given),
        ``SigAlg`` and ``Signature``.
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.logout_response import OneLogin_Saml2_Logout_Response
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

    idp_slo_url = settings.get("idp", {}).get("singleLogoutService", {}).get("url", "")
    if not idp_slo_url:
        raise ValueError("IdP has no SLO URL configured")

    saml_settings = OneLogin_Saml2_Settings(settings)
    logout_response = OneLogin_Saml2_Logout_Response(saml_settings)
    logout_response.build(in_response_to)

    parameters = {"SAMLResponse": logout_response.get_response()}
    if relay_state:
        parameters["RelayState"] = relay_state
    auth = OneLogin_Saml2_Auth({"http_host": "", "script_name": "", "get_data": {}}, settings)
    auth.add_response_signature(parameters, saml_settings.get_security_data()["signatureAlgorithm"])
    return str(OneLogin_Saml2_Utils.redirect(idp_slo_url, parameters))
