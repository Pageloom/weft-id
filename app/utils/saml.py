"""SAML utilities for certificate generation and encryption."""

import base64
import datetime
import hashlib
import xml.etree.ElementTree as ET
from typing import Any

import settings
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _get_encryption_key() -> bytes:
    """Get or generate encryption key from settings."""
    key_str = settings.SAML_KEY_ENCRYPTION_KEY
    # Ensure the key is valid base64 and correct length for Fernet
    try:
        key_bytes = base64.urlsafe_b64decode(key_str)
        if len(key_bytes) == 32:
            return base64.urlsafe_b64encode(key_bytes)
    except Exception:
        pass
    # Fallback: derive from the string (not ideal but better than random)
    # Use first 32 bytes of SHA256 hash
    key_hash = hashlib.sha256(key_str.encode()).digest()
    return base64.urlsafe_b64encode(key_hash)


_cipher = Fernet(_get_encryption_key())


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
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Loom Identity Platform"),
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
    if isinstance(cert, list):
        cert = cert[0] if cert else None
    if not cert:
        raise ValueError("IdP metadata missing X.509 certificate")

    # Format certificate as PEM if needed
    if not cert.startswith("-----BEGIN"):
        cert = f"-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----"

    return {
        "entity_id": entity_id,
        "sso_url": sso_url,
        "slo_url": slo_url,
        "certificate_pem": cert,
    }


def fetch_idp_metadata(url: str, timeout: int = 10) -> str:
    """
    Fetch IdP metadata XML from a URL.

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
        with urllib.request.urlopen(req, timeout=timeout) as response:
            content = response.read().decode("utf-8")

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


def generate_sp_metadata_xml(
    entity_id: str,
    acs_url: str,
    certificate_pem: str,
    slo_url: str | None = None,
) -> str:
    """
    Generate SP metadata XML for IdPs to consume.

    Args:
        entity_id: SP entity ID (usually the metadata URL)
        acs_url: Assertion Consumer Service URL
        certificate_pem: PEM-encoded SP signing certificate
        slo_url: Optional Single Logout URL

    Returns:
        XML metadata string
    """
    # Extract the raw certificate data (without PEM headers)
    cert_lines = certificate_pem.strip().split("\n")
    cert_data = "".join(line for line in cert_lines if not line.startswith("-----"))

    slo_section = ""
    if slo_url:
        slo_section = f"""
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{slo_url}" />"""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="{entity_id}">
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
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{acs_url}"
        index="0"
        isDefault="true" />{slo_section}
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
        root = ET.fromstring(xml_str)

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


def process_logout_request(
    settings: dict[str, Any],
    request_data: dict[str, Any],
) -> tuple[str | None, str | None, str | None]:
    """
    Process an incoming SAML LogoutRequest from IdP (IdP-initiated SLO).

    Args:
        settings: python3-saml settings dict (from build_saml_settings)
        request_data: Request data dict with get_data or post_data containing SAMLRequest

    Returns:
        Tuple of (name_id, session_index, request_id)
        - name_id: The NameID of the user to log out (None if parsing fails)
        - session_index: The session index (None if not provided)
        - request_id: The ID of the LogoutRequest (for response correlation)
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    auth = OneLogin_Saml2_Auth(request_data, settings)

    try:
        # Process the SLO request (this validates signature, etc.)
        # We use keep_local_session=True because we handle session ourselves
        auth.process_slo(
            keep_local_session=True,
            delete_session_cb=lambda: None,
        )

        # Get the NameID from the request
        name_id = auth.get_nameid()
        session_index = auth.get_session_index()
        request_id = auth.get_last_request_id()

        return name_id, session_index, request_id

    except Exception:
        return None, None, None


def build_logout_response(
    settings: dict[str, Any],
    in_response_to: str | None = None,
) -> str:
    """
    Build a SAML LogoutResponse for IdP-initiated SLO.

    Args:
        settings: python3-saml settings dict (from build_saml_settings)
        in_response_to: The ID of the LogoutRequest we're responding to

    Returns:
        Redirect URL with encoded LogoutResponse
    """
    from onelogin.saml2.logout_response import OneLogin_Saml2_Logout_Response
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    from onelogin.saml2.utils import OneLogin_Saml2_Utils

    saml_settings = OneLogin_Saml2_Settings(settings)

    # Build the logout response
    logout_response = OneLogin_Saml2_Logout_Response(saml_settings)
    logout_response.build(in_response_to)

    # Get the IdP's SLO URL
    idp_slo_url = settings.get("idp", {}).get("singleLogoutService", {}).get("url", "")

    if not idp_slo_url:
        raise ValueError("IdP has no SLO URL configured")

    # Encode and build redirect URL
    response_encoded = OneLogin_Saml2_Utils.deflate_and_base64_encode(logout_response.get_xml())

    # Build redirect URL with SAMLResponse parameter
    separator = "&" if "?" in idp_slo_url else "?"
    redirect_url = f"{idp_slo_url}{separator}SAMLResponse={response_encoded}"

    return redirect_url
