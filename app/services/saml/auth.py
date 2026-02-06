"""SAML authentication request and response processing.

This module handles the core SAML authentication flow:
- Building SAML AuthnRequest
- Processing and validating SAML responses
- Testing SAML connections
"""

import logging

import database
from schemas.saml import (
    IdPConfig,
    IdPForLogin,
    SAMLAttributes,
    SAMLAuthResult,
    SAMLTestResult,
)
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
from services.saml._converters import idp_row_to_config
from services.saml._helpers import get_saml_attribute, get_saml_group_attributes
from utils.saml import build_saml_settings, decrypt_private_key

logger = logging.getLogger(__name__)


def _prepare_saml_auth(
    tenant_id: str,
    idp_id: str,
    saml_response: str | None = None,
    request_data: dict | None = None,
) -> tuple:
    """Build a OneLogin_Saml2_Auth instance for the given IdP.

    Loads IdP config, SP certificate, decrypts the private key, and
    constructs the SAML auth object.

    Returns:
        Tuple of (auth, idp) where auth is OneLogin_Saml2_Auth and idp is IdPConfig.
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    idp = get_idp_for_saml_login(tenant_id, idp_id)
    sp_cert = database.saml.get_sp_certificate(tenant_id)

    if sp_cert is None:
        raise NotFoundError(
            message="SP certificate not configured",
            code="sp_certificate_not_found",
        )

    sp_private_key = decrypt_private_key(sp_cert["private_key_pem_enc"])
    sp_acs_url = idp.sp_entity_id.replace("/saml/metadata", "/saml/acs")

    settings = build_saml_settings(
        sp_entity_id=idp.sp_entity_id,
        sp_acs_url=sp_acs_url,
        sp_certificate_pem=sp_cert["certificate_pem"],
        sp_private_key_pem=sp_private_key,
        idp_entity_id=idp.entity_id,
        idp_sso_url=idp.sso_url,
        idp_certificate_pem=idp.certificate_pem,
        idp_slo_url=idp.slo_url,
    )

    if request_data is None:
        request_data = {
            "https": "on",
            "http_host": "",
            "script_name": "",
            "get_data": {},
            "post_data": {},
        }

    if saml_response is not None:
        request_data["post_data"] = {"SAMLResponse": saml_response}

    auth = OneLogin_Saml2_Auth(request_data, settings)
    return auth, idp


def _extract_mapped_attributes(
    auth: object,
    idp: IdPConfig,
) -> dict:
    """Extract and map SAML attributes from a processed auth response.

    Returns:
        Dict with keys: email, first_name, last_name, groups, name_id,
        name_id_format, raw_attributes.
    """
    raw_attributes = auth.get_attributes()
    name_id = auth.get_nameid()
    name_id_format = auth.get_nameid_format()

    mapping = idp.attribute_mapping
    email = get_saml_attribute(raw_attributes, mapping.get("email", "email"))
    first_name = get_saml_attribute(raw_attributes, mapping.get("first_name", "firstName"))
    last_name = get_saml_attribute(raw_attributes, mapping.get("last_name", "lastName"))
    groups = get_saml_group_attributes(raw_attributes, mapping.get("groups", "groups"))

    return {
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
        "groups": groups,
        "name_id": name_id,
        "name_id_format": name_id_format,
        "raw_attributes": raw_attributes,
    }


def get_enabled_idps_for_login(tenant_id: str) -> list[IdPForLogin]:
    """
    Get enabled IdPs for login page display.

    No authorization required (used on login page).
    """
    rows = database.saml.get_enabled_identity_providers(tenant_id)
    return [
        IdPForLogin(
            id=str(row["id"]),
            name=row["name"],
            provider_type=row["provider_type"],
        )
        for row in rows
    ]


def get_default_idp(tenant_id: str) -> IdPConfig | None:
    """
    Get the default IdP for the tenant.

    No authorization required.
    """
    row = database.saml.get_default_identity_provider(tenant_id)
    return idp_row_to_config(row) if row else None


def get_idp_for_saml_login(tenant_id: str, idp_id: str) -> IdPConfig:
    """
    Get IdP configuration for SAML login by IdP ID.

    Validates that the IdP exists and is enabled.

    No authorization required (used during login flow).
    """
    row = database.saml.get_identity_provider(tenant_id, idp_id)

    if row is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    if not row["is_enabled"]:
        raise ForbiddenError(
            message="Identity provider is not enabled",
            code="idp_disabled",
        )

    return idp_row_to_config(row)


def get_idp_by_issuer(tenant_id: str, issuer: str) -> IdPConfig:
    """
    Get IdP configuration by issuer (entity_id).

    Used to look up the IdP from a SAML response's Issuer field.
    Validates that the IdP exists and is enabled.

    No authorization required (used during login flow).

    Args:
        tenant_id: Tenant ID
        issuer: The Issuer entity ID from the SAML response

    Returns:
        IdPConfig for the matching IdP

    Raises:
        NotFoundError if no IdP matches the issuer
        ForbiddenError if the IdP is disabled
    """
    row = database.saml.get_identity_provider_by_entity_id(tenant_id, issuer)

    if row is None:
        raise NotFoundError(
            message="Identity provider not found for issuer",
            code="idp_issuer_not_found",
            details={"issuer": issuer},
        )

    if not row["is_enabled"]:
        raise ForbiddenError(
            message="Identity provider is not enabled",
            code="idp_disabled",
        )

    return idp_row_to_config(row)


def build_authn_request(
    tenant_id: str,
    idp_id: str,
    relay_state: str | None = None,
) -> tuple[str, str]:
    """
    Build SAML AuthnRequest and return redirect URL.

    No authorization required (used during login flow).

    Args:
        tenant_id: Tenant ID
        idp_id: IdP ID to authenticate with
        relay_state: Optional state to preserve through SAML flow

    Returns:
        Tuple of (redirect_url, request_id)
        request_id should be stored in session for response validation
    """
    auth, _idp = _prepare_saml_auth(tenant_id, idp_id)

    # Generate AuthnRequest
    redirect_url = auth.login(relay_state or "")
    request_id = auth.get_last_request_id()

    return redirect_url, request_id


def process_saml_response(
    tenant_id: str,
    idp_id: str,
    saml_response: str,
    request_id: str | None = None,
    request_data: dict | None = None,
) -> SAMLAuthResult:
    """
    Process and validate SAML response from IdP.

    Performs:
    - Signature validation (required, unsigned rejected)
    - NotOnOrAfter validation (replay prevention)
    - Attribute extraction

    No authorization required (used during login flow).

    Args:
        tenant_id: Tenant ID
        idp_id: IdP ID that sent the response
        saml_response: Base64-encoded SAML response
        request_id: Expected request ID (from session) for InResponseTo validation
        request_data: Request data dict for python3-saml

    Returns:
        SAMLAuthResult with attributes and authentication status

    Raises:
        ValidationError for invalid signatures, expired assertions, etc.
    """
    auth, idp = _prepare_saml_auth(tenant_id, idp_id, saml_response, request_data)

    # Process the response
    auth.process_response(request_id=request_id)

    # Check for errors
    errors = auth.get_errors()
    if errors:
        error_reason = auth.get_last_error_reason()
        raise ValidationError(
            message=f"SAML response validation failed: {error_reason or ', '.join(errors)}",
            code="saml_validation_failed",
            details={"errors": errors},
        )

    if not auth.is_authenticated():
        raise ValidationError(
            message="SAML authentication failed",
            code="saml_auth_failed",
        )

    # Extract and map attributes
    attrs = _extract_mapped_attributes(auth, idp)

    if not attrs["email"]:
        raise ValidationError(
            message="SAML response missing email attribute",
            code="saml_missing_email",
        )

    return SAMLAuthResult(
        attributes=SAMLAttributes(
            email=attrs["email"],
            first_name=attrs["first_name"],
            last_name=attrs["last_name"],
            name_id=attrs["name_id"],
            groups=attrs["groups"],
        ),
        session_index=auth.get_session_index(),
        name_id_format=attrs["name_id_format"],
        idp_id=idp_id,
        idp_name=idp.name,
        requires_mfa=idp.require_platform_mfa,
        groups=attrs["groups"],
    )


def process_saml_test_response(
    tenant_id: str,
    idp_id: str,
    saml_response: str,
    request_id: str | None = None,
    request_data: dict | None = None,
) -> SAMLTestResult:
    """
    Process SAML response for connection testing.

    Similar to process_saml_response() but:
    - Returns SAMLTestResult instead of raising exceptions
    - Includes all raw attributes for display
    - Does NOT create session or provision users

    No authorization required (used during test flow).

    Args:
        tenant_id: Tenant ID
        idp_id: IdP ID that sent the response
        saml_response: Base64-encoded SAML response
        request_id: Expected request ID (from session) for InResponseTo validation
        request_data: Request data dict for python3-saml

    Returns:
        SAMLTestResult with success status and assertion details or error info
    """
    try:
        auth, idp = _prepare_saml_auth(tenant_id, idp_id, saml_response, request_data)
        auth.process_response(request_id=request_id)

        # Check for errors
        errors = auth.get_errors()
        if errors:
            error_reason = auth.get_last_error_reason()
            error_str = str(error_reason).lower() if error_reason else ""

            # Categorize error type
            if "signature" in error_str:
                error_type = "signature_error"
            elif "expired" in error_str or "notonorafter" in error_str:
                error_type = "expired"
            else:
                error_type = "invalid_response"

            return SAMLTestResult(
                success=False,
                error_type=error_type,
                error_detail=error_reason or ", ".join(errors),
            )

        if not auth.is_authenticated():
            return SAMLTestResult(
                success=False,
                error_type="auth_failed",
                error_detail="SAML authentication failed",
            )

        # Extract and map attributes
        attrs = _extract_mapped_attributes(auth, idp)

        return SAMLTestResult(
            success=True,
            name_id=attrs["name_id"],
            name_id_format=attrs["name_id_format"],
            session_index=auth.get_session_index(),
            attributes=attrs["raw_attributes"],
            parsed_email=attrs["email"],
            parsed_first_name=attrs["first_name"],
            parsed_last_name=attrs["last_name"],
        )

    except NotFoundError as e:
        return SAMLTestResult(
            success=False,
            error_type="idp_not_found",
            error_detail=str(e),
        )
    except ForbiddenError as e:
        return SAMLTestResult(
            success=False,
            error_type="idp_disabled",
            error_detail=str(e),
        )
    except Exception as e:
        logger.exception("SAML test failed with unexpected error")
        return SAMLTestResult(
            success=False,
            error_type="unexpected_error",
            error_detail=str(e),
        )
