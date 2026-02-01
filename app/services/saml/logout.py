"""Single Logout (SLO) flows for SAML SSO.

This module handles SP-initiated and IdP-initiated logout flows.
"""

import logging

import database
from utils.saml import (
    build_logout_request,
    build_logout_response,
    build_saml_settings,
    decrypt_private_key,
    extract_issuer_from_response,
    process_logout_request,
)

logger = logging.getLogger(__name__)


def initiate_sp_logout(
    tenant_id: str,
    saml_idp_id: str,
    name_id: str,
    name_id_format: str | None,
    session_index: str | None,
    base_url: str,
) -> str | None:
    """
    Build SP-initiated logout request.

    No authorization required (called during logout flow).

    Returns redirect URL if IdP has SLO configured, None otherwise.
    SLO errors are logged but don't raise exceptions (non-blocking).

    Args:
        tenant_id: Tenant ID
        saml_idp_id: ID of the IdP the user logged in with
        name_id: NameID from the original SAML assertion
        name_id_format: NameID format (optional)
        session_index: Session index from the original assertion (optional)
        base_url: Base URL for building SP SLO URL

    Returns:
        Redirect URL for IdP SLO, or None if SLO not configured
    """
    try:
        # Get IdP configuration
        idp = database.saml.get_identity_provider(tenant_id, saml_idp_id)
        if not idp or not idp.get("slo_url"):
            return None

        # Get SP certificate
        sp_cert = database.saml.get_sp_certificate(tenant_id)
        if not sp_cert:
            logger.warning(f"No SP certificate for tenant {tenant_id}, skipping SLO")
            return None

        # Decrypt private key
        sp_private_key = decrypt_private_key(sp_cert["private_key_pem_enc"])

        # Build SAML settings
        sp_entity_id = f"{base_url}/saml/metadata"
        sp_acs_url = f"{base_url}/saml/acs"
        sp_slo_url = f"{base_url}/saml/slo"

        settings = build_saml_settings(
            sp_entity_id=sp_entity_id,
            sp_acs_url=sp_acs_url,
            sp_certificate_pem=sp_cert["certificate_pem"],
            sp_private_key_pem=sp_private_key,
            idp_entity_id=idp["entity_id"],
            idp_sso_url=idp["sso_url"],
            idp_certificate_pem=idp["certificate_pem"],
            idp_slo_url=idp["slo_url"],
            sp_slo_url=sp_slo_url,
        )

        # Build logout request
        redirect_url, request_id = build_logout_request(
            settings=settings,
            name_id=name_id,
            name_id_format=name_id_format,
            session_index=session_index,
        )

        logger.info(f"SLO initiated for tenant {tenant_id}, IdP {saml_idp_id}")
        return redirect_url

    except Exception as e:
        # SLO errors should never block logout
        logger.warning(f"SLO initiation failed for tenant {tenant_id}: {e}")
        return None


def process_idp_logout_request(
    tenant_id: str,
    saml_request: str,
    base_url: str,
    issuer: str | None = None,
) -> str | None:
    """
    Process an IdP-initiated LogoutRequest and return a LogoutResponse.

    No authorization required (called during logout flow).

    This is a "best effort" implementation. With cookie-based sessions,
    we cannot truly invalidate a specific user's session server-side.
    We acknowledge the request and return a success response to maintain
    protocol compliance with the IdP.

    Args:
        tenant_id: Tenant ID
        saml_request: Base64-encoded SAMLRequest (LogoutRequest)
        base_url: Base URL for SP
        issuer: Issuer from the request (used to identify IdP)

    Returns:
        Redirect URL with LogoutResponse, or None if processing fails
    """
    try:
        # Try to extract issuer from the SAML request if not provided
        if not issuer:
            issuer = extract_issuer_from_response(saml_request)

        if not issuer:
            logger.warning("IdP-initiated SLO: Could not determine issuer")
            return None

        # Get IdP by issuer
        idp = database.saml.get_identity_provider_by_entity_id(tenant_id, issuer)
        if not idp or not idp.get("slo_url"):
            logger.warning(f"IdP-initiated SLO: No IdP found for issuer {issuer}")
            return None

        # Get SP certificate
        sp_cert = database.saml.get_sp_certificate(tenant_id)
        if not sp_cert:
            logger.warning(f"IdP-initiated SLO: No SP certificate for tenant {tenant_id}")
            return None

        # Build SAML settings
        sp_private_key = decrypt_private_key(sp_cert["private_key_pem_enc"])
        sp_entity_id = f"{base_url}/saml/metadata"
        sp_acs_url = f"{base_url}/saml/acs"
        sp_slo_url = f"{base_url}/saml/slo"

        settings = build_saml_settings(
            sp_entity_id=sp_entity_id,
            sp_acs_url=sp_acs_url,
            sp_certificate_pem=sp_cert["certificate_pem"],
            sp_private_key_pem=sp_private_key,
            idp_entity_id=idp["entity_id"],
            idp_sso_url=idp["sso_url"],
            idp_certificate_pem=idp["certificate_pem"],
            idp_slo_url=idp["slo_url"],
            sp_slo_url=sp_slo_url,
        )

        # Process the incoming LogoutRequest
        request_data = {
            "http_host": "",
            "script_name": "",
            "get_data": {"SAMLRequest": saml_request},
            "post_data": {},
        }

        name_id, session_index, request_id = process_logout_request(settings, request_data)

        if name_id:
            logger.info(
                f"IdP-initiated SLO for NameID {name_id} from IdP {idp['name']}. "
                "Note: Cookie-based sessions cannot be server-side invalidated."
            )

        # Build and return LogoutResponse
        redirect_url = build_logout_response(settings, in_response_to=request_id)

        # Note: We don't log this event to the user event log because:
        # 1. There's no authenticated user context (IdP is the actor)
        # 2. The warning log above captures the event for operational monitoring

        return redirect_url

    except Exception as e:
        logger.warning(f"IdP-initiated SLO failed for tenant {tenant_id}: {e}")
        return None
