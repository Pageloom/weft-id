"""SP lookup and SSO response building.

Functions used by the SSO flow for looking up SPs, getting user consent info,
and building signed SAML responses.
"""

import logging

import database
from schemas.service_providers import SPConfig
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.service_providers._converters import _row_to_config
from utils.saml_idp import make_idp_entity_id

logger = logging.getLogger(__name__)


def get_service_provider_by_id(tenant_id: str, sp_id: str) -> dict | None:
    """Look up an SP by ID. No auth check required.

    Used by the SSO router for IdP-initiated flows.
    Tenant scoping is enforced by RLS at the database layer.

    Returns:
        Raw database row dict, or None if not found.
    """
    return database.service_providers.get_service_provider(tenant_id, sp_id)


def get_user_consent_info(tenant_id: str, user_id: str) -> dict | None:
    """Get user display info for the SSO consent screen.

    Returns dict with email, first_name, last_name, or None if user or
    primary email not found. No authorization check needed (user is
    viewing their own info).
    """
    user = database.users.get_user_by_id(tenant_id, user_id)
    if user is None:
        return None
    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email is None:
        return None
    return {
        "email": primary_email["email"],
        "first_name": user.get("first_name", ""),
        "last_name": user.get("last_name", ""),
    }


def get_sp_by_entity_id(tenant_id: str, entity_id: str) -> SPConfig | None:
    """Look up an SP by entity ID. No auth check required.

    Used by the SSO endpoint to find the SP that sent the AuthnRequest.
    Tenant scoping is enforced by RLS at the database layer.
    """
    row = database.service_providers.get_service_provider_by_entity_id(tenant_id, entity_id)
    if row is None:
        return None
    return _row_to_config(row)


def build_sso_response(
    tenant_id: str,
    user_id: str,
    sp_entity_id: str,
    authn_request_id: str | None,
    base_url: str,
) -> tuple[str, str, str]:
    """Build a signed SAML Response for an SSO assertion.

    Args:
        tenant_id: Tenant ID
        user_id: Authenticated user's ID
        sp_entity_id: Entity ID of the requesting SP
        authn_request_id: ID from the AuthnRequest (for InResponseTo)
        base_url: Base URL for building entity ID

    Returns:
        Tuple of (base64_encoded_response, acs_url, session_index)

    Raises:
        NotFoundError: If SP or signing certificate not found
        ValidationError: If user data is missing
    """
    from utils.saml import decrypt_private_key
    from utils.saml_assertion import build_saml_response

    # 1. Look up SP
    sp_row = database.service_providers.get_service_provider_by_entity_id(tenant_id, sp_entity_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    # 1b. Reject SPs where trust has not been established
    if not sp_row.get("trust_established", False):
        raise ValidationError(
            message="Service provider setup is not complete",
            code="sp_trust_not_established",
        )

    # 2. Get signing certificate (per-SP first, then tenant fallback)
    sp_id = str(sp_row["id"])
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert is None:
        cert = database.saml.get_sp_certificate(tenant_id)
    if cert is None:
        raise NotFoundError(
            message="IdP signing certificate not configured",
            code="idp_certificate_not_found",
        )

    # 3. Decrypt private key
    private_key_pem = decrypt_private_key(cert["private_key_pem_enc"])

    # 4. Get user info
    user = database.users.get_user_by_id(tenant_id, user_id)
    if user is None:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    primary_email_row = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email_row is None:
        raise ValidationError(
            message="User has no primary email",
            code="user_no_email",
        )

    email = primary_email_row["email"]

    # 5. Build user attributes
    first_name = user.get("first_name", "")
    last_name = user.get("last_name", "")
    user_attributes: dict[str, str | list[str]] = {
        "email": email,
        "firstName": first_name,
        "lastName": last_name,
        "displayName": f"{first_name} {last_name}".strip(),
    }

    # 5b. Include group claims if enabled for this SP
    if sp_row.get("include_group_claims", False):
        group_names = database.groups.get_effective_group_names(tenant_id, user_id)
        if group_names:
            user_attributes["groups"] = group_names

    # 6. Resolve NameID value and format
    from services.service_providers.nameid import resolve_name_id

    issuer_entity_id = make_idp_entity_id(tenant_id, sp_id)
    name_id_format = sp_row.get(
        "nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )

    name_id, resolved_format = resolve_name_id(
        tenant_id=tenant_id,
        user_id=user_id,
        sp_id=sp_id,
        nameid_format=name_id_format,
        user_email=email,
    )

    # 6b. Get per-SP attribute mapping (if configured)
    attribute_mapping = sp_row.get("attribute_mapping")

    # 6c. Encrypt assertion if SP provides an encryption certificate
    encryption_cert = sp_row.get("encryption_certificate_pem")
    assertion_encrypted = encryption_cert is not None

    saml_response_b64, session_index = build_saml_response(
        issuer_entity_id=issuer_entity_id,
        sp_entity_id=sp_entity_id,
        sp_acs_url=sp_row["acs_url"],
        name_id=name_id,
        name_id_format=resolved_format,
        authn_request_id=authn_request_id,
        user_attributes=user_attributes,
        certificate_pem=cert["certificate_pem"],
        private_key_pem=private_key_pem,
        attribute_mapping=attribute_mapping,
        encryption_certificate_pem=encryption_cert,
    )

    # 7. Log event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="service_provider",
        artifact_id=str(sp_row["id"]),
        event_type="sso_assertion_issued",
        metadata={
            "sp_entity_id": sp_entity_id,
            "sp_name": sp_row["name"],
            "assertion_encrypted": assertion_encrypted,
        },
    )

    return saml_response_b64, sp_row["acs_url"], session_index
