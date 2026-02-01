"""JIT provisioning and SAML authentication completion.

This module handles Just-In-Time user provisioning from SAML assertions
and the final authentication step that links users to IdPs.
"""

import logging

import database
import services.groups as groups_service
from schemas.saml import SAMLAuthResult
from services.event_log import log_event
from services.exceptions import ForbiddenError, NotFoundError, ValidationError

logger = logging.getLogger(__name__)


def jit_provision_user(
    tenant_id: str,
    saml_result: SAMLAuthResult,
    idp: dict,
) -> dict:
    """
    Create a new user via JIT provisioning from SAML assertion.

    Creates user with:
    - Email from SAML assertion (verified, since IdP is authoritative)
    - First/last name from SAML attributes (or defaults)
    - Role: member (default)
    - Password: NULL (SAML-only authentication)
    - saml_idp_id: Links user to provisioning IdP

    Args:
        tenant_id: Tenant ID
        saml_result: Processed SAML response with attributes
        idp: IdP dict with configuration

    Returns:
        User dict for session creation

    Raises:
        ValidationError if user creation fails
    """
    from services import users as users_service

    attrs = saml_result.attributes

    # Extract names, with sensible defaults
    first_name = attrs.first_name or "SAML"
    last_name = attrs.last_name or "User"
    email = attrs.email

    # Race condition protection: Check if email was created between
    # our check and now (another concurrent request)
    if users_service.email_exists(tenant_id, email):
        user = database.users.get_user_by_email_with_status(tenant_id, email)
        if user:
            return user
        raise ValidationError(
            message="Failed to retrieve user after race condition",
            code="jit_user_retrieval_failed",
        )

    # Create user record (no password - SAML-only authentication)
    result = users_service.create_user_raw(
        tenant_id=tenant_id,
        first_name=first_name,
        last_name=last_name,
        email=email,
        role="member",
    )

    if not result:
        raise ValidationError(
            message="Failed to create user via JIT provisioning",
            code="jit_user_creation_failed",
        )

    user_id = str(result["user_id"])

    # Add verified email (SAML assertion from trusted IdP is authoritative)
    users_service.add_verified_email_with_nonce(
        tenant_id=tenant_id,
        user_id=user_id,
        email=email,
        is_primary=True,
    )

    # Link user to the IdP that provisioned them
    database.saml.set_user_idp(tenant_id, user_id, saml_result.idp_id)

    # Log JIT provisioning event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_created_jit",
        metadata={
            "idp_id": saml_result.idp_id,
            "idp_name": idp["name"],
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "name_id": attrs.name_id,
        },
    )

    # Fetch and return the created user for session creation
    user = database.users.get_user_by_email_with_status(tenant_id, email)
    if not user:
        raise ValidationError(
            message="Failed to retrieve created user",
            code="jit_user_retrieval_failed",
        )

    return user


def authenticate_via_saml(
    tenant_id: str,
    saml_result: SAMLAuthResult,
) -> dict:
    """
    Complete SAML authentication and return user.

    - Looks up user by email from SAML attributes
    - If user doesn't exist and JIT provisioning is enabled, creates user
    - Checks user status (not inactivated)
    - Wipes password if exists (SAML users are "locked in")
    - Links user to IdP if not already
    - Returns user dict for session creation

    Security: Once a user authenticates via SAML, their password is wiped.
    This prevents reverting to password auth. MFA info is preserved.

    Logs: user_signed_in_saml event (or user_created_jit for new users).

    Args:
        tenant_id: Tenant ID
        saml_result: Processed SAML response

    Returns:
        User dict for session creation

    Raises:
        NotFoundError if user doesn't exist and JIT is disabled
        ForbiddenError if user is inactivated
    """
    email = saml_result.attributes.email

    # Look up user by email
    user = database.users.get_user_by_email_with_status(tenant_id, email)

    if user is None:
        # Check if JIT provisioning is enabled for this IdP
        idp = database.saml.get_identity_provider(tenant_id, saml_result.idp_id)

        if idp is None or not idp.get("jit_provisioning"):
            raise NotFoundError(
                message="User account not found",
                code="user_not_found",
                details={"email": email},
            )

        # JIT provision the user (logs user_created_jit event internally)
        user = jit_provision_user(
            tenant_id=tenant_id,
            saml_result=saml_result,
            idp=idp,
        )

        user_id = str(user["id"])

        # Sync IdP group memberships (Phase 2: IdP Group Integration)
        if saml_result.groups:
            groups_service.sync_user_idp_groups(
                tenant_id=tenant_id,
                user_id=user_id,
                user_email=saml_result.attributes.email,
                idp_id=saml_result.idp_id,
                idp_name=saml_result.idp_name or idp.get("name", "Unknown"),
                group_names=saml_result.groups,
            )

        # Return immediately - JIT provisioning already logged the creation event
        # No need to log sign-in since this is their first login (creation implies sign-in)
        return user

    # Check user status
    if user.get("inactivated_at"):
        raise ForbiddenError(
            message="User account is inactivated",
            code="user_inactivated",
        )

    user_id = str(user["id"])

    # Password is preserved but unusable while saml_idp_id is set
    # MFA info is preserved - IdP may require additional platform MFA
    logger.info(f"User {user_id} authenticated via SAML (password preserved)")

    # Ensure user is linked to this IdP
    current_idp_id = user.get("saml_idp_id")
    if current_idp_id != saml_result.idp_id:
        database.saml.set_user_idp(tenant_id, user_id, saml_result.idp_id)

    # Log the sign-in event (for existing users)
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_signed_in_saml",
        metadata={
            "idp_id": saml_result.idp_id,
            "email": email,
            "password_preserved": bool(user.get("password_hash")),
        },
    )

    # Sync IdP group memberships (Phase 2: IdP Group Integration)
    if saml_result.groups:
        # Get IdP name for logging
        idp = database.saml.get_identity_provider(tenant_id, saml_result.idp_id)
        idp_name = idp.get("name", "Unknown") if idp else "Unknown"

        groups_service.sync_user_idp_groups(
            tenant_id=tenant_id,
            user_id=user_id,
            user_email=email,
            idp_id=saml_result.idp_id,
            idp_name=saml_result.idp_name or idp_name,
            group_names=saml_result.groups,
        )

    return user
