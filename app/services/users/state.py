"""User lifecycle state operations.

This module provides business logic for user state transitions:
- inactivate_user
- reactivate_user
- self_reactivate_super_admin
- anonymize_user

These operations manage the user lifecycle from active to inactivated
to anonymized (GDPR right to be forgotten).
"""

import database
from schemas.api import UserDetail
from services.auth import require_admin, require_super_admin
from services.event_log import log_event
from services.exceptions import (
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser
from services.users.crud import get_user


def inactivate_user(
    requesting_user: RequestingUser,
    user_id: str,
) -> UserDetail:
    """
    Inactivate a user account (soft-disable login).

    Inactivated users cannot sign in but retain all their data.
    This operation is reversible via reactivate_user().

    Authorization: Requires admin role. Cannot inactivate self,
    service users, or the last super_admin.

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user to inactivate

    Returns:
        UserDetail for the inactivated user

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If user does not exist
        ValidationError: If inactivation would violate constraints
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Get user
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
            details={"user_id": user_id},
        )

    # Cannot inactivate yourself
    if str(user["id"]) == requesting_user["id"]:
        raise ValidationError(
            message="Cannot inactivate your own account",
            code="self_inactivation",
        )

    # Cannot inactivate service users
    if database.users.is_service_user(tenant_id, user_id):
        raise ValidationError(
            message="Cannot inactivate service user. Delete the associated OAuth2 client first.",
            code="service_user_inactivation",
        )

    # Already inactivated?
    if user.get("is_inactivated"):
        raise ValidationError(
            message="User is already inactivated",
            code="already_inactivated",
        )

    # Cannot inactivate last super_admin
    if user["role"] == "super_admin":
        active_super_admins = database.users.count_active_super_admins(tenant_id)
        if active_super_admins <= 1:
            raise ValidationError(
                message="Cannot inactivate the last super_admin",
                code="last_super_admin",
            )

    # Perform inactivation
    database.users.inactivate_user(tenant_id, user_id)

    # Revoke all OAuth tokens to immediately cut API access
    database.oauth2.revoke_all_user_tokens(tenant_id, user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_inactivated",
    )

    # Return updated user
    return get_user(requesting_user, user_id)


def reactivate_user(
    requesting_user: RequestingUser,
    user_id: str,
) -> UserDetail:
    """
    Reactivate an inactivated user account.

    Authorization: Requires admin role. Cannot reactivate anonymized users
    (anonymization is irreversible).

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user to reactivate

    Returns:
        UserDetail for the reactivated user

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If user does not exist
        ValidationError: If user is anonymized or not inactivated
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
            details={"user_id": user_id},
        )

    if user.get("is_anonymized"):
        raise ValidationError(
            message="Cannot reactivate anonymized user - anonymization is irreversible",
            code="anonymized_user",
        )

    if not user.get("is_inactivated"):
        raise ValidationError(
            message="User is not inactivated",
            code="not_inactivated",
        )

    database.users.reactivate_user(tenant_id, user_id)

    # Clear any reactivation denial flag
    database.users.clear_reactivation_denied(tenant_id, user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_reactivated",
    )

    return get_user(requesting_user, user_id)


def anonymize_user(
    requesting_user: RequestingUser,
    user_id: str,
) -> UserDetail:
    """
    Anonymize a user account (GDPR right to be forgotten).

    This is IRREVERSIBLE. Scrubs all PII:
    - User name becomes "[Anonymized] User"
    - Email addresses are anonymized
    - MFA data is deleted
    - Password is cleared

    The user record is preserved for audit log integrity.

    Authorization: Requires super_admin role. Cannot anonymize self,
    service users, or the last super_admin.

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user to anonymize

    Returns:
        UserDetail for the anonymized user

    Raises:
        ForbiddenError: If user lacks super_admin permissions
        NotFoundError: If user does not exist
        ValidationError: If anonymization would violate constraints
    """
    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
            details={"user_id": user_id},
        )

    # Cannot anonymize yourself
    if str(user["id"]) == requesting_user["id"]:
        raise ValidationError(
            message="Cannot anonymize your own account",
            code="self_anonymization",
        )

    # Cannot anonymize service users
    if database.users.is_service_user(tenant_id, user_id):
        raise ValidationError(
            message="Cannot anonymize service user. Delete the associated OAuth2 client first.",
            code="service_user_anonymization",
        )

    # Already anonymized?
    if user.get("is_anonymized"):
        raise ValidationError(
            message="User is already anonymized",
            code="already_anonymized",
        )

    # Cannot anonymize last super_admin (if they're a super_admin)
    if user["role"] == "super_admin":
        active_super_admins = database.users.count_active_super_admins(tenant_id)
        if active_super_admins <= 1:
            raise ValidationError(
                message="Cannot anonymize the last super_admin",
                code="last_super_admin",
            )

    # Capture user info for logging before anonymization
    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    user_email = primary_email["email"] if primary_email else None

    # Perform anonymization (order matters)
    # 1. Anonymize emails
    database.user_emails.anonymize_user_emails(tenant_id, user_id)

    # 2. Delete MFA data
    database.mfa.delete_all_user_mfa_data(tenant_id, user_id)

    # 3. Anonymize user record
    database.users.anonymize_user(tenant_id, user_id)

    # Log the event (with pre-anonymization info for audit trail)
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_anonymized",
        metadata={
            "anonymized_user_name": f"{user['first_name']} {user['last_name']}",
            "anonymized_user_email": user_email,
            "anonymized_user_role": user["role"],
        },
    )

    return get_user(requesting_user, user_id)
