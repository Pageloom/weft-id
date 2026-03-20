"""Password change, admin-forced reset, and self-service reset service functions."""

import logging

import database
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser
from utils.crypto import derive_hmac_key
from utils.email import send_password_reset_email
from utils.password import hash_password, verify_password
from utils.password_strength import compute_hibp_monitoring_data, validate_password
from utils.tokens import (
    PURPOSE_PASSWORD_RESET,
    extract_user_id_from_url_token,
    generate_url_token,
    verify_url_token,
)

logger = logging.getLogger(__name__)


def _get_policy(tenant_id: str) -> tuple[int, int]:
    """Get password policy for a tenant, returning (min_length, min_score)."""
    policy = database.security.get_password_policy(tenant_id)
    min_length = policy["minimum_password_length"] if policy else 14
    min_score = policy["minimum_zxcvbn_score"] if policy else 3
    return min_length, min_score


def _compute_hibp_and_policy_data(password: str, min_length: int, min_score: int) -> dict:
    """Compute HIBP monitoring data and policy-at-set values.

    Returns a dict of keyword arguments for update_password().
    """
    hmac_key = derive_hmac_key("hibp")
    prefix, check_hmac = compute_hibp_monitoring_data(password, hmac_key)
    return {
        "hibp_prefix": prefix,
        "hibp_check_hmac": check_hmac,
        "policy_length_at_set": min_length,
        "policy_score_at_set": min_score,
    }


def _revoke_oauth2_tokens(tenant_id: str, user_id: str, reason: str) -> None:
    """Revoke all OAuth2 tokens for a user and log the event."""
    revoked = database.oauth2.revoke_all_user_tokens(tenant_id, user_id)
    if revoked > 0:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            event_type="oauth2_user_tokens_revoked",
            artifact_type="user",
            artifact_id=user_id,
            metadata={"reason": reason, "tokens_revoked": revoked},
        )


def change_password(
    requesting_user: RequestingUser,
    current_password: str,
    new_password: str,
) -> None:
    """Change the current user's password.

    Authorization: Authenticated user changing their own password.
    Requires current password verification and strength validation.

    Args:
        requesting_user: The authenticated user
        current_password: Current password for verification
        new_password: New password to set

    Raises:
        ValidationError: If current password is wrong or new password is weak
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = requesting_user["id"]

    # Fetch password hash to verify current password
    password_hash_val = database.users.get_password_hash(tenant_id, user_id)
    if not password_hash_val:
        raise ValidationError(
            message="This account does not use password authentication.",
            code="no_password",
        )

    # Verify current password
    if not verify_password(password_hash_val, current_password):
        raise ValidationError(
            message="Current password is incorrect.",
            code="invalid_current_password",
        )

    # Reject same-password reuse
    if verify_password(password_hash_val, new_password):
        raise ValidationError(
            message="New password must be different from your current password.",
            code="password_same_as_current",
        )

    # Validate new password strength
    min_length, min_score = _get_policy(tenant_id)

    # Get user email for zxcvbn context
    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    user_inputs = [primary_email["email"]] if primary_email else []

    strength = validate_password(
        new_password,
        minimum_length=min_length,
        minimum_score=min_score,
        user_role=requesting_user.get("role"),
        user_inputs=user_inputs,
    )
    if not strength.is_valid:
        issue = strength.issues[0]
        raise ValidationError(message=issue.message, code=issue.code)

    # Update password with HIBP monitoring and policy data
    new_hash = hash_password(new_password)
    lifecycle_data = _compute_hibp_and_policy_data(new_password, min_length, min_score)
    database.users.update_password(tenant_id, user_id, new_hash, **lifecycle_data)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        event_type="password_changed",
        artifact_type="user",
        artifact_id=user_id,
    )


def force_password_reset(
    requesting_user: RequestingUser,
    target_user_id: str,
) -> None:
    """Force a user to change their password on next login.

    Authorization: Requires admin role. Admins can force reset on any user
    including super admins. Cannot force reset on yourself.

    Also revokes all OAuth2 tokens for the user, since tokens issued via
    authorization_code flow represent user-level grants that are no longer
    trustworthy. Client credentials tokens use a different user_id and
    are not affected.

    Args:
        requesting_user: The admin performing the action
        target_user_id: The user to force reset

    Raises:
        ForbiddenError: If not admin
        NotFoundError: If target user not found
        ValidationError: If target is self or not a password user
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]

    if requesting_user["id"] == target_user_id:
        raise ValidationError(
            message="You cannot force a password reset on your own account. "
            "Use the password change page instead.",
            code="cannot_force_reset_self",
        )

    target_user = database.users.get_user_by_id(tenant_id, target_user_id)
    if not target_user:
        raise NotFoundError(
            message="User not found.",
            code="user_not_found",
        )

    if not target_user.get("has_password"):
        raise ValidationError(
            message="This user authenticates via an identity provider "
            "and does not have a password.",
            code="no_password",
        )

    if target_user.get("is_inactivated"):
        raise ValidationError(
            message="Cannot force password reset on an inactivated user.",
            code="user_inactivated",
        )

    database.users.set_password_reset_required(tenant_id, target_user_id, True)

    # Revoke OAuth2 tokens (authorization_code grants)
    _revoke_oauth2_tokens(tenant_id, target_user_id, "admin_forced")

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="password_reset_forced",
        artifact_type="user",
        artifact_id=target_user_id,
        metadata={
            "target_user_name": f"{target_user['first_name']} {target_user['last_name']}",
        },
    )


def complete_forced_password_reset(
    tenant_id: str,
    user_id: str,
    new_password: str,
) -> None:
    """Complete a forced password reset.

    This is called from the forced reset page, where the user is not yet
    fully authenticated (no session). Authorization is handled by the
    session's pending_password_reset_user_id.

    Args:
        tenant_id: Tenant ID
        user_id: User completing the reset
        new_password: New password

    Raises:
        ValidationError: If password is weak or user not found
    """
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise ValidationError(message="User not found.", code="user_not_found")

    # Reject same-password reuse
    password_hash_val = database.users.get_password_hash(tenant_id, user_id)
    if password_hash_val and verify_password(password_hash_val, new_password):
        raise ValidationError(
            message="New password must be different from your current password.",
            code="password_same_as_current",
        )

    # Validate new password strength
    min_length, min_score = _get_policy(tenant_id)

    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    user_inputs = [primary_email["email"]] if primary_email else []

    strength = validate_password(
        new_password,
        minimum_length=min_length,
        minimum_score=min_score,
        user_role=user.get("role"),
        user_inputs=user_inputs,
    )
    if not strength.is_valid:
        issue = strength.issues[0]
        raise ValidationError(message=issue.message, code=issue.code)

    # Update password (also clears password_reset_required flag)
    new_hash = hash_password(new_password)
    lifecycle_data = _compute_hibp_and_policy_data(new_password, min_length, min_score)
    database.users.update_password(tenant_id, user_id, new_hash, **lifecycle_data)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        event_type="password_reset_completed",
        artifact_type="user",
        artifact_id=user_id,
    )


def request_password_reset(
    tenant_id: str,
    email: str,
    base_url: str,
    client_ip: str | None = None,
) -> None:
    """Request a self-service password reset.

    Sends a reset link to the user's email if the account is eligible.
    Always returns normally (never reveals whether the email exists).

    Args:
        tenant_id: Tenant ID
        email: Email address to send the reset link to
        base_url: Base URL for building the reset link
        client_ip: Client IP for audit logging
    """
    email = email.strip().lower()

    user = database.users.get_user_by_email_for_reset(tenant_id, email)

    # Silently bail for non-existent, IdP-federated, no-password, or inactivated users
    if not user:
        return
    if user.get("saml_idp_id"):
        return
    if not user.get("has_password"):
        return
    if user.get("is_inactivated"):
        return

    user_id = str(user["user_id"])
    state = str(user["password_changed_at"]) if user.get("password_changed_at") else ""

    token = generate_url_token(user_id, PURPOSE_PASSWORD_RESET, ttl_seconds=1800, state=state)

    reset_url = f"{base_url.rstrip('/')}/reset-password/{token}"
    send_password_reset_email(email, reset_url)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        event_type="password_reset_requested",
        artifact_type="user",
        artifact_id=user_id,
        metadata={"email": email, "ip": client_ip},
    )


def complete_self_service_password_reset(
    tenant_id: str,
    user_id: str,
    new_password: str,
) -> None:
    """Complete a self-service password reset.

    Called after the user clicks the reset link and submits a new password.
    Authorization is handled by token verification in the router.

    No same-password reuse check (user has forgotten their password).

    Args:
        tenant_id: Tenant ID
        user_id: User completing the reset
        new_password: New password

    Raises:
        ValidationError: If password is weak or user not found
    """
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise ValidationError(message="User not found.", code="user_not_found")

    # Validate new password strength
    min_length, min_score = _get_policy(tenant_id)

    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    user_inputs = [primary_email["email"]] if primary_email else []

    strength = validate_password(
        new_password,
        minimum_length=min_length,
        minimum_score=min_score,
        user_role=user.get("role"),
        user_inputs=user_inputs,
    )
    if not strength.is_valid:
        issue = strength.issues[0]
        raise ValidationError(message=issue.message, code=issue.code)

    # Update password (sets password_changed_at, which invalidates the token)
    new_hash = hash_password(new_password)
    lifecycle_data = _compute_hibp_and_policy_data(new_password, min_length, min_score)
    database.users.update_password(tenant_id, user_id, new_hash, **lifecycle_data)

    # Revoke OAuth2 tokens
    _revoke_oauth2_tokens(tenant_id, user_id, "self_service_reset")

    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        event_type="password_self_reset_completed",
        artifact_type="user",
        artifact_id=user_id,
    )


_RESET_TTL = 1800  # 30 minutes


def validate_reset_token(tenant_id: str, token: str) -> dict | None:
    """Validate a password reset URL token.

    Extracts the user_id from the token, looks up the user to get
    password_changed_at for state verification, then verifies the HMAC.

    Args:
        tenant_id: Tenant ID
        token: The URL token from the reset link

    Returns:
        A dict with user_id, role, and password policy info if valid,
        or None if the token is invalid or expired.
    """
    user_id = extract_user_id_from_url_token(token)
    if not user_id:
        return None

    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        return None

    state = str(user.get("password_changed_at") or "")
    verified_user_id = verify_url_token(
        token, PURPOSE_PASSWORD_RESET, ttl_seconds=_RESET_TTL, state=state
    )
    if not verified_user_id:
        return None

    min_length, min_score = _get_policy(tenant_id)
    if user.get("role") == "super_admin":
        min_length = max(min_length, 20)

    return {
        "user_id": verified_user_id,
        "role": user.get("role"),
        "minimum_password_length": min_length,
        "minimum_zxcvbn_score": min_score,
    }
