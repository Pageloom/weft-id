"""MFA service layer.

This module provides business logic for MFA operations:
- MFA status retrieval
- TOTP setup and verification
- Email MFA enable/downgrade
- Backup code management
- Admin MFA reset

All functions:
- Receive a RequestingUser for authorization (where applicable)
- Return Pydantic models from app/schemas/api.py
- Raise ServiceError subclasses on failures
- Have no knowledge of HTTP concepts
"""

import database
from schemas.api import (
    BackupCodesResponse,
    BackupCodesStatusResponse,
    MFAEnableResponse,
    MFAStatus,
    TOTPSetupResponse,
)
from services.activity import track_activity
from services.event_log import log_event
from services.exceptions import (
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser
from utils.mfa import (
    create_email_otp,
    decrypt_secret,
    encrypt_secret,
    format_secret_for_display,
    generate_backup_codes,
    generate_totp_secret,
    generate_totp_uri,
    hash_code,
    verify_email_otp,
    verify_totp_code,
)

# =============================================================================
# Authorization Helpers (private)
# =============================================================================


def _require_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not admin or super_admin."""
    if user["role"] not in ("admin", "super_admin"):
        # Log authorization failure before raising
        log_event(
            tenant_id=user["tenant_id"],
            actor_user_id=user["id"],
            artifact_type="user",
            artifact_id=user["id"],
            event_type="authorization_denied",
            metadata={
                "required_role": "admin",
                "actual_role": user["role"],
                "service": "mfa",
            },
            request_metadata=user.get("request_metadata"),
        )
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
            required_role="admin",
        )


# =============================================================================
# Internal Helpers (private)
# =============================================================================


def _build_mfa_status(tenant_id: str, user_data: dict) -> MFAStatus:
    """Build MFAStatus from user data."""
    backup_codes = database.mfa.list_backup_codes(tenant_id, user_data["id"])
    remaining = sum(1 for c in backup_codes if c.get("used_at") is None)

    return MFAStatus(
        enabled=user_data.get("mfa_enabled", False),
        method=user_data.get("mfa_method"),
        has_backup_codes=len(backup_codes) > 0,
        backup_codes_remaining=remaining,
    )


def _get_refreshed_user(tenant_id: str, user_id: str) -> dict:
    """Get fresh user data from database. Raises ValidationError if not found."""
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise ValidationError(
            message="Failed to retrieve user",
            code="user_retrieval_failed",
        )
    return user


def _generate_and_store_backup_codes(tenant_id: str, user_id: str) -> list[str]:
    """Generate backup codes, hash and store them, return plaintext codes."""
    # Delete existing backup codes
    database.mfa.delete_backup_codes(tenant_id, user_id)

    # Generate new backup codes
    backup_codes = generate_backup_codes()

    # Store hashed backup codes
    for code_str in backup_codes:
        code_hash = hash_code(code_str.replace("-", ""))
        database.mfa.create_backup_code(tenant_id, user_id, code_hash, tenant_id)

    return backup_codes


# =============================================================================
# MFA Status
# =============================================================================


def get_mfa_status(
    requesting_user: RequestingUser,
    user_data: dict,
) -> MFAStatus:
    """
    Get MFA status for a user.

    Authorization: User can only get their own MFA status.

    Args:
        requesting_user: The authenticated user making the request
        user_data: The user data dict (should match requesting_user)

    Returns:
        MFAStatus with current state
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    tenant_id = requesting_user["tenant_id"]
    return _build_mfa_status(tenant_id, user_data)


def get_backup_codes_status(
    requesting_user: RequestingUser,
    user_data: dict,
) -> BackupCodesStatusResponse:
    """
    Get backup codes status for a user.

    Authorization: User can only get their own backup codes status.

    Args:
        requesting_user: The authenticated user making the request
        user_data: The user data dict (should match requesting_user)

    Returns:
        BackupCodesStatusResponse with total, used, remaining counts
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    tenant_id = requesting_user["tenant_id"]
    backup_codes = database.mfa.list_backup_codes(tenant_id, user_data["id"])

    total = len(backup_codes)
    used = sum(1 for c in backup_codes if c.get("used_at") is not None)
    remaining = total - used

    return BackupCodesStatusResponse(total=total, used=used, remaining=remaining)


# =============================================================================
# TOTP Setup Flow
# =============================================================================


def setup_totp(
    requesting_user: RequestingUser,
    user_data: dict,
) -> TOTPSetupResponse:
    """
    Initiate TOTP setup for a user.

    Generates a new TOTP secret and stores it unverified.
    The secret must be verified via verify_totp_and_enable() to complete setup.

    Authorization: User can only setup their own TOTP.

    Args:
        requesting_user: The authenticated user making the request
        user_data: The user data dict (should match requesting_user)

    Returns:
        TOTPSetupResponse with secret and provisioning URI

    Raises:
        ValidationError: If TOTP is already active
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = user_data["id"]

    # Prevent TOTP setup if TOTP is already active
    if user_data.get("mfa_method") == "totp":
        raise ValidationError(
            message="TOTP is already active. Downgrade to email MFA first to reconfigure.",
            code="totp_already_active",
        )

    # Generate TOTP secret
    secret = generate_totp_secret()
    secret_encrypted = encrypt_secret(secret)

    # Get user email for URI
    email_row = database.user_emails.get_primary_email(tenant_id, user_id)
    email = email_row["email"] if email_row else "user@example.com"

    # Generate URI for QR code
    uri = generate_totp_uri(secret, email)
    secret_display = format_secret_for_display(secret)

    # Store unverified secret
    database.mfa.create_totp_secret(tenant_id, user_id, secret_encrypted, tenant_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="user",
        artifact_id=str(user_id),
        event_type="totp_setup_initiated",
    )

    return TOTPSetupResponse(secret=secret_display, uri=uri)


def verify_totp_and_enable(
    requesting_user: RequestingUser,
    user_data: dict,
    code: str,
) -> BackupCodesResponse:
    """
    Verify TOTP code and enable TOTP MFA.

    After successful verification, backup codes are generated and returned.

    Authorization: User can only verify their own TOTP.

    Args:
        requesting_user: The authenticated user making the request
        user_data: The user data dict (should match requesting_user)
        code: The 6-digit TOTP code to verify

    Returns:
        BackupCodesResponse with generated backup codes

    Raises:
        ValidationError: If no TOTP setup in progress or code is invalid
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = user_data["id"]

    # Get unverified secret
    row = database.mfa.get_totp_secret(tenant_id, user_id, "totp")

    if not row:
        raise ValidationError(
            message="No TOTP setup in progress. Start setup first.",
            code="no_totp_pending",
        )

    secret = decrypt_secret(row["secret_encrypted"])
    code_clean = code.replace(" ", "").replace("-", "")

    if not verify_totp_code(secret, code_clean):
        raise ValidationError(
            message="Invalid TOTP code",
            code="invalid_totp_code",
        )

    # Mark secret as verified
    database.mfa.verify_totp_secret(tenant_id, user_id, "totp")

    # Enable TOTP MFA on user account
    database.mfa.enable_mfa(tenant_id, user_id, "totp")

    # Generate and store backup codes
    backup_codes = _generate_and_store_backup_codes(tenant_id, user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="user",
        artifact_id=str(user_id),
        event_type="mfa_totp_enabled",
    )

    return BackupCodesResponse(codes=backup_codes, count=len(backup_codes))


# =============================================================================
# Email MFA / Downgrade Flow
# =============================================================================


def enable_email_mfa(
    requesting_user: RequestingUser,
    user_data: dict,
) -> tuple[MFAEnableResponse, dict | None]:
    """
    Enable email MFA for a user.

    If user currently has TOTP enabled, this initiates a downgrade process
    (returns pending_verification=True and notification info for OTP delivery).

    If user has no MFA or already has email MFA, this enables email MFA directly.

    Authorization: User can only enable their own email MFA.

    Args:
        requesting_user: The authenticated user making the request
        user_data: The user data dict (should match requesting_user)

    Returns:
        Tuple of (MFAEnableResponse, notification_info or None)
        - If downgrade needed: response has pending_verification=True,
          notification_info has {"email": ..., "code": ...}
        - If enabled directly: response has status, notification_info is None

    Raises:
        ValidationError: If no primary email for verification (downgrade case)
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = user_data["id"]
    current_method = user_data.get("mfa_method")

    if current_method == "totp":
        # Downgrading from TOTP to email - require verification
        email_row = database.user_emails.get_primary_email(tenant_id, user_id)

        if not email_row:
            raise ValidationError(
                message="No primary email found for verification",
                code="no_primary_email",
            )

        # Create email OTP (stored in database, returns plaintext code)
        code = create_email_otp(tenant_id, user_id)

        response = MFAEnableResponse(
            status=None,
            pending_verification=True,
            message="Verification code sent. Use the verify-downgrade endpoint to complete.",
        )

        # Return notification info so route can send the email
        notification_info = {
            "email": email_row["email"],
            "code": code,
        }
        return response, notification_info

    # Normal case: enable email MFA directly
    database.mfa.enable_mfa(tenant_id, user_id, "email")

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="user",
        artifact_id=str(user_id),
        event_type="mfa_email_enabled",
    )

    # Refresh user data
    updated_user = _get_refreshed_user(tenant_id, user_id)

    response = MFAEnableResponse(
        status=_build_mfa_status(tenant_id, updated_user),
        pending_verification=False,
        message=None,
    )

    return response, None


def verify_mfa_downgrade(
    requesting_user: RequestingUser,
    user_data: dict,
    code: str,
) -> MFAStatus:
    """
    Complete TOTP to email MFA downgrade by verifying the email OTP.

    Authorization: User can only verify their own downgrade.

    Args:
        requesting_user: The authenticated user making the request
        user_data: The user data dict (should match requesting_user)
        code: The 6-digit email OTP code

    Returns:
        Updated MFAStatus

    Raises:
        ValidationError: If not in TOTP state or code is invalid
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = user_data["id"]

    # Verify user currently has TOTP
    if user_data.get("mfa_method") != "totp":
        raise ValidationError(
            message="This endpoint is only for downgrading from TOTP to email MFA",
            code="invalid_mfa_state",
        )

    # Verify the email OTP
    code_clean = code.replace(" ", "").replace("-", "")
    if not verify_email_otp(tenant_id, user_id, code_clean):
        raise ValidationError(
            message="Invalid or expired verification code",
            code="invalid_email_otp",
        )

    # Downgrade to email MFA
    database.mfa.set_mfa_method(tenant_id, user_id, "email")

    # Delete TOTP secrets
    database.mfa.delete_totp_secrets(tenant_id, user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="user",
        artifact_id=str(user_id),
        event_type="mfa_downgraded_to_email",
    )

    # Refresh user data
    updated_user = _get_refreshed_user(tenant_id, user_id)

    return _build_mfa_status(tenant_id, updated_user)


# =============================================================================
# MFA Management
# =============================================================================


def disable_mfa(
    requesting_user: RequestingUser,
    user_data: dict,
) -> MFAStatus:
    """
    Disable MFA for a user.

    Removes all MFA protection. TOTP secrets and backup codes are deleted.

    Authorization: User can only disable their own MFA.

    Args:
        requesting_user: The authenticated user making the request
        user_data: The user data dict (should match requesting_user)

    Returns:
        Updated MFAStatus (with enabled=False)
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = user_data["id"]

    # Capture previous method for logging
    previous_method = user_data.get("mfa_method")

    # Disable MFA
    database.mfa.enable_mfa(tenant_id, user_id, "email")  # Reset method first
    database.users.update_mfa_status(tenant_id, user_id, enabled=False)

    # Delete TOTP secrets and backup codes
    database.mfa.delete_totp_secrets(tenant_id, user_id)
    database.mfa.delete_backup_codes(tenant_id, user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="user",
        artifact_id=str(user_id),
        event_type="mfa_disabled",
        metadata={"previous_method": previous_method},
    )

    # Refresh user data
    updated_user = _get_refreshed_user(tenant_id, user_id)

    return _build_mfa_status(tenant_id, updated_user)


def regenerate_backup_codes(
    requesting_user: RequestingUser,
    user_data: dict,
) -> BackupCodesResponse:
    """
    Regenerate backup codes for a user.

    Deletes all existing backup codes and generates new ones.

    Authorization: User can only regenerate their own backup codes.

    Args:
        requesting_user: The authenticated user making the request
        user_data: The user data dict (should match requesting_user)

    Returns:
        BackupCodesResponse with new codes

    Raises:
        ValidationError: If MFA is not enabled
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = user_data["id"]

    if not user_data.get("mfa_enabled"):
        raise ValidationError(
            message="MFA must be enabled to regenerate backup codes",
            code="mfa_not_enabled",
        )

    # Generate and store new backup codes
    backup_codes = _generate_and_store_backup_codes(tenant_id, user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="user",
        artifact_id=str(user_id),
        event_type="mfa_backup_codes_regenerated",
    )

    return BackupCodesResponse(codes=backup_codes, count=len(backup_codes))


# =============================================================================
# Admin Operations
# =============================================================================


def reset_user_mfa(
    requesting_user: RequestingUser,
    target_user_id: str,
) -> MFAStatus:
    """
    Reset MFA for a user (admin operation).

    Disables MFA and deletes all TOTP secrets and backup codes.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated admin making the request
        target_user_id: UUID of the user to reset

    Returns:
        Updated MFAStatus for the target user

    Raises:
        ForbiddenError: If requesting user is not admin
        NotFoundError: If target user does not exist
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify user exists
    user = database.users.get_user_by_id(tenant_id, target_user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
            details={"user_id": target_user_id},
        )

    # Capture previous state for logging
    previous_method = user.get("mfa_method")
    was_enabled = user.get("mfa_enabled", False)

    # Disable MFA
    database.users.update_mfa_status(tenant_id, target_user_id, enabled=False)

    # Delete TOTP secrets and backup codes
    database.mfa.delete_totp_secrets(tenant_id, target_user_id)
    database.mfa.delete_backup_codes(tenant_id, target_user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=target_user_id,
        event_type="mfa_reset_by_admin",
        metadata={
            "previous_method": previous_method,
            "was_enabled": was_enabled,
        },
    )

    # Refresh user data
    updated_user = _get_refreshed_user(tenant_id, target_user_id)

    return _build_mfa_status(tenant_id, updated_user)


# =============================================================================
# Utility Functions (for HTML routes)
# =============================================================================


def list_backup_codes_raw(tenant_id: str, user_id: str) -> list[dict]:
    """
    Get raw backup codes list for a user.

    This is a utility function for HTML templates that need the raw database
    rows (e.g., to display masked codes with used_at timestamps).

    Args:
        tenant_id: Tenant ID
        user_id: User UUID

    Returns:
        List of backup code dicts from database
    """
    return database.mfa.list_backup_codes(tenant_id, user_id)


def get_pending_totp_setup(tenant_id: str, user_id: str) -> tuple[str, str] | None:
    """
    Get pending TOTP setup info (secret and URI) for re-display on error.

    This is a utility function for HTML routes that need to re-display
    the TOTP setup page when verification fails.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID

    Returns:
        Tuple of (secret_display, uri) or None if no pending setup
    """
    row = database.mfa.get_totp_secret(tenant_id, user_id, "totp")
    if not row:
        return None

    secret = decrypt_secret(row["secret_encrypted"])
    email_row = database.user_emails.get_primary_email(tenant_id, user_id)
    email = email_row["email"] if email_row else "user@example.com"

    uri = generate_totp_uri(secret, email)
    secret_display = format_secret_for_display(secret)

    return secret_display, uri


def generate_initial_backup_codes(tenant_id: str, user_id: str) -> list[str]:
    """
    Generate initial backup codes for a user (without requiring MFA to be enabled).

    This is for the HTML route that generates initial backup codes without
    the MFA enabled check that regenerate_backup_codes has.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID

    Returns:
        List of plaintext backup code strings
    """
    return _generate_and_store_backup_codes(tenant_id, user_id)
