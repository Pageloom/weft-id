"""Email service layer.

This module provides business logic for email operations:
- User email CRUD (list, add, delete, set primary)
- Email verification
- Admin email management

All functions:
- Receive a RequestingUser for authorization (where applicable)
- Return Pydantic models from app/schemas/api.py
- Raise ServiceError subclasses on failures
- Have no knowledge of HTTP concepts
"""

from datetime import UTC, datetime

import database
from schemas.api import EmailInfo
from services.activity import track_activity
from services.event_log import log_event
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser

# =============================================================================
# Authorization Helpers (private)
# =============================================================================


def _require_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not admin or super_admin."""
    if user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
            required_role="admin",
        )


def _can_manage_emails(requesting_user: RequestingUser, target_user_id: str) -> bool:
    """Check if requesting user can manage target user's emails."""
    # Admin/super_admin can manage any user's emails
    if requesting_user["role"] in ("admin", "super_admin"):
        return True
    # Users can only manage their own emails
    return requesting_user["id"] == target_user_id


# =============================================================================
# Conversion Helpers (private)
# =============================================================================


def _email_row_to_info(row: dict) -> EmailInfo:
    """Convert database email row to EmailInfo schema."""
    return EmailInfo(
        id=str(row["id"]),
        email=row["email"],
        is_primary=row["is_primary"],
        verified_at=row.get("verified_at"),
        created_at=row["created_at"],
    )


# =============================================================================
# Email CRUD Operations
# =============================================================================


def list_user_emails(
    requesting_user: RequestingUser,
    user_id: str,
) -> list[EmailInfo]:
    """
    List all email addresses for a user.

    Authorization: Admin can list any user's emails.
    Users can only list their own emails.

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user whose emails to list

    Returns:
        List of EmailInfo objects

    Raises:
        ForbiddenError: If user lacks permissions
        NotFoundError: If user does not exist
    """
    if not _can_manage_emails(requesting_user, user_id):
        raise ForbiddenError(
            message="Cannot access other user's emails",
            code="email_access_denied",
        )

    tenant_id = requesting_user["tenant_id"]
    track_activity(tenant_id, requesting_user["id"])

    # Verify user exists (for admin operations)
    if requesting_user["id"] != user_id:
        user = database.users.get_user_by_id(tenant_id, user_id)
        if not user:
            raise NotFoundError(
                message="User not found",
                code="user_not_found",
                details={"user_id": user_id},
            )

    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    return [_email_row_to_info(e) for e in emails]


def add_user_email(
    requesting_user: RequestingUser,
    user_id: str,
    email: str,
    is_admin_action: bool = False,
    allow_users_add_emails: bool = True,
) -> EmailInfo:
    """
    Add an email address to a user's account.

    Authorization:
    - Admin can add to any user (email is auto-verified)
    - Users can add to their own account (email requires verification)
    - Super_admin bypasses tenant settings

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user to add email to
        email: Email address to add
        is_admin_action: Whether this is an admin adding email (auto-verify)
        allow_users_add_emails: Tenant setting for user self-service

    Returns:
        Created EmailInfo

    Raises:
        ForbiddenError: If user lacks permissions
        NotFoundError: If user does not exist
        ConflictError: If email already exists
        ValidationError: If email format is invalid
    """
    tenant_id = requesting_user["tenant_id"]
    email_lower = email.strip().lower()

    # Authorization check
    if not _can_manage_emails(requesting_user, user_id):
        raise ForbiddenError(
            message="Cannot add email to other user's account",
            code="email_access_denied",
        )

    # Check tenant setting for non-admin, non-super_admin users
    if (
        not is_admin_action
        and requesting_user["role"] != "super_admin"
        and not allow_users_add_emails
    ):
        raise ForbiddenError(
            message="Adding email addresses is disabled by administrator",
            code="email_add_disabled",
        )

    # Verify user exists (for admin operations)
    if requesting_user["id"] != user_id:
        user = database.users.get_user_by_id(tenant_id, user_id)
        if not user:
            raise NotFoundError(
                message="User not found",
                code="user_not_found",
                details={"user_id": user_id},
            )

    # Check for conflicts
    if database.user_emails.email_exists(tenant_id, email_lower):
        raise ConflictError(
            message="Email address already exists",
            code="email_exists",
            details={"email": email_lower},
        )

    # Add email - admin adds are pre-verified, user adds require verification
    if is_admin_action:
        result = database.user_emails.add_verified_email(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            user_id=user_id,
            email=email_lower,
            is_primary=False,
        )
    else:
        result = database.user_emails.add_email(
            tenant_id=tenant_id,
            user_id=user_id,
            email=email_lower,
            tenant_id_value=tenant_id,
        )

    if not result:
        raise ValidationError(
            message="Failed to add email address",
            code="email_add_failed",
        )

    # Fetch created email to return full info
    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    for e in emails:
        if e["email"] == email_lower:
            # Log the event
            log_event(
                tenant_id=tenant_id,
                actor_user_id=requesting_user["id"],
                artifact_type="user",
                artifact_id=user_id,
                event_type="email_added",
                metadata={
                    "email": email_lower,
                    "email_id": str(e["id"]),
                    "is_admin_action": is_admin_action,
                    "auto_verified": is_admin_action,
                },
                request_metadata=requesting_user.get("request_metadata"),
            )
            return _email_row_to_info(e)

    # Fallback if fetch fails (shouldn't happen)
    return EmailInfo(
        id=str(result["id"]),
        email=email_lower,
        is_primary=False,
        verified_at=datetime.now(UTC) if is_admin_action else None,
        created_at=datetime.now(UTC),
    )


def delete_user_email(
    requesting_user: RequestingUser,
    user_id: str,
    email_id: str,
) -> None:
    """
    Delete an email address from a user's account.

    Authorization: Admin can delete from any user's account.
    Users can only delete from their own account.

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user
        email_id: UUID of the email to delete

    Raises:
        ForbiddenError: If user lacks permissions
        NotFoundError: If email does not exist
        ValidationError: If trying to delete primary email or last email
    """
    if not _can_manage_emails(requesting_user, user_id):
        raise ForbiddenError(
            message="Cannot delete other user's email",
            code="email_access_denied",
        )

    tenant_id = requesting_user["tenant_id"]

    # Verify email exists and belongs to user
    email = database.user_emails.get_email_by_id(tenant_id, email_id, user_id)
    if not email:
        raise NotFoundError(
            message="Email not found",
            code="email_not_found",
            details={"email_id": email_id},
        )

    # Cannot delete primary email
    if email["is_primary"]:
        raise ValidationError(
            message="Cannot delete primary email address",
            code="cannot_delete_primary",
        )

    # Check that user will have at least one email left
    email_count = database.user_emails.count_user_emails(tenant_id, user_id)
    if email_count <= 1:
        raise ValidationError(
            message="Cannot delete last email address",
            code="must_keep_one_email",
        )

    # Capture email address for logging before deletion
    email_address = email["email"]

    database.user_emails.delete_email(tenant_id, email_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="email_deleted",
        metadata={
            "email_id": email_id,
            "email": email_address,
        },
        request_metadata=requesting_user.get("request_metadata"),
    )


def set_primary_email(
    requesting_user: RequestingUser,
    user_id: str,
    email_id: str,
) -> EmailInfo:
    """
    Set an email address as the primary email for a user.

    Authorization: Admin can set primary for any user.
    Users can only set primary for their own account.

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user
        email_id: UUID of the email to set as primary

    Returns:
        Updated EmailInfo

    Raises:
        ForbiddenError: If user lacks permissions
        NotFoundError: If email does not exist
        ValidationError: If email is not verified
    """
    if not _can_manage_emails(requesting_user, user_id):
        raise ForbiddenError(
            message="Cannot modify other user's primary email",
            code="email_access_denied",
        )

    tenant_id = requesting_user["tenant_id"]

    # Verify email exists and belongs to user
    email = database.user_emails.get_email_by_id(tenant_id, email_id, user_id)
    if not email:
        raise NotFoundError(
            message="Email not found",
            code="email_not_found",
            details={"email_id": email_id},
        )

    # Email must be verified
    if not email["verified_at"]:
        raise ValidationError(
            message="Cannot set unverified email as primary",
            code="email_not_verified",
        )

    # If already primary, just return it
    if email["is_primary"]:
        emails = database.user_emails.list_user_emails(tenant_id, user_id)
        for e in emails:
            if str(e["id"]) == email_id:
                return _email_row_to_info(e)

    # Capture the new primary email address for logging
    new_primary_email = email["email"]

    # Unset current primary and set new one
    database.user_emails.unset_primary_emails(tenant_id, user_id)
    database.user_emails.set_primary_email(tenant_id, email_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="primary_email_changed",
        metadata={
            "email_id": email_id,
            "email": new_primary_email,
        },
        request_metadata=requesting_user.get("request_metadata"),
    )

    # Fetch updated email
    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    for e in emails:
        if str(e["id"]) == email_id:
            return _email_row_to_info(e)

    raise ValidationError(
        message="Failed to retrieve updated email",
        code="email_retrieval_failed",
    )


def get_email_for_verification(
    tenant_id: str,
    email_id: str,
) -> dict | None:
    """
    Get email info needed for verification.

    This is a utility function without authorization - used during
    verification flow where user may not be fully authenticated.

    Args:
        tenant_id: Tenant ID
        email_id: Email UUID

    Returns:
        Dict with id, user_id, email, verified_at, verify_nonce or None
    """
    return database.user_emails.get_email_for_verification(tenant_id, email_id)


def verify_email(
    tenant_id: str,
    email_id: str,
    user_id: str,
    nonce: int,
) -> EmailInfo:
    """
    Verify an email address using the verification nonce.

    Args:
        tenant_id: Tenant ID
        email_id: Email UUID
        user_id: User UUID (for ownership verification)
        nonce: Verification nonce from email link

    Returns:
        Verified EmailInfo

    Raises:
        NotFoundError: If email does not exist
        ValidationError: If already verified or nonce is invalid
    """
    # Get email for verification
    email = database.user_emails.get_email_for_verification(tenant_id, email_id)

    if not email:
        raise NotFoundError(
            message="Email not found",
            code="email_not_found",
            details={"email_id": email_id},
        )

    # Verify email belongs to user
    if str(email["user_id"]) != str(user_id):
        raise NotFoundError(
            message="Email not found",
            code="email_not_found",
            details={"email_id": email_id},
        )

    # Check if already verified
    if email["verified_at"]:
        raise ValidationError(
            message="Email already verified",
            code="already_verified",
        )

    # Verify nonce
    if email["verify_nonce"] != nonce:
        raise ValidationError(
            message="Invalid verification code",
            code="invalid_nonce",
        )

    # Mark as verified
    database.user_emails.verify_email(tenant_id, email_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="email_verified",
        metadata={
            "email_id": email_id,
            "email": email["email"],
        },
        request_metadata=None,
    )

    # Fetch updated email
    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    for e in emails:
        if str(e["id"]) == email_id:
            return _email_row_to_info(e)

    raise ValidationError(
        message="Failed to retrieve verified email",
        code="email_retrieval_failed",
    )


def resend_verification(
    requesting_user: RequestingUser,
    user_id: str,
    email_id: str,
) -> dict:
    """
    Get email info for resending verification.

    Args:
        requesting_user: The authenticated user making the request
        user_id: User UUID
        email_id: Email UUID

    Returns:
        Dict with email and verify_nonce for sending verification

    Raises:
        ForbiddenError: If user lacks permissions
        NotFoundError: If email does not exist
    """
    if not _can_manage_emails(requesting_user, user_id):
        raise ForbiddenError(
            message="Cannot access other user's emails",
            code="email_access_denied",
        )

    tenant_id = requesting_user["tenant_id"]
    track_activity(tenant_id, requesting_user["id"])

    email = database.user_emails.get_email_with_nonce(tenant_id, email_id, user_id)
    if not email:
        raise NotFoundError(
            message="Email not found",
            code="email_not_found",
            details={"email_id": email_id},
        )

    return {
        "email": email["email"],
        "verify_nonce": email["verify_nonce"],
        "email_id": str(email["id"]),
    }


def get_primary_email(tenant_id: str, user_id: str) -> str | None:
    """
    Get the primary email address for a user.

    This is a utility function without authorization.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID

    Returns:
        Primary email address string, or None if not found
    """
    result = database.user_emails.get_primary_email(tenant_id, user_id)
    return result["email"] if result else None


def get_email_address_by_id(tenant_id: str, user_id: str, email_id: str) -> str | None:
    """
    Get an email address string by its ID.

    This is a utility function without authorization.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID
        email_id: Email UUID

    Returns:
        Email address string, or None if not found
    """
    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    for e in emails:
        if str(e["id"]) == str(email_id):
            return str(e["email"])
    return None


def get_user_with_primary_email(tenant_id: str, user_id: str) -> dict | None:
    """
    Get user info with their primary email address.

    This is a utility function without authorization - used for
    MFA verification flows where user isn't fully logged in yet.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID

    Returns:
        Dict with user info and primary email, or None if not found
    """
    return database.user_emails.get_user_with_primary_email(tenant_id, user_id)


def verify_email_by_nonce(tenant_id: str, email_id: str, nonce: int) -> bool:
    """
    Verify an email address using its nonce (public endpoint flow).

    This is a utility function without authorization - used for
    public email verification links where user isn't authenticated.

    Unlike verify_email(), this only checks the nonce and doesn't
    require user_id (used in public verification flow).

    Args:
        tenant_id: Tenant ID
        email_id: Email UUID
        nonce: Verification nonce from email link

    Returns:
        True if successfully verified, False if nonce doesn't match
    """
    email = database.user_emails.get_email_for_verification(tenant_id, email_id)
    if not email:
        return False

    if email["verify_nonce"] != nonce:
        return False

    database.user_emails.verify_email(tenant_id, email_id)
    return True
