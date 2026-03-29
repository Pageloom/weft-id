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

from datetime import UTC, date, datetime

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
) -> EmailInfo:
    """
    Add an email address to a user's account.

    Authorization:
    - Admin can add to any user (email is auto-verified)

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user to add email to
        email: Email address to add
        is_admin_action: Whether this is an admin adding email (auto-verify)

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


def check_routing_change(tenant_id: str, user_id: str, email: str) -> dict | None:
    """
    Check whether promoting an email to primary would change the user's IdP routing.

    Compares the user's current IdP assignment with the IdP bound to the
    new email's domain. Returns routing change details if they differ.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        email: Email address being promoted

    Returns:
        Dict with current_idp_name and new_idp_name if routing would change,
        or None if no change.
    """
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        return None

    current_idp_id = user.get("saml_idp_id")
    current_idp_name = user.get("saml_idp_name") or "Password authentication"

    domain = email.split("@")[1] if "@" in email else ""
    domain_idp = database.saml.get_idp_for_domain(tenant_id, domain) if domain else None

    new_idp_id = str(domain_idp["id"]) if domain_idp else None
    new_idp_name = domain_idp["name"] if domain_idp else "Password authentication"

    # Compare: convert current_idp_id to string for comparison
    current_idp_str = str(current_idp_id) if current_idp_id else None
    if current_idp_str == new_idp_id:
        return None

    return {
        "current_idp_name": current_idp_name,
        "new_idp_name": new_idp_name,
    }


def compute_email_change_impact(
    tenant_id: str,
    user_id: str,
    new_email: str,
) -> dict:
    """Compute the full downstream impact of changing a user's primary email.

    Determines which SPs will see a different NameID in assertions and
    whether IdP routing will change. Used by the single-user promote
    confirmation dialog and the bulk change primary email dry-run.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        new_email: The email address that would become primary

    Returns:
        Dict with:
            sp_impacts: list of dicts with sp_name, sp_entity_id,
                nameid_format_label, impact ("will_change" | "not_affected")
            routing_change: dict from check_routing_change() or None
            summary: dict with affected_sp_count, unaffected_sp_count, total_sp_count
    """
    from constants.nameid_formats import (
        NAMEID_FORMAT_PERSISTENT,
        NAMEID_FORMAT_TRANSIENT,
        NAMEID_FORMAT_URI_TO_LABEL,
    )

    # Get all SPs this user can access, with their NameID format
    accessible_sps = database.sp_group_assignments.get_accessible_sps_with_nameid_for_user(
        tenant_id, user_id
    )

    # Classify each SP's impact
    sp_impacts = []
    affected_count = 0
    for sp in accessible_sps:
        nameid_format = sp.get("nameid_format", "")
        label = NAMEID_FORMAT_URI_TO_LABEL.get(nameid_format, "unknown")

        if nameid_format in (NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_TRANSIENT):
            impact = "not_affected"
        else:
            # emailAddress and unspecified both use the primary email
            impact = "will_change"
            affected_count += 1

        sp_impacts.append(
            {
                "sp_id": str(sp["id"]),
                "sp_name": sp["name"],
                "sp_entity_id": sp.get("entity_id", ""),
                "nameid_format_label": label,
                "impact": impact,
            }
        )

    # Check IdP routing change
    routing_change = check_routing_change(tenant_id, user_id, new_email)

    total = len(sp_impacts)
    return {
        "sp_impacts": sp_impacts,
        "routing_change": routing_change,
        "summary": {
            "affected_sp_count": affected_count,
            "unaffected_sp_count": total - affected_count,
            "total_sp_count": total,
        },
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


def increment_set_password_nonce(tenant_id: str, email_id: str) -> None:
    """
    Invalidate a set-password link by incrementing its nonce.

    Call this after a successful password set to prevent reuse of the link.

    Args:
        tenant_id: Tenant ID
        email_id: Email UUID
    """
    database.user_emails.increment_set_password_nonce(tenant_id, email_id)


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

    # Log the event using the email owner as the actor
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(email["user_id"]),
        artifact_type="user",
        artifact_id=str(email["user_id"]),
        event_type="email_verified",
        metadata={
            "email_id": email_id,
            "email": email["email"],
            "flow": "public_link",
        },
    )

    # Auto-assign to domain-linked groups
    from services import settings as settings_service

    settings_service.auto_assign_user_to_domain_groups(
        tenant_id, str(email["user_id"]), email["email"], str(email["user_id"])
    )

    return True


# =============================================================================
# Bulk Operations Helpers
# =============================================================================


def list_users_by_ids_with_emails(
    tenant_id: str,
    user_ids: list[str],
) -> tuple[list[dict], dict[str, list[str]]]:
    """Fetch users by IDs and their secondary emails for bulk operations.

    Args:
        tenant_id: Tenant ID
        user_ids: List of user UUIDs

    Returns:
        Tuple of (users_list, secondary_emails_by_user_id).
        users_list: dicts with id, first_name, last_name, email.
        secondary_emails_by_user_id: dict mapping user_id to list of email strings.
    """
    from collections import defaultdict

    users = database.users.list_users_by_ids(tenant_id, user_ids)

    uid_list = [str(u["id"]) for u in users]
    rows = database.user_emails.list_emails_for_users(tenant_id, uid_list)

    secondaries: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        secondaries[str(row["user_id"])].append(row["email"])

    return users, secondaries


def resolve_users_from_filter(
    tenant_id: str,
    search: str | None = None,
    roles: list[str] | None = None,
    statuses: list[str] | None = None,
    auth_methods: list[str] | None = None,
    domain: str | None = None,
    group_id: str | None = None,
    has_secondary_email: bool | str | None = None,
    activity_start: date | None = None,
    activity_end: date | None = None,
    role_negate: bool = False,
    status_negate: bool = False,
    auth_method_negate: bool = False,
    domain_negate: bool = False,
    group_negate: bool = False,
    group_include_children: bool = True,
) -> list[str]:
    """Resolve filter criteria into a list of user IDs.

    Queries the database with the same filters as the user list page,
    without pagination, and returns all matching user IDs.
    """
    rows = database.users.list_users(
        tenant_id,
        search=search,
        page=1,
        page_size=10000,
        roles=roles,
        statuses=statuses,
        auth_methods=auth_methods,
        domain=domain,
        group_id=group_id,
        has_secondary_email=has_secondary_email,
        activity_start=activity_start,
        activity_end=activity_end,
        role_negate=role_negate,
        status_negate=status_negate,
        auth_method_negate=auth_method_negate,
        domain_negate=domain_negate,
        group_negate=group_negate,
        group_include_children=group_include_children,
    )
    return [str(r["id"]) for r in rows]
