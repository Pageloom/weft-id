"""User CRUD operations.

This module provides business logic for user create, read, update, delete:
- list_users
- get_user
- create_user
- update_user
- delete_user

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/api.py
- Raise ServiceError subclasses on failures
- Log events after successful writes
- Track activity for reads
"""

from datetime import date

import database
from schemas.api import (
    UserCreate,
    UserDetail,
    UserListResponse,
    UserUpdate,
)
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser
from services.users._converters import (
    _fetch_user_detail,
    _user_row_to_detail,
    _user_row_to_summary,
)
from services.users._validation import _validate_role_change


def list_users(
    requesting_user: RequestingUser,
    page: int = 1,
    limit: int = 25,
    search: str | None = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    roles: list[str] | None = None,
    statuses: list[str] | None = None,
    auth_methods: list[str] | None = None,
    domain: str | None = None,
    group_id: str | None = None,
    has_secondary_email: bool | str | None = None,
    activity_start: date | None = None,
    activity_end: date | None = None,
) -> UserListResponse:
    """
    List all users in the tenant with pagination and search.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request
        page: Page number (1-indexed)
        limit: Results per page
        search: Optional search term for name or email
        sort_by: Field to sort by (name, email, role, created_at, last_login)
        sort_order: Sort order (asc or desc)
        roles: Optional list of roles to filter by
        statuses: Optional list of statuses to filter by
        auth_methods: Optional list of auth method keys to filter by
        domain: Optional email domain to filter by
        group_id: Optional group UUID to filter by membership
        has_secondary_email: Optional filter by presence of secondary email addresses
        activity_start: Optional filter by activity on or after this date
        activity_end: Optional filter by activity on or before this date

    Returns:
        UserListResponse with paginated results

    Raises:
        ForbiddenError: If user lacks admin permissions
    """
    require_admin(requesting_user, log_failure=True, service_name="users")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get users
    users = database.users.list_users(
        tenant_id=tenant_id,
        search=search,
        sort_field=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=limit,
        roles=roles,
        statuses=statuses,
        auth_methods=auth_methods,
        domain=domain,
        group_id=group_id,
        has_secondary_email=has_secondary_email,
        activity_start=activity_start,
        activity_end=activity_end,
    )

    # Get total count
    total = database.users.count_users(
        tenant_id,
        search,
        roles,
        statuses,
        auth_methods,
        domain=domain,
        group_id=group_id,
        has_secondary_email=has_secondary_email,
        activity_start=activity_start,
        activity_end=activity_end,
    )

    return UserListResponse(
        items=[_user_row_to_summary(u) for u in users],
        total=total,
        page=page,
        limit=limit,
    )


def get_user(
    requesting_user: RequestingUser,
    user_id: str,
) -> UserDetail:
    """
    Get detailed information about a specific user.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user to retrieve

    Returns:
        UserDetail with full user information including emails

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If user does not exist
    """
    require_admin(requesting_user, log_failure=True, service_name="users")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    return _fetch_user_detail(requesting_user["tenant_id"], user_id)


def create_user(
    requesting_user: RequestingUser,
    user_data: UserCreate,
    auto_create_email: bool = True,
) -> UserDetail:
    """
    Create a new user.

    Authorization: Requires admin role. Only super_admin can create users
    with admin or super_admin roles.

    Args:
        requesting_user: The authenticated user making the request
        user_data: User creation data (first_name, last_name, email, role)
        auto_create_email: If True, automatically creates a verified email for the user.
                          If False, caller is responsible for email creation.

    Returns:
        UserDetail for the created user

    Raises:
        ForbiddenError: If user lacks required permissions
        ConflictError: If email already exists
        ValidationError: If creation fails
    """
    require_admin(requesting_user, log_failure=True, service_name="users")

    tenant_id = requesting_user["tenant_id"]

    # Only super_admin can create admin/super_admin users
    if user_data.role in ("admin", "super_admin") and requesting_user["role"] != "super_admin":
        raise ForbiddenError(
            message=f"Only super_admin can create users with {user_data.role} role",
            code="role_escalation_denied",
            required_role="super_admin",
        )

    # Check if email already exists
    if database.user_emails.email_exists(tenant_id, user_data.email):
        raise ConflictError(
            message="Email already exists",
            code="email_exists",
            details={"email": user_data.email},
        )

    # Create user
    result = database.users.create_user(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        email=user_data.email,
        role=user_data.role,
    )

    if not result:
        raise ValidationError(
            message="Failed to create user",
            code="user_creation_failed",
        )

    user_id = result["user_id"]

    # Add verified email (if auto_create_email is enabled)
    if auto_create_email:
        database.user_emails.add_verified_email(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            user_id=user_id,
            email=user_data.email,
            is_primary=True,
        )

        # Auto-assign to domain-linked groups
        from services import settings as settings_service

        settings_service.auto_assign_user_to_domain_groups(
            tenant_id, user_id, user_data.email, requesting_user["id"]
        )

    # Fetch created user
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise ValidationError(
            message="Failed to retrieve created user",
            code="user_retrieval_failed",
        )

    user["email"] = user_data.email

    emails = database.user_emails.list_user_emails(tenant_id, user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=str(user_id),
        event_type="user_created",
        metadata={
            "role": user_data.role,
            "email": user_data.email,
        },
    )

    return _user_row_to_detail(user, emails, is_service=False)


def resend_invitation(
    requesting_user: RequestingUser,
    target_user_id: str,
) -> dict:
    """
    Resend the invitation email to a user who has not completed onboarding.

    Authorization: Requires admin role.

    Increments the appropriate nonce to invalidate any previous invitation link,
    then returns the data the router needs to build the URL and send the email.

    Args:
        requesting_user: The authenticated admin making the request
        target_user_id: UUID of the user to resend invitation to

    Returns:
        Dict with email_id, email, nonce, invitation_type ('set_password' or 'verify')

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If target user not found or has no primary email
        ValidationError: If user has already set a password
    """
    require_admin(requesting_user, log_failure=True, service_name="users")

    tenant_id = requesting_user["tenant_id"]

    user = database.users.get_user_by_id(tenant_id, target_user_id)
    if not user:
        raise NotFoundError(
            message="User not found.",
            code="user_not_found",
        )

    if user.get("has_password"):
        raise ValidationError(
            message="This user has already set a password and completed onboarding.",
            code="already_onboarded",
        )

    if user.get("is_inactivated"):
        raise ValidationError(
            message="Cannot resend invitation to an inactivated user.",
            code="user_inactivated",
        )

    if user.get("is_anonymized"):
        raise ValidationError(
            message="Cannot resend invitation to an anonymized user.",
            code="user_anonymized",
        )

    primary_email = database.user_emails.get_primary_email_for_resend(tenant_id, target_user_id)
    if not primary_email:
        raise NotFoundError(
            message="User has no primary email address.",
            code="no_primary_email",
        )

    email_id = str(primary_email["id"])

    if primary_email["verified_at"]:
        # Email is verified: increment set_password_nonce, send set-password link
        database.user_emails.increment_set_password_nonce(tenant_id, email_id)
        nonce = primary_email["set_password_nonce"] + 1
        invitation_type = "set_password"
    else:
        # Email is unverified: increment verify_nonce, send verification link
        database.user_emails.increment_verify_nonce(tenant_id, email_id)
        nonce = primary_email["verify_nonce"] + 1
        invitation_type = "verify"

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="invitation_resent",
        artifact_type="user",
        artifact_id=target_user_id,
        metadata={
            "target_user_name": f"{user['first_name']} {user['last_name']}",
            "email": primary_email["email"],
            "invitation_type": invitation_type,
        },
    )

    return {
        "email_id": email_id,
        "email": primary_email["email"],
        "nonce": nonce,
        "invitation_type": invitation_type,
        "first_name": user["first_name"],
        "last_name": user["last_name"],
    }


def update_user(
    requesting_user: RequestingUser,
    user_id: str,
    user_update: UserUpdate,
) -> UserDetail:
    """
    Update a user's information.

    Authorization: Requires admin role. Only super_admin can change roles
    to/from super_admin. Cannot demote the last super_admin.

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user to update
        user_update: Fields to update (first_name, last_name, role)

    Returns:
        UserDetail for the updated user

    Raises:
        ForbiddenError: If user lacks required permissions
        NotFoundError: If user does not exist
        ValidationError: If update would leave no super_admins
    """
    require_admin(requesting_user, log_failure=True, service_name="users")

    tenant_id = requesting_user["tenant_id"]

    # Get existing user
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
            details={"user_id": user_id},
        )

    # Check role change restrictions
    if user_update.role:
        _validate_role_change(tenant_id, user, user_update.role, requesting_user)

    # Track changes for logging
    changes: dict = {}

    # Update name if provided
    if user_update.first_name or user_update.last_name:
        first_name = user_update.first_name or user["first_name"]
        last_name = user_update.last_name or user["last_name"]
        if user_update.first_name and user_update.first_name != user["first_name"]:
            changes["first_name"] = {"old": user["first_name"], "new": user_update.first_name}
        if user_update.last_name and user_update.last_name != user["last_name"]:
            changes["last_name"] = {"old": user["last_name"], "new": user_update.last_name}
        database.users.update_user_profile(tenant_id, user_id, first_name, last_name)

    # Update role if provided
    if user_update.role:
        if user_update.role != user["role"]:
            changes["role"] = {"old": user["role"], "new": user_update.role}
        database.users.update_user_role(tenant_id, user_id, user_update.role)

    # Log the event if there were actual changes
    if changes:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_updated",
            metadata={"changes": changes},
        )

    return _fetch_user_detail(tenant_id, user_id)


def delete_user(
    requesting_user: RequestingUser,
    user_id: str,
) -> None:
    """
    Delete a user.

    Authorization: Requires admin role. Cannot delete service users
    (linked to OAuth2 clients). Cannot delete yourself.

    Args:
        requesting_user: The authenticated user making the request
        user_id: UUID of the user to delete

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If user does not exist
        ValidationError: If user is a service user or self-deletion attempted
    """
    require_admin(requesting_user, log_failure=True, service_name="users")

    tenant_id = requesting_user["tenant_id"]

    # Check if user exists
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
            details={"user_id": user_id},
        )

    # Cannot delete service users
    if database.users.is_service_user(tenant_id, user_id):
        raise ValidationError(
            message="Cannot delete service user. Delete the associated OAuth2 client first.",
            code="service_user_deletion",
        )

    # Cannot delete yourself
    if str(user["id"]) == requesting_user["id"]:
        raise ValidationError(
            message="Cannot delete your own account",
            code="self_deletion",
        )

    # Capture user info for logging before deletion
    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    user_email = primary_email["email"] if primary_email else None

    # Delete user
    database.users.delete_user(tenant_id, user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_deleted",
        metadata={
            "deleted_user_name": f"{user['first_name']} {user['last_name']}",
            "deleted_user_email": user_email,
            "deleted_user_role": user["role"],
        },
    )
