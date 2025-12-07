"""User service layer.

This module provides business logic for user operations:
- User CRUD (list, get, create, update, delete)
- Current user profile management

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/api.py
- Raise ServiceError subclasses on failures
- Have no knowledge of HTTP concepts
"""

import database
from schemas.api import (
    EmailInfo,
    UserCreate,
    UserDetail,
    UserListResponse,
    UserProfile,
    UserProfileUpdate,
    UserSummary,
    UserUpdate,
)
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


def _require_super_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not super_admin."""
    if user["role"] != "super_admin":
        raise ForbiddenError(
            message="Super admin access required",
            code="super_admin_required",
            required_role="super_admin",
        )


# =============================================================================
# Utility Functions (no authorization required)
# =============================================================================


def check_collation_exists(tenant_id: str, collation: str) -> bool:
    """
    Check if a database collation exists.

    This is a utility function without authorization - used for
    determining locale-aware sorting support.

    Args:
        tenant_id: Tenant ID
        collation: Collation name (e.g., "sv-SE-x-icu")

    Returns:
        True if collation exists in the database, False otherwise
    """
    return database.users.check_collation_exists(tenant_id, collation)


def count_users(tenant_id: str, search: str | None = None) -> int:
    """
    Count users in a tenant, optionally filtered by search term.

    This is a utility function without authorization.

    Args:
        tenant_id: Tenant ID
        search: Optional search term

    Returns:
        Total count of matching users
    """
    return database.users.count_users(tenant_id, search)


def list_users_raw(
    tenant_id: str,
    search: str | None = None,
    sort_field: str = "created_at",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 25,
    collation: str | None = None,
) -> list[dict]:
    """
    List users with pagination - returns raw dicts for HTML templates.

    This is a utility function without authorization - caller must
    have already verified admin access.

    Args:
        tenant_id: Tenant ID
        search: Optional search term
        sort_field: Field to sort by
        sort_order: Sort order (asc or desc)
        page: Page number (1-indexed)
        page_size: Results per page
        collation: Optional collation for locale-aware sorting

    Returns:
        List of user dicts
    """
    return database.users.list_users(
        tenant_id=tenant_id,
        search=search,
        sort_field=sort_field,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
        collation=collation,
    )


def email_exists(tenant_id: str, email: str) -> bool:
    """
    Check if an email address already exists in the tenant.

    This is a utility function without authorization.

    Args:
        tenant_id: Tenant ID
        email: Email address to check

    Returns:
        True if email exists, False otherwise
    """
    return database.user_emails.email_exists(tenant_id, email)


def get_tenant_name(tenant_id: str) -> str:
    """
    Get the display name for a tenant.

    This is a utility function without authorization.

    Args:
        tenant_id: Tenant ID

    Returns:
        Tenant name or "Loom" as default
    """
    tenant_info = database.tenants.get_tenant_by_id(tenant_id)
    return tenant_info.get("name", "Loom") if tenant_info else "Loom"


def create_user_raw(
    tenant_id: str,
    first_name: str,
    last_name: str,
    email: str,
    role: str,
) -> dict | None:
    """
    Create a user record without email setup.

    This is a low-level utility function without authorization.
    Caller must have already verified permissions.

    Args:
        tenant_id: Tenant ID
        first_name: User's first name
        last_name: User's last name
        email: User's email (for the user record)
        role: User role

    Returns:
        Dict with user_id if successful, None otherwise
    """
    return database.users.create_user(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        first_name=first_name,
        last_name=last_name,
        email=email,
        role=role,
    )


def add_verified_email_with_nonce(
    tenant_id: str,
    user_id: str,
    email: str,
    is_primary: bool = True,
) -> dict | None:
    """
    Add a verified email address to a user.

    This is a low-level utility function without authorization.
    Caller must have already verified permissions.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        email: Email address
        is_primary: Whether to set as primary

    Returns:
        Dict with email id if successful, None otherwise
    """
    result = database.user_emails.add_verified_email(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        user_id=user_id,
        email=email,
        is_primary=is_primary,
    )
    if result and is_primary:
        database.user_emails.set_primary_email(tenant_id, result["id"])
    return result


def add_unverified_email_with_nonce(
    tenant_id: str,
    user_id: str,
    email: str,
    is_primary: bool = True,
) -> dict | None:
    """
    Add an unverified email address to a user.

    This is a low-level utility function without authorization.
    Caller must have already verified permissions.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        email: Email address
        is_primary: Whether to set as primary

    Returns:
        Dict with email id and verify_nonce if successful, None otherwise
    """
    result = database.user_emails.add_email(
        tenant_id=tenant_id,
        user_id=user_id,
        email=email,
        tenant_id_value=tenant_id,
    )
    if result and is_primary:
        database.user_emails.set_primary_email(tenant_id, result["id"])
    return result


# =============================================================================
# Conversion Helpers (private)
# =============================================================================


def _user_row_to_profile(user: dict) -> UserProfile:
    """Convert database user dict to UserProfile schema."""
    return UserProfile(
        id=str(user["id"]),
        email=user.get("email", ""),
        first_name=user["first_name"],
        last_name=user["last_name"],
        role=user["role"],
        timezone=user.get("tz"),
        locale=user.get("locale"),
        mfa_enabled=user.get("mfa_enabled", False),
        mfa_method=user.get("mfa_method"),
        created_at=user["created_at"],
        last_login=user.get("last_login"),
    )


def _user_row_to_summary(user: dict) -> UserSummary:
    """Convert database user dict to UserSummary schema."""
    return UserSummary(
        id=str(user["id"]),
        email=user.get("email"),
        first_name=user["first_name"],
        last_name=user["last_name"],
        role=user["role"],
        created_at=user["created_at"],
        last_login=user.get("last_login"),
    )


def _user_row_to_detail(user: dict, emails: list[dict], is_service: bool) -> UserDetail:
    """Convert database user dict to UserDetail schema."""
    email_list = [
        EmailInfo(
            id=str(e["id"]),
            email=e["email"],
            is_primary=e["is_primary"],
            verified_at=e.get("verified_at"),
            created_at=e["created_at"],
        )
        for e in emails
    ]
    return UserDetail(
        id=str(user["id"]),
        email=user.get("email"),
        first_name=user["first_name"],
        last_name=user["last_name"],
        role=user["role"],
        timezone=user.get("tz"),
        locale=user.get("locale"),
        mfa_enabled=user.get("mfa_enabled", False),
        mfa_method=user.get("mfa_method"),
        created_at=user["created_at"],
        last_login=user.get("last_login"),
        emails=email_list,
        is_service_user=is_service,
    )


# =============================================================================
# User CRUD (Admin operations)
# =============================================================================


def list_users(
    requesting_user: RequestingUser,
    page: int = 1,
    limit: int = 25,
    search: str | None = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
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

    Returns:
        UserListResponse with paginated results

    Raises:
        ForbiddenError: If user lacks admin permissions
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Get users
    users = database.users.list_users(
        tenant_id=tenant_id,
        search=search,
        sort_field=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=limit,
    )

    # Get total count
    total = database.users.count_users(tenant_id, search)

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
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Get user
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
            details={"user_id": user_id},
        )

    # Get primary email
    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email:
        user["email"] = primary_email["email"]

    # Get all emails
    emails = database.user_emails.list_user_emails(tenant_id, user_id)

    # Check if service user
    is_service = database.users.is_service_user(tenant_id, user_id)

    return _user_row_to_detail(user, emails, is_service)


def create_user(
    requesting_user: RequestingUser,
    user_data: UserCreate,
) -> UserDetail:
    """
    Create a new user.

    Authorization: Requires admin role. Only super_admin can create users
    with admin or super_admin roles.

    Args:
        requesting_user: The authenticated user making the request
        user_data: User creation data (first_name, last_name, email, role)

    Returns:
        UserDetail for the created user

    Raises:
        ForbiddenError: If user lacks required permissions
        ConflictError: If email already exists
        ValidationError: If creation fails
    """
    _require_admin(requesting_user)

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

    # Add verified email
    database.user_emails.add_verified_email(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        user_id=user_id,
        email=user_data.email,
        is_primary=True,
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

    return _user_row_to_detail(user, emails, is_service=False)


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
    _require_admin(requesting_user)

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
        current_role = user["role"]
        new_role = user_update.role

        # Only super_admin can change to/from super_admin
        if (new_role == "super_admin" or current_role == "super_admin") and requesting_user[
            "role"
        ] != "super_admin":
            raise ForbiddenError(
                message="Only super_admin can change super_admin roles",
                code="super_admin_role_change_denied",
                required_role="super_admin",
            )

        # Prevent demoting the last super_admin
        if current_role == "super_admin" and new_role != "super_admin":
            super_admins = database.users.list_users(
                tenant_id=tenant_id,
                search=None,
                sort_field="created_at",
                sort_order="asc",
                page=1,
                page_size=100,
            )
            super_admin_count = sum(1 for u in super_admins if u["role"] == "super_admin")
            if super_admin_count <= 1:
                raise ValidationError(
                    message="Cannot demote the last super_admin",
                    code="last_super_admin",
                )

    # Update name if provided
    if user_update.first_name or user_update.last_name:
        first_name = user_update.first_name or user["first_name"]
        last_name = user_update.last_name or user["last_name"]
        database.users.update_user_profile(tenant_id, user_id, first_name, last_name)

    # Update role if provided
    if user_update.role:
        database.users.update_user_role(tenant_id, user_id, user_update.role)

    # Fetch updated user
    updated_user = database.users.get_user_by_id(tenant_id, user_id)
    if not updated_user:
        raise ValidationError(
            message="Failed to retrieve updated user",
            code="user_retrieval_failed",
        )

    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email:
        updated_user["email"] = primary_email["email"]

    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    is_service = database.users.is_service_user(tenant_id, user_id)

    return _user_row_to_detail(updated_user, emails, is_service)


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
    _require_admin(requesting_user)

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

    # Delete user
    database.users.delete_user(tenant_id, user_id)


# =============================================================================
# Current User Profile (Self-service operations)
# =============================================================================


def get_current_user_profile(
    requesting_user: RequestingUser,
    user_data: dict,
) -> UserProfile:
    """
    Get the current user's profile.

    Authorization: Any authenticated user.

    Args:
        requesting_user: The authenticated user making the request
        user_data: The full user dict from authentication (includes email)

    Returns:
        UserProfile for the current user
    """
    return _user_row_to_profile(user_data)


def update_current_user_profile(
    requesting_user: RequestingUser,
    user_data: dict,
    profile_update: UserProfileUpdate,
) -> UserProfile:
    """
    Update the current user's profile.

    Authorization: Any authenticated user (for their own profile).

    Args:
        requesting_user: The authenticated user making the request
        user_data: The full user dict from authentication
        profile_update: Fields to update (first_name, last_name, timezone, locale)

    Returns:
        Updated UserProfile

    Raises:
        NotFoundError: If user no longer exists
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = requesting_user["id"]

    # Update profile fields if provided
    if profile_update.first_name or profile_update.last_name:
        first_name = profile_update.first_name or user_data["first_name"]
        last_name = profile_update.last_name or user_data["last_name"]
        database.users.update_user_profile(
            tenant_id=tenant_id,
            user_id=user_id,
            first_name=first_name,
            last_name=last_name,
        )

    if profile_update.timezone and profile_update.locale:
        database.users.update_user_timezone_and_locale(
            tenant_id=tenant_id,
            user_id=user_id,
            timezone=profile_update.timezone,
            locale=profile_update.locale,
        )
    elif profile_update.timezone:
        database.users.update_user_timezone(
            tenant_id=tenant_id,
            user_id=user_id,
            timezone=profile_update.timezone,
        )
    elif profile_update.locale:
        database.users.update_user_locale(
            tenant_id=tenant_id,
            user_id=user_id,
            locale=profile_update.locale,
        )

    # Fetch updated user
    updated_user = database.users.get_user_by_id(tenant_id, user_id)
    if not updated_user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    # Add primary email
    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email:
        updated_user["email"] = primary_email["email"]

    return _user_row_to_profile(updated_user)


# =============================================================================
# Utility Functions (for other services/routes to use)
# =============================================================================


def get_available_roles() -> list[str]:
    """
    Get list of available user roles.

    Returns:
        List of role names: member, admin, super_admin
    """
    return ["member", "admin", "super_admin"]


def get_user_by_id_raw(tenant_id: str, user_id: str) -> dict | None:
    """
    Get a user by ID (raw dict).

    This is a utility function without authorization - used for
    authentication flows where the user isn't fully logged in yet.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID

    Returns:
        User dict or None if not found
    """
    return database.users.get_user_by_id(tenant_id, user_id)


def update_password(tenant_id: str, user_id: str, password_hash: str) -> None:
    """
    Update a user's password hash.

    This is a utility function without authorization - called after
    validation in set_password route.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID
        password_hash: Hashed password to store
    """
    database.users.update_password(tenant_id, user_id, password_hash)
