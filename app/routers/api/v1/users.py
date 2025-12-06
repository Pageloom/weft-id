"""User API endpoints."""

from typing import Annotated

import database
from api_dependencies import get_current_user_api, require_admin_api
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, HTTPException, Query
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

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


def _user_to_profile(user: dict) -> UserProfile:
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


def _user_to_summary(user: dict) -> UserSummary:
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


def _user_to_detail(user: dict, emails: list[dict], is_service: bool) -> UserDetail:
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


@router.get("/me", response_model=UserProfile)
def get_current_user_profile(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Get the current user's profile.

    Supports authentication via:
    - Bearer token (OAuth2)
    - Session cookie

    Returns:
        User profile including id, email, name, role, timezone, locale, MFA status
    """
    return _user_to_profile(user)


@router.patch("/me", response_model=UserProfile)
def update_current_user_profile(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    profile_update: UserProfileUpdate,
):
    """
    Update the current user's profile.

    Supports authentication via:
    - Bearer token (OAuth2)
    - Session cookie

    Request Body:
        first_name: User's first name (optional)
        last_name: User's last name (optional)
        timezone: IANA timezone (optional, e.g., "America/New_York")
        locale: Two-letter locale code (optional, e.g., "en")

    Returns:
        Updated user profile

    Note:
        Only provided fields are updated. Omitted fields remain unchanged.
    """
    # Update profile fields if provided
    if profile_update.first_name or profile_update.last_name:
        # Update name
        first_name = profile_update.first_name or user["first_name"]
        last_name = profile_update.last_name or user["last_name"]

        database.users.update_user_profile(
            tenant_id=tenant_id,
            user_id=user["id"],
            first_name=first_name,
            last_name=last_name,
        )

    if profile_update.timezone and profile_update.locale:
        # Update both timezone and locale
        database.users.update_user_timezone_and_locale(
            tenant_id=tenant_id,
            user_id=user["id"],
            timezone=profile_update.timezone,
            locale=profile_update.locale,
        )
    elif profile_update.timezone:
        # Update timezone only
        database.users.update_user_timezone(
            tenant_id=tenant_id,
            user_id=user["id"],
            timezone=profile_update.timezone,
        )
    elif profile_update.locale:
        # Update locale only
        database.users.update_user_locale(
            tenant_id=tenant_id,
            user_id=user["id"],
            locale=profile_update.locale,
        )

    # Fetch updated user
    updated_user = database.users.get_user_by_id(tenant_id, user["id"])

    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Add primary email
    primary_email = database.user_emails.get_primary_email(tenant_id, updated_user["id"])
    if primary_email:
        updated_user["email"] = primary_email["email"]

    return _user_to_profile(updated_user)


# ============================================================================
# Admin User Management Endpoints
# ============================================================================


@router.get("", response_model=UserListResponse)
def list_users(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(25, ge=1, le=100, description="Number of results per page"),
    search: str | None = Query(None, description="Search by name or email"),
    sort_by: str = Query(
        "created_at", description="Sort field (name, email, role, created_at, last_login)"
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order"),
):
    """
    List all users in the tenant with pagination and search.

    Requires admin role.

    Query Parameters:
        page: Page number (default: 1)
        limit: Results per page (default: 25, max: 100)
        search: Search term for name or email
        sort_by: Field to sort by (name, email, role, created_at, last_login)
        sort_order: Sort order (asc or desc)

    Returns:
        Paginated list of users
    """
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
        items=[_user_to_summary(u) for u in users],
        total=total,
        page=page,
        limit=limit,
    )


@router.get("/{user_id}", response_model=UserDetail)
def get_user(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    Get detailed information about a specific user.

    Requires admin role.

    Path Parameters:
        user_id: User UUID

    Returns:
        Detailed user information including emails and service user status
    """
    # Get user
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get primary email
    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email:
        user["email"] = primary_email["email"]

    # Get all emails
    emails = database.user_emails.list_user_emails(tenant_id, user_id)

    # Check if service user
    is_service = database.users.is_service_user(tenant_id, user_id)

    return _user_to_detail(user, emails, is_service)


@router.post("", response_model=UserDetail, status_code=201)
def create_user(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_data: UserCreate,
):
    """
    Create a new user.

    Requires admin role. Only super_admin can create users with super_admin role.

    The user is created without a password. They will need to set their password
    via the password reset flow when they receive their invitation email.

    Request Body:
        first_name: User's first name
        last_name: User's last name
        email: Primary email address
        role: User role (defaults to 'member')

    Returns:
        Created user details
    """
    # Check role restrictions
    if user_data.role == "super_admin" and admin["role"] != "super_admin":
        raise HTTPException(
            status_code=403,
            detail="Only super_admin can create users with super_admin role",
        )

    # Check if email already exists
    if database.user_emails.email_exists(tenant_id, user_data.email):
        raise HTTPException(status_code=409, detail="Email already exists")

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
        raise HTTPException(status_code=500, detail="Failed to create user")

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
        raise HTTPException(status_code=500, detail="Failed to retrieve created user")

    user["email"] = user_data.email

    emails = database.user_emails.list_user_emails(tenant_id, user_id)

    return _user_to_detail(user, emails, is_service=False)


@router.patch("/{user_id}", response_model=UserDetail)
def update_user(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
    user_update: UserUpdate,
):
    """
    Update a user's information.

    Requires admin role. Only super_admin can change roles to/from super_admin.

    Path Parameters:
        user_id: User UUID

    Request Body:
        first_name: New first name (optional)
        last_name: New last name (optional)
        role: New role (optional, requires super_admin to set super_admin)

    Returns:
        Updated user details
    """
    # Get existing user
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check role change restrictions
    if user_update.role:
        current_role = user["role"]
        new_role = user_update.role

        # Only super_admin can change to/from super_admin
        if (new_role == "super_admin" or current_role == "super_admin") and admin[
            "role"
        ] != "super_admin":
            raise HTTPException(
                status_code=403,
                detail="Only super_admin can change super_admin roles",
            )

        # Prevent demoting the last super_admin
        if current_role == "super_admin" and new_role != "super_admin":
            # Count super_admins
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
                raise HTTPException(
                    status_code=400,
                    detail="Cannot demote the last super_admin",
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
        raise HTTPException(status_code=500, detail="Failed to retrieve updated user")

    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email:
        updated_user["email"] = primary_email["email"]

    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    is_service = database.users.is_service_user(tenant_id, user_id)

    return _user_to_detail(updated_user, emails, is_service)


@router.delete("/{user_id}", status_code=204)
def delete_user(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    Delete a user.

    Requires admin role. Cannot delete service users (linked to OAuth2 clients).

    Path Parameters:
        user_id: User UUID

    Returns:
        204 No Content on success
    """
    # Check if user exists
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Cannot delete service users
    if database.users.is_service_user(tenant_id, user_id):
        raise HTTPException(
            status_code=400,
            detail="Cannot delete service user. Delete the associated OAuth2 client first.",
        )

    # Cannot delete yourself
    if str(user["id"]) == str(admin["id"]):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    # Delete user
    database.users.delete_user(tenant_id, user_id)

    return None
