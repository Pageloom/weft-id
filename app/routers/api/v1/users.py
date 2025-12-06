"""User API endpoints."""

from datetime import UTC, datetime
from typing import Annotated

import database
from api_dependencies import get_current_user_api, require_admin_api
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, HTTPException, Query
from schemas.api import (
    BackupCodesResponse,
    BackupCodesStatusResponse,
    EmailCreate,
    EmailInfo,
    EmailList,
    EmailOTPVerifyRequest,
    EmailVerifyRequest,
    MFAEnableResponse,
    MFAStatus,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    UserCreate,
    UserDetail,
    UserListResponse,
    UserProfile,
    UserProfileUpdate,
    UserSummary,
    UserUpdate,
)
from utils.email import (
    send_email_verification,
    send_mfa_code_email,
    send_primary_email_changed_notification,
    send_secondary_email_added_notification,
    send_secondary_email_removed_notification,
)
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


@router.get("/roles", response_model=list[str])
def list_roles(
    admin: Annotated[dict, Depends(require_admin_api)],
):
    """
    List available user roles.

    Requires admin role.

    Returns:
        List of role names: member, admin, super_admin
    """
    return ["member", "admin", "super_admin"]


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
# User Email Management Endpoints
# ============================================================================


def _email_to_info(email: dict) -> EmailInfo:
    """Convert database email dict to EmailInfo schema."""
    return EmailInfo(
        id=str(email["id"]),
        email=email["email"],
        is_primary=email["is_primary"],
        verified_at=email.get("verified_at"),
        created_at=email["created_at"],
    )


@router.get("/me/emails", response_model=EmailList)
def list_current_user_emails(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    List all email addresses for the current user.

    Returns:
        List of email addresses with their verification status
    """
    emails = database.user_emails.list_user_emails(tenant_id, user["id"])
    return EmailList(items=[_email_to_info(e) for e in emails])


@router.post("/me/emails", response_model=EmailInfo, status_code=201)
def add_current_user_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    email_data: EmailCreate,
):
    """
    Add a new email address to the current user's account.

    The email will be unverified until the user clicks the verification link
    sent to the email address.

    Request Body:
        email: Email address to add

    Returns:
        Created email info (unverified)

    Note:
        May be restricted by tenant security settings (allow_users_add_emails).
        Super admins can always add emails.
    """
    # Check if user is allowed to add emails
    if user.get("role") != "super_admin":
        security_settings = database.security.can_user_add_emails(tenant_id)
        if security_settings and not security_settings.get("allow_users_add_emails"):
            raise HTTPException(
                status_code=403,
                detail="Adding email addresses is disabled by administrator",
            )

    email_lower = email_data.email.lower()

    # Check if email already exists
    if database.user_emails.email_exists(tenant_id, email_lower):
        raise HTTPException(status_code=409, detail="Email address already exists")

    # Add email (unverified)
    result = database.user_emails.add_email(tenant_id, user["id"], email_lower, user["tenant_id"])

    if not result:
        raise HTTPException(status_code=500, detail="Failed to add email address")

    # Send verification email
    # Note: For API, we construct a generic verification URL
    # The frontend should handle the actual verification flow
    verification_url = (
        f"/api/v1/users/me/emails/{result['id']}/verify?nonce={result['verify_nonce']}"
    )
    send_email_verification(email_lower, verification_url)

    # Fetch the created email from the list (has created_at)
    emails = database.user_emails.list_user_emails(tenant_id, user["id"])
    for e in emails:
        if str(e["id"]) == str(result["id"]):
            return _email_to_info(e)

    # Fallback: return basic info with current timestamp
    return EmailInfo(
        id=str(result["id"]),
        email=email_lower,
        is_primary=False,
        verified_at=None,
        created_at=datetime.now(UTC),
    )


@router.delete("/me/emails/{email_id}", status_code=204)
def delete_current_user_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    email_id: str,
):
    """
    Delete an email address from the current user's account.

    Path Parameters:
        email_id: Email UUID

    Returns:
        204 No Content on success

    Note:
        Cannot delete the primary email address.
    """
    # Verify email belongs to user
    email = database.user_emails.get_email_by_id(tenant_id, email_id, user["id"])

    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    if email["is_primary"]:
        raise HTTPException(status_code=400, detail="Cannot delete primary email address")

    database.user_emails.delete_email(tenant_id, email_id)
    return None


@router.post("/me/emails/{email_id}/set-primary", response_model=EmailInfo)
def set_current_user_primary_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    email_id: str,
):
    """
    Set an email address as the primary email for the current user.

    Path Parameters:
        email_id: Email UUID

    Returns:
        Updated email info

    Note:
        Email must be verified before it can be set as primary.
    """
    # Verify email belongs to user
    email = database.user_emails.get_email_by_id(tenant_id, email_id, user["id"])

    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    if not email["verified_at"]:
        raise HTTPException(status_code=400, detail="Cannot set unverified email as primary")

    if email["is_primary"]:
        # Already primary, just return it
        emails = database.user_emails.list_user_emails(tenant_id, user["id"])
        for e in emails:
            if str(e["id"]) == email_id:
                return _email_to_info(e)

    # Unset current primary and set new one
    database.user_emails.unset_primary_emails(tenant_id, user["id"])
    database.user_emails.set_primary_email(tenant_id, email_id)

    # Fetch updated email
    emails = database.user_emails.list_user_emails(tenant_id, user["id"])
    for e in emails:
        if str(e["id"]) == email_id:
            return _email_to_info(e)

    raise HTTPException(status_code=500, detail="Failed to retrieve updated email")


@router.post("/me/emails/{email_id}/resend-verification")
def resend_current_user_email_verification(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    email_id: str,
):
    """
    Resend verification email for an unverified email address.

    Path Parameters:
        email_id: Email UUID

    Returns:
        Success message
    """
    # Get email with nonce
    email = database.user_emails.get_email_with_nonce(tenant_id, email_id, user["id"])

    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    # Send verification email
    verification_url = f"/api/v1/users/me/emails/{email['id']}/verify?nonce={email['verify_nonce']}"
    send_email_verification(email["email"], verification_url)

    return {"message": "Verification email sent"}


@router.post("/me/emails/{email_id}/verify", response_model=EmailInfo)
def verify_current_user_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    email_id: str,
    verify_request: EmailVerifyRequest,
):
    """
    Verify an email address using the verification nonce.

    Path Parameters:
        email_id: Email UUID

    Request Body:
        nonce: Verification nonce from email link

    Returns:
        Verified email info
    """
    # Get email for verification
    email = database.user_emails.get_email_for_verification(tenant_id, email_id)

    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    # Verify email belongs to user
    if str(email["user_id"]) != str(user["id"]):
        raise HTTPException(status_code=404, detail="Email not found")

    # Check if already verified
    if email["verified_at"]:
        raise HTTPException(status_code=400, detail="Email already verified")

    # Verify nonce
    if email["verify_nonce"] != verify_request.nonce:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # Mark as verified
    database.user_emails.verify_email(tenant_id, email_id)

    # Fetch updated email
    emails = database.user_emails.list_user_emails(tenant_id, user["id"])
    for e in emails:
        if str(e["id"]) == email_id:
            return _email_to_info(e)

    raise HTTPException(status_code=500, detail="Failed to retrieve verified email")


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


# ============================================================================
# Admin Email Management Endpoints
# ============================================================================


@router.get("/{user_id}/emails", response_model=EmailList)
def list_user_emails(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    List all email addresses for a specific user.

    Requires admin role.

    Path Parameters:
        user_id: User UUID

    Returns:
        List of email addresses with their verification status
    """
    # Verify user exists
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    return EmailList(items=[_email_to_info(e) for e in emails])


@router.post("/{user_id}/emails", response_model=EmailInfo, status_code=201)
def add_user_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
    email_data: EmailCreate,
):
    """
    Add a new email address to a user's account (admin operation).

    Requires admin role. Email is added as verified (no verification required).

    Path Parameters:
        user_id: User UUID

    Request Body:
        email: Email address to add

    Returns:
        Created email info (verified)

    Note:
        Sends notification to user's primary email about the added address.
    """
    # Verify user exists
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    email_lower = email_data.email.lower()

    # Check if email already exists
    if database.user_emails.email_exists(tenant_id, email_lower):
        raise HTTPException(status_code=409, detail="Email address already exists")

    # Add verified email
    result = database.user_emails.add_verified_email(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        user_id=user_id,
        email=email_lower,
        is_primary=False,
    )

    if not result:
        raise HTTPException(status_code=500, detail="Failed to add email address")

    # Send notification to primary email
    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email:
        admin_name = f"{admin['first_name']} {admin['last_name']}"
        send_secondary_email_added_notification(primary_email["email"], email_lower, admin_name)

    # Fetch created email
    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    for e in emails:
        if e["email"] == email_lower:
            return _email_to_info(e)

    raise HTTPException(status_code=500, detail="Failed to retrieve created email")


@router.delete("/{user_id}/emails/{email_id}", status_code=204)
def delete_user_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
    email_id: str,
):
    """
    Delete an email address from a user's account (admin operation).

    Requires admin role.

    Path Parameters:
        user_id: User UUID
        email_id: Email UUID

    Returns:
        204 No Content on success

    Note:
        Cannot delete the primary email address.
        Sends notification to user's primary email about the removal.
    """
    # Verify user exists
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify email belongs to user
    email = database.user_emails.get_email_by_id(tenant_id, email_id, user_id)
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    if email["is_primary"]:
        raise HTTPException(status_code=400, detail="Cannot delete primary email address")

    # Get email address before deletion for notification
    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    email_address = None
    for e in emails:
        if str(e["id"]) == email_id:
            email_address = e["email"]
            break

    database.user_emails.delete_email(tenant_id, email_id)

    # Send notification to primary email
    if email_address:
        primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
        if primary_email and primary_email["email"] != email_address:
            admin_name = f"{admin['first_name']} {admin['last_name']}"
            send_secondary_email_removed_notification(
                primary_email["email"], email_address, admin_name
            )

    return None


@router.post("/{user_id}/emails/{email_id}/set-primary", response_model=EmailInfo)
def set_user_primary_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
    email_id: str,
):
    """
    Set an email address as the primary email for a user (admin operation).

    Requires admin role.

    Path Parameters:
        user_id: User UUID
        email_id: Email UUID

    Returns:
        Updated email info

    Note:
        Email must be verified before it can be set as primary.
        Sends notification to the old primary email about the change.
    """
    # Verify user exists
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify email belongs to user
    email = database.user_emails.get_email_by_id(tenant_id, email_id, user_id)
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    if not email["verified_at"]:
        raise HTTPException(status_code=400, detail="Cannot set unverified email as primary")

    if email["is_primary"]:
        # Already primary, just return it
        emails = database.user_emails.list_user_emails(tenant_id, user_id)
        for e in emails:
            if str(e["id"]) == email_id:
                return _email_to_info(e)

    # Get current primary email for notification
    old_primary = database.user_emails.get_primary_email(tenant_id, user_id)

    # Unset current primary and set new one
    database.user_emails.unset_primary_emails(tenant_id, user_id)
    database.user_emails.set_primary_email(tenant_id, email_id)

    # Get new primary email address
    emails = database.user_emails.list_user_emails(tenant_id, user_id)
    new_primary_email = None
    result_email = None
    for e in emails:
        if str(e["id"]) == email_id:
            new_primary_email = e["email"]
            result_email = _email_to_info(e)
            break

    # Send notification to old primary email
    if old_primary and new_primary_email and old_primary["email"] != new_primary_email:
        admin_name = f"{admin['first_name']} {admin['last_name']}"
        send_primary_email_changed_notification(old_primary["email"], new_primary_email, admin_name)

    if result_email:
        return result_email

    raise HTTPException(status_code=500, detail="Failed to retrieve updated email")


# ============================================================================
# User MFA Management Endpoints
# ============================================================================


def _get_mfa_status(tenant_id: str, user: dict) -> MFAStatus:
    """Get MFA status for a user."""
    backup_codes = database.mfa.list_backup_codes(tenant_id, user["id"])
    remaining = sum(1 for c in backup_codes if c.get("used_at") is None)

    return MFAStatus(
        enabled=user.get("mfa_enabled", False),
        method=user.get("mfa_method"),
        has_backup_codes=len(backup_codes) > 0,
        backup_codes_remaining=remaining,
    )


@router.get("/me/mfa", response_model=MFAStatus)
def get_current_user_mfa_status(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Get the current user's MFA status.

    Returns:
        MFA status including enabled state, method, and backup codes availability
    """
    return _get_mfa_status(tenant_id, user)


@router.post("/me/mfa/totp/setup", response_model=TOTPSetupResponse)
def setup_current_user_totp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Initiate TOTP (authenticator app) setup for the current user.

    Generates a new TOTP secret and returns it along with the QR code URI.
    The secret is stored unverified until confirmed via the verify endpoint.

    Returns:
        TOTP setup details including secret (for manual entry) and URI (for QR codes)

    Note:
        If TOTP is already active, user must downgrade to email MFA first.
    """
    # Prevent TOTP setup if TOTP is already active
    if user.get("mfa_method") == "totp":
        raise HTTPException(
            status_code=400,
            detail="TOTP is already active. Downgrade to email MFA first to reconfigure.",
        )

    # Generate TOTP secret
    secret = generate_totp_secret()
    secret_encrypted = encrypt_secret(secret)

    # Get user email for URI
    email_row = database.user_emails.get_primary_email(tenant_id, user["id"])
    email = email_row["email"] if email_row else "user@example.com"

    # Generate URI for QR code
    uri = generate_totp_uri(secret, email)
    secret_display = format_secret_for_display(secret)

    # Store unverified secret
    database.mfa.create_totp_secret(tenant_id, user["id"], secret_encrypted, tenant_id)

    return TOTPSetupResponse(secret=secret_display, uri=uri)


@router.post("/me/mfa/totp/verify", response_model=BackupCodesResponse)
def verify_current_user_totp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    verify_request: TOTPVerifyRequest,
):
    """
    Verify TOTP code and enable TOTP MFA for the current user.

    After successful verification, backup codes are generated and returned.
    These codes should be saved securely as they are only shown once.

    Request Body:
        code: 6-digit TOTP code from authenticator app

    Returns:
        Backup codes (save these securely, only shown once)
    """
    # Get unverified secret
    row = database.mfa.get_totp_secret(tenant_id, user["id"], "totp")

    if not row:
        raise HTTPException(
            status_code=400,
            detail="No TOTP setup in progress. Start setup first.",
        )

    secret = decrypt_secret(row["secret_encrypted"])
    code_clean = verify_request.code.replace(" ", "").replace("-", "")

    if not verify_totp_code(secret, code_clean):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    # Mark secret as verified
    database.mfa.verify_totp_secret(tenant_id, user["id"], "totp")

    # Enable TOTP MFA on user account
    database.mfa.enable_mfa(tenant_id, user["id"], "totp")

    # Delete existing backup codes (to replace them with new ones)
    database.mfa.delete_backup_codes(tenant_id, user["id"])

    # Generate backup codes
    backup_codes = generate_backup_codes()

    # Store hashed backup codes
    for code_str in backup_codes:
        code_hash = hash_code(code_str.replace("-", ""))
        database.mfa.create_backup_code(tenant_id, user["id"], code_hash, tenant_id)

    return BackupCodesResponse(codes=backup_codes, count=len(backup_codes))


@router.post("/me/mfa/email/enable", response_model=MFAEnableResponse)
def enable_current_user_email_mfa(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Enable email-only MFA for the current user.

    If user currently has TOTP enabled, this initiates a downgrade process:
    - An email OTP is sent to the user's primary email
    - The verify-downgrade endpoint must be called with the OTP to complete

    If user has no MFA or already has email MFA, this enables/confirms email MFA directly.

    Returns:
        MFA status if enabled directly, or pending_verification=true if downgrade required
    """
    current_method = user.get("mfa_method")

    if current_method == "totp":
        # Downgrading from TOTP to email - require verification
        email_row = database.user_emails.get_primary_email(tenant_id, user["id"])

        if not email_row:
            raise HTTPException(
                status_code=400,
                detail="No primary email found for verification",
            )

        # Create and send email OTP
        code = create_email_otp(tenant_id, user["id"])
        send_mfa_code_email(email_row["email"], code)

        return MFAEnableResponse(
            status=None,
            pending_verification=True,
            message="Verification code sent. Use the verify-downgrade endpoint to complete.",
        )

    # Normal case: enable email MFA directly
    database.mfa.enable_mfa(tenant_id, user["id"], "email")

    # Refresh user data
    updated_user = database.users.get_user_by_id(tenant_id, user["id"])
    if not updated_user:
        raise HTTPException(status_code=500, detail="Failed to retrieve user")

    return MFAEnableResponse(
        status=_get_mfa_status(tenant_id, updated_user),
        pending_verification=False,
        message=None,
    )


@router.post("/me/mfa/email/verify-downgrade", response_model=MFAStatus)
def verify_current_user_mfa_downgrade(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    verify_request: EmailOTPVerifyRequest,
):
    """
    Complete TOTP to email MFA downgrade by verifying the email OTP.

    This endpoint should be called after enable_current_user_email_mfa
    returns pending_verification=true.

    Request Body:
        code: 6-digit email OTP code

    Returns:
        Updated MFA status
    """
    # Verify user currently has TOTP
    if user.get("mfa_method") != "totp":
        raise HTTPException(
            status_code=400,
            detail="This endpoint is only for downgrading from TOTP to email MFA",
        )

    # Verify the email OTP
    code_clean = verify_request.code.replace(" ", "").replace("-", "")
    if not verify_email_otp(tenant_id, user["id"], code_clean):
        raise HTTPException(status_code=400, detail="Invalid or expired verification code")

    # Downgrade to email MFA
    database.mfa.set_mfa_method(tenant_id, user["id"], "email")

    # Delete TOTP secrets
    database.mfa.delete_totp_secrets(tenant_id, user["id"])

    # Refresh user data
    updated_user = database.users.get_user_by_id(tenant_id, user["id"])
    if not updated_user:
        raise HTTPException(status_code=500, detail="Failed to retrieve user")

    return _get_mfa_status(tenant_id, updated_user)


@router.post("/me/mfa/disable", response_model=MFAStatus)
def disable_current_user_mfa(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Disable MFA for the current user.

    Removes all MFA protection from the account. TOTP secrets and backup codes
    are deleted.

    Returns:
        Updated MFA status
    """
    # Disable MFA
    database.mfa.enable_mfa(tenant_id, user["id"], "email")  # Reset to email first
    database.users.update_mfa_status(tenant_id, user["id"], enabled=False)

    # Delete TOTP secrets and backup codes
    database.mfa.delete_totp_secrets(tenant_id, user["id"])
    database.mfa.delete_backup_codes(tenant_id, user["id"])

    # Refresh user data
    updated_user = database.users.get_user_by_id(tenant_id, user["id"])
    if not updated_user:
        raise HTTPException(status_code=500, detail="Failed to retrieve user")

    return _get_mfa_status(tenant_id, updated_user)


@router.get("/me/mfa/backup-codes", response_model=BackupCodesStatusResponse)
def get_current_user_backup_codes_status(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Get backup codes status for the current user.

    Returns the count and usage status of backup codes.
    For security, actual codes are not returned (only shown once when generated).

    Returns:
        Backup codes status (total, used, remaining)
    """
    backup_codes = database.mfa.list_backup_codes(tenant_id, user["id"])

    total = len(backup_codes)
    used = sum(1 for c in backup_codes if c.get("used_at") is not None)
    remaining = total - used

    return BackupCodesStatusResponse(total=total, used=used, remaining=remaining)


@router.post("/me/mfa/backup-codes/regenerate", response_model=BackupCodesResponse)
def regenerate_current_user_backup_codes(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Regenerate backup codes for the current user.

    Deletes all existing backup codes and generates new ones.
    Save the returned codes securely as they are only shown once.

    Returns:
        New backup codes (save these securely, only shown once)

    Note:
        MFA must be enabled to regenerate backup codes.
    """
    if not user.get("mfa_enabled"):
        raise HTTPException(
            status_code=400,
            detail="MFA must be enabled to regenerate backup codes",
        )

    # Delete existing backup codes
    database.mfa.delete_backup_codes(tenant_id, user["id"])

    # Generate new backup codes
    backup_codes = generate_backup_codes()

    # Store hashed backup codes
    for code_str in backup_codes:
        code_hash = hash_code(code_str.replace("-", ""))
        database.mfa.create_backup_code(tenant_id, user["id"], code_hash, tenant_id)

    return BackupCodesResponse(codes=backup_codes, count=len(backup_codes))


# ============================================================================
# Admin MFA Management Endpoints
# ============================================================================


@router.post("/{user_id}/mfa/reset", response_model=MFAStatus)
def reset_user_mfa(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    Reset MFA for a user (admin operation).

    Disables MFA and deletes all TOTP secrets and backup codes for the user.
    Use this when a user has lost access to their MFA device/codes.

    Requires admin role.

    Path Parameters:
        user_id: User UUID

    Returns:
        Updated MFA status
    """
    # Verify user exists
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Disable MFA
    database.users.update_mfa_status(tenant_id, user_id, enabled=False)

    # Delete TOTP secrets and backup codes
    database.mfa.delete_totp_secrets(tenant_id, user_id)
    database.mfa.delete_backup_codes(tenant_id, user_id)

    # Refresh user data
    updated_user = database.users.get_user_by_id(tenant_id, user_id)
    if not updated_user:
        raise HTTPException(status_code=500, detail="Failed to retrieve user")

    return _get_mfa_status(tenant_id, updated_user)
