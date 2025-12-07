"""User API endpoints."""

from typing import Annotated

from api_dependencies import get_current_user_api, require_admin_api
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query
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
from services import emails as emails_service
from services import mfa as mfa_service
from services import settings as settings_service
from services import users as users_service
from services.exceptions import ServiceError
from services.types import RequestingUser
from utils.email import (
    send_email_verification,
    send_mfa_code_email,
    send_primary_email_changed_notification,
    send_secondary_email_added_notification,
    send_secondary_email_removed_notification,
)
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


def _to_requesting_user(user: dict, tenant_id: str) -> RequestingUser:
    """Convert route user dict to RequestingUser for service layer."""
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=user.get("role", "member"),
    )


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
    return users_service.get_available_roles()


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
    requesting_user = _to_requesting_user(user, tenant_id)
    return users_service.get_current_user_profile(requesting_user, user)


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
    requesting_user = _to_requesting_user(user, tenant_id)
    try:
        return users_service.update_current_user_profile(requesting_user, user, profile_update)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        emails = emails_service.list_user_emails(requesting_user, str(user["id"]))
        return EmailList(items=emails)
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        user_id = str(user["id"])

        # Get tenant setting for user email add permission
        allow_add = settings_service.can_users_add_emails(tenant_id)

        # Add email via service (user action, not admin)
        email_info = emails_service.add_user_email(
            requesting_user,
            user_id,
            email_data.email,
            is_admin_action=False,
            allow_users_add_emails=allow_add,
        )

        # Get verification info to send email
        verification_info = emails_service.resend_verification(
            requesting_user, user_id, email_info.id
        )

        # Send verification email
        verification_url = (
            f"/api/v1/users/me/emails/{email_info.id}/verify"
            f"?nonce={verification_info['verify_nonce']}"
        )
        send_email_verification(email_info.email, verification_url)

        return email_info
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        emails_service.delete_user_email(requesting_user, str(user["id"]), email_id)
        return None
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        return emails_service.set_primary_email(requesting_user, str(user["id"]), email_id)
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        verification_info = emails_service.resend_verification(
            requesting_user, str(user["id"]), email_id
        )

        # Send verification email
        verification_url = (
            f"/api/v1/users/me/emails/{verification_info['email_id']}/verify"
            f"?nonce={verification_info['verify_nonce']}"
        )
        send_email_verification(verification_info["email"], verification_url)

        return {"message": "Verification email sent"}
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        return emails_service.verify_email(
            tenant_id, email_id, str(user["id"]), verify_request.nonce
        )
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    requesting_user = _to_requesting_user(admin, tenant_id)
    try:
        return users_service.list_users(
            requesting_user,
            page=page,
            limit=limit,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


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
    requesting_user = _to_requesting_user(admin, tenant_id)
    try:
        return users_service.get_user(requesting_user, user_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


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
    requesting_user = _to_requesting_user(admin, tenant_id)
    try:
        return users_service.create_user(requesting_user, user_data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


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
    requesting_user = _to_requesting_user(admin, tenant_id)
    try:
        return users_service.update_user(requesting_user, user_id, user_update)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


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
    requesting_user = _to_requesting_user(admin, tenant_id)
    try:
        users_service.delete_user(requesting_user, user_id)
        return None
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


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
    try:
        requesting_user = _to_requesting_user(admin, tenant_id)
        emails = emails_service.list_user_emails(requesting_user, user_id)
        return EmailList(items=emails)
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(admin, tenant_id)

        # Get primary email before adding (for notification)
        primary_email = emails_service.get_primary_email(tenant_id, user_id)

        # Add verified email via service (admin action)
        email_info = emails_service.add_user_email(
            requesting_user,
            user_id,
            email_data.email,
            is_admin_action=True,
        )

        # Send notification to primary email
        if primary_email:
            admin_name = f"{admin['first_name']} {admin['last_name']}"
            send_secondary_email_added_notification(primary_email, email_info.email, admin_name)

        return email_info
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(admin, tenant_id)

        # Get email address before deletion for notification
        email_address = emails_service.get_email_address_by_id(tenant_id, user_id, email_id)

        # Delete the email (service handles validation)
        emails_service.delete_user_email(requesting_user, user_id, email_id)

        # Send notification to primary email
        if email_address:
            primary_email = emails_service.get_primary_email(tenant_id, user_id)
            if primary_email and primary_email != email_address:
                admin_name = f"{admin['first_name']} {admin['last_name']}"
                send_secondary_email_removed_notification(primary_email, email_address, admin_name)

        return None
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(admin, tenant_id)

        # Get current primary email for notification before change
        old_primary = emails_service.get_primary_email(tenant_id, user_id)

        # Set new primary (service handles all validation)
        result = emails_service.set_primary_email(requesting_user, user_id, email_id)

        # Send notification to old primary email if it changed
        if old_primary and old_primary != result.email:
            admin_name = f"{admin['first_name']} {admin['last_name']}"
            send_primary_email_changed_notification(old_primary, result.email, admin_name)

        return result
    except ServiceError as e:
        raise translate_to_http_exception(e)


# ============================================================================
# User MFA Management Endpoints
# ============================================================================


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        return mfa_service.get_mfa_status(requesting_user, user)
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        return mfa_service.setup_totp(requesting_user, user)
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        return mfa_service.verify_totp_and_enable(requesting_user, user, verify_request.code)
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        response, notification_info = mfa_service.enable_email_mfa(requesting_user, user)

        # Send OTP email if downgrade is in progress
        if notification_info:
            send_mfa_code_email(notification_info["email"], notification_info["code"])

        return response
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        return mfa_service.verify_mfa_downgrade(requesting_user, user, verify_request.code)
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        return mfa_service.disable_mfa(requesting_user, user)
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        return mfa_service.get_backup_codes_status(requesting_user, user)
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(user, tenant_id)
        return mfa_service.regenerate_backup_codes(requesting_user, user)
    except ServiceError as e:
        raise translate_to_http_exception(e)


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
    try:
        requesting_user = _to_requesting_user(admin, tenant_id)
        return mfa_service.reset_user_mfa(requesting_user, user_id)
    except ServiceError as e:
        raise translate_to_http_exception(e)
