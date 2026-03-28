"""Admin user management API endpoints."""

from datetime import date
from typing import Annotated

import routers.api.v1.users as _pkg
from api_dependencies import require_admin_api, require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query, Request
from schemas.api import (
    UserCreate,
    UserDetail,
    UserListResponse,
    UserUpdate,
)
from schemas.saml import UserIdpAssignment
from schemas.service_providers import UserAccessibleAppList
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter()


# ============================================================================
# Admin User Management Endpoints
# ============================================================================


@router.get("/", response_model=UserListResponse)
def list_users(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(25, ge=1, le=250, description="Number of results per page"),
    search: str | None = Query(None, description="Search by name or email"),
    sort_by: str = Query(
        "created_at",
        description="Sort field (name, email, role, created_at, last_login, last_activity_at)",
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order"),
    role: str | None = Query(
        None, description="Comma-separated role filter (member,admin,super_admin)"
    ),
    status: str | None = Query(
        None, description="Comma-separated status filter (active,inactivated,anonymized)"
    ),
    auth_method: str | None = Query(None, description="Comma-separated auth method filter"),
    domain: str | None = Query(None, description="Filter by email domain"),
    group_id: str | None = Query(None, description="Filter by group membership (group UUID)"),
    has_secondary_email: bool | None = Query(None, description="Filter by secondary email"),
    activity_start: date | None = Query(None, description="Activity start date (YYYY-MM-DD)"),
    activity_end: date | None = Query(None, description="Activity end date (YYYY-MM-DD)"),
):
    """
    List all users in the tenant with pagination and search.

    Requires admin role.

    Query Parameters:
        page: Page number (default: 1)
        limit: Results per page (default: 25, max: 250)
        search: Search term for name or email
        sort_by: Field to sort by (name, email, role, created_at, last_login, last_activity_at)
        sort_order: Sort order (asc or desc)
        role: Comma-separated role filter (member, admin, super_admin)
        status: Comma-separated status filter (active, inactivated, anonymized)
        auth_method: Comma-separated auth method keys
        domain: Filter by email domain (e.g. example.com)
        group_id: Filter by group membership (group UUID)
        has_secondary_email: Filter by secondary email existence (true/false)
        activity_start: Filter by activity start date (YYYY-MM-DD, inclusive)
        activity_end: Filter by activity end date (YYYY-MM-DD, inclusive)

    Returns:
        Paginated list of users
    """
    # Parse filters
    roles: list[str] | None = None
    if role:
        allowed_roles = {"member", "admin", "super_admin"}
        roles = [r.strip() for r in role.split(",") if r.strip() in allowed_roles]
        if not roles:
            roles = None

    statuses: list[str] | None = None
    if status:
        allowed_statuses = {"active", "inactivated", "anonymized"}
        statuses = [s.strip() for s in status.split(",") if s.strip() in allowed_statuses]
        if not statuses:
            statuses = None

    auth_methods: list[str] | None = None
    if auth_method:
        auth_methods = [m.strip() for m in auth_method.split(",") if m.strip()]
        if not auth_methods:
            auth_methods = None

    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return _pkg.users_service.list_users(
            requesting_user,
            page=page,
            limit=limit,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            roles=roles,
            statuses=statuses,
            auth_methods=auth_methods,
            domain=domain,
            group_id=group_id,
            has_secondary_email=has_secondary_email,
            activity_start=activity_start,
            activity_end=activity_end,
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
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return _pkg.users_service.get_user(requesting_user, user_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/", response_model=UserDetail, status_code=201)
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
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return _pkg.users_service.create_user(requesting_user, user_data)
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
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return _pkg.users_service.update_user(requesting_user, user_id, user_update)
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
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        _pkg.users_service.delete_user(requesting_user, user_id)
        return None
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# ============================================================================
# Admin User State Management Endpoints
# ============================================================================


@router.post("/{user_id}/inactivate", response_model=UserDetail)
def inactivate_user(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    Inactivate a user account (soft-disable login).

    Inactivated users cannot sign in but retain all their data.
    This operation is reversible via the reactivate endpoint.

    Requires admin role.

    Path Parameters:
        user_id: User UUID

    Returns:
        Updated user details

    Errors:
        403: Insufficient permissions
        404: User not found
        400: Cannot inactivate self, service users, or last super_admin
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        return _pkg.users_service.inactivate_user(requesting_user, user_id)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/{user_id}/reactivate", response_model=UserDetail)
def reactivate_user(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    Reactivate an inactivated user account.

    Restores login access for a previously inactivated user.

    Requires admin role.

    Path Parameters:
        user_id: User UUID

    Returns:
        Updated user details

    Errors:
        403: Insufficient permissions
        404: User not found
        400: User is not inactivated, or user was anonymized
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        return _pkg.users_service.reactivate_user(requesting_user, user_id)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/{user_id}/anonymize", response_model=UserDetail)
def anonymize_user(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    user_id: str,
):
    """
    Anonymize a user account (GDPR right to be forgotten).

    This is IRREVERSIBLE. Scrubs all PII:
    - User name becomes "[Anonymized] User"
    - Email addresses are anonymized
    - MFA data is deleted
    - Password is cleared

    The user record is preserved for audit log integrity.

    Requires super_admin role.

    Path Parameters:
        user_id: User UUID

    Returns:
        Updated user details (with anonymized data)

    Errors:
        403: Insufficient permissions (super_admin required)
        404: User not found
        400: Cannot anonymize self, service users, or last super_admin
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        return _pkg.users_service.anonymize_user(requesting_user, user_id)
    except ServiceError as e:
        raise translate_to_http_exception(e)


# ============================================================================
# Admin User IdP Assignment Endpoints
# ============================================================================


@router.put("/{user_id}/idp", status_code=204)
def assign_user_idp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    user_id: str,
    assignment: UserIdpAssignment,
):
    """
    Assign a user to a SAML IdP or set them as password-only.

    Every user must be either:
    - Password user (saml_idp_id = null) - authenticates with password
    - IdP user (saml_idp_id = UUID) - authenticates via SAML

    Security constraints:
    - Assigning to IdP wipes password (keeps MFA)
    - Removing from IdP inactivates user and unverifies emails

    Requires super_admin role.

    Path Parameters:
        user_id: User UUID

    Request Body:
        saml_idp_id: IdP UUID to assign, or null for password-only

    Returns:
        204 No Content on success

    Errors:
        403: Insufficient permissions (super_admin required)
        404: User or IdP not found
        400: Invalid assignment (e.g., already assigned to same IdP)
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        _pkg.saml_service.assign_user_idp(
            requesting_user=requesting_user,
            user_id=user_id,
            saml_idp_id=assignment.saml_idp_id,
        )
        return None
    except ServiceError as e:
        raise translate_to_http_exception(e)


# ============================================================================
# Admin User Accessible Apps Endpoints
# ============================================================================


@router.get("/{user_id}/accessible-apps", response_model=UserAccessibleAppList)
def get_user_accessible_apps(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    Get all applications accessible to a user, with group attribution.

    Returns service providers the user can access via group membership
    (with granting group details) or because they are available to all users.

    Requires admin role.

    Path Parameters:
        user_id: User UUID

    Returns:
        items: List of accessible apps, each with:
            - id: SP UUID
            - name: SP display name
            - description: SP description (nullable)
            - entity_id: SAML entity ID (nullable)
            - available_to_all: Whether SP is available to all users
            - granting_groups: List of groups granting access (id, name)
        total: Total number of accessible apps

    Errors:
        403: Insufficient permissions (admin required)
        404: User not found
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        return _pkg.sp_service.get_user_accessible_apps_admin(requesting_user, user_id)
    except ServiceError as e:
        raise translate_to_http_exception(e)


# ============================================================================
# Admin User Invitation Endpoints
# ============================================================================


@router.post("/{user_id}/resend-invitation", status_code=204)
def resend_invitation(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    Resend the invitation email to a user who has not completed onboarding.

    Generates a fresh invitation link (invalidating the previous one) and sends
    the appropriate email based on the user's email verification status.

    Requires admin role.

    Path Parameters:
        user_id: User UUID

    Returns:
        204 No Content on success

    Errors:
        403: Insufficient permissions (admin required)
        404: User not found
        400: User has already set a password (already_onboarded),
             user is inactivated, or user is anonymized
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, request)
        result = _pkg.users_service.resend_invitation(requesting_user, user_id)
    except ServiceError as e:
        raise translate_to_http_exception(e)

    org_name = _pkg.users_service.get_tenant_name(tenant_id)
    admin_name = f"{admin.get('first_name')} {admin.get('last_name')}"

    if result["invitation_type"] == "set_password":
        password_set_url = (
            f"{request.base_url}set-password?email_id={result['email_id']}&nonce={result['nonce']}"
        )
        _pkg.send_new_user_privileged_domain_notification(
            result["email"], admin_name, org_name, password_set_url, tenant_id=tenant_id
        )
    else:
        verification_url = f"{request.base_url}verify-email/{result['email_id']}/{result['nonce']}"
        _pkg.send_new_user_invitation(
            result["email"], admin_name, org_name, verification_url, tenant_id=tenant_id
        )

    return None
