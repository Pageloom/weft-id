"""Admin user management API endpoints."""

from typing import Annotated

import routers.api.v1.users as _pkg
from api_dependencies import require_admin_api, require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query
from schemas.api import (
    UserCreate,
    UserDetail,
    UserListResponse,
    UserUpdate,
)
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
    limit: int = Query(25, ge=1, le=100, description="Number of results per page"),
    search: str | None = Query(None, description="Search by name or email"),
    sort_by: str = Query(
        "created_at",
        description="Sort field (name, email, role, created_at, last_login, last_activity_at)",
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
        sort_by: Field to sort by (name, email, role, created_at, last_login, last_activity_at)
        sort_order: Sort order (asc or desc)

    Returns:
        Paginated list of users
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return _pkg.users_service.list_users(
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
