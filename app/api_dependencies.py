"""FastAPI dependencies for API endpoints with dual authentication support."""

from typing import Annotated

import database
from dependencies import get_tenant_id_from_request
from fastapi import Depends, Header, HTTPException, Request
from fastapi.security import APIKeyCookie, OAuth2PasswordBearer
from utils import auth
from utils.request_context import set_api_client_context

# Security schemes for OpenAPI documentation
# These are used to show the "Authorize" button in Swagger UI
# auto_error=False because we handle authentication manually in get_current_user_api
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/oauth2/token", auto_error=False)
session_cookie_scheme = APIKeyCookie(name="session", auto_error=False)


def get_current_user_api(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    """
    Get the currently authenticated user from either Bearer token OR session cookie.

    This dependency supports dual authentication:
    1. Bearer token in Authorization header (OAuth2)
    2. Session cookie (existing web authentication)

    Args:
        request: FastAPI request object
        tenant_id: Tenant ID extracted from hostname
        authorization: Authorization header (optional)

    Returns:
        dict: The authenticated user data

    Raises:
        HTTPException: 401 if not authenticated

    Example:
        # Bearer token authentication
        Authorization: Bearer loom_access_abc123...

        # Session cookie authentication
        Cookie: session=...
    """
    # Try Bearer token first
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]

        # Validate token (scoped to the tenant from request)
        token_data = database.oauth2.validate_token(token, tenant_id)

        if token_data:
            # Token is valid and matches tenant
            # Get user from token's user_id
            user = database.users.get_user_by_id(tenant_id, token_data["user_id"])

            if user:
                # Set API client context for event logging
                # token_data["client_id"] is the internal UUID (FK to oauth2_clients.id)
                client = database.oauth2.get_client_by_id(
                    tenant_id, str(token_data["client_id"])
                )
                if client:
                    set_api_client_context(
                        client_id=client["client_id"],
                        client_name=client["name"],
                        client_type=client["client_type"],
                    )

                # Add primary email to user dict (API responses include email)
                primary_email = database.user_emails.get_primary_email(tenant_id, user["id"])
                if primary_email:
                    user["email"] = primary_email["email"]
                return user

    # Fall back to session cookie
    user = auth.get_current_user(request, tenant_id)
    if user:
        # Add primary email to user dict (API responses include email)
        primary_email = database.user_emails.get_primary_email(tenant_id, user["id"])
        if primary_email:
            user["email"] = primary_email["email"]
        return user

    # Not authenticated via either method
    raise HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_admin_api(
    user: Annotated[dict, Depends(get_current_user_api)],
) -> dict:
    """
    Require admin or super_admin role for API endpoints.

    Args:
        user: Authenticated user from get_current_user_api

    Returns:
        dict: The authenticated user data with admin role

    Raises:
        HTTPException: 403 if user lacks admin permissions
    """
    user_role = user.get("role")
    if user_role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    return user


def require_super_admin_api(
    user: Annotated[dict, Depends(get_current_user_api)],
) -> dict:
    """
    Require super_admin role for API endpoints.

    Args:
        user: Authenticated user from get_current_user_api

    Returns:
        dict: The authenticated user data with super_admin role

    Raises:
        HTTPException: 403 if user lacks super_admin permissions
    """
    user_role = user.get("role")
    if user_role != "super_admin":
        raise HTTPException(
            status_code=403,
            detail="Super admin access required",
        )

    return user
