"""FastAPI dependencies for request handling."""

from typing import Annotated, cast

import database
import settings
from fastapi import Depends, HTTPException, Request
from utils import auth


class RedirectError(Exception):
    """Exception that triggers an HTTP redirect.

    Use this in dependencies to redirect unauthenticated or unauthorized users.
    Must be registered with FastAPI's exception handler in main.py.
    """

    def __init__(self, url: str, status_code: int = 303):
        self.url = url
        self.status_code = status_code


def normalize_host(h: str | None) -> str:
    """Normalize host header by removing port and trailing dots."""
    h = (h or "").split(":")[0].rstrip(".").lower()
    return h


def get_tenant_id_from_request(request: Request) -> str:
    """Extract tenant ID from request hostname."""
    host = normalize_host(request.headers.get("x-forwarded-host") or request.headers.get("host"))

    if not host.endswith(f".{settings.BASE_DOMAIN}"):
        raise HTTPException(status_code=404, detail="Unknown host")

    subdomain = host.split(".")[0]

    row = database.tenants.get_tenant_by_subdomain(subdomain)

    if not row:
        raise HTTPException(status_code=404, detail=f"No tenant configured for host {host}")

    return cast(str, row["id"])


def get_current_user(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
) -> dict | None:
    """Get the currently authenticated user from session.

    This is a dependency wrapper around utils.auth.get_current_user.
    Returns user dict if authenticated, None otherwise.
    """
    return auth.get_current_user(request, tenant_id)


def require_current_user(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
) -> dict:
    """Require authentication, redirect to /login if not authenticated.

    This dependency should be used at the router level or individual route level
    to enforce authentication before the handler executes.

    Returns:
        dict: The authenticated user data

    Raises:
        RedirectResponse: Redirects to /login if user is not authenticated
    """
    user = auth.get_current_user(request, tenant_id)
    if not user:
        raise RedirectError(url="/login", status_code=303)
    return user


def require_admin(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
) -> dict:
    """Require admin role, redirect if user lacks admin permissions.

    This dependency enforces that the user is authenticated AND has admin
    or super_admin role before the handler executes.

    Returns:
        dict: The authenticated user data with admin role

    Raises:
        RedirectResponse: Redirects to /login if not authenticated,
                         or /dashboard if lacking admin permissions
    """
    user = auth.get_current_user(request, tenant_id)
    if not user:
        raise RedirectError(url="/login", status_code=303)

    user_role = user.get("role")
    if user_role not in ("admin", "super_admin"):
        raise RedirectError(url="/dashboard", status_code=303)

    return user


def require_super_admin(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
) -> dict:
    """Require super_admin role, redirect if user lacks super admin permissions.

    This dependency enforces that the user is authenticated AND has
    super_admin role before the handler executes.

    Returns:
        dict: The authenticated user data with super_admin role

    Raises:
        RedirectResponse: Redirects to /login if not authenticated,
                         or /dashboard if lacking super_admin permissions
    """
    user = auth.get_current_user(request, tenant_id)
    if not user:
        raise RedirectError(url="/login", status_code=303)

    user_role = user.get("role")
    if user_role != "super_admin":
        raise RedirectError(url="/dashboard", status_code=303)

    return user
