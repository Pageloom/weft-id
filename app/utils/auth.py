"""Authentication utilities for login and session management."""

from typing import Annotated

import database
from dependencies import get_tenant_id_from_request
from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from utils.password import verify_password


def verify_login(tenant_id: str, email: str, password: str) -> dict | None:
    """
    Verify email and password for a user within a tenant.
    Returns user dict if valid, None otherwise.
    Updates last_login timestamp on success.
    """
    # Find user by email within tenant
    user_email = database.users.get_user_by_email(tenant_id, email)

    if not user_email or not user_email["password_hash"]:
        return None

    # Verify password
    if not verify_password(user_email["password_hash"], password):
        return None

    user_id = user_email["user_id"]

    # Update last_login
    database.users.update_last_login(tenant_id, user_id)

    # Fetch and return full user record (including MFA fields)
    user = database.users.get_user_by_id(tenant_id, user_id)

    return user


def get_current_user(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
) -> dict | None:
    """
    Get the currently authenticated user from session.
    Returns user dict if authenticated, None otherwise.
    Checks session timeout if configured for the tenant.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return None

    # Check session timeout
    session_start = request.session.get("session_start")
    if session_start:
        # Fetch tenant security settings to check for session timeout
        security_settings = database.security.get_session_timeout(tenant_id)

        if security_settings and security_settings["session_timeout_seconds"]:
            import time

            current_time = int(time.time())
            session_duration = current_time - session_start
            timeout_seconds = security_settings["session_timeout_seconds"]

            if session_duration > timeout_seconds:
                # Session has expired, clear it
                request.session.clear()
                return None

    user = database.users.get_user_by_id(tenant_id, user_id)

    return user


def require_auth(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
) -> dict | RedirectResponse:
    """
    Require authentication. Redirects to /login if not authenticated.
    Returns user dict if authenticated, or RedirectResponse if not.
    """
    user = get_current_user(request, tenant_id)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return user
