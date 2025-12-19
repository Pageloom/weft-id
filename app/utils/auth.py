"""Authentication utilities for login and session management."""

import database
from fastapi import Request
from utils.password import verify_password


def verify_login(tenant_id: str, email: str, password: str) -> dict | None:
    """
    Verify email and password for a user within a tenant.
    Returns user dict if valid, None otherwise.
    Updates last_login timestamp on success.

    Returns None if user is inactivated (cannot log in).
    """
    # Find user by email within tenant
    user_email = database.users.get_user_by_email(tenant_id, email)

    if not user_email or not user_email["password_hash"]:
        return None

    # Verify password
    if not verify_password(user_email["password_hash"], password):
        return None

    user_id = user_email["user_id"]

    # Fetch full user record (including inactivation status)
    user = database.users.get_user_by_id(tenant_id, user_id)

    # Block login for inactivated users
    if user and user.get("is_inactivated"):
        return None

    # Update last_login and re-fetch to get updated timestamp
    database.users.update_last_login(tenant_id, user_id)

    # Re-fetch to include updated last_login
    return database.users.get_user_by_id(tenant_id, user_id)


def get_current_user(request: Request, tenant_id: str) -> dict | None:
    """
    Get the currently authenticated user from session.
    Returns user dict if authenticated, None otherwise.
    Checks session timeout if configured for the tenant.

    If user was inactivated after session started, clears session and returns None.
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

    # Check if user was inactivated after session started
    if user and user.get("is_inactivated"):
        # Force logout for inactivated users
        request.session.clear()
        return None

    return user
