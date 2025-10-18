"""Multi-factor authentication routes for setup and verification."""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import database
from dependencies import get_tenant_id_from_request
from utils.auth import get_current_user
from utils.email import send_mfa_code_email
from utils.mfa import (
    create_email_otp,
    decrypt_secret,
    encrypt_secret,
    format_secret_for_display,
    generate_backup_codes,
    generate_totp_secret,
    generate_totp_uri,
    get_totp_secret,
    hash_code,
    verify_backup_code,
    verify_email_otp,
    verify_totp_code,
)
from utils.template_context import get_template_context

router = APIRouter(prefix="/mfa", tags=["mfa"])
templates = Jinja2Templates(directory="templates")


@router.get("/verify", response_class=HTMLResponse)
def mfa_verify_page(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Render MFA verification page."""
    # Check for pending MFA session
    pending_user_id = request.session.get("pending_mfa_user_id")
    pending_method = request.session.get("pending_mfa_method")

    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=303)

    # Get user email for display
    user = database.fetchone(
        tenant_id,
        """
        select u.id, ue.email
        from users u
        join user_emails ue on ue.user_id = u.id and ue.is_primary = true
        where u.id = :user_id
        """,
        {"user_id": pending_user_id},
    )

    return templates.TemplateResponse(
        "mfa_verify.html",
        {"request": request, "method": pending_method, "user": user, "nav": {}},
    )


@router.post("/verify")
def mfa_verify(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    code: Annotated[str, Form()],
    timezone: Annotated[str, Form()] = "",
    locale: Annotated[str, Form()] = "",
):
    """Handle MFA verification form submission."""
    pending_user_id = request.session.get("pending_mfa_user_id")
    pending_method = request.session.get("pending_mfa_method")

    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=303)

    verified = False
    code_clean = code.replace(" ", "").replace("-", "")

    # Try primary MFA method (totp)
    if pending_method == "totp":
        secret = get_totp_secret(tenant_id, pending_user_id, pending_method)
        if secret:
            verified = verify_totp_code(secret, code_clean)

    # Try email OTP
    if not verified:
        verified = verify_email_otp(tenant_id, pending_user_id, code_clean)

    # Try backup codes
    if not verified:
        verified = verify_backup_code(tenant_id, pending_user_id, code_clean)

    if not verified:
        user = database.fetchone(
            tenant_id,
            """
            select u.id, ue.email
            from users u
            join user_emails ue on ue.user_id = u.id and ue.is_primary = true
            where u.id = :user_id
            """,
            {"user_id": pending_user_id},
        )
        return templates.TemplateResponse(
            "mfa_verify.html",
            {
                "request": request,
                "method": pending_method,
                "user": user,
                "error": "Invalid or expired code",
                "nav": {},
            },
        )

    # MFA verified - complete login
    request.session["user_id"] = pending_user_id
    request.session["session_start"] = int(__import__("time").time())

    # Fetch tenant security settings to configure session persistence
    security_settings = database.fetchone(
        tenant_id,
        """
        select persistent_sessions, session_timeout_seconds
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )

    # Store session configuration in session for middleware to use
    if security_settings:
        persistent = security_settings.get("persistent_sessions", True)
        timeout = security_settings.get("session_timeout_seconds")
    else:
        # Defaults: persistent sessions enabled, no timeout
        persistent = True
        timeout = None

    # Store max_age preference - will be used when setting the cookie
    # If persistent_sessions is False, max_age should be None (session cookie)
    # If persistent_sessions is True and timeout is set, use that timeout
    # If persistent_sessions is True and no timeout, use a long max_age (e.g., 30 days)
    if not persistent:
        request.session["_max_age"] = None  # Session cookie (expires on browser close)
    elif timeout:
        request.session["_max_age"] = timeout  # Use configured timeout
    else:
        request.session["_max_age"] = 30 * 24 * 3600  # 30 days as default for persistent

    # Update timezone and locale if provided (prefer from this form, fallback to session from login)
    tz_to_update = timezone or request.session.get("pending_timezone", "")
    locale_to_update = locale or request.session.get("pending_locale", "")

    # Get current values
    current_user = database.fetchone(
        tenant_id, "select tz, locale from users where id = :user_id", {"user_id": pending_user_id}
    )

    tz_changed = tz_to_update and (not current_user or current_user.get("tz") != tz_to_update)
    locale_changed = locale_to_update and (
        not current_user or current_user.get("locale") != locale_to_update
    )

    if tz_changed and locale_changed:
        database.execute(
            tenant_id,
            "update users set tz = :tz, locale = :locale, last_login = now() where id = :user_id",
            {"tz": tz_to_update, "locale": locale_to_update, "user_id": pending_user_id},
        )
    elif tz_changed:
        database.execute(
            tenant_id,
            "update users set tz = :tz, last_login = now() where id = :user_id",
            {"tz": tz_to_update, "user_id": pending_user_id},
        )
    elif locale_changed:
        database.execute(
            tenant_id,
            "update users set locale = :locale, last_login = now() where id = :user_id",
            {"locale": locale_to_update, "user_id": pending_user_id},
        )
    else:
        # Just update last_login
        database.execute(
            tenant_id,
            "update users set last_login = now() where id = :user_id",
            {"user_id": pending_user_id},
        )

    request.session.pop("pending_mfa_user_id", None)
    request.session.pop("pending_mfa_method", None)
    request.session.pop("pending_timezone", None)
    request.session.pop("pending_locale", None)

    return RedirectResponse(url="/dashboard", status_code=303)


@router.post("/verify/send-email")
def mfa_send_email_code(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Send email OTP code as fallback."""
    pending_user_id = request.session.get("pending_mfa_user_id")
    pending_method = request.session.get("pending_mfa_method")

    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=303)

    # Only allow email codes for users with email-only MFA
    # Users with TOTP should use their configured method or backup codes
    if pending_method == "totp":
        return RedirectResponse(url="/mfa/verify", status_code=303)

    # Generate and send email code
    code = create_email_otp(tenant_id, pending_user_id)

    # Get user email
    user = database.fetchone(
        tenant_id,
        """
        select ue.email
        from user_emails ue
        where ue.user_id = :user_id and ue.is_primary = true
        """,
        {"user_id": pending_user_id},
    )

    if user:
        send_mfa_code_email(user["email"], code)

    return RedirectResponse(url="/mfa/verify?email_sent=1", status_code=303)
