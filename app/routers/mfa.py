"""Multi-factor authentication routes for setup and verification.

Architectural Note: This module contains a direct log_event() call for the user_signed_in
event after successful MFA verification. This is an accepted exception to the "event
logging in services" pattern because MFA verification completes the authentication flow
and session establishment, which occurs at the router level.
"""

from typing import Annotated

import services.emails as emails_service
import services.users as users_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from middleware.csrf import make_csrf_token_func
from services.exceptions import RateLimitError
from utils.email import send_mfa_code_email
from utils.mfa import (
    create_email_otp,
    get_totp_secret,
    verify_backup_code,
    verify_email_otp,
    verify_totp_code,
)
from utils.ratelimit import MINUTE, ratelimit
from utils.templates import templates

router = APIRouter(prefix="/mfa", tags=["mfa"], include_in_schema=False)


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
    user = emails_service.get_user_with_primary_email(tenant_id, pending_user_id)

    return templates.TemplateResponse(
        request,
        "mfa_verify.html",
        {
            "method": pending_method,
            "user": user,
            "nav": {},
            "csrf_token": make_csrf_token_func(request),
        },
    )


@router.post("/verify")
def mfa_verify(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    code: Annotated[str, Form(max_length=100)],
    timezone: Annotated[str, Form(max_length=50)] = "",
    locale: Annotated[str, Form(max_length=10)] = "",
):
    """Handle MFA verification form submission."""
    pending_user_id = request.session.get("pending_mfa_user_id")
    pending_method = request.session.get("pending_mfa_method")

    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=303)

    # Rate limiting: prevent brute force on MFA codes
    try:
        ratelimit.prevent(
            "mfa_verify:user:{user_id}",
            limit=5,
            timespan=MINUTE * 15,
            user_id=pending_user_id,
        )
    except RateLimitError:
        user = emails_service.get_user_with_primary_email(tenant_id, pending_user_id)
        return templates.TemplateResponse(
            request,
            "mfa_verify.html",
            {
                "method": pending_method,
                "user": user,
                "error": "Too many attempts. Please try again later.",
                "nav": {},
                "csrf_token": make_csrf_token_func(request),
            },
        )

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
        user = emails_service.get_user_with_primary_email(tenant_id, pending_user_id)
        return templates.TemplateResponse(
            request,
            "mfa_verify.html",
            {
                "method": pending_method,
                "user": user,
                "error": "Invalid or expired code",
                "nav": {},
                "csrf_token": make_csrf_token_func(request),
            },
        )

    # MFA verified. Before completing login, check whether the tenant requires
    # enhanced auth strength and the user is still on email-only. If so, funnel
    # them into the enrollment page instead of finalizing the session. The user
    # is NOT yet fully signed in at this point: we deliberately do not emit
    # user_signed_in, do not regenerate the session, and keep pending_mfa_*
    # around so the helper can re-enter if enrollment is abandoned.
    current_user = users_service.get_user_by_id_raw(tenant_id, pending_user_id)
    if current_user and users_service.user_must_enroll_enhanced(tenant_id, current_user):
        # Persist tz/locale across the enrollment redirect so the completion
        # helper can apply them once enrollment finishes.
        if timezone:
            request.session["pending_timezone"] = timezone
        if locale:
            request.session["pending_locale"] = locale
        request.session["pending_enhanced_enrollment_user_id"] = pending_user_id
        return RedirectResponse(url="/login/enroll-enhanced-auth", status_code=303)

    # Regular MFA-satisfied login: complete via the shared helper.
    from routers.auth._login_completion import complete_authenticated_login

    return complete_authenticated_login(
        request=request,
        tenant_id=tenant_id,
        user_id=pending_user_id,
        mfa_method=pending_method or "email",
        timezone=timezone,
        locale=locale,
    )


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

    # Rate limiting: prevent abuse of email sending
    try:
        ratelimit.prevent(
            "mfa_email:user:{user_id}",
            limit=3,
            timespan=MINUTE * 5,
            user_id=pending_user_id,
        )
    except RateLimitError:
        return RedirectResponse(url="/mfa/verify?error=too_many_requests", status_code=303)

    # Generate and send email code
    code = create_email_otp(tenant_id, pending_user_id)

    # Get user email
    primary_email = emails_service.get_primary_email(tenant_id, pending_user_id)

    if primary_email:
        send_mfa_code_email(primary_email, code, tenant_id=tenant_id)

    return RedirectResponse(url="/mfa/verify?email_sent=1", status_code=303)
