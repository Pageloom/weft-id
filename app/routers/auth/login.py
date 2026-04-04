"""Login and email verification endpoints.

Architectural Note: This module contains direct log_event() calls for authentication
events (login_failed). This is an accepted exception to the "event logging in services"
pattern because authentication events are fundamentally tied to session management
which occurs at the router level. These events track security-relevant authentication
state changes, not business logic mutations.
"""

from typing import Annotated

import services.emails as emails_service
import services.saml as saml_service
import services.settings as settings_service
import services.users as users_service
import settings
from dependencies import get_current_user, get_tenant_id_from_request
from fastapi import APIRouter, Cookie, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from middleware.csrf import make_csrf_token_func
from routers.auth._helpers import (
    _get_client_ip,
    _route_after_email_verification,
    _route_without_verification,
)
from services.event_log import log_event
from services.exceptions import RateLimitError, ServiceError
from utils.auth import verify_login_with_status
from utils.csp_nonce import get_csp_nonce
from utils.email import (
    send_email_possession_code,
    send_mfa_code_email,
)
from utils.email_verification import (
    create_trust_cookie,
    create_verification_cookie,
    generate_verification_code,
    get_trust_cookie_name,
    get_verification_cookie_email,
    validate_trust_cookie,
    validate_verification_cookie,
)
from utils.mfa import create_email_otp
from utils.ratelimit import HOUR, MINUTE, ratelimit
from utils.request_metadata import extract_request_metadata
from utils.templates import templates

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """
    Render login page (email-first flow with verification).

    Query params:
    - prefill_email: Pre-fill email field (after email check)
    - show_password: Show password form (after email routing determined password)
    - success: Success message
    - error: Error message
    """
    # If already authenticated, redirect to dashboard
    user = get_current_user(request, tenant_id)
    if user:
        return RedirectResponse(url="/dashboard", status_code=303)

    # Get query params
    success = request.query_params.get("success")
    error = request.query_params.get("error")
    prefill_email = request.query_params.get("prefill_email", "")
    show_password = request.query_params.get("show_password") == "true"

    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "success": success,
            "error": error,
            "prefill_email": prefill_email,
            "show_password": show_password,
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
    )


@router.post("/login/send-code")
def send_verification_code(
    request: Request,
    response: Response,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email: Annotated[str, Form()],
):
    """
    Send email possession verification code (anti-enumeration step 1).

    Always sends an email and creates a verification cookie, regardless of
    whether the email exists in the system. This prevents enumeration.
    """
    from urllib.parse import quote

    # Normalize email
    email = email.strip().lower()

    # Basic email format validation
    if not email or "@" not in email:
        return RedirectResponse(
            url=f"/login?error=invalid_email&prefill_email={quote(email)}",
            status_code=303,
        )

    client_ip = _get_client_ip(request)

    # Check tenant setting: direct routing vs email verification
    if not settings_service.requires_email_verification_for_login(tenant_id):
        # Direct routing: route immediately without email verification
        try:
            ratelimit.prevent(
                "login_route:ip:{ip}:tenant:{tenant}",
                limit=30,
                timespan=MINUTE * 5,
                ip=client_ip,
                tenant=str(tenant_id),
            )
        except RateLimitError:
            return RedirectResponse(
                url=f"/login?error=too_many_requests&prefill_email={quote(email)}",
                status_code=303,
            )
        return _route_without_verification(request, tenant_id, email)

    # Email verification flow: rate limit and send code
    # Rate limiting: prevent abuse of email sending
    try:
        ratelimit.prevent("email_send:ip:{ip}", limit=10, timespan=HOUR, ip=client_ip)
        ratelimit.prevent("email_send:email:{email}", limit=5, timespan=MINUTE * 10, email=email)
    except RateLimitError:
        return RedirectResponse(
            url=f"/login?error=too_many_requests&prefill_email={quote(email)}",
            status_code=303,
        )

    # Check if user has a valid trust cookie for this email
    trust_cookie_name = get_trust_cookie_name(email)
    trust_cookie = request.cookies.get(trust_cookie_name)

    if trust_cookie and validate_trust_cookie(trust_cookie, email, tenant_id):
        # User has proven email ownership recently, skip verification
        # Route them directly based on their account status
        return _route_after_email_verification(request, tenant_id, email)

    # Generate and send verification code
    code = generate_verification_code()
    send_email_possession_code(email, code, tenant_id=tenant_id)

    # Create verification cookie
    cookie_value = create_verification_cookie(email, code, tenant_id)

    # Redirect to verification page and set cookie
    redirect = RedirectResponse(url="/login/verify", status_code=303)
    redirect.set_cookie(
        key="email_verify_pending",
        value=cookie_value,
        max_age=settings.VERIFICATION_CODE_EXPIRY_SECONDS,
        httponly=True,
        samesite="lax",
        secure=not settings.IS_DEV,
    )
    return redirect


@router.get("/login/verify", response_class=HTMLResponse)
def verify_code_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email_verify_pending: Annotated[str | None, Cookie()] = None,
):
    """
    Show verification code entry form (anti-enumeration step 2).
    """
    # Check for verification cookie
    if not email_verify_pending:
        return RedirectResponse(url="/login", status_code=303)

    # Get email from cookie for display
    email = get_verification_cookie_email(email_verify_pending)
    if not email:
        # Cookie expired or invalid
        return RedirectResponse(url="/login?error=session_expired", status_code=303)

    # Get query params for messages
    error = request.query_params.get("error")
    success = request.query_params.get("success")

    return templates.TemplateResponse(
        request,
        "email_verification.html",
        {
            "request": request,
            "email": email,
            "error": error,
            "success": success,
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
    )


@router.post("/login/verify-code")
def verify_code(
    request: Request,
    response: Response,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    code: Annotated[str, Form()],
    email_verify_pending: Annotated[str | None, Cookie()] = None,
):
    """
    Validate verification code and route to appropriate auth flow (anti-enumeration step 3).
    """
    # Check for verification cookie
    if not email_verify_pending:
        return RedirectResponse(url="/login?error=session_expired", status_code=303)

    # Get email from cookie for rate limiting
    email_for_limit = get_verification_cookie_email(email_verify_pending) or "unknown"
    client_ip = _get_client_ip(request)

    # Rate limiting: prevent brute force on verification codes
    try:
        ratelimit.prevent(
            "verify_code:ip:{ip}:email:{email}",
            limit=5,
            timespan=MINUTE * 5,
            ip=client_ip,
            email=email_for_limit,
        )
    except RateLimitError:
        return RedirectResponse(url="/login/verify?error=too_many_attempts", status_code=303)

    # Validate the code
    is_valid, email, cookie_tenant_id = validate_verification_cookie(
        email_verify_pending, code.strip()
    )

    if not is_valid or not email:
        return RedirectResponse(url="/login/verify?error=invalid_code", status_code=303)

    # Verify tenant matches (compare as strings to handle UUID/string differences)
    if cookie_tenant_id != str(tenant_id):
        return RedirectResponse(url="/login?error=session_expired", status_code=303)

    # Create trust cookie for future logins (30-day bypass)
    trust_cookie_value = create_trust_cookie(email, tenant_id)
    trust_cookie_name = get_trust_cookie_name(email)
    trust_max_age = settings.TRUST_COOKIE_EXPIRY_DAYS * 24 * 60 * 60

    # Clear the verification pending cookie and set trust cookie
    redirect = _route_after_email_verification(request, tenant_id, email)
    redirect.delete_cookie("email_verify_pending")
    redirect.set_cookie(
        key=trust_cookie_name,
        value=trust_cookie_value,
        max_age=trust_max_age,
        httponly=True,
        samesite="strict",
        secure=not settings.IS_DEV,
    )
    return redirect


@router.post("/login/resend-code")
def resend_verification_code(
    request: Request,
    response: Response,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email_verify_pending: Annotated[str | None, Cookie()] = None,
):
    """
    Resend verification code to the email in the current verification session.
    """
    # Check for verification cookie to get the email
    if not email_verify_pending:
        return RedirectResponse(url="/login", status_code=303)

    email = get_verification_cookie_email(email_verify_pending)
    if not email:
        return RedirectResponse(url="/login", status_code=303)

    # Rate limiting: prevent abuse of resend functionality
    client_ip = _get_client_ip(request)
    try:
        ratelimit.prevent("resend_code:ip:{ip}", limit=5, timespan=MINUTE * 10, ip=client_ip)
    except RateLimitError:
        return RedirectResponse(url="/login/verify?error=too_many_requests", status_code=303)

    # Generate new code and send
    code = generate_verification_code()
    send_email_possession_code(email, code, tenant_id=tenant_id)

    # Create new verification cookie
    cookie_value = create_verification_cookie(email, code, tenant_id)

    # Redirect back to verification page with success message
    redirect = RedirectResponse(url="/login/verify?success=code_sent", status_code=303)
    redirect.set_cookie(
        key="email_verify_pending",
        value=cookie_value,
        max_age=settings.VERIFICATION_CODE_EXPIRY_SECONDS,
        httponly=True,
        samesite="lax",
        secure=not settings.IS_DEV,
    )
    return redirect


@router.post("/login")
def login(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    timezone: Annotated[str, Form()] = "",
    locale: Annotated[str, Form()] = "",
):
    """Handle login form submission (step 2 after email check)."""
    # Normalize email for consistent rate limiting
    email_normalized = email.strip().lower()
    client_ip = _get_client_ip(request)

    # Rate limiting: hard block after too many attempts
    try:
        ratelimit.prevent(
            "login_block:ip:{ip}:email:{email}",
            limit=20,
            timespan=MINUTE * 15,
            ip=client_ip,
            email=email_normalized,
        )
    except RateLimitError:
        # Check if SSO is enabled for template context
        sso_enabled = len(saml_service.get_enabled_idps_for_login(tenant_id)) > 0
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "error": "Too many login attempts. Please try again later.",
                "sso_enabled": sso_enabled,
                "prefill_email": email,
                "show_password": True,
                "csrf_token": make_csrf_token_func(request),
                "csp_nonce": get_csp_nonce(request),
            },
        )

    # Soft limit - log for monitoring
    ratelimit.log(
        "login_attempts:ip:{ip}:email:{email}",
        limit=5,
        timespan=MINUTE * 5,
        ip=client_ip,
        email=email_normalized,
    )

    result = verify_login_with_status(tenant_id, email, password)

    # Check if SSO is enabled for template context
    sso_enabled = len(saml_service.get_enabled_idps_for_login(tenant_id)) > 0

    if result["status"] == "invalid_credentials":
        # Log failed login attempt for security monitoring
        # Try to find user by email to get their ID for the artifact
        user_id = users_service.get_user_id_by_email(tenant_id, email_normalized)
        artifact_id = user_id if user_id else tenant_id
        log_event(
            tenant_id=tenant_id,
            actor_user_id=artifact_id,  # Use user ID if known, tenant ID if unknown
            artifact_type="user",
            artifact_id=artifact_id,
            event_type="login_failed",
            metadata={
                "email_attempted": email_normalized,
                "failure_reason": "invalid_credentials",
            },
            request_metadata=extract_request_metadata(request),
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "error": "Invalid email or password",
                "sso_enabled": sso_enabled,
                "prefill_email": email,
                "show_password": True,
                "csrf_token": make_csrf_token_func(request),
                "csp_nonce": get_csp_nonce(request),
            },
        )

    if result["status"] in ("inactivated", "pending", "denied"):
        # User is inactivated - show special page
        # Note: use "inactivated_user" instead of "user" to avoid triggering
        # the nav bar in base.html (which requires nav context)
        inactivated_user = result["user"]
        # Log failed login attempt for inactivated user
        log_event(
            tenant_id=tenant_id,
            actor_user_id=str(inactivated_user["id"]),
            artifact_type="user",
            artifact_id=str(inactivated_user["id"]),
            event_type="login_failed",
            metadata={
                "email_attempted": email_normalized,
                "failure_reason": result["status"],
            },
            request_metadata=extract_request_metadata(request),
        )
        return templates.TemplateResponse(
            request,
            "account_inactivated.html",
            {
                "request": request,
                "inactivated_user": inactivated_user,
                "status": result["status"],
                "can_request": result.get("can_request_reactivation", False),
                "csrf_token": make_csrf_token_func(request),
                "csp_nonce": get_csp_nonce(request),
            },
        )

    user = result["user"]

    # Check for forced password reset before proceeding to MFA
    if user.get("password_reset_required"):
        request.session["pending_password_reset_user_id"] = str(user["id"])
        return RedirectResponse(url="/login/reset-password", status_code=303)

    # MFA is now mandatory for all users
    # Store pending MFA info in session
    request.session["pending_mfa_user_id"] = str(user["id"])
    request.session["pending_mfa_method"] = user.get("mfa_method", "email")
    # Store timezone and locale for later update (after MFA verification)
    if timezone:
        request.session["pending_timezone"] = timezone
    if locale:
        request.session["pending_locale"] = locale

    # If email MFA, send code immediately
    if user.get("mfa_method") == "email":
        code = create_email_otp(tenant_id, user["id"])
        # Get user's email
        primary_email = emails_service.get_primary_email(tenant_id, user["id"])
        if primary_email:
            send_mfa_code_email(primary_email, code, tenant_id=tenant_id)

    # Redirect to MFA verification
    return RedirectResponse(url="/mfa/verify", status_code=303)


@router.get("/login/reset-password", response_class=HTMLResponse)
def forced_password_reset_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Display forced password reset page.

    Shown after successful password authentication when an admin has flagged
    the account for a forced reset. The user cannot proceed without changing
    their password.
    """
    pending_user_id = request.session.get("pending_password_reset_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=303)

    policy = settings_service.get_password_policy(tenant_id)
    min_length = policy["minimum_password_length"]
    # Check if user is super_admin (requires minimum 14)
    pending_user = users_service.get_user_by_id_raw(tenant_id, pending_user_id)
    if pending_user and pending_user.get("role") == "super_admin" and min_length < 14:
        min_length = 14
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "forced_password_reset.html",
        {
            "request": request,
            "minimum_password_length": min_length,
            "minimum_zxcvbn_score": policy["minimum_zxcvbn_score"],
            "error": error,
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
    )


@router.post("/login/reset-password")
def forced_password_reset(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    new_password: Annotated[str, Form()],
    new_password_confirm: Annotated[str, Form()],
):
    """Handle forced password reset form submission.

    After successful reset, the user proceeds to MFA verification as normal.
    """
    pending_user_id = request.session.get("pending_password_reset_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=303)

    if new_password != new_password_confirm:
        return RedirectResponse(
            url="/login/reset-password?error=passwords_dont_match", status_code=303
        )

    try:
        users_service.complete_forced_password_reset(tenant_id, pending_user_id, new_password)
    except ServiceError as exc:
        return RedirectResponse(url=f"/login/reset-password?error={exc.code}", status_code=303)

    # Clear forced reset session and proceed to MFA
    request.session.pop("pending_password_reset_user_id", None)

    # Fetch user for MFA setup
    user = users_service.get_user_by_id_raw(tenant_id, pending_user_id)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    request.session["pending_mfa_user_id"] = str(user["id"])
    request.session["pending_mfa_method"] = user.get("mfa_method", "email")

    # If email MFA, send code
    if user.get("mfa_method") == "email":
        code = create_email_otp(tenant_id, user["id"])
        primary_email = emails_service.get_primary_email(tenant_id, user["id"])
        if primary_email:
            send_mfa_code_email(primary_email, code, tenant_id=tenant_id)

    return RedirectResponse(url="/mfa/verify", status_code=303)
