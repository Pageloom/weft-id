"""Authentication routes for login/logout."""

from typing import Annotated

import services.emails as emails_service
import services.saml as saml_service
import services.users as users_service
import settings
from dependencies import get_current_user, get_tenant_id_from_request
from fastapi import APIRouter, Cookie, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from middleware.csrf import make_csrf_token_func
from services.event_log import log_event
from services.exceptions import RateLimitError
from utils.auth import verify_login_with_status
from utils.csp_nonce import get_csp_nonce
from utils.email import (
    send_email_possession_code,
    send_mfa_code_email,
    send_reactivation_request_admin_notification,
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


def _get_client_ip(request: Request) -> str:
    """Get client IP address from request headers or connection."""
    # Check X-Forwarded-For header (set by reverse proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain (original client)
        return forwarded_for.split(",")[0].strip()
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    return "unknown"


router = APIRouter(prefix="", tags=["auth"], include_in_schema=False)
templates = Jinja2Templates(directory="templates")


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

    # Rate limiting: prevent abuse of email sending
    client_ip = _get_client_ip(request)
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
    send_email_possession_code(email, code)

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
        samesite="lax",
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
    send_email_possession_code(email, code)

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


@router.get("/login/super-admin-reactivate", response_class=HTMLResponse)
def super_admin_reactivate_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user_id: str,
    prefill_email: str = "",
):
    """Show self-reactivation page for inactivated super admins."""
    user = users_service.get_user_by_id_raw(tenant_id, user_id)
    if not user:
        return RedirectResponse(url="/login?error=user_not_found", status_code=303)

    if user.get("role") != "super_admin":
        return RedirectResponse(url="/login?error=account_inactivated", status_code=303)

    if not user.get("is_inactivated"):
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request,
        "super_admin_reactivate.html",
        {
            "request": request,
            "user": user,
            "prefill_email": prefill_email,
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
    )


@router.post("/login/super-admin-reactivate")
def super_admin_reactivate_confirm(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user_id: Annotated[str, Form()],
):
    """Confirm and execute super admin self-reactivation."""
    try:
        request_metadata = extract_request_metadata(request)
        users_service.self_reactivate_super_admin(
            tenant_id=tenant_id,
            user_id=user_id,
            request_metadata=request_metadata,
        )

        # Check if user has password
        user = users_service.get_user_by_id_raw(tenant_id, user_id)
        primary_email = emails_service.get_primary_email(tenant_id, user_id)

        if user and user.get("has_password") and primary_email:
            # Has password - redirect to login
            from urllib.parse import quote

            return RedirectResponse(
                url=f"/login?prefill_email={quote(primary_email)}&show_password=true&success=account_reactivated",
                status_code=303,
            )
        else:
            # No password - show special message
            return RedirectResponse(
                url="/login?success=account_reactivated_no_password",
                status_code=303,
            )
    except Exception:
        return RedirectResponse(url="/login?error=reactivation_failed", status_code=303)


def _route_after_email_verification(
    request: Request, tenant_id: str, email: str
) -> RedirectResponse:
    """
    Route user to appropriate auth flow after email possession is verified.

    This is safe to call because the user has proven they own the email address.
    """
    from urllib.parse import quote

    result = saml_service.determine_auth_route(tenant_id, email)

    if result.route_type == "password":
        return RedirectResponse(
            url=f"/login?prefill_email={quote(email)}&show_password=true",
            status_code=303,
        )

    if result.route_type in ("idp", "idp_jit"):
        return RedirectResponse(
            url=f"/saml/login/{result.idp_id}",
            status_code=303,
        )

    if result.route_type == "inactivated":
        # Check if super admin - allow self-reactivation
        if result.user_id:
            user = users_service.get_user_by_id_raw(tenant_id, result.user_id)
            if user and user.get("role") == "super_admin":
                return RedirectResponse(
                    url=f"/login/super-admin-reactivate?user_id={result.user_id}&prefill_email={quote(email)}",
                    status_code=303,
                )
        # Regular users/admins see inactivation error
        return RedirectResponse(
            url=f"/login?error=account_inactivated&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "not_found":
        return RedirectResponse(
            url=f"/login?error=user_not_found&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "idp_disabled":
        return RedirectResponse(
            url=f"/login?error=idp_disabled&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "no_auth_method":
        return RedirectResponse(
            url=f"/login?error=no_auth_method&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "invalid_email":
        return RedirectResponse(
            url=f"/login?error=invalid_email&prefill_email={quote(email)}",
            status_code=303,
        )

    # Unknown route type - fallback to password form
    return RedirectResponse(
        url=f"/login?prefill_email={quote(email)}&show_password=true",
        status_code=303,
    )


@router.post("/login/check-email")
def check_email_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email: Annotated[str, Form()],
):
    """
    DEPRECATED: Direct email check without verification.

    This endpoint is kept for backwards compatibility but should not be used.
    Use /login/send-code instead which requires email possession verification.
    """
    from urllib.parse import quote

    result = saml_service.determine_auth_route(tenant_id, email)

    if result.route_type == "password":
        # User should authenticate with password
        return RedirectResponse(
            url=f"/login?prefill_email={quote(email)}&show_password=true",
            status_code=303,
        )

    if result.route_type in ("idp", "idp_jit"):
        # User should authenticate via SAML IdP
        return RedirectResponse(
            url=f"/saml/login/{result.idp_id}",
            status_code=303,
        )

    if result.route_type == "inactivated":
        # User is inactivated
        return RedirectResponse(
            url=f"/login?error=account_inactivated&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "not_found":
        # No user found and no JIT route
        return RedirectResponse(
            url=f"/login?error=user_not_found&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "idp_disabled":
        # User's IdP is disabled - they can't authenticate
        return RedirectResponse(
            url=f"/login?error=idp_disabled&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "no_auth_method":
        # User exists but has no password and no IdP - should not happen
        return RedirectResponse(
            url=f"/login?error=no_auth_method&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "invalid_email":
        return RedirectResponse(
            url=f"/login?error=invalid_email&prefill_email={quote(email)}",
            status_code=303,
        )

    # Unknown route type - fallback to password form
    return RedirectResponse(
        url=f"/login?prefill_email={quote(email)}&show_password=true",
        status_code=303,
    )


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
            send_mfa_code_email(primary_email, code)

    # Redirect to MFA verification
    return RedirectResponse(url="/mfa/verify", status_code=303)


@router.post("/logout")
def logout(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Handle logout with optional SAML SLO.

    If the user logged in via SAML and the IdP has SLO configured,
    initiates Single Logout by redirecting to the IdP. Otherwise,
    just clears the local session.

    SLO errors are logged but never block local logout.
    """
    from services import saml as saml_service

    # Get session data before clearing
    user_id = request.session.get("user_id")
    saml_idp_id = request.session.get("saml_idp_id")
    saml_name_id = request.session.get("saml_name_id")
    saml_name_id_format = request.session.get("saml_name_id_format")
    saml_session_index = request.session.get("saml_session_index")

    # Log the logout event before clearing session
    if user_id:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_signed_out",
            metadata={
                "saml_slo_attempted": saml_idp_id is not None and saml_name_id is not None,
            },
            request_metadata=extract_request_metadata(request),
        )

    # Clear local session first (critical - do this before SLO attempt)
    request.session.clear()

    # Attempt SLO if this was a SAML session
    if saml_idp_id and saml_name_id:
        try:
            # Get base URL for SLO callback
            host = request.headers.get("x-forwarded-host", request.url.netloc)
            base_url = f"https://{host}"

            slo_redirect = saml_service.initiate_sp_logout(
                tenant_id=tenant_id,
                saml_idp_id=saml_idp_id,
                name_id=saml_name_id,
                name_id_format=saml_name_id_format,
                session_index=saml_session_index,
                base_url=base_url,
            )
            if slo_redirect:
                return RedirectResponse(url=slo_redirect, status_code=303)
        except Exception:
            # SLO errors should NOT block logout - just log and continue
            import logging

            logging.getLogger(__name__).warning(
                f"SLO failed for user {user_id}, continuing with local logout"
            )

    return RedirectResponse(url="/login", status_code=303)


@router.post("/request-reactivation")
def request_reactivation(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user_id: Annotated[str, Form()],
):
    """
    Initiate reactivation request flow.

    Sends verification email, then creates reactivation request after verification.
    """
    from services import reactivation as reactivation_service

    # Verify user exists and can request reactivation
    check = reactivation_service.can_request_reactivation(tenant_id, user_id)
    if not check["can_request"]:
        reason = check["reason"]
        if reason == "previously_denied":
            return templates.TemplateResponse(
                request,
                "account_inactivated.html",
                {
                    "request": request,
                    "user": {"id": user_id},
                    "status": "denied",
                    "can_request": False,
                    "csrf_token": make_csrf_token_func(request),
                    "csp_nonce": get_csp_nonce(request),
                },
            )
        elif reason == "request_pending":
            return templates.TemplateResponse(
                request,
                "account_inactivated.html",
                {
                    "request": request,
                    "user": {"id": user_id},
                    "status": "pending",
                    "can_request": False,
                    "csrf_token": make_csrf_token_func(request),
                    "csp_nonce": get_csp_nonce(request),
                },
            )
        else:
            return RedirectResponse(url="/login?error=invalid_request", status_code=303)

    # Get user's email and info
    primary_email = emails_service.get_primary_email(tenant_id, user_id)
    if not primary_email:
        return RedirectResponse(url="/login?error=no_email", status_code=303)

    user = users_service.get_user_by_id_raw(tenant_id, user_id)
    if user:
        first = user.get("first_name", "")
        last = user.get("last_name", "")
        user_name = f"{first} {last}".strip()
    else:
        user_name = "Unknown"

    # Create a reactivation request directly (simplified flow without email verification)
    # In a production system, you might want email verification first
    request_metadata = extract_request_metadata(request)
    reactivation_service.create_request(tenant_id, user_id, request_metadata=request_metadata)

    # Notify admins about the reactivation request
    admin_emails = users_service.get_admin_emails(tenant_id)
    requests_url = str(request.url_for("reactivation_requests_list"))
    for admin_email in admin_emails:
        send_reactivation_request_admin_notification(
            to_email=admin_email,
            user_name=user_name,
            user_email=primary_email,
            requests_url=requests_url,
        )

    # Show success message
    return templates.TemplateResponse(
        request,
        "reactivation_requested.html",
        {
            "request": request,
            "email": primary_email,
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
    )


@router.get("/verify-email/{email_id}/{nonce}")
def verify_email_public(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email_id: str,
    nonce: int,
):
    """
    Verify an email address using the verification link (public endpoint).

    This is used for new users who don't have passwords yet and can't log in.
    """
    # Look up the email by ID and nonce
    email = emails_service.get_email_for_verification(tenant_id, email_id)

    if not email:
        # Email not found - redirect to login
        return RedirectResponse(url="/login?error=verification_failed", status_code=303)

    # Check if already verified
    if email["verified_at"]:
        # Already verified - check if user has password
        user = users_service.get_user_by_id_raw(tenant_id, email["user_id"])
        if user and not user.get("password_hash"):
            # User verified but no password set - redirect to set password
            return RedirectResponse(url=f"/set-password?email_id={email_id}", status_code=303)
        # User has password - redirect to login
        return RedirectResponse(url="/login?success=already_verified", status_code=303)

    # Verify nonce matches
    if email["verify_nonce"] != nonce:
        # Invalid nonce - redirect to login with error
        return RedirectResponse(url="/login?error=invalid_verification_link", status_code=303)

    # Mark as verified and increment nonce
    emails_service.verify_email_by_nonce(tenant_id, email_id, nonce)

    # Get user to check if they have a password
    user = users_service.get_user_by_id_raw(tenant_id, email["user_id"])
    if user and not user.get("password_hash"):
        # New user without password - redirect to set password page
        return RedirectResponse(url=f"/set-password?email_id={email_id}", status_code=303)

    # Existing user adding new email - redirect to login/account
    return RedirectResponse(url="/login?success=email_verified", status_code=303)


@router.get("/set-password", response_class=HTMLResponse)
def set_password_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Display set password page for new users who have verified their email."""
    email_id = request.query_params.get("email_id")

    if not email_id:
        return RedirectResponse(url="/login", status_code=303)

    # Look up the email to get the user's email address
    # We need to get the email to find the user_id first
    email = emails_service.get_email_for_verification(tenant_id, email_id)

    if not email:
        return RedirectResponse(url="/login?error=invalid_link", status_code=303)

    # Check if email is verified
    if not email.get("verified_at"):
        return RedirectResponse(url="/login?error=email_not_verified", status_code=303)

    # Check if user already has a password
    user = users_service.get_user_by_id_raw(tenant_id, email["user_id"])
    if not user or user.get("password_hash"):
        return RedirectResponse(url="/login", status_code=303)

    # Get success/error messages from query params
    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "set_password.html",
        {
            "request": request,
            "email": email["email"],
            "email_id": email_id,
            "success": success,
            "error": error,
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
    )


@router.post("/set-password")
def set_password(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email_id: Annotated[str, Form()],
    password: Annotated[str, Form()],
    password_confirm: Annotated[str, Form()],
):
    """Set password for a new user who has verified their email."""
    # Look up the email
    email = emails_service.get_email_for_verification(tenant_id, email_id)

    if not email:
        return RedirectResponse(url="/login?error=invalid_link", status_code=303)

    # Check if email is verified
    if not email.get("verified_at"):
        return RedirectResponse(url="/login?error=email_not_verified", status_code=303)

    # Check if user already has a password
    user = users_service.get_user_by_id_raw(tenant_id, email["user_id"])
    if not user or user.get("password_hash"):
        return RedirectResponse(url="/login", status_code=303)

    # Validate passwords match
    if password != password_confirm:
        return RedirectResponse(
            url=f"/set-password?email_id={email_id}&error=passwords_dont_match", status_code=303
        )

    # Validate password strength
    from utils.password import hash_password

    if len(password) < 8:
        return RedirectResponse(
            url=f"/set-password?email_id={email_id}&error=password_too_short", status_code=303
        )

    # Set the password
    password_hash = hash_password(password)
    users_service.update_password(tenant_id, user["id"], password_hash)

    # Log the password set event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user["id"]),
        artifact_type="user",
        artifact_id=str(user["id"]),
        event_type="password_set",
        request_metadata=extract_request_metadata(request),
    )

    # Store user info in session to start MFA flow (same as regular login)
    request.session["pending_mfa_user_id"] = str(user["id"])
    request.session["pending_mfa_method"] = user.get("mfa_method", "email")

    # If email MFA, send code immediately
    if user.get("mfa_method") == "email":
        code = create_email_otp(tenant_id, user["id"])
        # Get user's email
        primary_email = emails_service.get_primary_email(tenant_id, user["id"])
        if primary_email:
            send_mfa_code_email(primary_email, code)

    # Redirect to MFA verification (same as after login)
    return RedirectResponse(url="/mfa/verify", status_code=303)


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Render dashboard for authenticated users."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Fetch user's primary email for display
    from utils.template_context import get_template_context

    primary_email = emails_service.get_primary_email(tenant_id, user["id"])

    user["email"] = primary_email if primary_email else "N/A"

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        get_template_context(request, tenant_id, user=user),
    )
