"""Authentication routes for login/logout."""

from typing import Annotated

import services.emails as emails_service
import services.users as users_service
from dependencies import get_current_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import database
from utils.auth import verify_login_with_status
from utils.email import send_mfa_code_email, send_reactivation_request_admin_notification
from utils.mfa import create_email_otp

router = APIRouter(prefix="", tags=["auth"], include_in_schema=False)
templates = Jinja2Templates(directory="templates")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Render login page."""
    # If already authenticated, redirect to dashboard
    user = get_current_user(request, get_tenant_id_from_request(request))
    if user:
        return RedirectResponse(url="/dashboard", status_code=303)

    # Get success/error messages from query params
    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "login.html", {"request": request, "success": success, "error": error}
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
    """Handle login form submission."""
    result = verify_login_with_status(tenant_id, email, password)

    if result["status"] == "invalid_credentials":
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid email or password"}
        )

    if result["status"] in ("inactivated", "pending", "denied"):
        # User is inactivated - show special page
        # Note: use "inactivated_user" instead of "user" to avoid triggering
        # the nav bar in base.html (which requires nav context)
        inactivated_user = result["user"]
        return templates.TemplateResponse(
            "account_inactivated.html",
            {
                "request": request,
                "inactivated_user": inactivated_user,
                "status": result["status"],
                "can_request": result.get("can_request_reactivation", False),
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
def logout(request: Request):
    """Handle logout."""
    request.session.clear()
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
                "account_inactivated.html",
                {
                    "request": request,
                    "user": {"id": user_id},
                    "status": "denied",
                    "can_request": False,
                },
            )
        elif reason == "request_pending":
            return templates.TemplateResponse(
                "account_inactivated.html",
                {
                    "request": request,
                    "user": {"id": user_id},
                    "status": "pending",
                    "can_request": False,
                },
            )
        else:
            return RedirectResponse(url="/login?error=invalid_request", status_code=303)

    # Get user's email and info
    primary_email = emails_service.get_primary_email(tenant_id, user_id)
    if not primary_email:
        return RedirectResponse(url="/login?error=no_email", status_code=303)

    user = users_service.get_user_by_id_raw(tenant_id, user_id)
    user_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() if user else "Unknown"

    # Create a reactivation request directly (simplified flow without email verification)
    # In a production system, you might want email verification first
    reactivation_service.create_request(tenant_id, user_id)

    # Notify admins about the reactivation request
    admin_emails = database.users.get_admin_emails(tenant_id)
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
        "reactivation_requested.html",
        {
            "request": request,
            "email": primary_email,
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
        "set_password.html",
        {
            "request": request,
            "email": email["email"],
            "email_id": email_id,
            "success": success,
            "error": error,
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
        "dashboard.html", get_template_context(request, tenant_id, user=user)
    )
