"""Authentication routes for login/logout."""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import database
from dependencies import get_tenant_id_from_request
from utils.auth import get_current_user, verify_login
from utils.email import send_mfa_code_email
from utils.mfa import create_email_otp

router = APIRouter(prefix="", tags=["auth"])
templates = Jinja2Templates(directory="templates")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Render login page."""
    # If already authenticated, redirect to dashboard
    user = get_current_user(request, get_tenant_id_from_request(request))
    if user:
        return RedirectResponse(url="/dashboard", status_code=303)

    return templates.TemplateResponse("login.html", {"request": request})


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
    user = verify_login(tenant_id, email, password)

    if not user:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid email or password"}
        )

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
        email_row = database.fetchone(
            tenant_id,
            "select email from user_emails where user_id = :user_id and is_primary = true",
            {"user_id": user["id"]},
        )
        if email_row:
            send_mfa_code_email(email_row["email"], code)

    # Redirect to MFA verification
    return RedirectResponse(url="/mfa/verify", status_code=303)


@router.post("/logout")
def logout(request: Request):
    """Handle logout."""
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Render dashboard for authenticated users."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Fetch user's primary email for display
    import database
    from utils.template_context import get_template_context

    email_row = database.fetchone(
        tenant_id,
        "select email from user_emails where user_id = :user_id and is_primary = true",
        {"user_id": user["id"]},
    )

    user["email"] = email_row["email"] if email_row else "N/A"

    return templates.TemplateResponse(
        "dashboard.html", get_template_context(request, tenant_id, user=user)
    )
