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


@router.get("/setup", response_class=HTMLResponse)
def mfa_setup_page(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Render MFA setup method selection page."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if MFA already enabled
    if user.get("mfa_enabled"):
        return RedirectResponse(url="/mfa/manage", status_code=303)

    return templates.TemplateResponse("mfa_setup.html", get_template_context(request, tenant_id))


@router.get("/setup/totp", response_class=HTMLResponse)
@router.post("/setup/totp")
def mfa_setup_totp(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Start TOTP (authenticator app) setup process."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Generate TOTP secret
    secret = generate_totp_secret()
    secret_encrypted = encrypt_secret(secret)

    # Get user email for URI
    email_row = database.fetchone(
        tenant_id,
        "select email from user_emails where user_id = :user_id and is_primary = true",
        {"user_id": user["id"]},
    )
    email = email_row["email"] if email_row else "user@example.com"

    # Generate URI for QR code
    uri = generate_totp_uri(secret, email)
    secret_display = format_secret_for_display(secret)

    # Store unverified secret
    database.execute(
        tenant_id,
        """
        insert into mfa_totp (tenant_id, user_id, secret_encrypted, method)
        values (:tenant_id, :user_id, :secret_encrypted, 'totp')
        on conflict (user_id, method) do update
        set secret_encrypted = excluded.secret_encrypted,
            verified_at = null
        """,
        {"tenant_id": tenant_id, "user_id": user["id"], "secret_encrypted": secret_encrypted},
    )

    return templates.TemplateResponse(
        "mfa_setup_totp.html",
        get_template_context(request, tenant_id, uri=uri, secret=secret_display),
    )


@router.post("/setup/email")
def mfa_setup_email(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Enable email-only MFA (no setup needed)."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Enable email MFA
    database.execute(
        tenant_id,
        "update users set mfa_enabled = true, mfa_method = :method where id = :user_id",
        {"method": "email", "user_id": user["id"]},
    )

    return RedirectResponse(url="/mfa/manage?enabled=1", status_code=303)


@router.post("/setup/verify")
def mfa_setup_verify(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    code: Annotated[str, Form()],
    method: Annotated[str, Form()],
):
    """Verify TOTP setup and enable MFA."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if method != "totp":
        return RedirectResponse(url="/mfa/setup", status_code=303)

    # Get unverified secret
    row = database.fetchone(
        tenant_id,
        """
        select secret_encrypted from mfa_totp
        where user_id = :user_id and method = :method
        """,
        {"user_id": user["id"], "method": method},
    )

    if not row:
        return RedirectResponse(url="/mfa/setup", status_code=303)

    secret = decrypt_secret(row["secret_encrypted"])
    code_clean = code.replace(" ", "").replace("-", "")

    if not verify_totp_code(secret, code_clean):
        # Get user email for error display
        email_row = database.fetchone(
            tenant_id,
            "select email from user_emails where user_id = :user_id and is_primary = true",
            {"user_id": user["id"]},
        )
        email = email_row["email"] if email_row else "user@example.com"
        uri = generate_totp_uri(secret, email)
        secret_display = format_secret_for_display(secret)

        return templates.TemplateResponse(
            "mfa_setup_totp.html",
            get_template_context(
                request, tenant_id, uri=uri, secret=secret_display, error="Invalid code"
            ),
        )

    # Mark as verified
    database.execute(
        tenant_id,
        "update mfa_totp set verified_at = now() where user_id = :user_id and method = :method",
        {"user_id": user["id"], "method": method},
    )

    # Enable MFA on user account
    database.execute(
        tenant_id,
        "update users set mfa_enabled = true, mfa_method = :method where id = :user_id",
        {"method": method, "user_id": user["id"]},
    )

    # Generate backup codes
    backup_codes = generate_backup_codes()

    # Store hashed backup codes
    for code_str in backup_codes:
        code_hash = hash_code(code_str.replace("-", ""))
        database.execute(
            tenant_id,
            """
            insert into mfa_backup_codes (tenant_id, user_id, code_hash)
            values (:tenant_id, :user_id, :code_hash)
            """,
            {"tenant_id": tenant_id, "user_id": user["id"], "code_hash": code_hash},
        )

    # Show backup codes
    return templates.TemplateResponse(
        "mfa_backup_codes.html", get_template_context(request, tenant_id, backup_codes=backup_codes)
    )


@router.get("/manage", response_class=HTMLResponse)
def mfa_manage(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Render MFA management page."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse("mfa_manage.html", get_template_context(request, tenant_id))


@router.post("/disable")
def mfa_disable(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Disable MFA for the current user."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Disable MFA
    database.execute(
        tenant_id,
        "update users set mfa_enabled = false, mfa_method = null where id = :user_id",
        {"user_id": user["id"]},
    )

    # Delete TOTP secrets
    database.execute(
        tenant_id, "delete from mfa_totp where user_id = :user_id", {"user_id": user["id"]}
    )

    # Delete backup codes
    database.execute(
        tenant_id, "delete from mfa_backup_codes where user_id = :user_id", {"user_id": user["id"]}
    )

    return RedirectResponse(url="/mfa/manage?disabled=1", status_code=303)


@router.post("/regenerate-backup-codes")
def mfa_regenerate_backup_codes(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Regenerate backup codes for the current user."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Delete existing backup codes
    database.execute(
        tenant_id, "delete from mfa_backup_codes where user_id = :user_id", {"user_id": user["id"]}
    )

    # Generate new backup codes
    backup_codes = generate_backup_codes()

    # Store hashed backup codes
    for code_str in backup_codes:
        code_hash = hash_code(code_str.replace("-", ""))
        database.execute(
            tenant_id,
            """
            insert into mfa_backup_codes (tenant_id, user_id, code_hash)
            values (:tenant_id, :user_id, :code_hash)
            """,
            {"tenant_id": tenant_id, "user_id": user["id"], "code_hash": code_hash},
        )

    # Show backup codes
    return templates.TemplateResponse(
        "mfa_backup_codes.html", get_template_context(request, tenant_id, backup_codes=backup_codes)
    )


@router.post("/generate-backup-codes")
def mfa_generate_backup_codes(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Generate initial backup codes for users who don't have any."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Generate new backup codes
    backup_codes = generate_backup_codes()

    # Store hashed backup codes
    for code_str in backup_codes:
        code_hash = hash_code(code_str.replace("-", ""))
        database.execute(
            tenant_id,
            """
            insert into mfa_backup_codes (tenant_id, user_id, code_hash)
            values (:tenant_id, :user_id, :code_hash)
            """,
            {"tenant_id": tenant_id, "user_id": user["id"], "code_hash": code_hash},
        )

    # Show backup codes
    return templates.TemplateResponse(
        "mfa_backup_codes.html", get_template_context(request, tenant_id, backup_codes=backup_codes)
    )
