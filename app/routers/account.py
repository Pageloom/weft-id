"""User account routes (profile, emails, MFA)."""

from typing import Annotated

import database
from dependencies import get_current_user, get_tenant_id_from_request, require_current_user
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child
from utils.email import send_email_verification
from utils.mfa import (
    decrypt_secret,
    encrypt_secret,
    format_secret_for_display,
    generate_backup_codes,
    generate_totp_secret,
    generate_totp_uri,
    hash_code,
    verify_email_otp,
    verify_totp_code,
)
from utils.template_context import get_template_context

router = APIRouter(
    prefix="/account",
    tags=["account"],
    dependencies=[Depends(require_current_user)],  # All routes require authentication
)
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
def account_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to first accessible account page."""
    # Get first accessible child page
    first_child = get_first_accessible_child("/account", user.get("role"))

    if first_child:
        return RedirectResponse(url=first_child, status_code=303)

    # Fallback if no accessible children (shouldn't happen)
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/profile", response_class=HTMLResponse)
def profile_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Display and edit user profile settings (name, etc)."""
    return templates.TemplateResponse(
        "settings_profile.html", get_template_context(request, tenant_id)
    )


@router.post("/profile")
def update_profile(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    first_name: Annotated[str, Form()],
    last_name: Annotated[str, Form()],
):
    """Update user profile information."""
    # Check if user is allowed to edit their profile
    # Super admins are always allowed, otherwise check tenant security setting
    if user.get("role") != "super_admin":
        security_settings = database.security.can_user_edit_profile(tenant_id)

        # If setting exists and is False, deny access
        if security_settings and not security_settings.get("allow_users_edit_profile"):
            return RedirectResponse(url="/account/profile", status_code=303)

    # Update user's name
    database.users.update_user_profile(tenant_id, user["id"], first_name.strip(), last_name.strip())

    return RedirectResponse(url="/account/profile", status_code=303)


@router.post("/profile/update-timezone")
def update_timezone(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    timezone: Annotated[str, Form()],
):
    """Update user's timezone."""
    # Validate timezone using zoneinfo
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        # This will raise ZoneInfoNotFoundError if invalid
        ZoneInfo(timezone)

        # Update user's timezone
        database.users.update_user_timezone(tenant_id, user["id"], timezone)
    except ZoneInfoNotFoundError:
        # Invalid timezone, skip update
        pass

    return RedirectResponse(url="/account/profile", status_code=303)


@router.post("/profile/update-regional")
def update_regional(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    timezone: Annotated[str, Form()],
    locale: Annotated[str, Form()],
):
    """Update user's timezone and locale."""
    # Validate timezone using zoneinfo
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    tz_valid = False
    try:
        # This will raise ZoneInfoNotFoundError if invalid
        ZoneInfo(timezone)
        tz_valid = True
    except ZoneInfoNotFoundError:
        # Invalid timezone, skip timezone update
        pass

    # Update both timezone and locale if timezone is valid
    if tz_valid and locale:
        database.users.update_user_timezone_and_locale(tenant_id, user["id"], timezone, locale)
    elif tz_valid:
        database.users.update_user_timezone(tenant_id, user["id"], timezone)
    elif locale:
        database.users.update_user_locale(tenant_id, user["id"], locale)

    return RedirectResponse(url="/account/profile", status_code=303)


@router.get("/emails", response_class=HTMLResponse)
def email_settings(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display and manage user email addresses."""
    # Fetch all email addresses for this user
    emails = database.user_emails.list_user_emails(tenant_id, user["id"])

    return templates.TemplateResponse(
        "settings_emails.html", get_template_context(request, tenant_id, emails=emails)
    )


@router.get("/mfa", response_class=HTMLResponse)
def mfa_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display and configure MFA settings."""
    # Check if user has backup codes
    backup_codes = database.mfa.list_backup_codes(tenant_id, user["id"])

    return templates.TemplateResponse(
        "settings_mfa.html",
        get_template_context(
            request,
            tenant_id,
            mfa_method=user.get("mfa_method", "email"),
            backup_codes=backup_codes,
        ),
    )


@router.post("/emails/add")
def add_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    email: Annotated[str, Form()],
):
    """Add a new email address to the user's account."""
    # Check if user is allowed to add emails
    # Super admins are always allowed, otherwise check tenant security setting
    if user.get("role") != "super_admin":
        security_settings = database.security.can_user_add_emails(tenant_id)

        # If setting exists and is False, deny access
        if security_settings and not security_settings.get("allow_users_add_emails"):
            return RedirectResponse(url="/account/emails", status_code=303)

    # Check if email already exists for this tenant
    if database.user_emails.email_exists(tenant_id, email.lower()):
        # Email already exists - redirect back with error
        # TODO: Add flash message support
        return RedirectResponse(url="/account/emails", status_code=303)

    # Add the new email (unverified)
    result = database.user_emails.add_email(tenant_id, user["id"], email.lower(), user["tenant_id"])

    # Send verification email
    if result:
        verification_url = (
            f"{request.base_url}account/emails/verify/{result['id']}/{result['verify_nonce']}"
        )
        send_email_verification(email.lower(), str(verification_url))

    return RedirectResponse(url="/account/emails", status_code=303)


@router.post("/emails/set-primary/{email_id}")
def set_primary_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    email_id: str,
):
    """Set an email as the primary email for the user."""
    # Verify the email belongs to this user and is verified
    email = database.user_emails.get_email_by_id(tenant_id, email_id, user["id"])

    if not email or not email["verified_at"]:
        # Can't set unverified email as primary
        return RedirectResponse(url="/account/emails", status_code=303)

    # Unset current primary
    database.user_emails.unset_primary_emails(tenant_id, user["id"])

    # Set new primary
    database.user_emails.set_primary_email(tenant_id, email_id)

    return RedirectResponse(url="/account/emails", status_code=303)


@router.post("/emails/delete/{email_id}")
def delete_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    email_id: str,
):
    """Delete an email address from the user's account."""
    # Verify the email belongs to this user and is not primary
    email = database.user_emails.get_email_by_id(tenant_id, email_id, user["id"])

    if not email or email["is_primary"]:
        # Can't delete primary email or email that doesn't exist
        return RedirectResponse(url="/account/emails", status_code=303)

    # Delete the email
    database.user_emails.delete_email(tenant_id, email_id)

    return RedirectResponse(url="/account/emails", status_code=303)


@router.post("/emails/resend-verification/{email_id}")
def resend_verification(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    email_id: str,
):
    """Resend verification email for an unverified email address."""
    # Verify the email belongs to this user
    email = database.user_emails.get_email_with_nonce(tenant_id, email_id, user["id"])

    if not email:
        return RedirectResponse(url="/account/emails", status_code=303)

    # Send verification email
    verification_url = (
        f"{request.base_url}account/emails/verify/{email['id']}/{email['verify_nonce']}"
    )
    send_email_verification(email["email"], str(verification_url))

    return RedirectResponse(url="/account/emails", status_code=303)


@router.get("/emails/verify/{email_id}/{nonce}")
def verify_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email_id: str,
    nonce: int,
):
    """Verify an email address using the verification link."""
    # Look up the email by ID and nonce
    email = database.user_emails.get_email_for_verification(tenant_id, email_id)

    if not email:
        return RedirectResponse(url="/login", status_code=303)

    # Check if already verified
    if email["verified_at"]:
        return RedirectResponse(url="/account/emails", status_code=303)

    # Verify nonce matches
    if email["verify_nonce"] != nonce:
        return RedirectResponse(url="/account/emails", status_code=303)

    # Mark as verified and increment nonce
    database.user_emails.verify_email(tenant_id, email_id)

    return RedirectResponse(url="/account/emails", status_code=303)


@router.get("/mfa/setup/totp", response_class=HTMLResponse)
@router.post("/mfa/setup/totp")
def mfa_setup_totp(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Start TOTP (authenticator app) setup process."""
    # Prevent TOTP setup if TOTP is already active
    # Users must downgrade to email OTP first, then re-enable TOTP
    if user.get("mfa_method") == "totp":
        return RedirectResponse(url="/account/mfa", status_code=303)

    # Generate TOTP secret
    secret = generate_totp_secret()
    secret_encrypted = encrypt_secret(secret)

    # Get user email for URI
    email_row = database.user_emails.get_primary_email(tenant_id, user["id"])
    email = email_row["email"] if email_row else "user@example.com"

    # Generate URI for QR code
    uri = generate_totp_uri(secret, email)
    secret_display = format_secret_for_display(secret)

    # Store unverified secret
    database.mfa.create_totp_secret(tenant_id, user["id"], secret_encrypted, tenant_id)

    return templates.TemplateResponse(
        "mfa_setup_totp.html",
        get_template_context(request, tenant_id, uri=uri, secret=secret_display),
    )


@router.post("/mfa/setup/email")
def mfa_setup_email(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Enable email-only MFA (or downgrade from TOTP - requires re-verification)."""
    # Check if user is downgrading from TOTP to email
    current_method = user.get("mfa_method")
    if current_method == "totp":
        # This is a downgrade - require email re-verification
        # Store pending downgrade in session
        request.session["pending_mfa_downgrade"] = "email"

        # Get primary email
        email_row = database.user_emails.get_primary_email(tenant_id, user["id"])

        if email_row:
            # Send verification code via email
            from utils.email import send_mfa_code_email
            from utils.mfa import create_email_otp

            code = create_email_otp(tenant_id, user["id"])
            send_mfa_code_email(email_row["email"], code)

        # Redirect to verification page
        return RedirectResponse(url="/account/mfa/downgrade-verify", status_code=303)

    # Normal case: switching to email MFA without downgrading
    database.mfa.enable_mfa(tenant_id, user["id"], "email")

    return RedirectResponse(url="/account/mfa", status_code=303)


@router.post("/mfa/setup/verify")
def mfa_setup_verify(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    code: Annotated[str, Form()],
    method: Annotated[str, Form()],
):
    """Verify TOTP setup and enable MFA."""
    if method != "totp":
        return RedirectResponse(url="/account/mfa", status_code=303)

    # Get unverified secret
    row = database.mfa.get_totp_secret(tenant_id, user["id"], method)

    if not row:
        return RedirectResponse(url="/account/mfa", status_code=303)

    secret = decrypt_secret(row["secret_encrypted"])
    code_clean = code.replace(" ", "").replace("-", "")

    if not verify_totp_code(secret, code_clean):
        # Get user email for error display
        email_row = database.user_emails.get_primary_email(tenant_id, user["id"])
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
    database.mfa.verify_totp_secret(tenant_id, user["id"], method)

    # Enable MFA on user account
    database.mfa.enable_mfa(tenant_id, user["id"], method)

    # Delete existing backup codes (to replace them with new ones)
    database.mfa.delete_backup_codes(tenant_id, user["id"])

    # Generate backup codes
    backup_codes = generate_backup_codes()

    # Store hashed backup codes
    for code_str in backup_codes:
        code_hash = hash_code(code_str.replace("-", ""))
        database.mfa.create_backup_code(tenant_id, user["id"], code_hash, tenant_id)

    # Show backup codes
    return templates.TemplateResponse(
        "mfa_backup_codes.html", get_template_context(request, tenant_id, backup_codes=backup_codes)
    )


@router.post("/mfa/regenerate-backup-codes")
def mfa_regenerate_backup_codes(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Regenerate backup codes for the current user."""
    # Delete existing backup codes
    database.mfa.delete_backup_codes(tenant_id, user["id"])

    # Generate new backup codes
    backup_codes = generate_backup_codes()

    # Store hashed backup codes
    for code_str in backup_codes:
        code_hash = hash_code(code_str.replace("-", ""))
        database.mfa.create_backup_code(tenant_id, user["id"], code_hash, tenant_id)

    # Show backup codes
    return templates.TemplateResponse(
        "mfa_backup_codes.html", get_template_context(request, tenant_id, backup_codes=backup_codes)
    )


@router.post("/mfa/generate-backup-codes")
def mfa_generate_backup_codes(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Generate initial backup codes for users who don't have any."""
    # Generate new backup codes
    backup_codes = generate_backup_codes()

    # Store hashed backup codes
    for code_str in backup_codes:
        code_hash = hash_code(code_str.replace("-", ""))
        database.mfa.create_backup_code(tenant_id, user["id"], code_hash, tenant_id)

    # Show backup codes
    return templates.TemplateResponse(
        "mfa_backup_codes.html", get_template_context(request, tenant_id, backup_codes=backup_codes)
    )


@router.get("/mfa/downgrade-verify", response_class=HTMLResponse)
def mfa_downgrade_verify_page(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Show verification page when downgrading from TOTP to email MFA."""
    # Check if there's a pending downgrade
    if not request.session.get("pending_mfa_downgrade"):
        return RedirectResponse(url="/account/mfa", status_code=303)

    return templates.TemplateResponse(
        "mfa_downgrade_verify.html", get_template_context(request, tenant_id)
    )


@router.post("/mfa/downgrade-verify")
def mfa_downgrade_verify(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    code: Annotated[str, Form()],
):
    """Verify email code and complete downgrade to email MFA."""
    # Check if there's a pending downgrade
    pending_method = request.session.get("pending_mfa_downgrade")
    if not pending_method:
        return RedirectResponse(url="/account/mfa", status_code=303)

    # Verify the email code
    code_clean = code.replace(" ", "").replace("-", "")
    if not verify_email_otp(tenant_id, user["id"], code_clean):
        return templates.TemplateResponse(
            "mfa_downgrade_verify.html",
            get_template_context(request, tenant_id, error="Invalid or expired code"),
        )

    # Code verified - complete the downgrade
    database.mfa.set_mfa_method(tenant_id, user["id"], pending_method)

    # Delete TOTP secrets (no longer needed)
    database.mfa.delete_totp_secrets(tenant_id, user["id"])

    # Clear session
    request.session.pop("pending_mfa_downgrade", None)

    return RedirectResponse(url="/account/mfa?downgraded=1", status_code=303)
