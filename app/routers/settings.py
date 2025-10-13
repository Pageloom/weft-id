"""User settings routes (profile, emails, MFA)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import database
from dependencies import get_tenant_id_from_request
from pages import get_first_accessible_child
from utils.auth import get_current_user
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

router = APIRouter(prefix="/settings", tags=["settings"])
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
def settings_index(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Redirect to first accessible settings page."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Get first accessible child page
    first_child = get_first_accessible_child("/settings", user.get("role"))

    if first_child:
        return RedirectResponse(url=first_child, status_code=303)

    # Fallback if no accessible children (shouldn't happen)
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/profile", response_class=HTMLResponse)
def profile_settings(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Display and edit user profile settings (name, etc)."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        "settings_profile.html", get_template_context(request, tenant_id)
    )


@router.post("/profile")
def update_profile(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    first_name: Annotated[str, Form()],
    last_name: Annotated[str, Form()],
):
    """Update user profile information."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Update user's name
    database.execute(
        tenant_id,
        """
        update users
        set first_name = :first_name, last_name = :last_name
        where id = :user_id
        """,
        {"first_name": first_name.strip(), "last_name": last_name.strip(), "user_id": user["id"]},
    )

    return RedirectResponse(url="/settings/profile", status_code=303)


@router.post("/profile/update-timezone")
def update_timezone(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    timezone: Annotated[str, Form()],
):
    """Update user's timezone."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Validate timezone using zoneinfo
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        # This will raise ZoneInfoNotFoundError if invalid
        ZoneInfo(timezone)

        # Update user's timezone
        database.execute(
            tenant_id,
            "update users set tz = :tz where id = :user_id",
            {"tz": timezone, "user_id": user["id"]},
        )
    except ZoneInfoNotFoundError:
        # Invalid timezone, skip update
        pass

    return RedirectResponse(url="/settings/profile", status_code=303)


@router.post("/profile/update-regional")
def update_regional(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    timezone: Annotated[str, Form()],
    locale: Annotated[str, Form()],
):
    """Update user's timezone and locale."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

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
        database.execute(
            tenant_id,
            "update users set tz = :tz, locale = :locale where id = :user_id",
            {"tz": timezone, "locale": locale, "user_id": user["id"]},
        )
    elif tz_valid:
        database.execute(
            tenant_id,
            "update users set tz = :tz where id = :user_id",
            {"tz": timezone, "user_id": user["id"]},
        )
    elif locale:
        database.execute(
            tenant_id,
            "update users set locale = :locale where id = :user_id",
            {"locale": locale, "user_id": user["id"]},
        )

    return RedirectResponse(url="/settings/profile", status_code=303)


@router.get("/emails", response_class=HTMLResponse)
def email_settings(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Display and manage user email addresses."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Fetch all email addresses for this user
    emails = database.fetchall(
        tenant_id,
        """
        select id, email, is_primary, verified_at, created_at
        from user_emails
        where user_id = :user_id
        order by is_primary desc, created_at asc
        """,
        {"user_id": user["id"]},
    )

    return templates.TemplateResponse(
        "settings_emails.html", get_template_context(request, tenant_id, emails=emails)
    )


@router.get("/mfa", response_class=HTMLResponse)
def mfa_settings(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Display and configure MFA settings."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if user has backup codes
    backup_codes = database.fetchall(
        tenant_id,
        """
        select id, code_hash, used_at from mfa_backup_codes
        where user_id = :user_id
        order by created_at asc
        """,
        {"user_id": user["id"]},
    )

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
    email: Annotated[str, Form()],
):
    """Add a new email address to the user's account."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if email already exists for this tenant
    existing = database.fetchone(
        tenant_id,
        "select id from user_emails where email = :email",
        {"email": email.lower()},
    )

    if existing:
        # Email already exists - redirect back with error
        # TODO: Add flash message support
        return RedirectResponse(url="/settings/emails", status_code=303)

    # Add the new email (unverified)
    result = database.fetchone(
        tenant_id,
        """
        insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
        values (:tenant_id, :user_id, :email, false, null)
        returning id, verify_nonce
        """,
        {"tenant_id": user["tenant_id"], "user_id": user["id"], "email": email.lower()},
    )

    # Send verification email
    if result:
        verification_url = (
            f"{request.base_url}settings/emails/verify/{result['id']}/{result['verify_nonce']}"
        )
        send_email_verification(email.lower(), str(verification_url))

    return RedirectResponse(url="/settings/emails", status_code=303)


@router.post("/emails/set-primary/{email_id}")
def set_primary_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email_id: str,
):
    """Set an email as the primary email for the user."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Verify the email belongs to this user and is verified
    email = database.fetchone(
        tenant_id,
        "select id, verified_at from user_emails where id = :email_id and user_id = :user_id",
        {"email_id": email_id, "user_id": user["id"]},
    )

    if not email or not email["verified_at"]:
        # Can't set unverified email as primary
        return RedirectResponse(url="/settings/emails", status_code=303)

    # Unset current primary
    database.execute(
        tenant_id,
        "update user_emails set is_primary = false where user_id = :user_id and is_primary = true",
        {"user_id": user["id"]},
    )

    # Set new primary
    database.execute(
        tenant_id,
        "update user_emails set is_primary = true where id = :email_id",
        {"email_id": email_id},
    )

    return RedirectResponse(url="/settings/emails", status_code=303)


@router.post("/emails/delete/{email_id}")
def delete_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email_id: str,
):
    """Delete an email address from the user's account."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Verify the email belongs to this user and is not primary
    email = database.fetchone(
        tenant_id,
        "select id, is_primary from user_emails where id = :email_id and user_id = :user_id",
        {"email_id": email_id, "user_id": user["id"]},
    )

    if not email or email["is_primary"]:
        # Can't delete primary email or email that doesn't exist
        return RedirectResponse(url="/settings/emails", status_code=303)

    # Delete the email
    database.execute(
        tenant_id,
        "delete from user_emails where id = :email_id",
        {"email_id": email_id},
    )

    return RedirectResponse(url="/settings/emails", status_code=303)


@router.post("/emails/resend-verification/{email_id}")
def resend_verification(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email_id: str,
):
    """Resend verification email for an unverified email address."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Verify the email belongs to this user
    email = database.fetchone(
        tenant_id,
        """
        select id, email, verify_nonce from user_emails
        where id = :email_id and user_id = :user_id
        """,
        {"email_id": email_id, "user_id": user["id"]},
    )

    if not email:
        return RedirectResponse(url="/settings/emails", status_code=303)

    # Send verification email
    verification_url = (
        f"{request.base_url}settings/emails/verify/{email['id']}/{email['verify_nonce']}"
    )
    send_email_verification(email["email"], str(verification_url))

    return RedirectResponse(url="/settings/emails", status_code=303)


@router.get("/emails/verify/{email_id}/{nonce}")
def verify_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email_id: str,
    nonce: int,
):
    """Verify an email address using the verification link."""
    # Look up the email by ID and nonce
    email = database.fetchone(
        tenant_id,
        """
        select id, user_id, email, verified_at, verify_nonce from user_emails
        where id = :email_id
        """,
        {"email_id": email_id},
    )

    if not email:
        return RedirectResponse(url="/login", status_code=303)

    # Check if already verified
    if email["verified_at"]:
        return RedirectResponse(url="/settings/emails", status_code=303)

    # Verify nonce matches
    if email["verify_nonce"] != nonce:
        return RedirectResponse(url="/settings/emails", status_code=303)

    # Mark as verified and increment nonce
    database.execute(
        tenant_id,
        """
        update user_emails
        set verified_at = now(), verify_nonce = verify_nonce + 1
        where id = :email_id
        """,
        {"email_id": email_id},
    )

    return RedirectResponse(url="/settings/emails", status_code=303)


@router.get("/mfa/setup/passcode", response_class=HTMLResponse)
@router.post("/mfa/setup/passcode")
def mfa_setup_passcode(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Start passcode setup process."""
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

    # Generate URI for password managers
    uri = generate_totp_uri(secret, email)
    secret_display = format_secret_for_display(secret)

    # Store unverified secret
    database.execute(
        tenant_id,
        """
        insert into mfa_totp (tenant_id, user_id, secret_encrypted, method)
        values (:tenant_id, :user_id, :secret_encrypted, 'passcode')
        on conflict (user_id, method) do update
        set secret_encrypted = excluded.secret_encrypted,
            verified_at = null
        """,
        {"tenant_id": tenant_id, "user_id": user["id"], "secret_encrypted": secret_encrypted},
    )

    return templates.TemplateResponse(
        "mfa_setup_passcode.html",
        get_template_context(request, tenant_id, uri=uri, secret=secret_display),
    )


@router.get("/mfa/setup/totp", response_class=HTMLResponse)
@router.post("/mfa/setup/totp")
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


@router.post("/mfa/setup/email")
def mfa_setup_email(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Enable email-only MFA (or downgrade from TOTP - requires re-verification)."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if user is downgrading from TOTP/Passcode to email
    current_method = user.get("mfa_method")
    if current_method in ("totp", "passcode"):
        # This is a downgrade - require email re-verification
        # Store pending downgrade in session
        request.session["pending_mfa_downgrade"] = "email"

        # Get primary email
        email_row = database.fetchone(
            tenant_id,
            "select email from user_emails where user_id = :user_id and is_primary = true",
            {"user_id": user["id"]},
        )

        if email_row:
            # Send verification code via email
            from utils.email import send_mfa_code_email
            from utils.mfa import create_email_otp

            code = create_email_otp(tenant_id, user["id"])
            send_mfa_code_email(email_row["email"], code)

        # Redirect to verification page
        return RedirectResponse(url="/settings/mfa/downgrade-verify", status_code=303)

    # Normal case: switching to email MFA without downgrading
    database.execute(
        tenant_id,
        "update users set mfa_enabled = true, mfa_method = :method where id = :user_id",
        {"method": "email", "user_id": user["id"]},
    )

    return RedirectResponse(url="/settings/mfa", status_code=303)


@router.post("/mfa/setup/verify")
def mfa_setup_verify(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    code: Annotated[str, Form()],
    method: Annotated[str, Form()],
):
    """Verify TOTP/Passcode setup and enable MFA."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if method not in ("passcode", "totp"):
        return RedirectResponse(url="/settings/mfa", status_code=303)

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
        return RedirectResponse(url="/settings/mfa", status_code=303)

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

        template = "mfa_setup_passcode.html" if method == "passcode" else "mfa_setup_totp.html"
        return templates.TemplateResponse(
            template,
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


@router.post("/mfa/regenerate-backup-codes")
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


@router.post("/mfa/generate-backup-codes")
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


@router.get("/mfa/downgrade-verify", response_class=HTMLResponse)
def mfa_downgrade_verify_page(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Show verification page when downgrading from TOTP to email MFA."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if there's a pending downgrade
    if not request.session.get("pending_mfa_downgrade"):
        return RedirectResponse(url="/settings/mfa", status_code=303)

    return templates.TemplateResponse(
        "mfa_downgrade_verify.html", get_template_context(request, tenant_id)
    )


@router.post("/mfa/downgrade-verify")
def mfa_downgrade_verify(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    code: Annotated[str, Form()],
):
    """Verify email code and complete downgrade to email MFA."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if there's a pending downgrade
    pending_method = request.session.get("pending_mfa_downgrade")
    if not pending_method:
        return RedirectResponse(url="/settings/mfa", status_code=303)

    # Verify the email code
    code_clean = code.replace(" ", "").replace("-", "")
    if not verify_email_otp(tenant_id, user["id"], code_clean):
        return templates.TemplateResponse(
            "mfa_downgrade_verify.html",
            get_template_context(request, tenant_id, error="Invalid or expired code"),
        )

    # Code verified - complete the downgrade
    database.execute(
        tenant_id,
        "update users set mfa_method = :method where id = :user_id",
        {"method": pending_method, "user_id": user["id"]},
    )

    # Delete TOTP secrets (no longer needed)
    database.execute(
        tenant_id,
        "delete from mfa_totp where user_id = :user_id",
        {"user_id": user["id"]},
    )

    # Clear session
    request.session.pop("pending_mfa_downgrade", None)

    return RedirectResponse(url="/settings/mfa?downgraded=1", status_code=303)


@router.get("/privileged-domains", response_class=HTMLResponse)
def privileged_domains(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Display and manage privileged domains for the tenant (super admin only)."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Only super admins can access this page
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    # Fetch all privileged domains for this tenant
    domains = database.fetchall(
        tenant_id,
        """
        select pd.id, pd.domain, pd.created_at, u.first_name, u.last_name
        from tenant_privileged_domains pd
        left join users u on pd.created_by = u.id
        order by pd.created_at desc
        """,
    )

    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "settings_privileged_domains.html",
        get_template_context(request, tenant_id, domains=domains, error=error),
    )


@router.post("/privileged-domains/add")
def add_privileged_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    domain: Annotated[str, Form()],
):
    """Add a new privileged domain (super admin only)."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Only super admins can manage privileged domains
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    # Clean and validate domain
    domain_clean = domain.strip().lower()

    # Remove @ prefix if present
    if domain_clean.startswith("@"):
        domain_clean = domain_clean[1:]

    # Basic validation: must contain a dot, no spaces, reasonable length
    if (
        not domain_clean
        or " " in domain_clean
        or "." not in domain_clean
        or len(domain_clean) > 253
        or len(domain_clean) < 3
    ):
        return RedirectResponse(
            url="/settings/privileged-domains?error=invalid_domain", status_code=303
        )

    # Check if domain already exists for this tenant
    existing = database.fetchone(
        tenant_id,
        "select id from tenant_privileged_domains where domain = :domain",
        {"domain": domain_clean},
    )

    if existing:
        return RedirectResponse(
            url="/settings/privileged-domains?error=domain_exists", status_code=303
        )

    # Insert the new privileged domain
    database.execute(
        tenant_id,
        """
        insert into tenant_privileged_domains (tenant_id, domain, created_by)
        values (:tenant_id, :domain, :created_by)
        """,
        {"tenant_id": tenant_id, "domain": domain_clean, "created_by": user["id"]},
    )

    return RedirectResponse(url="/settings/privileged-domains", status_code=303)


@router.post("/privileged-domains/delete/{domain_id}")
def delete_privileged_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    domain_id: str,
):
    """Delete a privileged domain (super admin only)."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Only super admins can manage privileged domains
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    # Delete the domain (RLS ensures it belongs to this tenant)
    database.execute(
        tenant_id,
        "delete from tenant_privileged_domains where id = :domain_id",
        {"domain_id": domain_id},
    )

    return RedirectResponse(url="/settings/privileged-domains", status_code=303)
