"""User account routes (profile, emails, MFA)."""

from pathlib import Path
from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_current_user,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pages import get_first_accessible_child
from routers.auth._helpers import _get_client_ip
from schemas.api import UserProfileUpdate
from services import bg_tasks as bg_tasks_service
from services import emails as emails_service
from services import exports as exports_service
from services import mfa as mfa_service
from services import settings as settings_service
from services import users as users_service
from services.exceptions import (
    ConflictError,
    NotFoundError,
    RateLimitError,
    ServiceError,
    ValidationError,
)
from utils.email import send_email_verification, send_mfa_code_email
from utils.qr import generate_qr_code_base64
from utils.ratelimit import HOUR, ratelimit
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/account",
    tags=["account"],
    dependencies=[Depends(require_current_user)],  # All routes require authentication
    include_in_schema=False,
)


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
        request, "settings_profile.html", get_template_context(request, tenant_id)
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
        if not settings_service.can_user_edit_profile(tenant_id):
            return RedirectResponse(url="/account/profile", status_code=303)

    # Update user's name via service
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    profile_update = UserProfileUpdate(
        first_name=first_name.strip(),
        last_name=last_name.strip(),
    )
    users_service.update_current_user_profile(requesting_user, user, profile_update)

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

        # Update user's timezone via service
        requesting_user = build_requesting_user(user, user["tenant_id"], request)
        profile_update = UserProfileUpdate(timezone=timezone)
        users_service.update_current_user_profile(requesting_user, user, profile_update)
    except ZoneInfoNotFoundError:
        # Invalid timezone, skip update
        pass

    return RedirectResponse(url="/account/profile", status_code=303)


@router.post("/profile/update-regional")
def update_regional(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    timezone: Annotated[str, Form()] = "",
    locale: Annotated[str, Form()] = "",
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

    # Build profile update with valid fields
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    profile_update = UserProfileUpdate(
        timezone=timezone if tz_valid else None,
        locale=locale if locale else None,
    )

    # Only call service if there's something to update
    if profile_update.timezone or profile_update.locale:
        users_service.update_current_user_profile(requesting_user, user, profile_update)

    return RedirectResponse(url="/account/profile", status_code=303)


@router.post("/profile/update-theme")
def update_theme(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    theme: Annotated[str, Form()],
):
    """Update user's theme preference."""
    # Validate theme
    if theme not in ("system", "light", "dark"):
        return RedirectResponse(url="/account/profile", status_code=303)

    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    profile_update = UserProfileUpdate(theme=theme)
    users_service.update_current_user_profile(requesting_user, user, profile_update)

    return RedirectResponse(url="/account/profile", status_code=303)


@router.get("/password", response_class=HTMLResponse)
def password_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display password change form. Only for password-authenticated users."""
    # Only show for users with a password (not IdP-federated)
    if user.get("saml_idp_id"):
        return RedirectResponse(url="/account/profile", status_code=303)

    policy = settings_service.get_password_policy(tenant_id)
    min_length = policy["minimum_password_length"]
    # Super admins always require at least 14 characters
    if user.get("role") == "super_admin" and min_length < 14:
        min_length = 14
    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "settings_password.html",
        get_template_context(
            request,
            tenant_id,
            minimum_password_length=min_length,
            minimum_zxcvbn_score=policy["minimum_zxcvbn_score"],
            success=success,
            error=error,
        ),
    )


@router.post("/password")
def change_password(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
    new_password_confirm: Annotated[str, Form()],
):
    """Handle password change form submission."""
    if user.get("saml_idp_id"):
        return RedirectResponse(url="/account/profile", status_code=303)

    try:
        ratelimit.prevent("pw_change:user:{user_id}", limit=5, timespan=HOUR, user_id=user["id"])
        ratelimit.prevent("pw_change:ip:{ip}", limit=10, timespan=HOUR, ip=_get_client_ip(request))
    except RateLimitError:
        return RedirectResponse(url="/account/password?error=too_many_attempts", status_code=303)

    if new_password != new_password_confirm:
        return RedirectResponse(url="/account/password?error=passwords_dont_match", status_code=303)

    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        users_service.change_password(requesting_user, current_password, new_password)
    except ValidationError as exc:
        return RedirectResponse(url=f"/account/password?error={exc.code}", status_code=303)

    return RedirectResponse(url="/account/password?success=password_changed", status_code=303)


@router.get("/emails", response_class=HTMLResponse)
def email_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display and manage user email addresses."""
    # Fetch all email addresses for this user via service
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    emails = emails_service.list_user_emails(requesting_user, user["id"])

    return templates.TemplateResponse(
        request, "settings_emails.html", get_template_context(request, tenant_id, emails=emails)
    )


@router.get("/mfa", response_class=HTMLResponse)
def mfa_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display and configure MFA settings."""
    # Check if user has backup codes via service
    backup_codes = mfa_service.list_backup_codes_raw(tenant_id, user["id"])

    return templates.TemplateResponse(
        request,
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
    allow_add = settings_service.can_users_add_emails(tenant_id)
    if user.get("role") != "super_admin" and not allow_add:
        return RedirectResponse(url="/account/emails", status_code=303)

    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        # Add email via service (non-admin action, requires verification)
        created_email = emails_service.add_user_email(
            requesting_user,
            user["id"],
            email,
            is_admin_action=False,
            allow_users_add_emails=allow_add,
        )

        # Get verification info and send verification email
        verification_info = emails_service.resend_verification(
            requesting_user, user["id"], created_email.id
        )
        verification_url = (
            f"{request.base_url}account/emails/verify/"
            f"{verification_info['email_id']}/{verification_info['verify_nonce']}"
        )
        send_email_verification(email.lower(), str(verification_url))
    except (ValidationError, NotFoundError, ConflictError):
        # Email exists or other error - redirect back silently
        pass

    return RedirectResponse(url="/account/emails", status_code=303)


@router.post("/emails/set-primary/{email_id}")
def set_primary_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    email_id: str,
):
    """Set an email as the primary email for the user."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        emails_service.set_primary_email(requesting_user, user["id"], email_id)
    except (NotFoundError, ValidationError):
        # Email not found or not verified - redirect back silently
        pass

    return RedirectResponse(url="/account/emails", status_code=303)


@router.post("/emails/delete/{email_id}")
def delete_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    email_id: str,
):
    """Delete an email address from the user's account."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        emails_service.delete_user_email(requesting_user, user["id"], email_id)
    except (NotFoundError, ValidationError):
        # Email not found, is primary, or is last email - redirect back silently
        pass

    return RedirectResponse(url="/account/emails", status_code=303)


@router.post("/emails/resend-verification/{email_id}")
def resend_verification_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    email_id: str,
):
    """Resend verification email for an unverified email address."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        verification_info = emails_service.resend_verification(
            requesting_user, user["id"], email_id
        )
        verification_url = (
            f"{request.base_url}account/emails/verify/"
            f"{verification_info['email_id']}/{verification_info['verify_nonce']}"
        )
        send_email_verification(verification_info["email"], str(verification_url))
    except NotFoundError:
        # Email not found - redirect back silently
        pass

    return RedirectResponse(url="/account/emails", status_code=303)


@router.get("/emails/verify/{email_id}/{nonce}")
def verify_email_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email_id: str,
    nonce: int,
):
    """Verify an email address using the verification link."""
    # First get email info to get the user_id
    email_info = emails_service.get_email_for_verification(tenant_id, email_id)

    if not email_info:
        return RedirectResponse(url="/login", status_code=303)

    # Check if already verified
    if email_info["verified_at"]:
        return RedirectResponse(url="/account/emails", status_code=303)

    try:
        emails_service.verify_email(tenant_id, email_id, str(email_info["user_id"]), nonce)
    except (NotFoundError, ValidationError):
        # Invalid nonce or email - redirect back silently
        return RedirectResponse(url="/account/emails", status_code=303)

    return RedirectResponse(url="/account/emails", status_code=303)


@router.get("/mfa/setup/totp", response_class=HTMLResponse)
@router.post("/mfa/setup/totp")
def mfa_setup_totp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Start TOTP (authenticator app) setup process."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        setup_response = mfa_service.setup_totp(requesting_user, user)
    except ValidationError:
        # TOTP already active - redirect back
        return RedirectResponse(url="/account/mfa", status_code=303)

    # Generate QR code locally to avoid leaking TOTP secret to third-party API
    qr_data_url = generate_qr_code_base64(setup_response.uri)

    return templates.TemplateResponse(
        request,
        "mfa_setup_totp.html",
        get_template_context(
            request,
            tenant_id,
            uri=setup_response.uri,
            secret=setup_response.secret,
            qr_data_url=qr_data_url,
        ),
    )


@router.post("/mfa/setup/email")
def mfa_setup_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Enable email-only MFA (or downgrade from TOTP - requires re-verification)."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    response, notification_info = mfa_service.enable_email_mfa(requesting_user, user)

    if response.pending_verification and notification_info:
        # Downgrading from TOTP - store session and send code
        request.session["pending_mfa_downgrade"] = "email"
        send_mfa_code_email(notification_info["email"], notification_info["code"])
        return RedirectResponse(url="/account/mfa/downgrade-verify", status_code=303)

    # Email MFA enabled directly
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

    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        backup_codes_response = mfa_service.verify_totp_and_enable(requesting_user, user, code)
        # Show backup codes
        return templates.TemplateResponse(
            request,
            "mfa_backup_codes.html",
            get_template_context(request, tenant_id, backup_codes=backup_codes_response.codes),
        )
    except ValidationError as e:
        if e.code == "invalid_totp_code":
            # Re-display setup page with error
            pending_setup = mfa_service.get_pending_totp_setup(tenant_id, user["id"])
            if pending_setup:
                secret_display, uri = pending_setup
                return templates.TemplateResponse(
                    request,
                    "mfa_setup_totp.html",
                    get_template_context(
                        request, tenant_id, uri=uri, secret=secret_display, error="Invalid code"
                    ),
                )
        # No pending setup or other error - redirect back
        return RedirectResponse(url="/account/mfa", status_code=303)


@router.post("/mfa/regenerate-backup-codes")
def mfa_regenerate_backup_codes(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Regenerate backup codes for the current user."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        backup_codes_response = mfa_service.regenerate_backup_codes(requesting_user, user)
        # Show backup codes
        return templates.TemplateResponse(
            request,
            "mfa_backup_codes.html",
            get_template_context(request, tenant_id, backup_codes=backup_codes_response.codes),
        )
    except ValidationError:
        # MFA not enabled - redirect back
        return RedirectResponse(url="/account/mfa", status_code=303)


@router.post("/mfa/generate-backup-codes")
def mfa_generate_backup_codes(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Generate initial backup codes for users who don't have any."""
    backup_codes = mfa_service.generate_initial_backup_codes(tenant_id, user["id"])

    # Show backup codes
    return templates.TemplateResponse(
        request,
        "mfa_backup_codes.html",
        get_template_context(request, tenant_id, backup_codes=backup_codes),
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
        request, "mfa_downgrade_verify.html", get_template_context(request, tenant_id)
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

    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        mfa_service.verify_mfa_downgrade(requesting_user, user, code)
        # Clear session
        request.session.pop("pending_mfa_downgrade", None)
        return RedirectResponse(url="/account/mfa?downgraded=1", status_code=303)
    except ValidationError as e:
        if e.code == "invalid_email_otp":
            return templates.TemplateResponse(
                request,
                "mfa_downgrade_verify.html",
                get_template_context(request, tenant_id, error="Invalid or expired code"),
            )
        # Other validation error - redirect back
        return RedirectResponse(url="/account/mfa", status_code=303)


# Background Jobs Routes


@router.get("/background-jobs", response_class=HTMLResponse)
def background_jobs_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display user's background jobs with polling."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)

    try:
        result = bg_tasks_service.list_user_jobs(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "account_background_jobs.html",
        get_template_context(
            request,
            tenant_id,
            jobs=result.jobs,
            has_active_jobs=result.has_active_jobs,
            success=success,
            error=error,
        ),
    )


@router.post("/background-jobs/delete")
async def delete_background_jobs(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Delete selected background jobs."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)

    # Get job IDs from form data (checkboxes)
    form = await request.form()
    job_ids = [str(val) for val in form.getlist("job_ids") if isinstance(val, str)]

    if not job_ids:
        return RedirectResponse(
            url="/account/background-jobs?error=no_jobs_selected", status_code=303
        )

    try:
        count = bg_tasks_service.delete_jobs(requesting_user, job_ids)
        return RedirectResponse(
            url=f"/account/background-jobs?success=deleted_{count}", status_code=303
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)


@router.get("/background-jobs/{job_id}/output", response_class=HTMLResponse)
def job_output_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    job_id: str,
):
    """Display job output and metadata."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)

    try:
        job = bg_tasks_service.get_job_detail(requesting_user, job_id)
    except NotFoundError:
        return RedirectResponse(url="/account/background-jobs?error=job_not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return templates.TemplateResponse(
        request,
        "account_job_output.html",
        get_template_context(request, tenant_id, job=job),
    )


@router.get("/background-jobs/download/{file_id}")
def download_background_job_file(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    file_id: str,
):
    """Download export file from background job."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)

    try:
        download_info = exports_service.get_download(requesting_user, file_id)
    except NotFoundError:
        return RedirectResponse(
            url="/account/background-jobs?error=file_not_found", status_code=303
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    if download_info["storage_type"] == "spaces":
        # Redirect to signed S3 URL
        return RedirectResponse(url=download_info["url"], status_code=302)
    else:
        # Serve local file
        file_path = Path(download_info["path"])
        if not file_path.exists():
            return RedirectResponse(
                url="/account/background-jobs?error=file_missing", status_code=303
            )

        return FileResponse(
            path=file_path,
            filename=download_info["filename"],
            media_type=download_info.get("content_type", "application/gzip"),
        )
