"""Email verification link and set-password endpoints for new users.

Architectural Note: This module contains a direct log_event() call for the password_set
event during onboarding. This is an accepted exception to the "event logging in services"
pattern because initial password setup during onboarding is part of the authentication
flow (tied to session establishment), not a regular user profile mutation.
"""

from typing import Annotated

import services.emails as emails_service
import services.settings as settings_service
import services.users as users_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from middleware.csrf import make_csrf_token_func
from services.event_log import log_event
from utils.crypto import derive_hmac_key
from utils.csp_nonce import get_csp_nonce
from utils.email import send_mfa_code_email
from utils.mfa import create_email_otp
from utils.password import hash_password
from utils.password_strength import compute_hibp_monitoring_data, validate_password
from utils.request_metadata import extract_request_metadata
from utils.templates import templates

router = APIRouter()


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
            # IdP users don't need a password. Redirect to login.
            if user.get("saml_idp_id"):
                return RedirectResponse(url="/login?success=email_verified_idp", status_code=303)
            # User verified but no password set - redirect to set password
            sp_nonce = email["set_password_nonce"]
            return RedirectResponse(
                url=f"/set-password?email_id={email_id}&nonce={sp_nonce}", status_code=303
            )
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
        # IdP users don't need a password. Redirect to login.
        if user.get("saml_idp_id"):
            return RedirectResponse(url="/login?success=email_verified_idp", status_code=303)
        # New user without password - redirect to set password page
        sp_nonce = email["set_password_nonce"]
        return RedirectResponse(
            url=f"/set-password?email_id={email_id}&nonce={sp_nonce}", status_code=303
        )

    # Existing user adding new email - redirect to login/account
    return RedirectResponse(url="/login?success=email_verified", status_code=303)


@router.get("/set-password", response_class=HTMLResponse)
def set_password_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Display set password page for new users who have verified their email."""
    email_id = request.query_params.get("email_id")
    nonce_str = request.query_params.get("nonce")

    if not email_id or nonce_str is None:
        return RedirectResponse(url="/login", status_code=303)

    try:
        nonce = int(nonce_str)
    except ValueError:
        return RedirectResponse(url="/login?error=invalid_link", status_code=303)

    # Look up the email to get the user's email address
    email = emails_service.get_email_for_verification(tenant_id, email_id)

    if not email:
        return RedirectResponse(url="/login?error=invalid_link", status_code=303)

    # Check if email is verified
    if not email.get("verified_at"):
        return RedirectResponse(url="/login?error=email_not_verified", status_code=303)

    # Validate the set-password nonce to ensure this is a one-time-use link
    if email["set_password_nonce"] != nonce:
        return RedirectResponse(url="/login?error=invalid_link", status_code=303)

    # Check if user already has a password or is assigned to an IdP
    user = users_service.get_user_by_id_raw(tenant_id, email["user_id"])
    if not user or user.get("password_hash"):
        return RedirectResponse(url="/login", status_code=303)
    if user.get("saml_idp_id"):
        return RedirectResponse(url="/login?success=email_verified_idp", status_code=303)

    # Load password policy for this tenant
    policy = settings_service.get_password_policy(tenant_id)
    min_length = policy["minimum_password_length"]
    if user.get("role") == "super_admin" and min_length < 14:
        min_length = 14

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
            "nonce": nonce,
            "minimum_password_length": min_length,
            "minimum_zxcvbn_score": policy["minimum_zxcvbn_score"],
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
    nonce: Annotated[int, Form()],
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

    # Validate the set-password nonce before any other processing
    if email["set_password_nonce"] != nonce:
        return RedirectResponse(url="/login?error=invalid_link", status_code=303)

    # Check if user already has a password or is assigned to an IdP
    user = users_service.get_user_by_id_raw(tenant_id, email["user_id"])
    if not user or user.get("password_hash"):
        return RedirectResponse(url="/login", status_code=303)
    if user.get("saml_idp_id"):
        return RedirectResponse(url="/login?success=email_verified_idp", status_code=303)

    # Validate passwords match
    if password != password_confirm:
        return RedirectResponse(
            url=f"/set-password?email_id={email_id}&nonce={nonce}&error=passwords_dont_match",
            status_code=303,
        )

    # Validate password strength
    policy = settings_service.get_password_policy(tenant_id)
    min_length = policy["minimum_password_length"]
    min_score = policy["minimum_zxcvbn_score"]
    strength = validate_password(
        password,
        minimum_length=min_length,
        minimum_score=min_score,
        user_role=user.get("role"),
        user_inputs=[email["email"]],
    )
    if not strength.is_valid:
        error_code = strength.issues[0].code
        return RedirectResponse(
            url=f"/set-password?email_id={email_id}&nonce={nonce}&error={error_code}",
            status_code=303,
        )

    # Set the password with HIBP monitoring and policy data
    password_hash = hash_password(password)
    hmac_key = derive_hmac_key("hibp")
    hibp_prefix, hibp_check_hmac = compute_hibp_monitoring_data(password, hmac_key)
    users_service.update_password(
        tenant_id,
        user["id"],
        password_hash,
        hibp_prefix=hibp_prefix,
        hibp_check_hmac=hibp_check_hmac,
        policy_length_at_set=min_length,
        policy_score_at_set=min_score,
    )

    # Invalidate the set-password link so it cannot be reused
    emails_service.increment_set_password_nonce(tenant_id, email_id)

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
            send_mfa_code_email(primary_email, code, tenant_id=tenant_id)

    # Redirect to MFA verification (same as after login)
    return RedirectResponse(url="/mfa/verify", status_code=303)
