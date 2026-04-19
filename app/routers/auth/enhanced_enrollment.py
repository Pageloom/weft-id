"""Enhanced auth enrollment (pre-auth TOTP or passkey setup).

When a tenant's `required_auth_strength` is `enhanced`, users who complete
baseline sign-in with only email-based MFA are funneled here to register
either a TOTP authenticator or a passkey before the session is finalized.
The user is NOT yet fully signed in during this flow: access is gated by
the session key `pending_enhanced_enrollment_user_id`, mirroring the
forced-password-reset pattern in `login.py`.
"""

from typing import Annotated

import services.mfa as mfa_service
import services.users as users_service
import services.webauthn as webauthn_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from middleware.csrf import make_csrf_token_func
from routers.auth._login_completion import complete_authenticated_login
from schemas.webauthn import CompleteRegistrationRequest
from services.event_log import log_event
from services.exceptions import ServiceError, ValidationError
from services.types import RequestingUser
from utils.csp_nonce import get_csp_nonce
from utils.qr import generate_qr_code_base64
from utils.templates import templates

router = APIRouter()


def _build_pending_requesting_user(user: dict, tenant_id: str) -> RequestingUser:
    """Build a RequestingUser for the not-yet-fully-signed-in pending user.

    The enrollment flow runs *before* session regeneration, so we synthesize
    a RequestingUser from the pending user dict rather than relying on the
    request-scoped current user (there isn't one yet).
    """
    return {
        "id": str(user["id"]),
        "tenant_id": tenant_id,
        "role": user.get("role", "member"),
    }


def _resolve_pending_user(request: Request, tenant_id: str) -> dict | None:
    """Look up the pending-enrollment user, clearing the gate on a miss.

    Returns the user dict on success. Returns None and clears the gate key
    if no pending user is bound or the user does not exist.
    """
    pending_user_id = request.session.get("pending_enhanced_enrollment_user_id")
    if not pending_user_id:
        return None
    user = users_service.get_user_by_id_raw(tenant_id, pending_user_id)
    if not user:
        request.session.pop("pending_enhanced_enrollment_user_id", None)
        return None
    return user


@router.get("/login/enroll-enhanced-auth", response_class=HTMLResponse)
def enroll_enhanced_auth_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Render the enrollment page offering TOTP or passkey setup."""
    pending_user_id = request.session.get("pending_enhanced_enrollment_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=303)

    user = users_service.get_user_by_id_raw(tenant_id, pending_user_id)
    if not user:
        request.session.pop("pending_enhanced_enrollment_user_id", None)
        return RedirectResponse(url="/login", status_code=303)

    requesting_user = _build_pending_requesting_user(user, tenant_id)

    try:
        setup_response = mfa_service.setup_totp(requesting_user, user)
        uri = setup_response.uri
        secret_display = setup_response.secret
    except ValidationError:
        # Already has an in-progress or active TOTP setup. Fall back to the
        # existing pending setup if one exists so we can still render a page.
        pending = mfa_service.get_pending_totp_setup(tenant_id, pending_user_id)
        if not pending:
            # TOTP is already fully active: user does not need enrollment.
            # Complete the login with totp as the method.
            request.session.pop("pending_enhanced_enrollment_user_id", None)
            request.session.pop("pending_mfa_user_id", None)
            request.session.pop("pending_mfa_method", None)
            return complete_authenticated_login(
                request=request,
                tenant_id=tenant_id,
                user_id=str(user["id"]),
                mfa_method="totp",
            )
        secret_display, uri = pending

    qr_data_url = generate_qr_code_base64(uri)

    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "enroll_enhanced_auth.html",
        {
            "request": request,
            "uri": uri,
            "secret": secret_display,
            "qr_data_url": qr_data_url,
            "error": error,
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
            "passkey_begin_url": "/login/enroll-enhanced-auth/passkey/begin",
            "passkey_complete_url": "/login/enroll-enhanced-auth/passkey/complete",
        },
    )


@router.post("/login/enroll-enhanced-auth")
def enroll_enhanced_auth_verify(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    code: Annotated[str, Form(max_length=100)],
):
    """Verify the TOTP code and complete sign-in."""
    pending_user_id = request.session.get("pending_enhanced_enrollment_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=303)

    user = users_service.get_user_by_id_raw(tenant_id, pending_user_id)
    if not user:
        request.session.pop("pending_enhanced_enrollment_user_id", None)
        return RedirectResponse(url="/login", status_code=303)

    requesting_user = _build_pending_requesting_user(user, tenant_id)

    try:
        mfa_service.verify_totp_and_enable(requesting_user, user, code)
    except ValidationError:
        return RedirectResponse(
            url="/login/enroll-enhanced-auth?error=invalid_code", status_code=303
        )

    # Emit dedicated enrollment-complete event (separate from mfa_totp_enabled
    # already emitted by the service, to make audit queries straightforward).
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user["id"]),
        artifact_type="user",
        artifact_id=str(user["id"]),
        event_type="user_enhanced_auth_enrolled",
        metadata={"method": "totp"},
    )

    # Clear enrollment gate and pending MFA keys, then complete the login.
    request.session.pop("pending_enhanced_enrollment_user_id", None)
    request.session.pop("pending_mfa_user_id", None)
    request.session.pop("pending_mfa_method", None)

    return complete_authenticated_login(
        request=request,
        tenant_id=tenant_id,
        user_id=str(user["id"]),
        mfa_method="totp",
    )


@router.post("/login/enroll-enhanced-auth/passkey/begin")
def enroll_enhanced_auth_passkey_begin(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Start a passkey registration ceremony for the pending enrollment user.

    Returns the ``PublicKeyCredentialCreationOptions`` envelope as JSON. The
    JS on the enrollment page hands this to ``navigator.credentials.create()``.
    """
    user = _resolve_pending_user(request, tenant_id)
    if user is None:
        return JSONResponse(
            status_code=403,
            content={"error": "no_pending_enrollment"},
        )

    requesting_user = _build_pending_requesting_user(user, tenant_id)
    try:
        result = webauthn_service.begin_registration(requesting_user, request)
    except ValidationError as exc:
        return JSONResponse(status_code=400, content={"error": exc.code})
    except ServiceError as exc:
        return JSONResponse(status_code=400, content={"error": exc.code})

    return JSONResponse({"publicKey": result.public_key})


@router.post("/login/enroll-enhanced-auth/passkey/complete")
async def enroll_enhanced_auth_passkey_complete(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Finish a passkey registration ceremony and complete sign-in.

    On success returns JSON ``{"redirect_url": "...", "backup_codes": [...] | null}``
    so the browser-side JS can follow the redirect via
    ``window.location.assign`` (after optionally showing the one-time
    backup-codes modal on first registration).
    """
    user = _resolve_pending_user(request, tenant_id)
    if user is None:
        return JSONResponse(
            status_code=403,
            content={"error": "no_pending_enrollment"},
        )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_json"},
        )

    try:
        payload = CompleteRegistrationRequest.model_validate(body)
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_payload"},
        )

    requesting_user = _build_pending_requesting_user(user, tenant_id)
    try:
        result = webauthn_service.complete_registration(requesting_user, request, payload)
    except ValidationError as exc:
        return JSONResponse(status_code=400, content={"error": exc.code})
    except ServiceError as exc:
        return JSONResponse(status_code=400, content={"error": exc.code})

    # Emit the dedicated enrollment-complete event. Mirrors the TOTP path;
    # only the ``method`` metadata differs.
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user["id"]),
        artifact_type="user",
        artifact_id=str(user["id"]),
        event_type="user_enhanced_auth_enrolled",
        metadata={"method": "passkey"},
    )

    # Clear the enrollment gate and any residual pending MFA keys, then run
    # the shared completion helper.
    request.session.pop("pending_enhanced_enrollment_user_id", None)
    request.session.pop("pending_mfa_user_id", None)
    request.session.pop("pending_mfa_method", None)

    redirect_response = complete_authenticated_login(
        request=request,
        tenant_id=tenant_id,
        user_id=str(user["id"]),
        mfa_method="passkey",
    )
    redirect_url = redirect_response.headers["location"]

    return JSONResponse(
        {
            "redirect_url": redirect_url,
            "backup_codes": result.backup_codes,
        }
    )
