"""Self-service password reset endpoints (forgot password)."""

import logging
from typing import Annotated

import services.users as users_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from middleware.csrf import make_csrf_token_func
from routers.auth._helpers import _get_client_ip
from services.exceptions import RateLimitError, ValidationError
from utils.csp_nonce import get_csp_nonce
from utils.ratelimit import HOUR, ratelimit
from utils.templates import templates

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    success: str | None = None,
    error: str | None = None,
):
    """Render the forgot password form."""
    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
            "success": success,
            "error": error,
        },
    )


@router.post("/forgot-password")
def forgot_password_submit(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    email: Annotated[str, Form()],
):
    """Process the forgot password email submission."""
    client_ip = _get_client_ip(request)

    # Rate limiting (swallow errors to prevent enumeration)
    try:
        ratelimit.prevent("pw_reset:email:{email}", limit=3, timespan=HOUR, email=email)
        ratelimit.prevent("pw_reset:ip:{ip}", limit=10, timespan=HOUR, ip=client_ip)
    except RateLimitError:
        # Still show the same success message to prevent enumeration
        return RedirectResponse(url="/forgot-password?success=email_sent", status_code=303)

    base_url = str(request.base_url).rstrip("/")
    users_service.request_password_reset(tenant_id, email, base_url, client_ip=client_ip)

    return RedirectResponse(url="/forgot-password?success=email_sent", status_code=303)


@router.get("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    token: str,
):
    """Render the set new password form after clicking a reset link."""
    result = users_service.validate_reset_token(tenant_id, token)
    if not result:
        return RedirectResponse(url="/forgot-password?error=invalid_or_expired", status_code=303)

    return templates.TemplateResponse(
        request,
        "reset_password.html",
        {
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
            "token": token,
            "minimum_password_length": result["minimum_password_length"],
            "minimum_zxcvbn_score": result["minimum_zxcvbn_score"],
            "error": None,
        },
    )


@router.post("/reset-password/{token}")
def reset_password_submit(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    token: str,
    new_password: Annotated[str, Form()],
    new_password_confirm: Annotated[str, Form()],
):
    """Process the new password submission."""
    # Re-verify token (state may have changed if password was already reset)
    result = users_service.validate_reset_token(tenant_id, token)
    if not result:
        return RedirectResponse(url="/forgot-password?error=invalid_or_expired", status_code=303)

    # Validate passwords match
    if new_password != new_password_confirm:
        return _render_reset_form_with_error(request, token, result, "passwords_dont_match")

    # Complete the reset
    try:
        users_service.complete_self_service_password_reset(
            tenant_id, result["user_id"], new_password
        )
    except ValidationError as e:
        return _render_reset_form_with_error(request, token, result, e.code)

    return RedirectResponse(url="/login?success=password_reset", status_code=303)


def _render_reset_form_with_error(
    request: Request,
    token: str,
    validation_result: dict,
    error: str,
) -> HTMLResponse:
    """Re-render the reset form with an error message."""
    return templates.TemplateResponse(
        request,
        "reset_password.html",
        {
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
            "token": token,
            "minimum_password_length": validation_result["minimum_password_length"],
            "minimum_zxcvbn_score": validation_result["minimum_zxcvbn_score"],
            "error": error,
        },
    )
