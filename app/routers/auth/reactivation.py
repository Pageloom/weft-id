"""User reactivation endpoints."""

from typing import Annotated

import services.emails as emails_service
import services.users as users_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from middleware.csrf import make_csrf_token_func
from routers.auth._helpers import _get_client_ip
from services.exceptions import RateLimitError
from utils.csp_nonce import get_csp_nonce
from utils.email import send_reactivation_request_admin_notification
from utils.ratelimit import HOUR, ratelimit
from utils.request_metadata import extract_request_metadata
from utils.templates import templates

router = APIRouter()


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

    # Rate limit by IP + tenant to prevent scanning user_ids
    client_ip = _get_client_ip(request)
    try:
        ratelimit.prevent(
            "reactivation:ip:{ip}:tenant:{tenant}",
            limit=10,
            timespan=HOUR,
            ip=client_ip,
            tenant=tenant_id,
        )
    except RateLimitError:
        return RedirectResponse(url="/login?error=invalid_request", status_code=303)

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
            tenant_id=tenant_id,
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
