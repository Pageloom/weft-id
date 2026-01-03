"""Reactivation Request API endpoints."""

from typing import Annotated

from api_dependencies import require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from schemas.reactivation import ReactivationRequest
from services import reactivation as reactivation_service
from services.exceptions import ServiceError
from utils.email import (
    send_account_reactivated_notification,
    send_reactivation_denied_notification,
)
from utils.service_errors import translate_to_http_exception

router = APIRouter(
    prefix="/api/v1/reactivation-requests",
    tags=["Reactivation Requests"],
    dependencies=[Depends(require_admin_api)],
)


@router.get("", response_model=list[ReactivationRequest])
def list_pending_requests(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
):
    """
    List pending reactivation requests.

    Requires admin or super_admin role.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        return reactivation_service.list_pending_requests(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/history", response_model=list[ReactivationRequest])
def list_previous_requests(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
):
    """
    List previously decided reactivation requests.

    Requires admin or super_admin role.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        return reactivation_service.list_previous_requests(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{request_id}/approve", response_model=ReactivationRequest)
def approve_request(
    request: Request,
    request_id: str,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
):
    """
    Approve a reactivation request.

    This reactivates the user's account, allowing them to sign in again.
    Requires admin or super_admin role.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        result = reactivation_service.approve_request(requesting_user, request_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    # Send notification email to the reactivated user
    if result.email:
        # Construct login URL - use the request's base URL
        login_url = str(request.url_for("login_page"))
        send_account_reactivated_notification(result.email, login_url)

    return result


@router.post("/{request_id}/deny", response_model=ReactivationRequest)
def deny_request(
    request: Request,
    request_id: str,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
):
    """
    Deny a reactivation request.

    The user will be permanently blocked from requesting reactivation again.
    Requires admin or super_admin role.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        result = reactivation_service.deny_request(requesting_user, request_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    # Send notification email to the denied user
    if result.email:
        send_reactivation_denied_notification(result.email)

    return result
