"""User lifecycle management routes (inactivation, reactivation, anonymization, MFA reset)."""

from datetime import UTC, datetime
from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_current_user,
)
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from pages import has_page_access
from services import emails as emails_service
from services import mfa as mfa_service
from services import users as users_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from utils.email import send_mfa_reset_notification
from utils.service_errors import render_error_page

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_current_user)],
    include_in_schema=False,
)


@router.post("/{user_id}/inactivate")
def inactivate_user_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Inactivate a user account (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.inactivate_user(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/users/{user_id}/danger?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/users/{user_id}/danger?success=user_inactivated", status_code=303
    )


@router.post("/{user_id}/reactivate")
def reactivate_user_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Reactivate an inactivated user account (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.reactivate_user(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/users/{user_id}/danger?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/users/{user_id}/danger?success=user_reactivated", status_code=303
    )


@router.post("/{user_id}/anonymize")
def anonymize_user_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Anonymize a user account - GDPR right to be forgotten (super_admin only)."""
    # Check super_admin permission
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.anonymize_user(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/users/{user_id}/danger?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}/danger?success=user_anonymized", status_code=303)


@router.post("/{user_id}/reset-mfa")
def reset_mfa_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Reset MFA for a user (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        mfa_service.reset_user_mfa(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/users/{user_id}/danger?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Send email notification to the user
    primary_email = emails_service.get_primary_email(tenant_id, user_id)
    if primary_email:
        admin_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
        reset_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        send_mfa_reset_notification(
            primary_email, admin_name, reset_time, tenant_id=requesting_user["tenant_id"]
        )

    return RedirectResponse(url=f"/users/{user_id}/danger?success=mfa_reset", status_code=303)
