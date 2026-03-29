"""User email management routes."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_current_user,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from pages import has_page_access
from services import emails as emails_service
from services import settings as settings_service
from services.exceptions import ConflictError, NotFoundError, ServiceError, ValidationError
from utils.email import (
    send_primary_email_changed_notification,
    send_secondary_email_added_notification,
    send_secondary_email_removed_notification,
)
from utils.service_errors import render_error_page

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_current_user)],
    include_in_schema=False,
)


@router.post("/{user_id}/add-email")
def add_user_email_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    email: Annotated[str, Form()],
):
    """Add a secondary email to a user (admin only, privileged domains only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Clean and validate email
    email_lower = email.strip().lower()

    if not email_lower or "@" not in email_lower:
        return RedirectResponse(
            url=f"/users/{user_id}/profile?error=invalid_email", status_code=303
        )

    # Extract domain and check if it's privileged (admin can only add privileged domains)
    domain = email_lower.split("@")[1]
    if not settings_service.is_privileged_domain(tenant_id, domain):
        return RedirectResponse(
            url=f"/users/{user_id}/profile?error=domain_not_privileged", status_code=303
        )

    # Add the email via service layer (admin action = auto-verified)
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        emails_service.add_user_email(requesting_user, user_id, email_lower, is_admin_action=True)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ConflictError:
        return RedirectResponse(url=f"/users/{user_id}/profile?error=email_exists", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Get primary email for notification
    primary_email = emails_service.get_primary_email(tenant_id, user_id)
    if primary_email:
        admin_name = f"{user.get('first_name')} {user.get('last_name')}"
        send_secondary_email_added_notification(
            primary_email, email_lower, admin_name, tenant_id=requesting_user["tenant_id"]
        )

    return RedirectResponse(url=f"/users/{user_id}/profile?success=email_added", status_code=303)


@router.post("/{user_id}/remove-email/{email_id}")
def remove_user_email_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    email_id: str,
):
    """Remove a secondary email from a user (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Get email address before deletion for notification
    email_address = emails_service.get_email_address_by_id(tenant_id, user_id, email_id)

    # Delete via service layer
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        emails_service.delete_user_email(requesting_user, user_id, email_id)
    except NotFoundError:
        return RedirectResponse(
            url=f"/users/{user_id}/profile?error=email_not_found", status_code=303
        )
    except ValidationError as exc:
        if exc.code == "cannot_delete_primary":
            return RedirectResponse(
                url=f"/users/{user_id}/profile?error=cannot_remove_primary", status_code=303
            )
        if exc.code == "must_keep_one_email":
            return RedirectResponse(
                url=f"/users/{user_id}/profile?error=must_keep_one_email", status_code=303
            )
        return render_error_page(request, tenant_id, exc)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Get primary email for notification
    if email_address:
        primary_email = emails_service.get_primary_email(tenant_id, user_id)
        if primary_email:
            admin_name = f"{user.get('first_name')} {user.get('last_name')}"
            send_secondary_email_removed_notification(
                primary_email, email_address, admin_name, tenant_id=requesting_user["tenant_id"]
            )

    return RedirectResponse(url=f"/users/{user_id}/profile?success=email_removed", status_code=303)


@router.post("/{user_id}/promote-email/{email_id}")
def promote_user_email_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    email_id: str,
    confirm_routing_change: Annotated[str, Form()] = "",
):
    """Promote a secondary email to primary (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Get old primary email info before changing (for notification)
    old_primary_email = emails_service.get_primary_email(tenant_id, user_id)

    # Get the new primary email address (for notification)
    new_primary_email = emails_service.get_email_address_by_id(tenant_id, user_id, email_id)

    # Check for downstream impact (SP assertions + IdP routing) before proceeding
    if new_primary_email and not confirm_routing_change:
        impact = emails_service.compute_email_change_impact(tenant_id, user_id, new_primary_email)
        has_impact = impact["summary"]["affected_sp_count"] > 0 or impact["routing_change"]
        if has_impact:
            return RedirectResponse(
                url=(f"/users/{user_id}/profile?warning=email_impact&email_id={email_id}"),
                status_code=303,
            )

    # Set primary via service layer
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        emails_service.set_primary_email(requesting_user, user_id, email_id)
        # If already primary, the service returns the email without error
        # Check if it was already primary (email unchanged)
        if old_primary_email == new_primary_email:
            return RedirectResponse(
                url=f"/users/{user_id}/profile?error=already_primary", status_code=303
            )
    except NotFoundError:
        return RedirectResponse(
            url=f"/users/{user_id}/profile?error=email_not_found", status_code=303
        )
    except ValidationError as exc:
        if exc.code == "email_not_verified":
            return RedirectResponse(
                url=f"/users/{user_id}/profile?error=email_not_verified", status_code=303
            )
        return render_error_page(request, tenant_id, exc)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Send notification to old primary email
    if old_primary_email and new_primary_email and old_primary_email != new_primary_email:
        admin_name = f"{user.get('first_name')} {user.get('last_name')}"
        send_primary_email_changed_notification(
            old_primary_email, new_primary_email, admin_name, tenant_id=requesting_user["tenant_id"]
        )

    return RedirectResponse(url=f"/users/{user_id}/profile?success=email_promoted", status_code=303)
