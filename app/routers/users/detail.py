"""User detail and profile update routes."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_current_user,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import has_page_access
from schemas.api import UserUpdate
from services import groups as groups_service
from services import saml as saml_service
from services import settings as settings_service
from services import users as users_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_current_user)],
    include_in_schema=False,
)


@router.get("/{user_id}", response_class=HTMLResponse)
def user_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Display detailed user information and allow admin edits."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        user_detail_data = users_service.get_user(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Get privileged domains for email validation (for the add-email form)
    privileged_domains = settings_service.get_privileged_domains_list(tenant_id)

    # Get IdPs list for super_admin (for auth method assignment)
    idps = []
    if user.get("role") == "super_admin":
        try:
            idp_list = saml_service.list_identity_providers(requesting_user)
            idps = idp_list.items
        except ServiceError:
            pass  # Ignore errors getting IdPs

    # Check if user's IdP requires platform MFA (for MFA reset section)
    idp_requires_mfa = False
    if user_detail_data.saml_idp_id:
        idp_requires_mfa = saml_service.idp_requires_platform_mfa(
            tenant_id, user_detail_data.saml_idp_id
        )

    # Get group memberships and available groups for assignment
    user_groups = None
    available_groups = []
    try:
        user_groups = groups_service.get_effective_memberships(requesting_user, user_id)
        available_groups = groups_service.list_available_groups_for_user(requesting_user, user_id)
    except ServiceError:
        pass  # Gracefully degrade if group data unavailable

    # Get success/error messages from query params
    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "user_detail.html",
        get_template_context(
            request,
            tenant_id,
            target_user=user_detail_data,
            emails=user_detail_data.emails,
            privileged_domains=privileged_domains,
            idps=idps,
            idp_requires_mfa=idp_requires_mfa,
            user_groups=user_groups,
            available_groups=available_groups,
            success=success,
            error=error,
        ),
    )


@router.post("/{user_id}/update-name")
def update_user_name(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    first_name: Annotated[str, Form()] = "",
    last_name: Annotated[str, Form()] = "",
):
    """Update a user's name (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Validate inputs
    first_name = first_name.strip()
    last_name = last_name.strip()

    if not first_name or not last_name:
        return RedirectResponse(url=f"/users/{user_id}?error=name_required", status_code=303)

    # Update the user's name via service layer
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.update_user(
            requesting_user, user_id, UserUpdate(first_name=first_name, last_name=last_name)
        )
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}?success=name_updated", status_code=303)


@router.post("/{user_id}/update-role")
def update_user_role_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    role: Annotated[str, Form()],
):
    """Update a user's role (super_admin only)."""
    # Check super_admin permission
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    # Validate role
    if role not in ["member", "admin", "super_admin"]:
        return RedirectResponse(url=f"/users/{user_id}?error=invalid_role", status_code=303)

    # Prevent changing own role (kept at route level for quick UI feedback)
    if str(user_id) == str(user.get("id")):
        return RedirectResponse(
            url=f"/users/{user_id}?error=cannot_change_own_role", status_code=303
        )

    # Update the user's role via service layer
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.update_user(requesting_user, user_id, UserUpdate(role=role))
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        # Handle last_super_admin error
        if exc.code == "last_super_admin":
            return RedirectResponse(
                url=f"/users/{user_id}?error=cannot_demote_last_super_admin", status_code=303
            )
        return render_error_page(request, tenant_id, exc)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}?success=role_updated", status_code=303)


@router.post("/{user_id}/update-idp")
def update_user_idp_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    saml_idp_id: Annotated[str, Form()] = "",
):
    """
    Assign a user to an IdP or set them as a password-only user.

    Super_admin only. Every user must be either:
    - Password user (saml_idp_id empty) - authenticates with password
    - IdP user (saml_idp_id set) - authenticates via SAML

    Security: Assigning to IdP wipes password. Removing from IdP inactivates user.
    """
    # Check super_admin permission
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    # Convert empty string to None for password-only
    idp_id = saml_idp_id.strip() if saml_idp_id else None

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.assign_user_idp(
            requesting_user=requesting_user,
            user_id=user_id,
            saml_idp_id=idp_id,
        )
    except NotFoundError as exc:
        return RedirectResponse(
            url=f"/users/{user_id}?error={exc.code}",
            status_code=303,
        )
    except ValidationError as exc:
        return RedirectResponse(
            url=f"/users/{user_id}?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}?success=idp_updated", status_code=303)
