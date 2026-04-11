"""User detail and profile update routes with tabbed layout."""

import logging
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
from services import emails as emails_service
from services import groups as groups_service
from services import saml as saml_service
from services import service_providers as sp_service
from services import settings as settings_service
from services import users as users_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from starlette.responses import Response
from utils.email import send_new_user_invitation, send_new_user_privileged_domain_notification
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_current_user)],
    include_in_schema=False,
)


def _load_user_common(
    request: Request,
    tenant_id: str,
    user: dict,
    user_id: str,
) -> dict | Response:
    """Load shared context for all user detail tabs.

    Returns a dict of common context values, or a RedirectResponse on error.
    """
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        user_detail_data = users_service.get_user(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Get group count for tab badge
    group_count = 0
    try:
        memberships = groups_service.get_effective_memberships(requesting_user, user_id)
        group_count = len(memberships.items) if memberships else 0
    except ServiceError:
        pass

    # Get app count for tab badge
    app_count = 0
    try:
        apps = sp_service.get_user_accessible_apps_admin(requesting_user, user_id)
        app_count = apps.total
    except ServiceError:
        pass

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return {
        "requesting_user": requesting_user,
        "user_detail_data": user_detail_data,
        "group_count": group_count,
        "app_count": app_count,
        "success": success,
        "error": error,
    }


# ============================================================================
# Tab GET handlers
# ============================================================================


@router.get("/{user_id}", response_class=HTMLResponse)
def user_detail_redirect(user_id: str):
    """Redirect bare user detail URL to profile tab."""
    return RedirectResponse(url=f"/users/{user_id}/profile", status_code=303)


@router.get("/{user_id}/profile", response_class=HTMLResponse)
def user_detail_profile(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Display user profile tab with info, name edit, role, auth method, and emails."""
    common = _load_user_common(request, tenant_id, user, user_id)
    if isinstance(common, Response):
        return common

    requesting_user = common["requesting_user"]
    user_detail_data = common["user_detail_data"]

    # Get privileged domains for email validation
    privileged_domains = settings_service.get_privileged_domains_list(tenant_id)

    # Get IdPs list for super_admin
    idps = []
    if user.get("role") == "super_admin":
        try:
            idp_list = saml_service.list_identity_providers(requesting_user)
            idps = idp_list.items
        except ServiceError:
            pass

    # Compute email change impact when warning=email_impact is present
    email_impact = None
    warning = request.query_params.get("warning")
    if warning == "email_impact":
        email_id = request.query_params.get("email_id", "")
        email_address = emails_service.get_email_address_by_id(tenant_id, user_id, email_id)
        if email_address:
            email_impact = emails_service.compute_email_change_impact(
                tenant_id, user_id, email_address
            )

    return templates.TemplateResponse(
        request,
        "user_detail_tab_profile.html",
        get_template_context(
            request,
            tenant_id,
            target_user=user_detail_data,
            emails=user_detail_data.emails,
            privileged_domains=privileged_domains,
            idps=idps,
            email_impact=email_impact,
            active_tab="profile",
            group_count=common["group_count"],
            app_count=common["app_count"],
            success=common["success"],
            error=common["error"],
        ),
    )


@router.get("/{user_id}/groups", response_class=HTMLResponse)
def user_detail_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Display user groups tab with memberships and add/remove."""
    common = _load_user_common(request, tenant_id, user, user_id)
    if isinstance(common, Response):
        return common

    requesting_user = common["requesting_user"]
    user_detail_data = common["user_detail_data"]

    # Get group memberships and available groups
    user_groups = None
    available_groups = []
    try:
        user_groups = groups_service.get_effective_memberships(requesting_user, user_id)
        available_groups = groups_service.list_available_groups_for_user(requesting_user, user_id)
    except ServiceError:
        pass

    return templates.TemplateResponse(
        request,
        "user_detail_tab_groups.html",
        get_template_context(
            request,
            tenant_id,
            target_user=user_detail_data,
            user_groups=user_groups,
            available_groups=available_groups,
            active_tab="groups",
            group_count=common["group_count"],
            app_count=common["app_count"],
            success=common["success"],
            error=common["error"],
        ),
    )


@router.get("/{user_id}/apps", response_class=HTMLResponse)
def user_detail_apps(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Display user apps tab with accessible applications and group attribution."""
    common = _load_user_common(request, tenant_id, user, user_id)
    if isinstance(common, Response):
        return common

    requesting_user = common["requesting_user"]
    user_detail_data = common["user_detail_data"]

    # Get accessible apps with attribution
    accessible_apps = None
    try:
        accessible_apps = sp_service.get_user_accessible_apps_admin(requesting_user, user_id)
    except ServiceError:
        pass

    return templates.TemplateResponse(
        request,
        "user_detail_tab_apps.html",
        get_template_context(
            request,
            tenant_id,
            target_user=user_detail_data,
            accessible_apps=accessible_apps,
            active_tab="apps",
            group_count=common["group_count"],
            app_count=common["app_count"],
            is_super_admin=requesting_user["role"] == "super_admin",
            success=common["success"],
            error=common["error"],
        ),
    )


@router.get("/{user_id}/danger", response_class=HTMLResponse)
def user_detail_danger(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Display user danger tab with inactivation, anonymization, and MFA reset."""
    common = _load_user_common(request, tenant_id, user, user_id)
    if isinstance(common, Response):
        return common

    user_detail_data = common["user_detail_data"]

    # Check if user's IdP requires platform MFA
    idp_requires_mfa = False
    if user_detail_data.saml_idp_id:
        idp_requires_mfa = saml_service.idp_requires_platform_mfa(
            tenant_id, user_detail_data.saml_idp_id
        )

    return templates.TemplateResponse(
        request,
        "user_detail_tab_danger.html",
        get_template_context(
            request,
            tenant_id,
            target_user=user_detail_data,
            idp_requires_mfa=idp_requires_mfa,
            active_tab="danger",
            group_count=common["group_count"],
            app_count=common["app_count"],
            success=common["success"],
            error=common["error"],
        ),
    )


# ============================================================================
# POST handlers
# ============================================================================


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
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    first_name = first_name.strip()
    last_name = last_name.strip()

    if not first_name or not last_name:
        return RedirectResponse(
            url=f"/users/{user_id}/profile?error=name_required", status_code=303
        )

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.update_user(
            requesting_user, user_id, UserUpdate(first_name=first_name, last_name=last_name)
        )
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}/profile?success=name_updated", status_code=303)


@router.post("/{user_id}/update-role")
def update_user_role_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    role: Annotated[str, Form()],
):
    """Update a user's role (super_admin only)."""
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    if role not in ["member", "admin", "super_admin"]:
        return RedirectResponse(url=f"/users/{user_id}/profile?error=invalid_role", status_code=303)

    if str(user_id) == str(user.get("id")):
        return RedirectResponse(
            url=f"/users/{user_id}/profile?error=cannot_change_own_role", status_code=303
        )

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.update_user(requesting_user, user_id, UserUpdate(role=role))
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        if exc.code == "last_super_admin":
            return RedirectResponse(
                url=f"/users/{user_id}/profile?error=cannot_demote_last_super_admin",
                status_code=303,
            )
        return render_error_page(request, tenant_id, exc)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}/profile?success=role_updated", status_code=303)


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
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

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
            url=f"/users/{user_id}/profile?error={exc.code}",
            status_code=303,
        )
    except ValidationError as exc:
        return RedirectResponse(
            url=f"/users/{user_id}/profile?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}/profile?success=idp_updated", status_code=303)


@router.post("/{user_id}/force-password-reset")
def force_password_reset_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Force a user to change their password on next login."""
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.force_password_reset(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/users/{user_id}/danger?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/users/{user_id}/danger?success=password_reset_forced", status_code=303
    )


@router.post("/{user_id}/resend-invitation")
def resend_invitation_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Resend invitation email to a user who has not completed onboarding."""
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        result = users_service.resend_invitation(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/users/{user_id}/profile?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    org_name = users_service.get_tenant_name(tenant_id)
    admin_name = f"{user.get('first_name')} {user.get('last_name')}"

    if result["invitation_type"] == "set_password":
        password_set_url = (
            f"{request.base_url}set-password?email_id={result['email_id']}&nonce={result['nonce']}"
        )
        send_new_user_privileged_domain_notification(
            result["email"], admin_name, org_name, password_set_url, tenant_id=tenant_id
        )
    else:
        verification_url = f"{request.base_url}verify-email/{result['email_id']}/{result['nonce']}"
        send_new_user_invitation(
            result["email"], admin_name, org_name, verification_url, tenant_id=tenant_id
        )

    return RedirectResponse(
        url=f"/users/{user_id}/profile?success=invitation_resent", status_code=303
    )
