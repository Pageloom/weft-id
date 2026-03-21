"""Branding settings routes (logo management, display settings)."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError as PydanticValidationError
from schemas.branding import BrandingSettingsUpdate, LogoMode, LogoSlot
from services import branding as branding_service
from services.exceptions import ServiceError, ValidationError
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/admin/settings",
    tags=["admin-settings-branding"],
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)


@router.get("/branding", response_class=HTMLResponse)
def admin_branding_redirect(
    request: Request,
):
    """Redirect to branding global tab."""
    return RedirectResponse(url="/admin/settings/branding/global", status_code=303)


@router.get("/branding/global", response_class=HTMLResponse)
def admin_branding_global(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display global branding settings (logos, site title, display mode)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        settings = branding_service.get_branding_settings(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "settings_branding_global.html",
        get_template_context(
            request,
            tenant_id,
            branding_settings=settings,
            success=success,
            error=error,
        ),
    )


@router.get("/branding/groups", response_class=HTMLResponse)
def admin_branding_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display group branding settings (avatar style, per-group logos)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        branding_settings = branding_service.get_branding_settings(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "settings_branding_groups.html",
        get_template_context(
            request,
            tenant_id,
            branding_settings=branding_settings,
            success=success,
            error=error,
        ),
    )


@router.post("/branding/global/upload/{slot}")
async def upload_branding_logo(
    request: Request,
    slot: LogoSlot,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    file: UploadFile,
):
    """Upload a logo image for a slot (light or dark)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        data = await file.read()
        branding_service.upload_logo(
            requesting_user,
            slot=slot,
            data=data,
            filename=file.filename,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/branding/global?success=logo_uploaded",
        status_code=303,
    )


@router.post("/branding/global/delete/{slot}")
def delete_branding_logo(
    request: Request,
    slot: LogoSlot,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Delete a logo image for a slot."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        branding_service.delete_logo(requesting_user, slot=slot)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/branding/global?success=logo_deleted",
        status_code=303,
    )


@router.post("/branding/global/settings")
def update_branding_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    logo_mode: Annotated[str, Form()],
    use_logo_as_favicon: Annotated[str, Form()] = "",
    site_title: Annotated[str, Form()] = "",
    show_title_in_nav: Annotated[str, Form()] = "",
):
    """Update global branding display settings (logo mode, favicon, title)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    # Retrieve current group_avatar_style to preserve it
    try:
        current = branding_service.get_branding_settings(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    try:
        settings_data = BrandingSettingsUpdate(
            logo_mode=LogoMode(logo_mode),
            use_logo_as_favicon=use_logo_as_favicon == "true",
            site_title=site_title or None,
            show_title_in_nav=show_title_in_nav == "true",
            group_avatar_style=current.group_avatar_style,
        )
    except (ValueError, PydanticValidationError):
        return render_error_page(
            request,
            tenant_id,
            ValidationError(message="Invalid branding settings", code="validation_error"),
        )

    try:
        branding_service.update_branding_settings(requesting_user, settings_data)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/branding/global?success=settings_updated",
        status_code=303,
    )


@router.post("/branding/groups/upload/{group_id}")
async def upload_group_logo_form(
    request: Request,
    group_id: str,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    file: UploadFile,
):
    """Upload a custom logo for a specific group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        data = await file.read()
        branding_service.upload_group_logo(
            requesting_user,
            group_id=group_id,
            data=data,
            filename=file.filename,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/branding/groups?success=logo_uploaded",
        status_code=303,
    )


@router.post("/branding/groups/delete/{group_id}")
def delete_group_logo_form(
    request: Request,
    group_id: str,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Remove a custom logo from a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        branding_service.delete_group_logo(requesting_user, group_id=group_id)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/branding/groups?success=logo_deleted",
        status_code=303,
    )
