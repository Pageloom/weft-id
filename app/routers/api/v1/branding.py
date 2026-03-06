"""Branding API endpoints."""

from typing import Annotated

from api_dependencies import require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, UploadFile
from schemas.branding import (
    BrandingSettings,
    BrandingSettingsUpdate,
    LogoSlot,
    MandalaRandomizeResponse,
    MandalaSaveRequest,
)
from services import branding as branding_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/branding", tags=["Branding"])


@router.get("", response_model=BrandingSettings)
def get_branding(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
):
    """Get current branding settings.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)

    try:
        return branding_service.get_branding_settings(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/logo/{slot}", response_model=BrandingSettings, status_code=201)
async def upload_logo(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    slot: LogoSlot,
    file: UploadFile,
):
    """Upload a logo image for the specified slot.

    Requires admin role.
    Accepts PNG (square, min 48x48) or SVG (square viewBox) up to 256KB.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)

    try:
        data = await file.read()
        return branding_service.upload_logo(
            requesting_user,
            slot=slot,
            data=data,
            filename=file.filename,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/logo/{slot}", status_code=204)
def delete_logo(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    slot: LogoSlot,
):
    """Delete a logo image for the specified slot.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)

    try:
        branding_service.delete_logo(requesting_user, slot=slot)
        return None
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.put("", response_model=BrandingSettings)
def update_branding(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    settings: BrandingSettingsUpdate,
):
    """Update branding display settings.

    Requires admin role.
    Switching to custom mode requires a light logo to be uploaded first.

    Request body:
    - logo_mode: Logo display mode (required)
    - use_logo_as_favicon: Use custom logo as favicon (default false)
    - site_title: Custom site title, max 30 chars (optional, null to clear)
    - show_title_in_nav: Show title in navigation bar (default true)
    - group_avatar_style: Default avatar style for group icons (default acronym)
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)

    try:
        return branding_service.update_branding_settings(requesting_user, settings)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/mandala/randomize", response_model=MandalaRandomizeResponse)
def randomize_mandala(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
):
    """Generate a random mandala for preview.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)

    try:
        return branding_service.randomize_mandala(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/mandala/save", response_model=BrandingSettings)
def save_mandala(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: MandalaSaveRequest,
):
    """Save a mandala as the tenant's custom logo.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)

    try:
        return branding_service.save_mandala_as_logo(requesting_user, body.seed)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
