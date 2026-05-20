"""Admin UI routes for the outbound SCIM tab on a Service Provider.

This module covers the per-SP SCIM tab introduced in iteration 5: a
configuration form, a credential listing with create / rotate / revoke
actions (state-changing flows go through `WeftUtils.apiFetch` against
the JSON API, so this router only renders the page), and a sync
activity panel that defers to the JSON API for pagination and refresh.
"""

import logging
from typing import Annotated

from dependencies import (
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import has_page_access
from services import service_providers as sp_service
from services.exceptions import ServiceError
from services.scim import admin as scim_admin_service
from services.types import RequestingUser
from utils.template_context import get_template_context
from utils.templates import templates

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/settings/service-providers",
    tags=["saml-idp", "scim"],
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)

SP_LIST_URL = "/admin/settings/service-providers"


def _build_requesting_user(user: dict, tenant_id: str) -> RequestingUser:
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=user.get("role", "user"),
    )


@router.get("/{sp_id}/scim", response_class=HTMLResponse)
def sp_tab_scim(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """SCIM tab: outbound provisioning configuration and activity."""
    if not has_page_access("/admin/settings/service-providers/detail/scim", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)
    try:
        sp_config = sp_service.get_service_provider(requesting_user, sp_id)
        group_count = sp_service.count_sp_group_assignments(requesting_user, sp_id)
    except ServiceError as exc:
        logger.warning("Failed to load SP for SCIM tab: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}?error={exc.message}", status_code=303)

    try:
        scim_config = scim_admin_service.get_scim_config(requesting_user, sp_id)
        credentials = scim_admin_service.list_credentials(requesting_user, sp_id)
        queue_status = scim_admin_service.get_queue_status(requesting_user, sp_id)
        sync_log = scim_admin_service.list_sync_log(requesting_user, sp_id, page=1, page_size=50)
    except ServiceError as exc:
        logger.warning("Failed to load SCIM data: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}/{sp_id}/details", status_code=303)

    context = get_template_context(
        request,
        tenant_id,
        sp=sp_config,
        group_count=group_count,
        scim_config=scim_config,
        credentials=credentials,
        queue_status=queue_status,
        sync_log=sync_log,
        active_tab="scim",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "saml_idp_sp_tab_scim.html", context)
