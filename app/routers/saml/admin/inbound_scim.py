"""Admin UI route for the inbound SCIM tab on a SAML identity provider.

Iteration 1 ships only the credential-management UI: a list of issued
tokens, a "create token" action (plaintext shown once in a modal), and a
revoke action. The actual SCIM endpoints under `/scim/v2/inbound/...`
arrive in iteration 2; until then, this tab still surfaces a base-URL
info block so admins can pre-stage the receiver configuration in Okta
or Entra.
"""

import logging
from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_super_admin,
)
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import has_page_access
from services import saml as saml_service
from services.exceptions import NotFoundError, ServiceError
from services.scim import inbound_credentials as inbound_creds_service
from utils.template_context import get_template_context
from utils.templates import templates
from utils.urls import tenant_base_url

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["saml-idp", "inbound-scim"],
    dependencies=[Depends(require_super_admin)],
    include_in_schema=False,
)

IDP_LIST_URL = "/admin/settings/identity-providers"


def _base_url(request: Request) -> str:
    """Construct the canonical https base URL from the request.

    Delegates to the single trusted host-derivation helper so the SCIM
    base URL surfaced to admins matches the `meta.location` URLs the
    inbound SCIM endpoints emit.
    """
    return tenant_base_url(request)


@router.get(
    "/admin/settings/identity-providers/{idp_id}/scim",
    response_class=HTMLResponse,
)
def idp_tab_scim_inbound(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Inbound SCIM provisioning tab: credentials list, create / revoke.

    Renders the per-IdP "SCIM Provisioning" tab. State-changing flows
    (`POST` / `DELETE`) go through `WeftUtils.apiFetch` against the
    `/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials`
    endpoints, so this route only paints the initial state.
    """
    if not has_page_access("/admin/settings/identity-providers/idp/scim", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        idp = saml_service.get_identity_provider(requesting_user, idp_id)
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to load IdP for inbound SCIM tab: %s", exc)
        return RedirectResponse(url=f"{IDP_LIST_URL}?error={exc.message}", status_code=303)

    try:
        tokens = inbound_creds_service.list_tokens(requesting_user, idp_id)
    except ServiceError as exc:
        logger.warning("Failed to load inbound SCIM tokens: %s", exc)
        return RedirectResponse(url=f"{IDP_LIST_URL}/{idp_id}/details", status_code=303)

    # The SCIM base URL displayed for copy/paste into Okta/Entra. The
    # actual endpoints stand up in iteration 2; the path is fixed now so
    # operators can pre-stage the receiver config and have it work the
    # moment iteration 2 deploys.
    scim_base_url = f"{_base_url(request)}/scim/v2/inbound/{idp_id}/"

    context = get_template_context(
        request,
        tenant_id,
        idp=idp,
        tokens=tokens,
        scim_base_url=scim_base_url,
        active_tab="scim",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "saml_idp_tab_scim_inbound.html", context)
