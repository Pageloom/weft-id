"""SAML IdP selection endpoint."""

from typing import Annotated
from urllib.parse import quote

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from services import saml as saml_service
from utils.csp_nonce import get_csp_nonce
from utils.templates import templates

router = APIRouter()


@router.get("/saml/select")
def saml_select_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """
    Display IdP selection page when multiple IdPs are available.
    """
    # Get enabled IdPs
    idps = saml_service.get_enabled_idps_for_login(tenant_id)

    if not idps:
        return RedirectResponse(url="/login?error=no_sso", status_code=303)

    # If only one IdP, redirect directly
    if len(idps) == 1:
        relay_state = request.query_params.get("relay_state", "/dashboard")
        return RedirectResponse(
            url=f"/saml/login/{idps[0].id}?relay_state={quote(relay_state, safe='')}",
            status_code=303,
        )

    relay_state = request.query_params.get("relay_state", "")

    return templates.TemplateResponse(
        request,
        "saml_idp_select.html",
        {
            "idps": idps,
            "relay_state": relay_state,
            "csp_nonce": get_csp_nonce(request),
        },
    )
