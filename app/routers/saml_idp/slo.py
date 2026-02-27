"""SAML IdP Single Logout (SLO) endpoints.

Handles SP-initiated SLO: downstream SPs send a LogoutRequest,
we clear the user's session and return a signed LogoutResponse.
"""

import logging
from typing import Annotated

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from utils.csp_nonce import get_csp_nonce
from utils.templates import templates

from ._helpers import get_base_url

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/saml/idp",
    tags=["saml-idp-slo"],
    include_in_schema=False,
)


@router.get("/slo")
def slo_redirect(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    SAMLRequest: str = Query(default=None),  # noqa: N803
    RelayState: str = Query(default=None),  # noqa: N803
):
    """HTTP-Redirect binding: SP sends LogoutRequest via query params."""
    if not SAMLRequest:
        logger.warning("SLO GET received without SAMLRequest")
        return RedirectResponse(url="/login", status_code=303)

    return _handle_slo_request(request, tenant_id, SAMLRequest, RelayState, binding="redirect")


@router.post("/slo")
async def slo_post(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """HTTP-POST binding: SP sends LogoutRequest via form POST."""
    form = await request.form()
    saml_request = form.get("SAMLRequest")
    relay_state = form.get("RelayState")

    if not saml_request:
        logger.warning("SLO POST received without SAMLRequest")
        return RedirectResponse(url="/login", status_code=303)

    return _handle_slo_request(
        request,
        tenant_id,
        str(saml_request),
        str(relay_state) if relay_state else None,
        binding="post",
    )


def _handle_slo_request(
    request: Request,
    tenant_id: str,
    saml_request: str,
    relay_state: str | None,
    binding: str,
) -> HTMLResponse | RedirectResponse:
    """Common handler for both GET and POST SLO bindings."""
    from services.service_providers.slo import process_sp_logout_request
    from utils.saml_slo import parse_sp_logout_request

    # 1. Parse the LogoutRequest
    try:
        parsed = parse_sp_logout_request(saml_request, binding)
    except ValueError as e:
        logger.warning("Invalid LogoutRequest: %s", e)
        return RedirectResponse(url="/login", status_code=303)

    # 2. Validate issuer is a registered SP and build LogoutResponse
    base_url = get_base_url(request)

    try:
        logout_response_b64, slo_url = process_sp_logout_request(
            tenant_id=tenant_id,
            parsed_request=parsed,
            base_url=base_url,
        )
    except Exception as e:
        logger.warning("Failed to process SLO request: %s", e)
        return RedirectResponse(url="/login", status_code=303)

    # 3. Clear session only after validating the request came from a registered SP
    request.session.clear()

    # 4. Render auto-submit form to POST LogoutResponse back to SP
    csp_nonce = get_csp_nonce(request)
    request.state.csp_form_action_url = slo_url

    return templates.TemplateResponse(
        request,
        "saml_idp_slo_post.html",
        {
            "slo_url": slo_url,
            "saml_response": logout_response_b64,
            "relay_state": relay_state,
            "csp_nonce": csp_nonce,
        },
    )
