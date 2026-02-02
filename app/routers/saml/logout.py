"""SAML Single Logout (SLO) endpoints."""

import logging
from typing import Annotated

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from routers.saml._helpers import get_base_url
from services import saml as saml_service

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/saml/slo")
def saml_slo_get(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """
    Handle SLO via HTTP-Redirect binding (GET).

    This can be either:
    1. SP-initiated: LogoutResponse from IdP after we initiated logout
    2. IdP-initiated: LogoutRequest from IdP via redirect binding

    We check for SAMLRequest (IdP-initiated) or SAMLResponse (SP callback).
    """
    saml_request = request.query_params.get("SAMLRequest")
    saml_response = request.query_params.get("SAMLResponse")

    if saml_request:
        # IdP-initiated logout via GET (HTTP-Redirect binding)
        logger.info("IdP-initiated SLO received via GET")
        base_url = get_base_url(request)

        redirect_url = saml_service.process_idp_logout_request(
            tenant_id=tenant_id,
            saml_request=saml_request,
            base_url=base_url,
        )

        if redirect_url:
            return RedirectResponse(url=redirect_url, status_code=303)

        # If processing failed, just redirect to login
        return RedirectResponse(url="/login?slo=complete", status_code=303)

    elif saml_response:
        # SP-initiated callback (LogoutResponse from IdP)
        logger.info("SLO callback received with LogoutResponse")

    else:
        logger.info("SLO callback received (no request or response)")

    # Always redirect to login - session is already cleared
    return RedirectResponse(url="/login?slo=complete", status_code=303)


@router.post("/saml/slo")
def saml_slo_post(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    saml_request: Annotated[str | None, Form(alias="SAMLRequest")] = None,
    saml_response: Annotated[str | None, Form(alias="SAMLResponse")] = None,
):
    """
    Handle SLO via HTTP-POST binding.

    This is typically IdP-initiated logout where the IdP sends
    a LogoutRequest via POST.
    """
    if saml_request:
        # IdP-initiated logout via POST
        logger.info("IdP-initiated SLO received via POST")
        base_url = get_base_url(request)

        redirect_url = saml_service.process_idp_logout_request(
            tenant_id=tenant_id,
            saml_request=saml_request,
            base_url=base_url,
        )

        if redirect_url:
            return RedirectResponse(url=redirect_url, status_code=303)

    elif saml_response:
        # SP-initiated callback via POST (less common)
        logger.info("SLO callback received via POST with LogoutResponse")

    else:
        logger.warning("SLO POST received with no SAMLRequest or SAMLResponse")

    # Always redirect to login
    return RedirectResponse(url="/login?slo=complete", status_code=303)
