"""SAML Single Logout (SLO) endpoint (WeftID as the service provider).

``/saml/slo`` receives two kinds of message from an upstream SAML IdP:

* A LogoutResponse, after WeftID started Single Logout (the session is
  already gone). The browser finishes where the logout was headed: an RP's
  return address stashed by ``routers.auth.logout.upstream_logout_response``,
  else the login page.
* A LogoutRequest, when the user signed out at the IdP (IdP-initiated). A
  validated request ends the WeftID session in this browser when it is the
  session the request names (same IdP, NameID and, when given, SessionIndex),
  then the browser returns to the IdP with the signed LogoutResponse. Only the
  front channel ends a session: a request sent server to server carries no
  session cookie, so it is answered and ends nothing.
"""

import logging
from typing import Annotated

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from routers.auth.logout import (
    frontchannel_logout_response,
    pending_logout_return_response,
    terminate_session,
)
from routers.saml._helpers import get_base_url
from services import saml as saml_service
from services.saml import IdpLogoutRequest

router = APIRouter()
logger = logging.getLogger(__name__)

_SLO_PATH = "/saml/slo"


def _request_data(request: Request, get_data: dict[str, str]) -> dict:
    """python3-saml request data for this endpoint (always https, like the SP URLs)."""
    data: dict = {
        "https": "on",
        "http_host": request.headers.get("x-forwarded-host", request.url.netloc),
        "script_name": _SLO_PATH,
        "get_data": get_data,
        "post_data": {},
    }
    if get_data:
        data["query_string"] = request.url.query
    return data


def _session_is_named(request: Request, logout: IdpLogoutRequest) -> bool:
    """Whether this browser's session is the upstream session the IdP ended."""
    session = request.session
    if not session.get("user_id"):
        return False
    if session.get("saml_idp_id") != logout.idp_id:
        return False
    if session.get("saml_name_id") != logout.name_id:
        return False
    if logout.session_indexes:
        return session.get("saml_session_index") in logout.session_indexes
    return True


def _handle_logout_request(
    request: Request,
    tenant_id: str,
    saml_request: str,
    relay_state: str | None,
    get_data: dict[str, str],
) -> Response:
    """Validate an IdP-initiated LogoutRequest, end the named session, answer."""
    logout = saml_service.process_idp_logout_request(
        tenant_id,
        saml_request,
        get_base_url(request),
        request_data=_request_data(request, get_data),
        relay_state=relay_state,
    )
    if logout is None:
        # Refused (logged). Nothing ended and nothing to answer.
        return RedirectResponse(url="/login", status_code=303)

    if _session_is_named(request, logout):
        terminated = terminate_session(
            request,
            tenant_id,
            metadata={"reason": "upstream_saml_slo", "saml_idp_id": logout.idp_id},
        )
        if terminated.frontchannel_logout_urls:
            return frontchannel_logout_response(
                request, terminated.frontchannel_logout_urls, logout.response_url
            )

    # redirect-ok: the IdP's registered SLO endpoint, carrying our LogoutResponse
    return RedirectResponse(url=logout.response_url, status_code=303)


def _finish_after_logout_response(request: Request) -> Response:
    """The IdP answered WeftID's LogoutRequest: finish the logout."""
    finish = pending_logout_return_response(request)
    if finish is not None:
        return finish
    return RedirectResponse(url="/login?slo=complete", status_code=303)


@router.get(_SLO_PATH)
def saml_slo_get(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """SLO over the HTTP-Redirect binding: a LogoutRequest or a LogoutResponse."""
    params = request.query_params
    saml_request = params.get("SAMLRequest")
    if saml_request:
        logger.info("IdP-initiated SLO received via GET")
        get_data = {
            key: value
            for key in ("SAMLRequest", "RelayState", "SigAlg", "Signature")
            if (value := params.get(key)) is not None
        }
        return _handle_logout_request(
            request, tenant_id, saml_request, params.get("RelayState"), get_data
        )

    if params.get("SAMLResponse"):
        logger.info("SLO callback received with LogoutResponse")
    else:
        logger.info("SLO callback received (no request or response)")
    return _finish_after_logout_response(request)


@router.post(_SLO_PATH)
def saml_slo_post(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    saml_request: Annotated[str | None, Form(alias="SAMLRequest", max_length=524288)] = None,
    saml_response: Annotated[str | None, Form(alias="SAMLResponse", max_length=524288)] = None,
    relay_state: Annotated[str | None, Form(alias="RelayState", max_length=2048)] = None,
):
    """SLO over the HTTP-POST binding: a LogoutRequest or a LogoutResponse."""
    if saml_request:
        logger.info("IdP-initiated SLO received via POST")
        return _handle_logout_request(request, tenant_id, saml_request, relay_state, {})

    if saml_response:
        logger.info("SLO callback received via POST with LogoutResponse")
    else:
        logger.warning("SLO POST received with no SAMLRequest or SAMLResponse")
    return _finish_after_logout_response(request)
