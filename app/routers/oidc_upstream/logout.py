"""OIDC upstream back-channel logout receiver.

``POST /auth/oidc/{connection_id}/backchannel-logout`` is the URL an admin
registers at the upstream IdP as the back-channel logout URI (Back-Channel
Logout 1.0, section 2.5). The IdP POSTs a form-encoded ``logout_token``; the
service validates it and ends the WeftID sessions it names.

Responses (section 2.8): 200 on success (including when no session matched),
400 ``invalid_request`` for any rejected token, with ``Cache-Control:
no-store``. The rejection detail goes to the audit log, never to the caller.
The endpoint is server-to-server: no session, CSRF-exempt, rate-limited per
tenant and source address.
"""

import logging
import uuid
from typing import Annotated

import services.oidc_upstream as oidc_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, Response
from services.exceptions import RateLimitError
from utils.ratelimit import MINUTE, ratelimit
from utils.request_metadata import extract_remote_address
from utils.urls import tenant_base_url

router = APIRouter()
logger = logging.getLogger(__name__)

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _invalid_request(description: str = "The logout token was rejected") -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"error": "invalid_request", "error_description": description},
        headers=_NO_STORE,
    )


@router.post("/auth/oidc/{connection_id}/backchannel-logout")
def backchannel_logout(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    connection_id: str,
    logout_token: Annotated[str | None, Form(max_length=16384)] = None,
):
    """Receive a logout token from an upstream OIDC IdP.

    Form fields:
        logout_token: The signed logout token (JWT), required.
    """
    client_ip = extract_remote_address(request) or "unknown"
    try:
        ratelimit.prevent(
            "oidc_backchannel_logout:tenant:{tenant_id}:ip:{ip}",
            limit=60,
            timespan=MINUTE * 5,
            tenant_id=tenant_id,
            ip=client_ip,
        )
    except RateLimitError:
        return JSONResponse(
            status_code=429,
            content={"error": "slow_down", "error_description": "Too many requests"},
            headers=_NO_STORE,
        )

    try:
        uuid.UUID(connection_id)
    except ValueError:
        return _invalid_request("Unknown connection")
    if not logout_token:
        return _invalid_request("logout_token is required")

    try:
        result = oidc_service.handle_backchannel_logout(
            tenant_id=tenant_id,
            connection_id=connection_id,
            logout_token=logout_token,
            issuer=tenant_base_url(request),
        )
    except oidc_service.LogoutTokenError as exc:
        logger.info("Upstream logout token rejected (%s): %s", exc.reason, exc)
        return _invalid_request()

    logger.info(
        "Upstream back-channel logout for connection %s ended %d session(s) by %s",
        connection_id,
        result.sessions_ended,
        result.matched_by,
    )
    return Response(status_code=200, headers=_NO_STORE)
