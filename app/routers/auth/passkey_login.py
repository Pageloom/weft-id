"""Passkey login endpoints.

These endpoints run BEFORE session regeneration and BEFORE the
``user_signed_in`` event. The success event (`passkey_auth_success`), the
`user_signed_in` event emitted via ``complete_authenticated_login``, and
`passkey_auth_failure` events are all logged from the service layer because
they are security-relevant state transitions tied into session establishment.
"""

from typing import Annotated

import services.webauthn as webauthn_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from routers.auth._helpers import _get_client_ip
from schemas.webauthn import BeginAuthenticationRequest, CompleteAuthenticationRequest
from services.exceptions import RateLimitError, ValidationError
from utils.ratelimit import MINUTE, ratelimit

router = APIRouter()


@router.post("/login/passkey/begin")
async def passkey_begin(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    payload: BeginAuthenticationRequest,
):
    """Start a passkey authentication ceremony.

    Returns a ``{"publicKey": ...}`` JSON envelope with the request options,
    or ``404 {"error": "not_eligible"}`` when the email is not associated
    with a passkey-eligible account. Anti-enumeration: the same 404 response
    is returned for nonexistent, IdP-linked, inactivated, and zero-passkey
    users.
    """
    email_normalized = payload.email.strip().lower()
    client_ip = _get_client_ip(request)

    # Share the login_block counter with the password flow so passkey +
    # password attempts are combined against the same per-IP + per-email
    # budget.
    try:
        ratelimit.prevent(
            "login_block:ip:{ip}:email:{email}",
            limit=20,
            timespan=MINUTE * 15,
            ip=client_ip,
            email=email_normalized,
        )
    except RateLimitError:
        return JSONResponse(
            status_code=429,
            content={"error": "too_many_requests"},
        )

    result = webauthn_service.begin_authentication(request, tenant_id, email_normalized)
    if result is None:
        return JSONResponse(status_code=404, content={"error": "not_eligible"})
    return {"publicKey": result.public_key}


@router.post("/login/passkey/complete")
async def passkey_complete(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    payload: CompleteAuthenticationRequest,
):
    """Finish a passkey authentication ceremony.

    On success: returns ``{"redirect_url": ...}`` (the JS follows it via
    ``window.location.assign``). On failure: returns 400 with
    ``{"error": <code>}`` where code is one of ``no_challenge``,
    ``expired_challenge``, ``corrupt_challenge``, ``unknown_credential``,
    ``bad_signature``, ``clone_suspected``.
    """
    client_ip = _get_client_ip(request)
    # Per-IP soft cap on complete calls prevents assertion spamming even if
    # the attacker never calls begin (which would otherwise be the throttle).
    try:
        ratelimit.prevent(
            "passkey_complete:ip:{ip}",
            limit=30,
            timespan=MINUTE * 5,
            ip=client_ip,
        )
    except RateLimitError:
        return JSONResponse(
            status_code=429,
            content={"error": "too_many_requests"},
        )

    try:
        redirect_url = webauthn_service.complete_authentication(request, tenant_id, payload)
    except ValidationError as exc:
        return JSONResponse(status_code=400, content={"error": exc.code})
    return {"redirect_url": redirect_url}
