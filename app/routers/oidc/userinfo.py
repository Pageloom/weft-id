"""OIDC userinfo endpoint.

Root-path, tenant-scoped, Bearer-authenticated: a relying party presents the
OAuth2 access token it obtained at the token endpoint and receives the identity
claims consistent with the ID token, gated by the token's granted scope. The
claims come from the same shared assembler the ID token uses, so the two can
never drift. Invalid/expired/revoked/missing tokens are rejected with the
correct OAuth2 protected-resource error by the bearer dependency.
"""

import logging
from typing import Annotated

from api_dependencies import get_oidc_userinfo_token
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from services import oidc as oidc_service
from utils.urls import tenant_base_url

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["oidc"],
    include_in_schema=False,
)


@router.get("/userinfo", response_model=None)
@router.post("/userinfo", response_model=None)
def userinfo(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    token_data: Annotated[dict, Depends(get_oidc_userinfo_token)],
) -> Response | dict:
    """Return the scope-gated userinfo claims for the presented access token.

    Accepts GET and POST (OpenID Connect Core 1.0, section 5.3.1). The access
    token is presented in the ``Authorization: Bearer`` header, or for POST
    alternatively as the ``access_token`` form field (RFC 6750 section 2.2);
    not both.

    The response always includes `sub` (the stable WeftID user id) and,
    depending on the token's granted scope, the same profile/email claims the
    ID token would carry. Emits ``oidc_userinfo_accessed``.

    A client registered with ``userinfo_signed_response_alg`` (RS256) gets
    the claims as a signed JWT (``application/jwt``, with ``iss`` and ``aud``).
    """
    client = token_data.get("client") or {}
    claims = oidc_service.get_userinfo(
        tenant_id=tenant_id,
        user_id=str(token_data["user_id"]),
        client_uuid=str(token_data["client_id"]),
        client_id=str(client.get("client_id", "")),
        scope=token_data.get("scope"),
    )
    signed = oidc_service.sign_userinfo(
        tenant_id=tenant_id, issuer=tenant_base_url(request), client=client, userinfo=claims
    )
    if signed is not None:
        return Response(content=signed, media_type="application/jwt")
    return claims
