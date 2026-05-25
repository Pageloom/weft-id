"""REST API endpoints for SAML Identity Provider sub-resources.

Currently scoped to inbound SCIM credential lifecycle (iteration 1 of
the inbound SCIM feature). Future iterations will add the SCIM-2.0
resource endpoints under `/scim/v2/inbound/{idp_id}/...`, but those are
a separate URL family (SCIM clients don't speak `/api/v1/`); they ship
in iteration 2 in a dedicated router.

Endpoints here are admin-facing JSON APIs that the per-IdP "SCIM
Provisioning" tab consumes via `WeftUtils.apiFetch`.
"""

from typing import Annotated

from api_dependencies import require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, status
from schemas.scim_inbound import (
    ScimInboundTokenCreate,
    ScimInboundTokenCreated,
    ScimInboundTokenList,
)
from services.exceptions import RateLimitError, ServiceError
from services.scim import inbound_credentials as inbound_creds_service
from utils.ratelimit import MINUTE, ratelimit
from utils.service_errors import translate_to_http_exception

router = APIRouter(
    prefix="/api/v1/saml-identity-providers", tags=["SAML Identity Providers", "Inbound SCIM"]
)


# =============================================================================
# Inbound SCIM credential lifecycle
# =============================================================================


@router.get(
    "/{idp_id}/inbound-scim/credentials",
    response_model=ScimInboundTokenList,
)
def list_inbound_scim_credentials_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """List inbound SCIM bearer tokens for one identity provider.

    Requires super_admin role.

    Returns both active and revoked tokens, newest first, so the admin
    UI can show revocation history. Token plaintext is NEVER returned --
    only metadata.

    Response fields per item: id, idp_id, name, created_by_user_id,
    created_at, revoked_at, last_used_at.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return inbound_creds_service.list_tokens(requesting_user, idp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/{idp_id}/inbound-scim/credentials",
    response_model=ScimInboundTokenCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_inbound_scim_credential_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    data: ScimInboundTokenCreate,
):
    """Mint a new inbound SCIM bearer token for an identity provider.

    Requires super_admin role.

    Request body:
    - name: Optional human-readable label for the token (e.g. "Okta
      production"). Max 255 chars. Helps operators identify which
      receiver a token is paired with when rotating.

    The server generates a 256-bit URL-safe token prefixed
    `wid_inbound_`, hashes it with SHA-256, and returns the plaintext
    ONCE in the response. The plaintext is **never** persisted -- only
    the hash is stored. There is no rotation / recovery path; if the
    plaintext is lost, create a new token and revoke the old one.

    Emits a `scim_inbound_token_created` audit event with the new token
    id and name in metadata.

    Response fields: id, idp_id, name, created_at, plaintext.

    Rate limit: 10 mints per minute per super-admin user. Defence in
    depth against a runaway script.
    """
    try:
        ratelimit.prevent(
            "scim_inbound_credential_create:user:{user_id}",
            limit=10,
            timespan=MINUTE,
            user_id=str(admin["id"]),
        )
    except RateLimitError as exc:
        raise translate_to_http_exception(exc)

    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return inbound_creds_service.create_token(requesting_user, idp_id, name=data.name)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete(
    "/{idp_id}/inbound-scim/credentials/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_inbound_scim_credential_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    token_id: str,
):
    """Immediately revoke an inbound SCIM bearer token.

    Requires super_admin role.

    There is no overlap window. The next inbound request authenticating
    with this token returns 401. Pair this with `POST` to migrate a
    receiver to a fresh token: create the new token, paste it into Okta
    or Entra, confirm sync, then revoke the old one.

    Emits a `scim_inbound_token_revoked` audit event.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        inbound_creds_service.revoke_token(requesting_user, idp_id, token_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
