"""Inbound SCIM credential service layer.

Manages the lifecycle of bearer tokens pasted into an upstream IdP
(Okta, Entra) so that IdP can authenticate to WeftID's inbound SCIM
endpoint family (iteration 2+).

Token storage is **hash-only**: a 32-byte URL-safe secret prefixed
`wid_inbound_` is generated, returned to the caller exactly once, and
stored as a SHA-256 hex digest. Plaintext is never recoverable. This
differs from the outbound credential service (which keeps an encrypted
plaintext because the outbound worker must replay the value to the
downstream SP).

Authorization: super-admin only. Every write emits an audit event.
"""

from __future__ import annotations

import hashlib
import secrets

import database
from schemas.scim_inbound import (
    ScimInboundToken,
    ScimInboundTokenCreated,
    ScimInboundTokenList,
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError
from services.types import RequestingUser

# Token plaintext layout: `wid_inbound_` + 32 bytes of URL-safe entropy
# (~43 chars after base64). The prefix gives operators a quick visual
# distinction from outbound tokens and from random credentials they may
# have elsewhere; the 32-byte body provides ~256 bits of entropy.
_TOKEN_PREFIX = "wid_inbound_"
_TOKEN_ENTROPY_BYTES = 32


def _generate_token() -> tuple[str, str]:
    """Mint a new bearer token. Returns (plaintext, sha256_hex_digest)."""
    plaintext = f"{_TOKEN_PREFIX}{secrets.token_urlsafe(_TOKEN_ENTROPY_BYTES)}"
    digest = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    return plaintext, digest


def _row_to_token(row: dict) -> ScimInboundToken:
    return ScimInboundToken(
        id=str(row["id"]),
        idp_id=str(row["idp_id"]),
        name=row.get("name"),
        created_by_user_id=str(row["created_by_user_id"]),
        created_at=row["created_at"],
        revoked_at=row.get("revoked_at"),
        last_used_at=row.get("last_used_at"),
    )


def _require_idp(tenant_id: str, idp_id: str) -> dict:
    """Look up the IdP row, raise NotFoundError if missing.

    The service-layer functions all key off `idp_id` and need to confirm
    it belongs to the tenant before creating or listing tokens. RLS
    isolates the lookup so a cross-tenant id returns None.
    """
    row = database.saml.get_identity_provider(tenant_id, idp_id)
    if row is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )
    return row


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def create_token(
    requesting_user: RequestingUser,
    idp_id: str,
    name: str | None = None,
) -> ScimInboundTokenCreated:
    """Mint a new inbound SCIM bearer token for an IdP connection.

    Returns the plaintext in the response. The plaintext is never
    persisted in cleartext: only its SHA-256 hex digest is stored. The
    caller MUST surface the plaintext to the operator immediately --
    there is no rotation / recovery path.

    Authorization: Requires super-admin role.
    Logs: `scim_inbound_token_created`.
    """
    require_super_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    _require_idp(tenant_id, idp_id)

    plaintext, digest = _generate_token()
    cleaned_name = (name or "").strip() or None

    row = database.scim_inbound_tokens.create_token(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        idp_id=idp_id,
        token_hash=digest,
        name=cleaned_name,
        created_by_user_id=requesting_user["id"],
    )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type="scim_inbound_token_created",
        metadata={
            "token_id": str(row["id"]),
            "name": cleaned_name,
        },
    )

    return ScimInboundTokenCreated(
        id=str(row["id"]),
        idp_id=idp_id,
        name=cleaned_name,
        created_at=row["created_at"],
        plaintext=plaintext,
    )


def list_tokens(
    requesting_user: RequestingUser,
    idp_id: str,
) -> ScimInboundTokenList:
    """List inbound SCIM tokens for one IdP (active and revoked), newest first.

    Plaintext / hash are never returned -- only metadata.

    Authorization: Requires super-admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    _require_idp(tenant_id, idp_id)

    rows = database.scim_inbound_tokens.list_tokens(tenant_id, idp_id)
    items = [_row_to_token(row) for row in rows]
    return ScimInboundTokenList(items=items, total=len(items))


def revoke_token(
    requesting_user: RequestingUser,
    idp_id: str,
    token_id: str,
) -> None:
    """Immediately revoke an inbound SCIM bearer token.

    There is no overlap window (unlike outbound). The next inbound
    request authenticating with this token returns 401.

    Authorization: Requires super-admin role.
    Logs: `scim_inbound_token_revoked`.
    """
    require_super_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    _require_idp(tenant_id, idp_id)

    # Validate the token belongs to this IdP (defence in depth -- RLS
    # would already block a cross-tenant id, but a cross-IdP id within
    # the same tenant must also be rejected so admins can't accidentally
    # revoke a token from a different connection by typo).
    row = database.scim_inbound_tokens.get_token(tenant_id, token_id)
    if row is None or str(row["idp_id"]) != str(idp_id):
        raise NotFoundError(
            message="Inbound SCIM token not found",
            code="scim_inbound_token_not_found",
        )

    rows = database.scim_inbound_tokens.revoke(tenant_id, token_id)
    if rows == 0:
        # Already revoked: treat as not-found to keep the contract simple.
        raise NotFoundError(
            message="Inbound SCIM token not found or already revoked",
            code="scim_inbound_token_not_found",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type="scim_inbound_token_revoked",
        metadata={"token_id": token_id},
    )
