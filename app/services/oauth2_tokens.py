"""OAuth2 token introspection (RFC 7662) and revocation (RFC 7009).

Both endpoints are called by an authenticated client, never by a user, so the
protocol functions take the authenticated client record instead of a
``RequestingUser``. Client authentication happens in the router, exactly as at
the token endpoint.

Who sees what:

- Introspection: a client always sees the tokens issued to it. A client with
  ``can_introspect_tenant_tokens`` (set by an admin) sees every token in the
  tenant, which is what makes it a resource server. Anything else is
  ``{"active": false}``, indistinguishable from an unknown token.
- Revocation: a client revokes only its own tokens. A token issued to another
  client is left alone and the call still succeeds (RFC 7009 section 2.2), so
  the response never reveals whether a token exists.

Introspection is a high-frequency machine read: it writes no audit event and
logs one INFO line per call instead (client, outcome, token type; never the
token). Revocation is a write and is audited.
"""

import logging

import database
from services.auth import require_admin, require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.oidc.subject import subject_for
from services.types import RequestingUser

logger = logging.getLogger(__name__)

INACTIVE: dict = {"active": False}


def _can_see(client: dict, token: dict, *, allow_tenant: bool) -> bool:
    if str(token["client_id"]) == str(client["id"]):
        return True
    return allow_tenant and bool(client.get("can_introspect_tenant_tokens"))


def introspect_token(tenant_id: str, client: dict, token: str, issuer: str) -> dict:
    """Describe a token for an authenticated client (RFC 7662 section 2.2).

    Args:
        tenant_id: Tenant ID
        client: The authenticated, active client making the call
        token: The token to describe (access or refresh)
        issuer: The tenant issuer, returned as ``iss``

    Returns:
        ``{"active": false}`` for a token that is unknown, expired, revoked, or
        not visible to the caller; otherwise ``active`` with ``scope``,
        ``client_id``, ``sub``, ``exp``, ``iat``, ``iss`` and, for an access
        token, ``token_type`` (``Bearer``). Absent values are omitted.
    """
    found = database.oauth2.find_token(tenant_id, token)
    if found is None or not _can_see(client, found, allow_tenant=True):
        logger.info(
            "OAuth2 introspection: client=%s active=false",
            client["client_id"],
        )
        return dict(INACTIVE)

    logger.info(
        "OAuth2 introspection: client=%s active=true token_type=%s token_client=%s",
        client["client_id"],
        found["token_type"],
        found["client_public_id"],
    )

    response: dict = {"active": True}
    if found.get("scope"):
        response["scope"] = found["scope"]
    response["client_id"] = found["client_public_id"]
    # The token's client's identifier for the user (pairwise for a pairwise app).
    response["sub"] = subject_for(found, str(found["user_id"]))
    if found["token_type"] == "access":
        response["token_type"] = "Bearer"
    response["exp"] = int(found["expires_at"].timestamp())
    response["iat"] = int(found["created_at"].timestamp())
    response["iss"] = issuer
    return response


def revoke_token(tenant_id: str, client: dict, token: str) -> bool:
    """Revoke one of the calling client's tokens (RFC 7009 section 2.1).

    Revoking a refresh token also revokes the access tokens minted from it.
    Revoking an access token leaves its refresh token alone.

    Logs: oauth2_token_revoked (only when a token was actually revoked).

    Args:
        tenant_id: Tenant ID
        client: The authenticated, active client making the call
        token: The token to revoke (access or refresh)

    Returns:
        True when a token was revoked. False for an unknown, expired, or
        already revoked token, or one issued to another client. The endpoint
        answers 200 either way.
    """
    found = database.oauth2.find_token(tenant_id, token)
    if found is None or not _can_see(client, found, allow_tenant=False):
        return False

    if database.oauth2.delete_token(tenant_id, str(found["id"])) == 0:
        return False

    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(found["user_id"]),
        artifact_type="oauth2_client",
        artifact_id=str(client["id"]),
        event_type="oauth2_token_revoked",
        metadata={
            "client_id": client["client_id"],
            "client_name": client.get("name"),
            "token_type": found["token_type"],
        },
    )
    return True


def set_tenant_introspection(
    requesting_user: RequestingUser, client_id: str, enabled: bool
) -> dict:
    """Allow or stop a client introspecting every token in the tenant.

    Authorization: Requires admin role; super_admin for a B2B client (B2B
    client management is super_admin only).
    Logs: oauth2_client_introspection_changed when the value changes.

    Args:
        requesting_user: The acting admin
        client_id: The string client_id (e.g. "weft-id_client_abc123")
        enabled: The new value

    Returns:
        The updated client dict

    Raises:
        NotFoundError: No such client
        ForbiddenError: Insufficient role
        ValidationError: Switching it on for a public client
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]

    old = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if old is None:
        raise NotFoundError(message="Client not found", code="oauth2_client_not_found")
    if old["client_type"] == "b2b":
        require_super_admin(requesting_user)
    if enabled and old.get("is_public"):
        # A public client cannot authenticate at the introspection endpoint.
        raise ValidationError(
            message="A public client cannot introspect tokens",
            code="public_client_no_introspection",
        )

    updated = database.oauth2.set_client_tenant_introspection(tenant_id, client_id, enabled)
    if updated is None:
        raise NotFoundError(message="Client not found", code="oauth2_client_not_found")

    if enabled != bool(old.get("can_introspect_tenant_tokens")):
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="oauth2_client",
            artifact_id=str(updated["id"]),
            event_type="oauth2_client_introspection_changed",
            metadata={
                "name": updated["name"],
                "client_id": client_id,
                "can_introspect_tenant_tokens": enabled,
            },
        )

    return updated
