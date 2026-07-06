"""OIDC-client access-control enforcement.

WeftID gates login to an OIDC-enabled OAuth2 client on the same group-based
grant model used by SAML service providers and forward-auth proxy apps: a user
may complete the OIDC authorize flow for a client only when the client is
``available_to_all`` or the user belongs to a group (directly or via the DAG)
that is assigned to the client. Enforcement runs at the authorize step, BEFORE
any authorization code is issued, so a denied user never receives a code, token,
or ID token.

Scope of enforcement: this applies ONLY to ``oidc_enabled`` clients. Plain
OAuth2 clients are never routed through this check and keep their existing
behavior (no grant requirement, no denial).

The decision reuses the single shared DAG-aware grant resolver
(:func:`database.sp_group_assignments.user_can_access_oauth2_client`); no
parallel resolver is introduced. Every denial is audited via
``oidc_access_denied`` (a security-relevant event), mirroring the
``proxy_access_denied`` audit in the forward-auth service.
"""

from __future__ import annotations

import database
from services.event_log import log_event


def user_can_access_client(
    *,
    tenant_id: str,
    user_id: str,
    client_uuid: str,
    client_id: str,
    client_name: str | None = None,
) -> bool:
    """Decide whether *user_id* may complete the OIDC authorize flow for a client.

    Authorization: this IS the authorization decision -- it resolves the user's
    group grant against the client. Intended to run inside the authorize request
    (which has request context for the audit log).

    Logs: ``oidc_access_denied`` on denial only (every deny is audited); an allow
    is not logged here (the subsequent ``oidc_id_token_issued`` records the
    successful hand-off).

    Args:
        tenant_id: Tenant ID for RLS scoping.
        user_id: The authenticating user's stable WeftID id.
        client_uuid: The client's internal UUID (grant target + audit artifact).
        client_id: The client's public client_id (recorded in audit metadata).
        client_name: The client's display name (recorded in audit metadata).

    Returns:
        True if the user may proceed, False otherwise.
    """
    allowed = database.sp_group_assignments.user_can_access_oauth2_client(
        tenant_id, user_id, client_uuid
    )
    if not allowed:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            event_type="oidc_access_denied",
            artifact_type="oauth2_client",
            artifact_id=client_uuid,
            metadata={"client_id": client_id, "client_name": client_name},
            dispatch_scim=False,
        )
    return allowed
