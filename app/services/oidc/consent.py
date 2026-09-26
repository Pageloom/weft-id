"""Remembered consent for OAuth2 / OIDC applications.

A consent grant records that a user allowed a client a set of scopes. The
authorization endpoint skips the consent page (and answers ``prompt=none``
with a code) when a grant covers every requested scope; allowing widens the
grant, denying never writes. Users see and revoke their own grants from User
Settings, admins see and revoke grants per client.

Two kinds of function live here:

- Flow helpers (``consent_covers``, ``record_consent``) take a ``tenant_id``
  and the already-authenticated user, like the rest of the OAuth2 flow
  services: the authorization endpoint has done its own authentication.
- Management functions take a ``RequestingUser`` and follow the standard
  service pattern (authorization, activity tracking, event logging).

Invalidation on client deactivation and user deactivation is done by the
owning services (``services.oauth2.deactivate_client`` and the user
lifecycle paths), which call the database layer directly next to their
token revocation; client deletion cascades at the database.
"""

import database
from schemas.oidc import ClientConsentGrantResponse, ConsentGrantResponse
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser

# ---------------------------------------------------------------------------
# Flow helpers (authorization endpoint)
# ---------------------------------------------------------------------------


def get_granted_scopes(tenant_id: str, client_uuid: str, user_id: str) -> set[str] | None:
    """Return the scopes the user has granted this client, or ``None`` when
    there is no grant at all (a bare grant returns an empty set)."""
    grant = database.oauth2.get_consent_grant(tenant_id, client_uuid, str(user_id))
    if grant is None:
        return None
    return set(grant["scopes"] or [])


def consent_covers(tenant_id: str, client_uuid: str, user_id: str, scopes: set[str]) -> bool:
    """True when an existing grant covers every requested scope.

    A request with no scope needs a bare grant: the user must have allowed
    the client at least once.
    """
    granted = get_granted_scopes(tenant_id, client_uuid, user_id)
    return granted is not None and scopes <= granted


def record_consent(tenant_id: str, client: dict, user_id: str, scopes: set[str]) -> dict:
    """Create or widen the user's grant for ``client`` after an Allow.

    Logs ``oauth2_consent_granted`` for a new grant and
    ``oauth2_consent_widened`` when new scopes were added to an existing one.
    A grant that already covers the scopes is returned untouched, with no
    write and no event.
    """
    user_id = str(user_id)
    client_uuid = str(client["id"])
    existing = database.oauth2.get_consent_grant(tenant_id, client_uuid, user_id)
    if existing is not None and scopes <= set(existing["scopes"] or []):
        return existing

    grant = database.oauth2.upsert_consent_grant(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        client_id=client_uuid,
        user_id=user_id,
        scopes=sorted(scopes),
    )
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="oauth2_consent_grant",
        artifact_id=str(grant["id"]),
        event_type="oauth2_consent_granted" if existing is None else "oauth2_consent_widened",
        metadata={
            "client_id": client["client_id"],
            "client_name": client.get("name"),
            "scopes": list(grant["scopes"] or []),
            "added_scopes": sorted(scopes - set((existing or {}).get("scopes") or [])),
        },
    )
    return grant


# ---------------------------------------------------------------------------
# Self-service (User Settings > Authorized Apps)
# ---------------------------------------------------------------------------


def _to_user_view(row: dict) -> ConsentGrantResponse:
    return ConsentGrantResponse(
        id=str(row["id"]),
        client_id=row["client_public_id"],
        client_name=row["client_name"],
        client_description=row.get("client_description"),
        client_is_active=bool(row.get("client_is_active", True)),
        scopes=list(row["scopes"] or []),
        granted_at=row["granted_at"],
        updated_at=row["updated_at"],
    )


def list_my_grants(requesting_user: RequestingUser) -> list[ConsentGrantResponse]:
    """List the applications the requesting user has allowed.

    Authorization: any authenticated user (own grants only).
    """
    tenant_id = requesting_user["tenant_id"]
    track_activity(tenant_id, requesting_user["id"])
    rows = database.oauth2.list_consent_grants_for_user(tenant_id, str(requesting_user["id"]))
    return [_to_user_view(row) for row in rows]


def revoke_my_grant(requesting_user: RequestingUser, grant_id: str) -> None:
    """Revoke one of the requesting user's own grants.

    Authorization: any authenticated user; a grant belonging to someone else
    is reported as not found.
    Logs: ``oauth2_consent_revoked`` with ``revoked_by = user``.
    """
    tenant_id = requesting_user["tenant_id"]
    grant = database.oauth2.get_consent_grant_by_id(tenant_id, grant_id)
    if grant is None or str(grant["user_id"]) != str(requesting_user["id"]):
        raise NotFoundError(message="Consent grant not found", code="consent_grant_not_found")

    _revoke(requesting_user, grant, revoked_by="user")


# ---------------------------------------------------------------------------
# Admin (per client)
# ---------------------------------------------------------------------------


def _get_normal_client(tenant_id: str, client_id: str) -> dict:
    client = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if client is None:
        raise NotFoundError(message="Application not found", code="oauth2_client_not_found")
    if client["client_type"] != "normal":
        raise ValidationError(
            message="Consent applies only to Apps (authorization-code clients)",
            code="consent_not_supported_for_client_type",
        )
    return client


def _to_client_view(row: dict) -> ClientConsentGrantResponse:
    name = " ".join(
        part for part in (row.get("user_first_name"), row.get("user_last_name")) if part
    )
    return ClientConsentGrantResponse(
        id=str(row["id"]),
        user_id=str(row["user_id"]),
        user_email=row.get("user_email"),
        user_name=name,
        scopes=list(row["scopes"] or []),
        granted_at=row["granted_at"],
        updated_at=row["updated_at"],
    )


def list_client_grants(
    requesting_user: RequestingUser, client_id: str
) -> list[ClientConsentGrantResponse]:
    """List every user's grant for a client.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    track_activity(tenant_id, requesting_user["id"])
    client = _get_normal_client(tenant_id, client_id)
    rows = database.oauth2.list_consent_grants_for_client(tenant_id, str(client["id"]))
    return [_to_client_view(row) for row in rows]


def revoke_client_grant(requesting_user: RequestingUser, client_id: str, grant_id: str) -> None:
    """Revoke one user's grant for a client, as an admin.

    Authorization: Requires admin role. A grant that does not belong to the
    named client is reported as not found.
    Logs: ``oauth2_consent_revoked`` with ``revoked_by = admin``.
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    client = _get_normal_client(tenant_id, client_id)
    grant = database.oauth2.get_consent_grant_by_id(tenant_id, grant_id)
    if grant is None or str(grant["client_id"]) != str(client["id"]):
        raise NotFoundError(message="Consent grant not found", code="consent_grant_not_found")

    _revoke(requesting_user, grant, revoked_by="admin")


def _revoke(requesting_user: RequestingUser, grant: dict, *, revoked_by: str) -> None:
    tenant_id = requesting_user["tenant_id"]
    rows = database.oauth2.delete_consent_grant(tenant_id, str(grant["id"]))
    if rows == 0:
        raise NotFoundError(message="Consent grant not found", code="consent_grant_not_found")

    client = database.oauth2.get_client_by_id(tenant_id, str(grant["client_id"]))
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oauth2_consent_grant",
        artifact_id=str(grant["id"]),
        event_type="oauth2_consent_revoked",
        metadata={
            "revoked_by": revoked_by,
            "user_id": str(grant["user_id"]),
            "client_id": client["client_id"] if client else None,
            "client_name": client.get("name") if client else None,
            "scopes": list(grant["scopes"] or []),
        },
    )
