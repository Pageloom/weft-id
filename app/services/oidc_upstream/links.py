"""Per-user OIDC disconnect (unlink) operations.

The OIDC upstream connector correlates users on the ``(idp_id, sub)`` link
table, not on a per-user assignment column like SAML's ``users.saml_idp_id``.
The link row *is* the assignment. This module exposes the per-user disconnect
path that Iteration 6 deferred: remove a user's link to a connection, scrub
the canonical attributes that still match that connection's last-mirrored
snapshot, drop the mirror rows, and, when it was the user's last link,
(mirroring SAML's ``assign_user_idp`` disconnect semantics) inactivate the
user and unverify their emails so they cannot silently fall back to password
authentication.

This is the one place the spec says the disconnect scrub actually fires: the
connection-delete path is guarded by ``link_count > 0``, so its scrub is a
no-op until every user is unlinked here first.
"""

import logging
import uuid

import database
from schemas.oidc_upstream import OIDCUserLink, OIDCUserLinkList
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError
from services.oidc.logout import end_user_oidc_sessions
from services.oidc_upstream.presets import provider_display_name
from services.types import RequestingUser

logger = logging.getLogger(__name__)


def _is_uuid(value: str) -> bool:
    """Whether a path value is a UUID (a malformed id is "not found", not a 500)."""
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def list_connection_linked_users(
    requesting_user: RequestingUser,
    connection_id: str,
) -> list[dict]:
    """List users linked to an OIDC connection for the admin disconnect surface.

    Authorization: Requires super_admin role.

    Returns a list of dicts with ``link_id``, ``user_id``, ``sub``,
    ``first_name``, ``last_name``, and ``email``.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    connection = database.oidc_upstream.get_connection(tenant_id, connection_id)
    if connection is None:
        raise NotFoundError(
            message="OIDC connection not found",
            code="oidc_connection_not_found",
        )

    rows = database.oidc_upstream.list_links_for_connection(tenant_id, connection_id)
    return [
        {
            "link_id": str(row["id"]),
            "user_id": str(row["user_id"]),
            "sub": row["sub"],
            "first_name": row.get("first_name"),
            "last_name": row.get("last_name"),
            "email": row.get("email"),
        }
        for row in rows
    ]


def list_user_links(
    requesting_user: RequestingUser,
    user_id: str,
) -> OIDCUserLinkList:
    """List every OIDC identity linked to a user, most recently used first.

    Authorization: Requires super_admin role.

    Raises:
        NotFoundError if the user does not exist.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    if not _is_uuid(user_id) or database.users.get_user_by_id(tenant_id, user_id) is None:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    rows = database.oidc_upstream.list_links_for_user(tenant_id, user_id)
    return OIDCUserLinkList(
        items=[
            OIDCUserLink(
                connection_id=str(row["idp_id"]),
                connection_name=row["connection_name"],
                provider_type=row["provider_type"],
                provider_label=provider_display_name(row["provider_type"]),
                connection_enabled=row["connection_enabled"],
                sub=row["sub"],
                created_at=row["created_at"],
                last_used_at=row["last_used_at"],
            )
            for row in rows
        ]
    )


def unlink_user_from_connection(
    requesting_user: RequestingUser,
    user_id: str,
    connection_id: str,
) -> None:
    """Disconnect a user from an OIDC connection.

    Removes the user's link to the connection, scrubs canonical
    ``user_attributes`` rows whose value still matches the connection's
    last-mirrored snapshot (``cause: idp_disconnect_scrub``), and drops the
    connection's mirror rows for this user. When that was the user's last
    OIDC link it also -- mirroring SAML's ``assign_user_idp`` disconnect
    semantics -- inactivates the user, unverifies their emails and revokes
    their tokens so they cannot fall back to password auth. A user with
    other links keeps signing in through them.

    Authorization: Requires super_admin role.
    Logs: user_oidc_idp_unlinked event (plus user_profile_updated scrub events,
    and user_inactivated when the last link is removed).

    Raises:
        NotFoundError if the user, connection, or link does not exist.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    user = database.users.get_user_by_id(tenant_id, user_id) if _is_uuid(user_id) else None
    if user is None:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    connection = (
        database.oidc_upstream.get_connection(tenant_id, connection_id)
        if _is_uuid(connection_id)
        else None
    )
    if connection is None:
        raise NotFoundError(
            message="OIDC connection not found",
            code="oidc_connection_not_found",
        )

    link = database.oidc_upstream.get_link_for_user_idp(tenant_id, user_id, connection_id)
    if link is None:
        raise NotFoundError(
            message="User is not linked to this OIDC connection",
            code="oidc_user_link_not_found",
        )

    # Scrub canonical attributes still matching this connection's mirror
    # snapshot, then drop the mirror rows. The scrub must run before the
    # mirror rows are deleted (it reads them).
    from services.oidc_upstream.attributes import scrub_oidc_canonical_matches_mirror

    scrubbed_count = scrub_oidc_canonical_matches_mirror(
        tenant_id=tenant_id,
        idp_id=connection_id,
        actor_user_id=requesting_user["id"],
        user_id=user_id,
    )
    database.oidc_upstream.delete_for_user_idp(tenant_id, user_id, connection_id)
    database.oidc_upstream.delete_link_for_user_idp(tenant_id, user_id, connection_id)

    # Only the last link mirrors SAML disconnect semantics (inactivate +
    # unverify + revoke tokens). A user with other links still signs in
    # through them.
    remaining_links = database.oidc_upstream.list_links_for_user(tenant_id, user_id)
    user_inactivated = not remaining_links
    if user_inactivated:
        database.users.unverify_user_emails(tenant_id, user_id)
        database.users.inactivate_user(tenant_id, user_id)
        database.oauth2.revoke_all_user_tokens(tenant_id, user_id)
        end_user_oidc_sessions(tenant_id=tenant_id, user_id=user_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_oidc_idp_unlinked",
        metadata={
            "idp_id": connection_id,
            "idp_name": connection["name"],
            "sub": link["sub"],
            "scrubbed_count": scrubbed_count,
            "remaining_links": len(remaining_links),
        },
    )

    if user_inactivated:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_inactivated",
            metadata={"cause": "oidc_disconnect"},
        )

    logger.info(
        "Unlinked user %s from OIDC connection %s (scrubbed %d attributes)",
        user_id,
        connection_id,
        scrubbed_count,
    )
