"""OIDC client management service.

Exposes the management surface for OIDC-enabled OAuth2 clients (the "Apps"
built on the authorization-code flow): the `oidc_enabled` toggle, the
`available_to_all` access-mode flag, the read-only discovery/JWKS endpoint
URLs, and group-based access assignments.

This mirrors the SAML SP group-assignment service (see
``services.service_providers.group_assignments``) rather than inventing a
parallel surface: the underlying grant table (``sp_group_assignments`` with the
``oauth2_client_id`` target) and resolver (``user_can_access_oauth2_client``)
already exist. This layer adds authorization, event logging, and validation.

Note on scopes: WeftID does NOT model a per-client allowed-scope allowlist.
Released claims are gated by the scopes a relying party REQUESTS at authorize
time (see ``services.oidc.claims``), and discovery advertises the tenant-wide
``SUPPORTED_SCOPES``. There is therefore no per-client scope field to manage.
"""

import logging

import database
from schemas.oidc import (
    OIDCClientDiscoveryInfo,
    OIDCClientGroupAssignment,
    OIDCClientGroupAssignmentList,
)
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError, ValidationError
from services.oidc.discovery import build_discovery_metadata
from services.types import RequestingUser

logger = logging.getLogger(__name__)


def _get_normal_client(tenant_id: str, client_id: str) -> dict:
    """Resolve a normal (authorization-code) client by its string client_id.

    Raises:
        NotFoundError: if no such client exists.
        ValidationError: if the client is not a normal client (OIDC only
            applies to interactive apps, never B2B service accounts).
    """
    client = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if client is None:
        raise NotFoundError(message="Application not found", code="oauth2_client_not_found")
    if client["client_type"] != "normal":
        raise ValidationError(
            message="OIDC settings apply only to Apps (authorization-code clients)",
            code="oidc_not_supported_for_client_type",
        )
    return client


def set_oidc_settings(
    requesting_user: RequestingUser,
    client_id: str,
    oidc_enabled: bool | None = None,
    available_to_all: bool | None = None,
) -> dict:
    """Update a client's OIDC settings (oidc_enabled and/or available_to_all).

    Authorization: Requires admin role.
    Logs: oidc_client_enabled / oidc_client_disabled when oidc_enabled changes;
    oidc_client_availability_changed when available_to_all changes.

    Args:
        requesting_user: The acting admin.
        client_id: The string client_id (e.g. "weft-id_client_abc123").
        oidc_enabled: New OIDC-enabled flag, or None to leave unchanged.
        available_to_all: New access-mode flag, or None to leave unchanged.

    Returns:
        The updated client dict.
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    old = _get_normal_client(tenant_id, client_id)

    updated = database.oauth2.update_client_oidc_settings(
        tenant_id=tenant_id,
        client_id=client_id,
        oidc_enabled=oidc_enabled,
        available_to_all=available_to_all,
    )
    if updated is None:
        raise NotFoundError(message="Application not found", code="oauth2_client_not_found")

    if oidc_enabled is not None and oidc_enabled != old.get("oidc_enabled"):
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="oauth2_client",
            artifact_id=str(updated["id"]),
            event_type="oidc_client_enabled" if oidc_enabled else "oidc_client_disabled",
            metadata={"name": updated["name"], "client_id": client_id},
        )

    if available_to_all is not None and available_to_all != old.get("available_to_all"):
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="oauth2_client",
            artifact_id=str(updated["id"]),
            event_type="oidc_client_availability_changed",
            metadata={
                "name": updated["name"],
                "client_id": client_id,
                "available_to_all": available_to_all,
            },
        )

    # Narrowing access from available-to-all to group-gated must revoke the
    # credentials issued under the broader policy: users now outside every
    # assigned group would otherwise keep their access tokens (up to 1h) and keep
    # refreshing (up to 30d). Revoke this client's outstanding tokens, forcing a
    # re-authorize that now runs the group check. Only when the client stays
    # OIDC-enabled (a plain OAuth2 client does not gate on groups at all).
    effective_oidc_enabled = (
        oidc_enabled if oidc_enabled is not None else updated.get("oidc_enabled")
    )
    narrowed_to_group_gated = available_to_all is False and old.get("available_to_all")
    if effective_oidc_enabled and narrowed_to_group_gated:
        database.oauth2.revoke_all_client_tokens(tenant_id, str(updated["id"]))

    return updated


def get_client_discovery_info(
    requesting_user: RequestingUser,
    client_id: str,
    base_url: str,
) -> OIDCClientDiscoveryInfo:
    """Return the tenant's OIDC endpoint URLs for a client, for copying into it.

    Authorization: Requires admin role.

    Args:
        requesting_user: The acting admin.
        client_id: The string client_id of the App.
        base_url: The tenant base URL (``https://<tenant-host>``) from the request.

    Returns:
        The read-only discovery/JWKS/authorization/token/userinfo URLs.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    _get_normal_client(requesting_user["tenant_id"], client_id)

    meta = build_discovery_metadata(base_url)
    return OIDCClientDiscoveryInfo(
        issuer=meta.issuer,
        discovery_url=f"{meta.issuer}/.well-known/openid-configuration",
        jwks_uri=meta.jwks_uri,
        authorization_endpoint=meta.authorization_endpoint,
        token_endpoint=meta.token_endpoint,
        userinfo_endpoint=meta.userinfo_endpoint,
    )


def list_client_group_assignments(
    requesting_user: RequestingUser,
    client_id: str,
) -> OIDCClientGroupAssignmentList:
    """List groups assigned to an OIDC client.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    client = _get_normal_client(tenant_id, client_id)

    rows = database.sp_group_assignments.list_assignments_for_oauth2_client(
        tenant_id, str(client["id"])
    )
    items = [
        OIDCClientGroupAssignment(
            id=str(row["id"]),
            oauth2_client_id=str(row["oauth2_client_id"]),
            group_id=str(row["group_id"]),
            group_name=row["group_name"],
            group_description=row.get("group_description"),
            group_type=row["group_type"],
            assigned_by=str(row["assigned_by"]),
            assigned_at=row["assigned_at"],
        )
        for row in rows
    ]
    return OIDCClientGroupAssignmentList(items=items, total=len(items))


def assign_client_to_group(
    requesting_user: RequestingUser,
    client_id: str,
    group_id: str,
) -> OIDCClientGroupAssignment:
    """Assign a group to an OIDC client.

    Authorization: Requires admin role.
    Logs: oidc_client_group_assigned.
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    client = _get_normal_client(tenant_id, client_id)

    group_row = database.groups.get_group_by_id(tenant_id, group_id)
    if group_row is None:
        raise NotFoundError(message="Group not found", code="group_not_found")

    row = database.sp_group_assignments.create_oauth2_client_assignment(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        oauth2_client_id=str(client["id"]),
        group_id=group_id,
        assigned_by=requesting_user["id"],
    )
    if row is None:
        raise ConflictError(
            message="Group is already assigned to this application",
            code="oidc_client_group_already_assigned",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oauth2_client",
        artifact_id=str(client["id"]),
        event_type="oidc_client_group_assigned",
        metadata={
            "group_id": str(group_id),
            "group_name": group_row["name"],
            "client_id": client_id,
            "name": client["name"],
        },
    )

    return OIDCClientGroupAssignment(
        id=str(row["id"]),
        oauth2_client_id=str(row["oauth2_client_id"]),
        group_id=str(row["group_id"]),
        group_name=group_row["name"],
        group_description=group_row.get("description"),
        group_type=group_row["group_type"],
        assigned_by=str(row["assigned_by"]),
        assigned_at=row["assigned_at"],
    )


def remove_client_group_assignment(
    requesting_user: RequestingUser,
    client_id: str,
    group_id: str,
) -> None:
    """Remove a group assignment from an OIDC client.

    Authorization: Requires admin role.
    Logs: oidc_client_group_unassigned.
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    client = _get_normal_client(tenant_id, client_id)

    deleted = database.sp_group_assignments.delete_oauth2_client_assignment(
        tenant_id, str(client["id"]), group_id
    )
    if deleted == 0:
        raise NotFoundError(
            message="Group assignment not found",
            code="oidc_client_group_assignment_not_found",
        )

    # Revoking a grant must also revoke the credentials that grant already
    # produced. Access is only enforced at authorize time, so users who lose
    # access here would otherwise keep their live access tokens (up to 1h) and
    # keep refreshing (up to 30d). Force everyone on this client to re-authorize
    # by revoking its outstanding tokens, mirroring deactivate_client(). Only
    # relevant when the client is group-gated: an available_to_all or non-OIDC
    # client does not derive access from group assignments, so nobody lost it.
    if client.get("oidc_enabled") and not client.get("available_to_all"):
        database.oauth2.revoke_all_client_tokens(tenant_id, str(client["id"]))

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oauth2_client",
        artifact_id=str(client["id"]),
        event_type="oidc_client_group_unassigned",
        metadata={"group_id": str(group_id), "client_id": client_id, "name": client["name"]},
    )


def bulk_assign_client_to_groups(
    requesting_user: RequestingUser,
    client_id: str,
    group_ids: list[str],
) -> int:
    """Bulk-assign groups to an OIDC client.

    Authorization: Requires admin role.
    Logs: oidc_client_groups_bulk_assigned.

    Returns:
        Number of new assignments created.
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    client = _get_normal_client(tenant_id, client_id)

    # Validate every group is owned by this tenant before inserting, mirroring the
    # single-assign path. The FK to groups(id) is satisfied by a row in any tenant
    # (FK checks bypass RLS), so without this an admin could inject a grant row
    # referencing a foreign group -- an invisible orphaned row plus a misleading
    # audit entry. Fail the whole batch closed if any group is foreign/unknown.
    for group_id in group_ids:
        if database.groups.get_group_by_id(tenant_id, group_id) is None:
            raise NotFoundError(message="Group not found", code="group_not_found")

    count = database.sp_group_assignments.bulk_create_oauth2_client_assignments(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        oauth2_client_id=str(client["id"]),
        group_ids=group_ids,
        assigned_by=requesting_user["id"],
    )

    if count > 0:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="oauth2_client",
            artifact_id=str(client["id"]),
            event_type="oidc_client_groups_bulk_assigned",
            metadata={
                "group_ids": [str(g) for g in group_ids],
                "count": count,
                "client_id": client_id,
                "name": client["name"],
            },
        )

    return count


def list_available_groups_for_client(
    requesting_user: RequestingUser,
    client_id: str,
) -> list[dict]:
    """List groups not yet assigned to an OIDC client (for the assign dropdown).

    Authorization: Requires admin role.

    Returns:
        List of dicts with id, name, group_type for unassigned groups.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    client = _get_normal_client(tenant_id, client_id)

    all_groups = database.groups.list_groups(tenant_id)
    assigned = database.sp_group_assignments.list_assignments_for_oauth2_client(
        tenant_id, str(client["id"])
    )
    assigned_ids = {str(row["group_id"]) for row in assigned}

    return [
        {"id": str(g["id"]), "name": g["name"], "group_type": g["group_type"]}
        for g in all_groups
        if str(g["id"]) not in assigned_ids
    ]
