"""Write-side service functions for the inbound SCIM Groups endpoints.

These power `POST /Groups`, `PUT /Groups/{id}`, `PATCH /Groups/{id}`, and
`DELETE /Groups/{id}`. The boundary contract mirrors `inbound_write.py`
(user writes): the router passes `tenant_id` + `idp_id` resolved from
the bearer token, and these functions return SCIM payload dicts or
raise `ScimWriteError`.

Design notes:

- **Group type**: every write here produces or operates on
  `group_type='idp'` rows scoped to the authenticating IdP. WeftID's
  manually managed `weftid` groups are out of reach for SCIM clients.
- **Membership ops**: delegated to `services.groups.idp` which already
  emits `idp_group_member_added` / `idp_group_member_removed` events.
  Those events are tagged in `EVENT_TYPE_SCIM_TRIGGERS` with
  `enqueue_membership_change`, so outbound SCIM replay is automatic --
  this service does NOT need a separate replay signal.
- **Member resolution**: `members[].value` is interpreted first as a
  WeftID user id; if it doesn't match an existing user bound to this
  IdP, we fall back to treating it as an upstream `externalId` and
  look up via `database.user_idp_attributes.get_user_id_by_external_id`.
  References to a user that doesn't yet exist reject with
  `400 invalidValue` (the IdP must POST `/Users` first; matches the
  documented Okta and Entra provisioning order).
- **displayName uniqueness**: per-IdP. POST and PUT/PATCH that produce
  a name collision return `409 uniqueness`. Defence-in-depth catches
  the rare race via `UniqueViolation` even without a partial unique
  index (the SCIM POST path is serial per IdP token in practice).
- **Parent / lineage**: SCIM clients cannot set group parent/child
  relationships. We silently ignore the `parent` / `parents` /
  `hierarchy` keys (per SCIM 2.0 §3.5.2 "unknown attributes" are
  permitted to be ignored). Local admins can still parent IdP groups
  under WeftID groups via the admin UI.
- **Audit trail**: this module emits `scim_group_received`,
  `scim_group_updated`, `scim_group_deleted` for the group-level audit
  trail. These are NOT in `EVENT_TYPE_SCIM_TRIGGERS` -- they cover
  metadata changes that don't require an outbound push (a rename
  doesn't change downstream membership; a delete cascades via per-member
  removal events already fired by the membership helpers).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import database
import psycopg.errors
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.groups.idp import (
    apply_membership_additions,
    apply_membership_removals,
)
from services.scim import inbound_read
from services.scim.inbound_write import ScimWriteError

logger = logging.getLogger(__name__)

# Upper bound on the number of `members[]` entries accepted in a single
# Group write. Each entry triggers per-member DB lookups during resolution,
# so an unbounded array (capped only by the 1 MiB body limit, ~tens of
# thousands of entries) would let one authenticated request drive O(N) work.
# This ceiling covers realistic group sizes; larger memberships should be
# synced incrementally via PATCH batches rather than one giant PUT.
_MAX_MEMBERS_PER_REQUEST = 5000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _looks_like_uuid(value: str) -> bool:
    """Return True if `value` parses as a UUID.

    SCIM `members[].value` can be either a WeftID-minted UUID or an
    upstream vendor id (Okta's `00u...`, etc.). We only attempt a
    `users.id` lookup for values that parse as UUIDs to avoid the
    `InvalidTextRepresentation` error psycopg raises when a non-UUID
    string hits a `uuid` column.
    """
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return True


def _idp_name(tenant_id: str, idp_id: str) -> str:
    """Best-effort fetch of the IdP display name (for event metadata).

    Falls back to the id if the IdP row is missing -- shouldn't happen
    in practice (the bearer-token FK cascades on IdP delete) but the
    write paths shouldn't 500 if it does.
    """
    row = database.fetchone(
        tenant_id,
        "select name from saml_identity_providers where id = :id",
        {"id": idp_id},
    )
    return row["name"] if row else idp_id


def _resolve_member_ref(
    tenant_id: str,
    idp_id: str,
    value: str,
) -> str:
    """Resolve a `members[].value` to a WeftID user id.

    Order of resolution:
    1. WeftID user id (uuid string) -- the canonical SCIM contract.
    2. Upstream `externalId` stored via `user_idp_attributes`.

    The user must already exist and be bound to this IdP. Raises
    `ScimWriteError(400, invalidValue)` if the reference cannot be
    resolved -- the IdP is expected to provision users via
    `POST /Users` before adding them to a group.
    """
    if not isinstance(value, str) or not value.strip():
        raise ScimWriteError(
            status_code=400,
            detail="Group member reference missing `value`.",
            scim_type="invalidValue",
        )
    candidate = value.strip()

    # Try as WeftID user id first if it parses as a UUID. Vendor values
    # (Okta `00u...`, Entra GUIDs that don't match our id space) skip
    # this lookup and go straight to the externalId fallback.
    if _looks_like_uuid(candidate):
        row = database.users.get_user_by_id(tenant_id, candidate)
        if row and str(row.get("saml_idp_id") or "") == str(idp_id):
            return str(row["id"])

    # Fall back to upstream externalId lookup.
    resolved = database.user_idp_attributes.get_user_id_by_external_id(tenant_id, idp_id, candidate)
    if resolved:
        # Confirm the resolved user is bound to this IdP.
        row = database.users.get_user_by_id(tenant_id, resolved)
        if row and str(row.get("saml_idp_id") or "") == str(idp_id):
            return resolved

    raise ScimWriteError(
        status_code=400,
        detail=(
            f"Group member `{candidate}` does not match a provisioned user "
            "for this IdP. POST /Users first."
        ),
        scim_type="invalidValue",
    )


def _resolve_members(
    tenant_id: str,
    idp_id: str,
    members: list[Any] | None,
) -> list[str]:
    """Resolve a SCIM `members[]` array to a deduped list of WeftID user ids."""
    if not members:
        return []
    if not isinstance(members, list):
        raise ScimWriteError(
            status_code=400,
            detail="`members` must be an array.",
            scim_type="invalidValue",
        )
    if len(members) > _MAX_MEMBERS_PER_REQUEST:
        # 413 carries no standard SCIM scimType (those are defined for 400
        # only, RFC 7644 §3.12), so it's left unset.
        raise ScimWriteError(
            status_code=413,
            detail=(
                f"`members` exceeds the per-request limit of "
                f"{_MAX_MEMBERS_PER_REQUEST}. Sync large memberships via "
                "incremental PATCH operations."
            ),
        )

    user_ids: list[str] = []
    seen: set[str] = set()
    for entry in members:
        if not isinstance(entry, dict):
            raise ScimWriteError(
                status_code=400,
                detail="Each member must be an object with a `value`.",
                scim_type="invalidValue",
            )
        value = entry.get("value")
        if not isinstance(value, str):
            raise ScimWriteError(
                status_code=400,
                detail="Member `value` must be a string.",
                scim_type="invalidValue",
            )
        resolved = _resolve_member_ref(tenant_id, idp_id, value)
        if resolved not in seen:
            seen.add(resolved)
            user_ids.append(resolved)
    return user_ids


def _extract_display_name(payload: dict) -> str | None:
    """Pull `displayName` and sanity-check it.

    A whitespace-only string is treated as missing; an empty / null
    `displayName` on POST raises -- a group with no name is not useful.
    """
    raw = payload.get("displayName") if isinstance(payload, dict) else None
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ScimWriteError(
            status_code=400,
            detail="`displayName` must be a string.",
            scim_type="invalidValue",
        )
    stripped = raw.strip()
    return stripped if stripped else None


def _ensure_group_for_idp(tenant_id: str, idp_id: str, group_id: str) -> dict:
    """Fetch an IdP group bound to this IdP, or raise 404."""
    row = database.groups.get_group_for_idp(tenant_id, idp_id, group_id)
    if row is None:
        raise ScimWriteError(status_code=404, detail="Group not found")
    return row


def _check_display_name_unique(
    tenant_id: str,
    idp_id: str,
    name: str,
    *,
    excluding_group_id: str | None = None,
) -> None:
    """Raise `409 uniqueness` if another IdP group already owns `name`."""
    existing = database.groups.get_group_by_idp_and_name(tenant_id, idp_id, name)
    if existing and (excluding_group_id is None or str(existing["id"]) != str(excluding_group_id)):
        raise ScimWriteError(
            status_code=409,
            detail=f"A group named `{name}` already exists for this IdP.",
            scim_type="uniqueness",
        )


def _group_payload(
    tenant_id: str,
    idp_id: str,
    group_id: str,
    *,
    group_location_builder,
    members_base_url: str,
) -> dict:
    """Build the SCIM Group response payload after a write."""
    location = group_location_builder(group_id)
    payload = inbound_read.get_group(
        tenant_id,
        idp_id,
        group_id,
        location=location,
        members_base_url=members_base_url,
    )
    if payload is None:  # pragma: no cover -- defensive
        raise ScimWriteError(
            status_code=500,
            detail="Group written but could not be re-read for response.",
        )
    return payload


def _bump_updated_at(tenant_id: str, group_id: str) -> None:
    """Force `groups.updated_at` to now() for accurate `meta.lastModified`."""
    database.execute(
        tenant_id,
        "update groups set updated_at = now() where id = :group_id",
        {"group_id": group_id},
    )


# ---------------------------------------------------------------------------
# Membership application
# ---------------------------------------------------------------------------


def _apply_membership_diff(
    tenant_id: str,
    idp_id: str,
    group_id: str,
    *,
    target_user_ids: set[str],
) -> tuple[list[str], list[str]]:
    """Add/remove memberships so the group's members match `target_user_ids`.

    Returns `(added_user_ids, removed_user_ids)`. Per-member events are
    emitted by the underlying `services.groups.idp` helpers.
    """
    current_rows = database.groups.list_group_members_for_scim(tenant_id, group_id)
    current_ids = {str(r["id"]) for r in current_rows}

    to_add = target_user_ids - current_ids
    to_remove = current_ids - target_user_ids

    idp_name = _idp_name(tenant_id, idp_id)

    for user_id in to_add:
        user_row = database.users.get_user_by_id(tenant_id, user_id)
        user_email = ""
        if user_row:
            primary = database.user_emails.get_primary_email(tenant_id, user_id)
            if primary:
                user_email = primary["email"]
        apply_membership_additions(
            tenant_id,
            user_id,
            user_email,
            idp_id,
            idp_name,
            {group_id},
        )

    for user_id in to_remove:
        user_row = database.users.get_user_by_id(tenant_id, user_id)
        user_email = ""
        if user_row:
            primary = database.user_emails.get_primary_email(tenant_id, user_id)
            if primary:
                user_email = primary["email"]
        apply_membership_removals(
            tenant_id,
            user_id,
            user_email,
            idp_id,
            idp_name,
            {group_id},
        )

    return sorted(to_add), sorted(to_remove)


# ---------------------------------------------------------------------------
# Public entrypoints
# ---------------------------------------------------------------------------


def create_group(
    tenant_id: str,
    idp_id: str,
    payload: dict,
    *,
    group_location_builder,
    members_base_url: str,
) -> dict:
    """SCIM `POST /Groups`: create an IdP group with optional members."""
    display_name = _extract_display_name(payload)
    if not display_name:
        raise ScimWriteError(
            status_code=400,
            detail="`displayName` is required.",
            scim_type="invalidValue",
        )

    _check_display_name_unique(tenant_id, idp_id, display_name)

    raw_members = payload.get("members") if isinstance(payload, dict) else None
    target_ids = set(_resolve_members(tenant_id, idp_id, raw_members))

    try:
        result = database.groups.create_idp_group(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            idp_id=idp_id,
            name=display_name,
            description=None,
        )
    except psycopg.errors.UniqueViolation as exc:
        # Concurrent POST won the name race.
        raise ScimWriteError(
            status_code=409,
            detail=f"A group named `{display_name}` already exists for this IdP.",
            scim_type="uniqueness",
        ) from exc

    if not result:
        raise ScimWriteError(
            status_code=500,
            detail="Failed to create group.",
        )

    group_id = str(result["id"])

    # Apply initial memberships (each fires `idp_group_member_added`).
    if target_ids:
        _apply_membership_diff(
            tenant_id,
            idp_id,
            group_id,
            target_user_ids=target_ids,
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="group",
        artifact_id=group_id,
        event_type="scim_group_received",
        metadata={
            "idp_id": idp_id,
            "display_name": display_name,
            "initial_member_count": len(target_ids),
        },
    )

    return _group_payload(
        tenant_id,
        idp_id,
        group_id,
        group_location_builder=group_location_builder,
        members_base_url=members_base_url,
    )


def replace_group(
    tenant_id: str,
    idp_id: str,
    group_id: str,
    payload: dict,
    *,
    group_location_builder,
    members_base_url: str,
) -> dict:
    """SCIM `PUT /Groups/{id}`: full-replace of displayName + members."""
    existing = _ensure_group_for_idp(tenant_id, idp_id, group_id)

    new_name = _extract_display_name(payload)
    if new_name is None:
        # PUT requires displayName; missing means "keep" per real-world
        # vendor behaviour (Okta omits unchanged scalars). We mirror that.
        new_name = existing["name"]

    if new_name != existing["name"]:
        _check_display_name_unique(
            tenant_id,
            idp_id,
            new_name,
            excluding_group_id=group_id,
        )
        try:
            database.groups.update_group(tenant_id, group_id, name=new_name)
        except psycopg.errors.UniqueViolation as exc:
            raise ScimWriteError(
                status_code=409,
                detail=f"A group named `{new_name}` already exists for this IdP.",
                scim_type="uniqueness",
            ) from exc

    raw_members = payload.get("members") if isinstance(payload, dict) else None
    # PUT with no `members` key: treat as "no change" rather than wipe.
    # An explicit empty list clears the membership.
    if raw_members is not None:
        target_ids = set(_resolve_members(tenant_id, idp_id, raw_members))
        _apply_membership_diff(
            tenant_id,
            idp_id,
            group_id,
            target_user_ids=target_ids,
        )

    _bump_updated_at(tenant_id, group_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="group",
        artifact_id=group_id,
        event_type="scim_group_updated",
        metadata={
            "idp_id": idp_id,
            "verb": "PUT",
            "display_name": new_name,
        },
    )

    return _group_payload(
        tenant_id,
        idp_id,
        group_id,
        group_location_builder=group_location_builder,
        members_base_url=members_base_url,
    )


# ---------------------------------------------------------------------------
# PATCH
# ---------------------------------------------------------------------------


def _patch_assert_path(raw_path: str | None) -> tuple[str, tuple[str, str] | None]:
    """Normalise a group PATCH path and extract any element filter.

    Returns `(path, filter_kv)`. Raises `400 invalidPath` for paths we
    don't support.
    """
    from services.scim.inbound_write import _normalise_patch_path_with_filter

    if raw_path is None:
        raise ScimWriteError(
            status_code=400,
            detail="Group PATCH requires a `path` for each operation.",
            scim_type="noTarget",
        )
    normalised, filter_kv = _normalise_patch_path_with_filter(raw_path)
    if normalised is None:
        raise ScimWriteError(
            status_code=400,
            detail=f"Path `{raw_path}` is not a supported PATCH target.",
            scim_type="invalidPath",
        )
    if normalised not in {"members", "displayname", "externalid"}:
        raise ScimWriteError(
            status_code=400,
            detail=f"Path `{raw_path}` is not a supported PATCH target.",
            scim_type="invalidPath",
        )
    return normalised, filter_kv


def _patch_op_members(
    tenant_id: str,
    idp_id: str,
    group_id: str,
    op: str,
    value: Any,
    filter_kv: tuple[str, str] | None,
) -> tuple[list[str], list[str]]:
    """Apply one `add` / `remove` / `replace` op on the `members` collection.

    Returns `(added, removed)` user-id lists. The semantics:
    - `add`: union new members into the existing set.
    - `remove` with element filter: remove the one matched user.
    - `remove` without value: clear all members.
    - `remove` with list value: remove each referenced user.
    - `replace`: replace the entire collection with `value`.
    """
    current_rows = database.groups.list_group_members_for_scim(tenant_id, group_id)
    current_ids = {str(r["id"]) for r in current_rows}

    if op == "replace":
        target = set(_resolve_members(tenant_id, idp_id, value if value else []))
        return _apply_membership_diff(tenant_id, idp_id, group_id, target_user_ids=target)

    if op == "add":
        new_members = _resolve_members(tenant_id, idp_id, value if value else [])
        target = current_ids | set(new_members)
        return _apply_membership_diff(tenant_id, idp_id, group_id, target_user_ids=target)

    # op == "remove"
    if filter_kv is not None:
        attr, ref_value = filter_kv
        if attr.lower() != "value":
            raise ScimWriteError(
                status_code=400,
                detail=f"Unsupported member filter attribute `{attr}` (expected `value`).",
                scim_type="invalidFilter",
            )
        # The filter targets a single user.
        user_id = _resolve_member_ref(tenant_id, idp_id, ref_value)
        target = current_ids - {user_id}
        return _apply_membership_diff(tenant_id, idp_id, group_id, target_user_ids=target)

    # No filter: remove value(s) listed, or clear if no value.
    if value is None or value == []:
        return _apply_membership_diff(tenant_id, idp_id, group_id, target_user_ids=set())

    if not isinstance(value, list):
        raise ScimWriteError(
            status_code=400,
            detail="`remove` on `members` requires an element filter or an array value.",
            scim_type="invalidValue",
        )
    removed = _resolve_members(tenant_id, idp_id, value)
    target = current_ids - set(removed)
    return _apply_membership_diff(tenant_id, idp_id, group_id, target_user_ids=target)


def patch_group(
    tenant_id: str,
    idp_id: str,
    group_id: str,
    patch_body: dict,
    *,
    group_location_builder,
    members_base_url: str,
) -> dict:
    """SCIM `PATCH /Groups/{id}` with Okta + Entra patterns.

    Supported ops:
    - `replace` on `displayName`.
    - `add` / `replace` on `members` (full or partial collection).
    - `remove` on `members[value eq "<id>"]` (Okta) or with a `value`
      array (Entra batched).
    """
    _ensure_group_for_idp(tenant_id, idp_id, group_id)

    if not isinstance(patch_body, dict):
        raise ScimWriteError(
            status_code=400,
            detail="PATCH body must be a JSON object.",
            scim_type="invalidSyntax",
        )

    ops = patch_body.get("Operations") or patch_body.get("operations")
    if not isinstance(ops, list) or not ops:
        raise ScimWriteError(
            status_code=400,
            detail="PATCH body must contain a non-empty `Operations` array.",
            scim_type="invalidSyntax",
        )

    new_name: str | None = None
    total_added: list[str] = []
    total_removed: list[str] = []

    for raw_op in ops:
        if not isinstance(raw_op, dict):
            raise ScimWriteError(
                status_code=400,
                detail="PATCH operations must be objects.",
                scim_type="invalidSyntax",
            )
        op_str = (raw_op.get("op") or "").strip().lower()
        if op_str not in {"add", "replace", "remove"}:
            raise ScimWriteError(
                status_code=400,
                detail=f"Unsupported PATCH op: `{raw_op.get('op')}`.",
                scim_type="invalidSyntax",
            )
        raw_path = raw_op.get("path")
        if raw_path is not None and not isinstance(raw_path, str):
            raise ScimWriteError(
                status_code=400,
                detail="PATCH path must be a string.",
                scim_type="invalidPath",
            )

        path, filter_kv = _patch_assert_path(raw_path)

        if path == "displayname":
            if op_str == "remove":
                raise ScimWriteError(
                    status_code=400,
                    detail="`remove` on `displayName` is not supported.",
                    scim_type="invalidValue",
                )
            value = raw_op.get("value")
            if isinstance(value, dict):
                value = value.get("displayName")
            if not isinstance(value, str) or not value.strip():
                raise ScimWriteError(
                    status_code=400,
                    detail="`displayName` value must be a non-empty string.",
                    scim_type="invalidValue",
                )
            new_name = value.strip()
        elif path == "externalid":
            # SCIM allows externalId on Groups; we accept and ignore (we
            # mint the id). Storing upstream group externalId is out of
            # scope for v1 -- documented in the iteration decisions log.
            continue
        elif path == "members":
            added, removed = _patch_op_members(
                tenant_id,
                idp_id,
                group_id,
                op_str,
                raw_op.get("value"),
                filter_kv,
            )
            total_added.extend(added)
            total_removed.extend(removed)

    if new_name is not None:
        existing = database.groups.get_group_for_idp(tenant_id, idp_id, group_id)
        if existing and new_name != existing["name"]:
            _check_display_name_unique(tenant_id, idp_id, new_name, excluding_group_id=group_id)
            try:
                database.groups.update_group(tenant_id, group_id, name=new_name)
            except psycopg.errors.UniqueViolation as exc:
                raise ScimWriteError(
                    status_code=409,
                    detail=f"A group named `{new_name}` already exists for this IdP.",
                    scim_type="uniqueness",
                ) from exc

    _bump_updated_at(tenant_id, group_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="group",
        artifact_id=group_id,
        event_type="scim_group_updated",
        metadata={
            "idp_id": idp_id,
            "verb": "PATCH",
            "ops": len(ops),
            "added": len(total_added),
            "removed": len(total_removed),
        },
    )

    return _group_payload(
        tenant_id,
        idp_id,
        group_id,
        group_location_builder=group_location_builder,
        members_base_url=members_base_url,
    )


def delete_group(
    tenant_id: str,
    idp_id: str,
    group_id: str,
) -> None:
    """SCIM `DELETE /Groups/{id}`: remove the IdP group.

    Per the iteration spec: memberships are removed (each emits
    `idp_group_member_removed` so downstream SPs get the deprovision
    cascade), but affected users are NOT deactivated.
    """
    existing = _ensure_group_for_idp(tenant_id, idp_id, group_id)

    # Remove memberships one by one so each fires an event the outbound
    # dispatch can use to enqueue downstream cascades.
    _apply_membership_diff(
        tenant_id,
        idp_id,
        group_id,
        target_user_ids=set(),
    )

    # Then delete the group row itself (cascades will clean up lineage).
    database.groups.delete_group(tenant_id, group_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="group",
        artifact_id=group_id,
        event_type="scim_group_deleted",
        metadata={
            "idp_id": idp_id,
            "display_name": existing["name"],
        },
    )
