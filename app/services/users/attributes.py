"""User attribute service layer.

Two-space storage model:

* ``user_attributes`` -- canonical user attribute set. Owned by the user
  or admin. Read by SP assertion builders. Writers: ``set_user_attribute``,
  ``clear_user_attribute``, and ``apply_idp_attributes`` (when the tenant
  has ``mirror_from_idp=true`` for the key).

* ``user_idp_attributes`` -- read-only audit/info copy of what each
  connected IdP last sent. Writer: ``apply_idp_attributes`` only.

Lock and policy enforcement happen here, not in the database. Admins
always bypass the per-attribute lock. The IdP-mirror writer is also not
subject to the lock -- "users can't edit" is not "the system can't
update".
"""

from __future__ import annotations

import database
from constants.user_attributes import (
    ATTRIBUTES_BY_KEY,
    is_standard_attribute,
    serialize,
)
from services.activity import track_activity
from services.event_log import log_event
from services.exceptions import (
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.settings.security import can_user_edit_profile
from services.types import RequestingUser

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_known_attribute(attribute_key: str) -> None:
    if not is_standard_attribute(attribute_key):
        raise ValidationError(
            message=f"Unknown attribute key: {attribute_key}",
            code="unknown_attribute_key",
            field="attribute_key",
        )


def _require_enabled(tenant_id: str, attribute_key: str) -> dict:
    """Return the config row, raising if the attribute is disabled or missing."""
    config = database.tenant_attribute_config.get_config(tenant_id, attribute_key)
    if config is None or not config.get("enabled"):
        raise ValidationError(
            message=f"Attribute {attribute_key} is not enabled for this tenant",
            code="attribute_not_enabled",
            field="attribute_key",
        )
    return config


def _enforce_self_edit_policy(
    requesting_user: RequestingUser,
    target_user_id: str,
    config: dict,
) -> None:
    """Enforce the locking + allow_users_edit_profile rules for one write.

    Admins (admin / super_admin) bypass both checks. Users acting on
    themselves are subject to:
      - the tenant ``allow_users_edit_profile`` setting
      - the per-attribute ``locked_for_users`` flag.
    """
    if requesting_user["role"] in ("admin", "super_admin"):
        return

    if requesting_user["id"] != target_user_id:
        # Non-admin acting on someone else is always forbidden here -- the
        # caller layer should not have routed this request to us.
        raise ForbiddenError(
            message="Cannot edit another user's profile",
            code="forbidden",
        )

    if not can_user_edit_profile(requesting_user["tenant_id"]):
        raise ForbiddenError(
            message="Profile editing is disabled by your organization",
            code="profile_editing_disabled",
        )

    if config.get("locked_for_users"):
        raise ForbiddenError(
            message="This attribute is locked. Only an administrator can change it.",
            code="attribute_locked",
        )


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def list_user_attributes(
    requesting_user: RequestingUser,
    user_id: str,
) -> list[dict]:
    """Return canonical attribute rows for ``user_id``.

    Authorization: a user can read their own attributes; admins can read
    any user in their tenant.
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    if requesting_user["id"] != user_id and requesting_user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Cannot read another user's attributes",
            code="forbidden",
        )
    return database.user_attributes.list_attributes(requesting_user["tenant_id"], user_id)


def get_user_attribute(
    requesting_user: RequestingUser,
    user_id: str,
    attribute_key: str,
) -> dict | None:
    """Return one canonical attribute row, or ``None`` if not set."""
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    if requesting_user["id"] != user_id and requesting_user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Cannot read another user's attributes",
            code="forbidden",
        )
    _require_known_attribute(attribute_key)
    return database.user_attributes.get_attribute(
        requesting_user["tenant_id"], user_id, attribute_key
    )


def list_user_idp_attributes(
    requesting_user: RequestingUser,
    user_id: str,
) -> list[dict]:
    """Return all IdP-mirror snapshot rows for ``user_id``.

    Authorization: admin / super_admin only. The IdP-mirror panel is not
    surfaced on self-service; users only see canonical values.
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    if requesting_user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
            required_role="admin",
        )
    return database.user_idp_attributes.list_attributes(requesting_user["tenant_id"], user_id)


# ---------------------------------------------------------------------------
# Writes (user / admin)
# ---------------------------------------------------------------------------


def set_user_attribute(
    requesting_user: RequestingUser,
    user_id: str,
    attribute_key: str,
    value: str,
) -> dict:
    """Set or update one canonical attribute value.

    Validates the attribute is enabled for the tenant, that the requester
    is allowed to edit (lock + tenant policy), and that the value passes
    per-type serialization. Emits ``user_profile_updated`` with
    ``cause=self_edit`` or ``cause=admin_edit`` when the value changes.
    """
    tenant_id = requesting_user["tenant_id"]

    _require_known_attribute(attribute_key)
    config = _require_enabled(tenant_id, attribute_key)
    _enforce_self_edit_policy(requesting_user, user_id, config)

    serialized = serialize(attribute_key, value)

    existing = database.user_attributes.get_attribute(tenant_id, user_id, attribute_key)
    old_value = existing["value"] if existing else None

    row = database.user_attributes.upsert_attribute(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        user_id=user_id,
        attribute_key=attribute_key,
        value=serialized,
    )

    if old_value != serialized:
        cause = "self_edit" if requesting_user["id"] == user_id else "admin_edit"
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_profile_updated",
            metadata={
                "cause": cause,
                "idp_id": None,
                "changes": {
                    attribute_key: {"old": old_value, "new": serialized},
                },
            },
        )

    return row


def clear_user_attribute(
    requesting_user: RequestingUser,
    user_id: str,
    attribute_key: str,
) -> bool:
    """Delete one canonical attribute row.

    Returns True if a row was deleted, False if there was nothing to
    delete. Lock and tenant policy apply identically to ``set``.
    """
    tenant_id = requesting_user["tenant_id"]

    _require_known_attribute(attribute_key)
    # Don't require enabled for clear -- if a tenant turned off an attribute
    # an admin should still be able to scrub stale values. We still need
    # the config row to know the lock state though.
    config = database.tenant_attribute_config.get_config(tenant_id, attribute_key) or {
        "locked_for_users": False,
    }
    _enforce_self_edit_policy(requesting_user, user_id, config)

    existing = database.user_attributes.get_attribute(tenant_id, user_id, attribute_key)
    if existing is None:
        return False

    rows_affected = database.user_attributes.delete_attribute(tenant_id, user_id, attribute_key)
    if rows_affected == 0:
        return False

    cause = "self_edit" if requesting_user["id"] == user_id else "admin_edit"
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_profile_updated",
        metadata={
            "cause": cause,
            "idp_id": None,
            "changes": {
                attribute_key: {"old": existing["value"], "new": None},
            },
        },
    )
    return True


# ---------------------------------------------------------------------------
# Writes (IdP mirror)
# ---------------------------------------------------------------------------


def apply_idp_attributes(
    tenant_id: str,
    user_id: str,
    idp_id: str,
    attributes: dict[str, str],
    *,
    actor_user_id: str,
) -> None:
    """Apply an IdP login's attribute set to both storage spaces.

    1. Validate ``idp_id`` belongs to ``tenant_id``.
    2. Replace the user's IdP-mirror snapshot for that IdP atomically.
    3. For each (key, value) where the tenant has ``enabled=true`` AND
       ``mirror_from_idp=true``, upsert ``user_attributes`` with the
       serialized value.
    4. Emit a single ``user_profile_updated`` event with
       ``cause=idp_mirror`` when one or more canonical values changed.

    Both writes happen inside one ``database.session()`` so observers
    never see a partial state.

    Unknown attribute keys (not in the standard registry) are dropped
    silently from both writes -- the per-IdP attribute_mapping is
    expected to filter, but defence in depth never hurts.
    """
    # 1. Tenant-IdP ownership check (defence in depth at service boundary;
    # the per-IdP attribute_mapping JSON is supposed to be in this tenant
    # already, but we verify before writing rows that reference idp_id).
    idp = database.saml.get_identity_provider(tenant_id, idp_id)
    if idp is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    # Filter to known attribute keys and serialize values up front so any
    # validation error rolls back nothing (we haven't written yet).
    serialized_attributes: dict[str, str] = {}
    for key, raw in attributes.items():
        if not is_standard_attribute(key):
            continue
        if raw is None or (isinstance(raw, str) and raw.strip() == ""):
            # Empty values are dropped (treated as "IdP no longer sends this").
            continue
        try:
            serialized_attributes[key] = serialize(key, raw)
        except (ValueError, ValidationError):
            # Skip malformed values silently -- the IdP login flow must not
            # fail because one attribute is wrong. The mirror table simply
            # won't carry it. Future iterations may surface a warning.
            continue

    # Determine which keys also flow into user_attributes.
    config_rows = database.tenant_attribute_config.list_config(tenant_id)
    config_by_key = {r["attribute_key"]: r for r in config_rows}

    mirror_writes: dict[str, str] = {}
    for key, value in serialized_attributes.items():
        cfg = config_by_key.get(key)
        if cfg and cfg.get("enabled") and cfg.get("mirror_from_idp"):
            mirror_writes[key] = value

    # Pre-compute changes for the event log (only canonical changes are
    # logged; the IdP-mirror snapshot is its own audit surface).
    existing_rows = {
        r["attribute_key"]: r["value"]
        for r in database.user_attributes.list_attributes(tenant_id, user_id)
    }
    changes: dict[str, dict[str, str | None]] = {}
    for key, new_value in mirror_writes.items():
        old_value = existing_rows.get(key)
        if old_value != new_value:
            changes[key] = {"old": old_value, "new": new_value}

    with database.session(tenant_id=tenant_id) as cur:
        # Replace the IdP-mirror snapshot for this IdP.
        if serialized_attributes:
            cur.execute(
                """
                delete from user_idp_attributes
                where user_id = %(user_id)s
                  and idp_id = %(idp_id)s
                  and attribute_key <> all(%(keys)s)
                """,
                {
                    "user_id": user_id,
                    "idp_id": idp_id,
                    "keys": list(serialized_attributes.keys()),
                },
            )
        else:
            cur.execute(
                """
                delete from user_idp_attributes
                where user_id = %(user_id)s and idp_id = %(idp_id)s
                """,
                {"user_id": user_id, "idp_id": idp_id},
            )

        for key, value in serialized_attributes.items():
            cur.execute(
                """
                insert into user_idp_attributes (
                    tenant_id, user_id, idp_id, attribute_key, value
                ) values (
                    %(tenant_id)s, %(user_id)s, %(idp_id)s,
                    %(attribute_key)s, %(value)s
                )
                on conflict (user_id, idp_id, attribute_key) do update set
                    value = excluded.value,
                    updated_at = now()
                """,
                {
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "idp_id": idp_id,
                    "attribute_key": key,
                    "value": value,
                },
            )

        # Mirror enabled+mirror_from_idp keys into user_attributes.
        for key, value in mirror_writes.items():
            cur.execute(
                """
                insert into user_attributes (
                    tenant_id, user_id, attribute_key, value
                ) values (
                    %(tenant_id)s, %(user_id)s, %(attribute_key)s, %(value)s
                )
                on conflict (user_id, attribute_key) do update set
                    value = excluded.value,
                    updated_at = now()
                """,
                {
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "attribute_key": key,
                    "value": value,
                },
            )

    # Single event for the canonical write set (if anything changed).
    if changes:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_profile_updated",
            metadata={
                "cause": "idp_mirror",
                "idp_id": idp_id,
                "changes": changes,
            },
        )


# ---------------------------------------------------------------------------
# Public re-exports for the registry helper used in tests
# ---------------------------------------------------------------------------


# Convenience for callers that want to introspect registry shape without
# importing the constants module directly.
__all__ = [
    "ATTRIBUTES_BY_KEY",
    "apply_idp_attributes",
    "clear_user_attribute",
    "get_user_attribute",
    "list_user_attributes",
    "list_user_idp_attributes",
    "set_user_attribute",
]
