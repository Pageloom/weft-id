"""Tenant attribute configuration service layer.

Lists and updates per-tenant per-attribute toggles
(``tenant_attribute_config``). Also provides the seed helper invoked
during tenant provisioning.

Only super_admin may update; tenant settings are global to the tenant.
"""

from __future__ import annotations

import database
from constants.user_attributes import STANDARD_ATTRIBUTES, is_standard_attribute
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser


def list_tenant_attribute_config(
    requesting_user: RequestingUser,
) -> list[dict]:
    """Return all attribute config rows for the requesting user's tenant.

    Authorization: any authenticated user in the tenant. The data is
    informational tenant configuration (which attributes are enabled,
    required, locked) and is needed by self-service profile rendering
    for member users, not just admin UIs. The read is therefore safe to
    expose at the service level. The public REST endpoints under
    ``/api/v1/tenant/attribute-config`` (both read and write) remain
    super_admin-gated at the router layer by deliberate choice; that
    gating does not reflect a service-level authorization requirement.
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    return database.tenant_attribute_config.list_config(requesting_user["tenant_id"])


def update_tenant_attribute_config(
    requesting_user: RequestingUser,
    attribute_key: str,
    *,
    enabled: bool,
    required: bool,
    mirror_from_idp: bool,
    locked_for_users: bool,
    send_to_sps_default: bool,
    allow_self_sourced_to_sp: bool = False,
) -> dict:
    """Update one attribute's config row.

    Authorization: super_admin only.

    Raises:
        ValidationError: unknown attribute key.
        NotFoundError: tenant has no row for this attribute (should be
            seeded; surface as a clear error rather than silently
            inserting).
    """
    require_super_admin(requesting_user)

    if not is_standard_attribute(attribute_key):
        raise ValidationError(
            message=f"Unknown attribute key: {attribute_key}",
            code="unknown_attribute_key",
            field="attribute_key",
        )

    tenant_id = requesting_user["tenant_id"]

    existing = database.tenant_attribute_config.get_config(tenant_id, attribute_key)
    if existing is None:
        raise NotFoundError(
            message=f"No config row for {attribute_key}; tenant seed missing",
            code="attribute_config_missing",
        )

    rows_affected = database.tenant_attribute_config.update_config(
        tenant_id,
        attribute_key=attribute_key,
        enabled=enabled,
        required=required,
        mirror_from_idp=mirror_from_idp,
        locked_for_users=locked_for_users,
        send_to_sps_default=send_to_sps_default,
        allow_self_sourced_to_sp=allow_self_sourced_to_sp,
    )
    if rows_affected == 0:
        # Race -- the row was deleted between get_config and update_config.
        raise NotFoundError(
            message=f"No config row for {attribute_key}",
            code="attribute_config_missing",
        )

    updated = database.tenant_attribute_config.get_config(tenant_id, attribute_key)
    assert updated is not None  # we just wrote

    # Build a changes diff for audit visibility.
    changes: dict[str, dict[str, bool]] = {}
    for flag in (
        "enabled",
        "required",
        "mirror_from_idp",
        "locked_for_users",
        "send_to_sps_default",
        "allow_self_sourced_to_sp",
    ):
        old_value = bool(existing.get(flag))
        new_value = bool(updated.get(flag))
        if old_value != new_value:
            changes[flag] = {"old": old_value, "new": new_value}

    if changes:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="tenant_attribute_config",
            artifact_id=str(updated["id"]),
            event_type="tenant_attribute_config_updated",
            metadata={
                "attribute_key": attribute_key,
                "changes": changes,
            },
        )

    return updated


def seed_tenant_attribute_config(tenant_id: str) -> int:
    """Insert default-flag rows for a freshly created tenant.

    Idempotent: ON CONFLICT DO NOTHING. Returns the number of attribute
    rows inserted (zero if already seeded).

    No authorization check -- this is invoked by tenant provisioning
    code (CLI, dev seeder) which runs in a system context. Callers must
    log a tenant_created or equivalent event themselves; this helper
    intentionally doesn't emit an event because the per-attribute
    defaults are not interesting audit material.
    """
    inserted = 0
    for attr in STANDARD_ATTRIBUTES:
        inserted += database.tenant_attribute_config.insert_config_row(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            attribute_key=attr.key,
            category=attr.category,
        )
    return inserted
