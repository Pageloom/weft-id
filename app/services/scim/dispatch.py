"""Event-log-driven SCIM dispatch.

`services.event_log.log_event` calls `scim_dispatch(...)` after writing an
event row. If the event type has a `scim_trigger` annotation in the event
type registry, the matching trigger function fans the change out into
`scim_push_queue` upserts via `services.scim.queue`.

Design rules:

- **Best-effort.** A failure here MUST NOT roll back the event row or
  surface to the caller. The cost of a missed enqueue is "the next change
  to this user picks it up." The cost of a failed enqueue rolling back a
  user-visible write is unacceptable. Every trigger wraps its work in
  try/except and logs on failure.
- **Eager fan-out.** Group-grant and membership changes resolve every
  affected user up front (via the closure table) instead of pushing one
  group entry that the worker would expand later. Queue depth is then a
  real "work remaining" metric, and each user's retry/backoff is isolated.
- **No worker imports.** This module does not touch `scim.client` or the
  HTTP transport. It only writes queue rows. The worker (iteration 4)
  drains them.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from constants.event_types import EVENT_TYPE_SCIM_TRIGGERS

from . import queue

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def scim_dispatch(
    event_type: str,
    tenant_id: str,
    actor_user_id: str,
    artifact_type: str,
    artifact_id: str,
    metadata: dict[str, Any] | None,
) -> None:
    """Look up the trigger for `event_type` and run it.

    Called from `services.event_log.log_event` after a successful event
    write. No-op when the event type has no annotation in
    `EVENT_TYPE_SCIM_TRIGGERS`.

    Never raises. Errors are logged with enough context for ops to
    reconstruct what failed without disrupting the caller.
    """
    trigger_name = EVENT_TYPE_SCIM_TRIGGERS.get(event_type)
    if trigger_name is None:
        return

    trigger = _TRIGGERS.get(trigger_name)
    if trigger is None:
        logger.error(
            "scim_dispatch: unknown trigger %r for event_type %r",
            trigger_name,
            event_type,
        )
        return

    try:
        trigger(tenant_id, artifact_id, metadata or {})
    except Exception:  # noqa: BLE001 -- best-effort dispatch, see module docstring
        logger.exception(
            "scim_dispatch: trigger %r raised for event_type=%s tenant=%s actor=%s artifact=%s/%s",
            trigger_name,
            event_type,
            tenant_id,
            actor_user_id,
            artifact_type,
            artifact_id,
        )


# ---------------------------------------------------------------------------
# Trigger functions
# ---------------------------------------------------------------------------


def enqueue_user_self(
    tenant_id: str,
    artifact_id: str,
    metadata: dict[str, Any],
) -> None:
    """User lifecycle / attribute change. `artifact_id` is the user id.

    Enqueues `("user", user_id, sp_id)` for every SCIM-enabled SP the user
    has access to via existing group grants. If the user has no SCIM SPs
    in scope, this is a clean no-op.

    Honours `metadata["scim_pre_resolved_sps"]` when present: the emitter
    has resolved the SP scope before the underlying state change (e.g. a
    hard delete that cascades `group_memberships`) and we use that list
    instead of re-querying. The hint is a list of SP id strings; an empty
    list is a clean no-op.
    """
    import database

    user_id = artifact_id

    pre_resolved = metadata.get("scim_pre_resolved_sps")
    if pre_resolved is not None:
        sp_ids = [str(sp_id) for sp_id in pre_resolved]
        for sp_id in sp_ids:
            try:
                queue.enqueue_user(tenant_id, sp_id, user_id)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "enqueue_user_self: enqueue failed (tenant=%s user=%s sp=%s)",
                    tenant_id,
                    user_id,
                    sp_id,
                )
        return

    try:
        sps = database.scim_scope.scim_sps_granting_user(tenant_id, user_id)
    except Exception:  # noqa: BLE001
        logger.exception(
            "enqueue_user_self: scope lookup failed (tenant=%s user=%s)",
            tenant_id,
            user_id,
        )
        return

    for sp in sps:
        sp_id = str(sp["id"])
        try:
            queue.enqueue_user(tenant_id, sp_id, user_id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "enqueue_user_self: enqueue failed (tenant=%s user=%s sp=%s)",
                tenant_id,
                user_id,
                sp_id,
            )


def enqueue_group_self(
    tenant_id: str,
    artifact_id: str,
    metadata: dict[str, Any],
) -> None:
    """Group lifecycle (created / updated / deleted). `artifact_id` is the
    group id.

    Enqueues `("group", group_id, sp_id)` for every SCIM-enabled SP that
    grants access via this group or any ancestor in `group_lineage`.
    Members are not re-pushed for a pure group-metadata change;
    membership triggers handle actual membership churn.
    """
    import database

    group_id = artifact_id

    try:
        sps = database.scim_scope.scim_sps_granting_via_group(tenant_id, group_id)
    except Exception:  # noqa: BLE001
        logger.exception(
            "enqueue_group_self: scope lookup failed (tenant=%s group=%s)",
            tenant_id,
            group_id,
        )
        return

    for sp in sps:
        sp_id = str(sp["id"])
        try:
            queue.enqueue_group(tenant_id, sp_id, group_id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "enqueue_group_self: enqueue failed (tenant=%s group=%s sp=%s)",
                tenant_id,
                group_id,
                sp_id,
            )


def enqueue_membership_change(
    tenant_id: str,
    artifact_id: str,
    metadata: dict[str, Any],
) -> None:
    """Group-membership change. `artifact_id` is the group id.

    The affected user id(s) live in metadata:
    - Single change events carry `metadata["user_id"]`.
    - Bulk-membership events carry `metadata["user_ids"]` (a list).

    For each SCIM-enabled SP that grants access via this group or any
    ancestor in `group_lineage`, enqueues `("user", user_id, sp_id)` for
    every affected user. SPs in `scim_membership_mode='direct'` also get
    `("group", group_id, sp_id)` so the group resource's `members` reflect
    the change.
    """
    import database

    group_id = artifact_id

    user_ids = _resolve_user_ids_from_membership_metadata(metadata)
    if not user_ids:
        logger.warning(
            "enqueue_membership_change: no user_id(s) in metadata for group=%s tenant=%s",
            group_id,
            tenant_id,
        )
        return

    try:
        sps = database.scim_scope.scim_sps_granting_via_group(tenant_id, group_id)
    except Exception:  # noqa: BLE001
        logger.exception(
            "enqueue_membership_change: scope lookup failed (tenant=%s group=%s)",
            tenant_id,
            group_id,
        )
        return

    for sp in sps:
        sp_id = str(sp["id"])
        for user_id in user_ids:
            try:
                queue.enqueue_user(tenant_id, sp_id, user_id)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "enqueue_membership_change: user enqueue failed (tenant=%s user=%s sp=%s)",
                    tenant_id,
                    user_id,
                    sp_id,
                )

        if sp.get("scim_membership_mode") == "direct":
            try:
                queue.enqueue_group(tenant_id, sp_id, group_id)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "enqueue_membership_change: group enqueue failed (tenant=%s group=%s sp=%s)",
                    tenant_id,
                    group_id,
                    sp_id,
                )


def enqueue_grant_fan_out(
    tenant_id: str,
    artifact_id: str,
    metadata: dict[str, Any],
) -> None:
    """SP-group assignment created/removed/bulk.

    For single-group events (`sp_group_assigned`, `sp_group_unassigned`)
    `artifact_id` is the SP id and `metadata["group_id"]` is the group.
    For bulk (`sp_groups_bulk_assigned`) `metadata["group_ids"]` is the
    list of groups.

    For each (sp, group) pair where the SP has SCIM enabled, resolves
    every transitive member of the group via the closure table and
    enqueues `("user", user_id, sp_id)`. Also enqueues
    `("group", group_id, sp_id)` so the SP sees the group resource itself.
    """
    import database

    sp_id = artifact_id
    group_ids = _resolve_group_ids_from_grant_metadata(metadata)
    if not group_ids:
        logger.warning(
            "enqueue_grant_fan_out: no group_id(s) in metadata for sp=%s tenant=%s",
            sp_id,
            tenant_id,
        )
        return

    try:
        scim_enabled = database.scim_scope.is_scim_enabled_sp(tenant_id, sp_id)
    except Exception:  # noqa: BLE001
        logger.exception(
            "enqueue_grant_fan_out: SP lookup failed (tenant=%s sp=%s)",
            tenant_id,
            sp_id,
        )
        return

    if not scim_enabled:
        return

    for group_id in group_ids:
        try:
            user_ids = database.scim_scope.transitive_user_ids_for_group(tenant_id, group_id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "enqueue_grant_fan_out: member lookup failed (tenant=%s group=%s)",
                tenant_id,
                group_id,
            )
            continue

        for user_id in user_ids:
            try:
                queue.enqueue_user(tenant_id, sp_id, user_id)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "enqueue_grant_fan_out: user enqueue failed (tenant=%s sp=%s user=%s)",
                    tenant_id,
                    sp_id,
                    user_id,
                )

        try:
            queue.enqueue_group(tenant_id, sp_id, group_id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "enqueue_grant_fan_out: group enqueue failed (tenant=%s sp=%s group=%s)",
                tenant_id,
                sp_id,
                group_id,
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_user_ids_from_membership_metadata(metadata: dict[str, Any]) -> list[str]:
    """Pull the affected user ids out of group_member_(added|removed)
    and the bulk equivalents.

    The single-event services use `metadata["user_id"]`; the bulk ones use
    `metadata["user_ids"]`. Returns `[]` if neither key is present or both
    are empty.
    """
    single = metadata.get("user_id")
    multi = metadata.get("user_ids")
    if single and not multi:
        return [str(single)]
    if multi:
        return [str(uid) for uid in multi if uid]
    return []


def _resolve_group_ids_from_grant_metadata(metadata: dict[str, Any]) -> list[str]:
    """Pull the affected group ids out of sp_group_(assigned|unassigned)
    and the bulk equivalent.

    Single-event services use `metadata["group_id"]`; the bulk one uses
    `metadata["group_ids"]`. Returns `[]` if neither key is present.
    """
    single = metadata.get("group_id")
    multi = metadata.get("group_ids")
    if single and not multi:
        return [str(single)]
    if multi:
        return [str(gid) for gid in multi if gid]
    return []


# ---------------------------------------------------------------------------
# Trigger registry
# ---------------------------------------------------------------------------


def enqueue_sp_tenant_fan_out(
    tenant_id: str,
    artifact_id: str,
    metadata: dict[str, Any],
) -> None:
    """SP `available_to_all` toggle. `artifact_id` is the SP id.

    When an SP with `available_to_all=true` is flipped (true->false or
    false->true), every tenant user's scope for that SP changes. This
    trigger walks every tenant user and enqueues a per-user push (the
    worker re-evaluates "still in scope?" at push time and emits the
    right verb: a deprovision for users who lost access, a create for
    users who gained it).

    The trigger reads `metadata["available_to_all"]` to confirm the
    change applies and `metadata["previous_available_to_all"]` to skip
    no-op events. If `available_to_all` is unchanged the dispatch is a
    no-op (this is the common case for `sp_access_mode_updated` events
    emitted by other shape changes in the future).
    """
    import database

    sp_id = artifact_id
    new_value = metadata.get("available_to_all")
    previous_value = metadata.get("previous_available_to_all")

    # If the metadata doesn't carry the toggle we cannot tell what
    # changed; bail to avoid enqueuing a tenant-wide fan-out by accident.
    if new_value is None:
        logger.warning(
            "enqueue_sp_tenant_fan_out: missing available_to_all metadata (sp=%s tenant=%s)",
            sp_id,
            tenant_id,
        )
        return

    # No actual change -> no fan-out.
    if previous_value is not None and bool(previous_value) == bool(new_value):
        return

    try:
        scim_enabled = database.scim_scope.is_scim_enabled_sp(tenant_id, sp_id)
    except Exception:  # noqa: BLE001
        logger.exception(
            "enqueue_sp_tenant_fan_out: SP lookup failed (tenant=%s sp=%s)",
            tenant_id,
            sp_id,
        )
        return

    if not scim_enabled:
        return

    try:
        user_ids = database.scim_scope.tenant_user_ids(tenant_id)
    except Exception:  # noqa: BLE001
        logger.exception(
            "enqueue_sp_tenant_fan_out: tenant user lookup failed (tenant=%s)",
            tenant_id,
        )
        return

    for user_id in user_ids:
        try:
            queue.enqueue_user(tenant_id, sp_id, user_id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "enqueue_sp_tenant_fan_out: enqueue failed (tenant=%s sp=%s user=%s)",
                tenant_id,
                sp_id,
                user_id,
            )


_TRIGGERS: dict[str, Callable[[str, str, dict[str, Any]], None]] = {
    "enqueue_user_self": enqueue_user_self,
    "enqueue_group_self": enqueue_group_self,
    "enqueue_membership_change": enqueue_membership_change,
    "enqueue_grant_fan_out": enqueue_grant_fan_out,
    "enqueue_sp_tenant_fan_out": enqueue_sp_tenant_fan_out,
}
