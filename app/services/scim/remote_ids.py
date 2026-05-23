"""WeftID -> SP-id mapping helpers with audit logging.

Sits between the worker and `database.scim_remote_ids`. The split exists
so the worker stays focused on dispatch logic while audit event emission
(and the wrapping `system_context()`) lives next to the rest of the SCIM
service code.

Audit events emitted here:

- ``scim_remote_id_mapped`` -- the receiver returned an `id` for the first
  time. Emitted only on the *first* successful mapping for a given
  (sp, resource_type, weftid_id); resync churn (re-POST after invalidation)
  does not re-fire because the upsert reports `was_inserted=False`.
- ``scim_remote_id_invalidated`` -- a 404 against a known mapping cleared
  the row so the next attempt re-POSTs. Emitted only when a row was
  actually deleted, so missing-mapping cases stay quiet.

Both events are operational tier (audit trail for "this happened" without
admin-visible noise). They are NOT in `EVENT_TYPE_SCIM_TRIGGERS`: dispatch
on a remote-id event would self-loop into the same queue we just drained.
"""

from __future__ import annotations

import logging

import database
from services.event_log import SYSTEM_ACTOR_ID, log_event
from utils.request_context import system_context

logger = logging.getLogger(__name__)


def record_mapping(
    tenant_id: str,
    sp_id: str,
    resource_type: str,
    weftid_id: str,
    remote_id: str,
) -> None:
    """Upsert the (sp, resource_type, weftid_id) -> remote_id mapping.

    Emits `scim_remote_id_mapped` only when the row is newly inserted
    (first time we have a mapping for this triple). Re-POSTs after a
    previous invalidation also count as "newly mapped" because the prior
    row was deleted by `invalidate_mapping`; the upsert produces a fresh
    INSERT, not an UPDATE.
    """
    try:
        _, was_inserted = database.scim_remote_ids.upsert(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            sp_id=sp_id,
            resource_type=resource_type,
            weftid_id=weftid_id,
            remote_id=remote_id,
        )
    except Exception:  # noqa: BLE001 -- best-effort observability
        logger.exception(
            "record_mapping: upsert failed (tenant=%s sp=%s %s=%s)",
            tenant_id,
            sp_id,
            resource_type,
            weftid_id,
        )
        return

    if not was_inserted:
        return

    try:
        with system_context():
            log_event(
                tenant_id=tenant_id,
                actor_user_id=SYSTEM_ACTOR_ID,
                event_type="scim_remote_id_mapped",
                artifact_type=resource_type,
                artifact_id=weftid_id,
                metadata={
                    "sp_id": sp_id,
                    "resource_type": resource_type,
                    "remote_id": remote_id,
                },
            )
    except Exception:  # noqa: BLE001
        logger.exception(
            "record_mapping: audit log failed (tenant=%s sp=%s %s=%s)",
            tenant_id,
            sp_id,
            resource_type,
            weftid_id,
        )


def invalidate_mapping(
    tenant_id: str,
    sp_id: str,
    resource_type: str,
    weftid_id: str,
    *,
    reason: str = "remote_404",
) -> bool:
    """Delete the mapping row so the next attempt re-POSTs.

    Returns True when a row was actually deleted (and an audit event was
    emitted). Returns False when no mapping existed (the worker called us
    defensively after a 404 without ever having had a mapping in the first
    place) -- in that case no audit event fires.
    """
    try:
        affected = database.scim_remote_ids.delete(tenant_id, sp_id, resource_type, weftid_id)
    except Exception:  # noqa: BLE001
        logger.exception(
            "invalidate_mapping: delete failed (tenant=%s sp=%s %s=%s)",
            tenant_id,
            sp_id,
            resource_type,
            weftid_id,
        )
        return False

    if affected == 0:
        return False

    try:
        with system_context():
            log_event(
                tenant_id=tenant_id,
                actor_user_id=SYSTEM_ACTOR_ID,
                event_type="scim_remote_id_invalidated",
                artifact_type=resource_type,
                artifact_id=weftid_id,
                metadata={
                    "sp_id": sp_id,
                    "resource_type": resource_type,
                    "reason": reason,
                },
            )
    except Exception:  # noqa: BLE001
        logger.exception(
            "invalidate_mapping: audit log failed (tenant=%s sp=%s %s=%s)",
            tenant_id,
            sp_id,
            resource_type,
            weftid_id,
        )
    return True
