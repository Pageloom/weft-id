"""Thin service wrapper over the SCIM push-queue database primitive.

The database layer (`database.scim_push_queue.upsert_entry`) is the dedupe
upsert primitive keyed `(sp_id, resource_type, resource_id)`. These wrappers
exist so dispatch code calls a typed, intention-revealing function instead
of passing literal resource-type strings around.

Re-enqueue is idempotent: bursts collapse into a single pending row via the
underlying UNIQUE constraint. See `database.scim_push_queue` for full
semantics.
"""

from __future__ import annotations

import database


def enqueue_user(tenant_id: str, sp_id: str, user_id: str) -> None:
    """Enqueue a SCIM push for one user resource against one SP."""
    database.scim_push_queue.upsert_entry(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        sp_id=sp_id,
        resource_type="user",
        resource_id=user_id,
    )


def enqueue_users_bulk(tenant_id: str, sp_id: str, user_ids: list[str]) -> int:
    """Enqueue SCIM pushes for many users against one SP in a single
    chunked statement.

    Wraps `database.scim_push_queue.bulk_upsert_users`. Use this when a
    fan-out touches "every user in the tenant" or any other batch large
    enough that one-by-one upserts would dominate the request latency.
    For single-user changes (the common path), keep using `enqueue_user`.

    An empty `user_ids` list is a clean no-op. Returns the number of
    rows affected.
    """
    return database.scim_push_queue.bulk_upsert_users(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        sp_id=sp_id,
        user_ids=user_ids,
    )


def enqueue_group(tenant_id: str, sp_id: str, group_id: str) -> None:
    """Enqueue a SCIM push for one group resource against one SP."""
    database.scim_push_queue.upsert_entry(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        sp_id=sp_id,
        resource_type="group",
        resource_id=group_id,
    )
