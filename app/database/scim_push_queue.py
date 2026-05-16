"""Outbound SCIM push queue (coalescing outbox).

Entries are keyed by `(sp_id, resource_type, resource_id)` so that bursts
of changes against the same resource collapse to a single pending row. On
re-enqueue (`upsert_entry`), `enqueued_at` is bumped and `attempts` /
`next_attempt_at` / `last_error` are reset so a previously-failing entry
gets a fresh shot after a new change lands.

The push worker skips rows where `dead_letter_at IS NOT NULL`.
"""

from typing import Any

from ._core import TenantArg, execute, fetchall, fetchone


def upsert_entry(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sp_id: str,
    resource_type: str,
    resource_id: str,
) -> dict:
    """Enqueue (or refresh) a push for one resource on one SP.

    Implements the dedupe upsert primitive: a re-enqueue resets the entry
    so retries-after-failure get a fresh attempts=0 / next_attempt_at=NULL
    state, but `dead_letter_at` is preserved so the worker continues to
    skip dead-lettered rows until a separate retry action clears the flag.

    Returns:
        Dict for the upserted row.
    """
    result = fetchone(
        tenant_id,
        """
        insert into scim_push_queue (
            tenant_id, sp_id, resource_type, resource_id
        ) values (
            :tenant_id, :sp_id, :resource_type, :resource_id
        )
        on conflict (sp_id, resource_type, resource_id) do update set
            enqueued_at = now(),
            attempts = 0,
            next_attempt_at = null,
            last_error = null
        returning id, tenant_id, sp_id, resource_type, resource_id,
                  enqueued_at, attempts, next_attempt_at, last_error,
                  dead_letter_at
        """,
        {
            "tenant_id": tenant_id_value,
            "sp_id": sp_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
        },
    )
    assert result is not None
    return result


def list_ready_entries(
    tenant_id: TenantArg,
    sp_id: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """List queue entries ready to be processed.

    An entry is "ready" when it is not dead-lettered and either has no
    `next_attempt_at` or its `next_attempt_at` is in the past.

    Args:
        tenant_id: Tenant scope for RLS.
        sp_id: If provided, restrict to a single SP.
        limit: Maximum rows to return (oldest enqueued_at first).
    """
    params: dict[str, Any] = {"limit": limit}
    sp_filter = ""
    if sp_id is not None:
        sp_filter = "and sp_id = :sp_id"
        params["sp_id"] = sp_id

    return fetchall(
        tenant_id,
        f"""
        select id, tenant_id, sp_id, resource_type, resource_id,
               enqueued_at, attempts, next_attempt_at, last_error,
               dead_letter_at
        from scim_push_queue
        where dead_letter_at is null
          and (next_attempt_at is null or next_attempt_at <= now())
          {sp_filter}
        order by enqueued_at
        limit :limit
        """,
        params,
    )


def get_entry(tenant_id: TenantArg, entry_id: str) -> dict | None:
    """Fetch a single queue entry by id."""
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, sp_id, resource_type, resource_id,
               enqueued_at, attempts, next_attempt_at, last_error,
               dead_letter_at
        from scim_push_queue
        where id = :id
        """,
        {"id": entry_id},
    )


def mark_attempt_failed(
    tenant_id: TenantArg,
    entry_id: str,
    error: str,
    next_attempt_at: Any,
) -> int:
    """Record a failed attempt and schedule the next try.

    Increments `attempts`, sets `next_attempt_at`, and stores `last_error`.

    Returns:
        Number of rows updated.
    """
    return execute(
        tenant_id,
        """
        update scim_push_queue
        set attempts = attempts + 1,
            next_attempt_at = :next_attempt_at,
            last_error = :error
        where id = :id
        """,
        {
            "id": entry_id,
            "next_attempt_at": next_attempt_at,
            "error": error,
        },
    )


def mark_dead_letter(tenant_id: TenantArg, entry_id: str, error: str) -> int:
    """Mark an entry as dead-lettered.

    The worker will skip rows with `dead_letter_at IS NOT NULL`. Use
    `clear_dead_letter` to revive an entry for retry.

    Returns:
        Number of rows updated.
    """
    return execute(
        tenant_id,
        """
        update scim_push_queue
        set dead_letter_at = now(),
            last_error = :error
        where id = :id
        """,
        {"id": entry_id, "error": error},
    )


def clear_dead_letter(tenant_id: TenantArg, entry_id: str) -> int:
    """Revive a dead-lettered entry for another round of attempts.

    Clears `dead_letter_at`, resets `attempts` and `next_attempt_at` so the
    worker picks it up on the next run. `last_error` is preserved for
    diagnostics; it will be overwritten on the next failure.

    Returns:
        Number of rows updated.
    """
    return execute(
        tenant_id,
        """
        update scim_push_queue
        set dead_letter_at = null,
            attempts = 0,
            next_attempt_at = null
        where id = :id and dead_letter_at is not null
        """,
        {"id": entry_id},
    )


def delete_entry(tenant_id: TenantArg, entry_id: str) -> int:
    """Remove a queue entry. Used after a successful push.

    Returns:
        Number of rows deleted.
    """
    return execute(
        tenant_id,
        "delete from scim_push_queue where id = :id",
        {"id": entry_id},
    )


def count_pending_for_sp(tenant_id: TenantArg, sp_id: str) -> dict:
    """Get pending and dead-letter counts for a service provider."""
    row = fetchone(
        tenant_id,
        """
        select
            count(*) filter (where dead_letter_at is null) as pending,
            count(*) filter (where dead_letter_at is not null) as dead_lettered
        from scim_push_queue
        where sp_id = :sp_id
        """,
        {"sp_id": sp_id},
    )
    if not row:
        return {"pending": 0, "dead_lettered": 0}
    return {
        "pending": int(row["pending"] or 0),
        "dead_lettered": int(row["dead_lettered"] or 0),
    }
