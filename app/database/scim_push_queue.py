"""Outbound SCIM push queue (coalescing outbox).

Entries are keyed by `(sp_id, resource_type, resource_id)` so that bursts
of changes against the same resource collapse to a single pending row. On
re-enqueue (`upsert_entry`), `enqueued_at` is bumped and `attempts` /
`next_attempt_at` / `last_error` are reset so a previously-failing entry
gets a fresh shot after a new change lands.

The push worker skips rows where `dead_letter_at IS NOT NULL`.
"""

from typing import Any

from ._core import UNSCOPED, TenantArg, execute, fetchall, fetchone


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


# Chunk size for `bulk_upsert_users`. Keeps each statement under Postgres'
# default `max_locks_per_transaction` and prevents the generated query from
# growing unbounded for very large tenants. Picked 1000 because:
# - At 1000 rows, the INSERT ... VALUES list is ~30 KB which is well within
#   the libpq buffer size.
# - 10 statements drains a 10k-user tenant; the round-trip count is small
#   enough to keep the request-thread cost reasonable even for the upper
#   bound the fan-out trigger expects to see.
_BULK_UPSERT_CHUNK_SIZE = 1000


def bulk_upsert_users(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sp_id: str,
    user_ids: list[str],
) -> int:
    """Enqueue (or refresh) a SCIM push for many users on one SP.

    Equivalent to calling `upsert_entry(..., 'user', user_id)` once per
    user but executed as one (or a small number of) batched INSERT ...
    VALUES ... ON CONFLICT statements instead of N synchronous round
    trips. Used by `enqueue_sp_tenant_fan_out` to keep a tenant-wide
    `available_to_all` toggle from monopolising the request thread.

    Semantics match `upsert_entry`:
    - New rows start with `attempts=0`, `next_attempt_at=NULL`,
      `last_error=NULL`, `dead_letter_at=NULL`.
    - Existing rows have `enqueued_at` bumped to `now()` and `attempts`,
      `next_attempt_at`, `last_error` reset. `dead_letter_at` is preserved
      so the worker keeps skipping known-bad rows until an explicit revive.

    Chunking: rows are inserted in groups of `_BULK_UPSERT_CHUNK_SIZE` to
    keep each statement bounded. An empty `user_ids` list is a clean
    no-op.

    Returns:
        Total number of rows inserted or updated across all chunks.
    """
    if not user_ids:
        return 0

    total = 0
    for start in range(0, len(user_ids), _BULK_UPSERT_CHUNK_SIZE):
        chunk = user_ids[start : start + _BULK_UPSERT_CHUNK_SIZE]

        # Build a parameterised VALUES list. Each row gets its own named
        # placeholder so psycopg validates them; the bulk parameter
        # `tenant_id` / `sp_id` are shared across all rows.
        values_clauses: list[str] = []
        params: dict[str, Any] = {
            "tenant_id": tenant_id_value,
            "sp_id": sp_id,
        }
        for i, uid in enumerate(chunk):
            placeholder = f"uid_{i}"
            values_clauses.append(f"(:tenant_id, :sp_id, 'user', :{placeholder})")
            params[placeholder] = uid

        affected = execute(
            tenant_id,
            f"""
            insert into scim_push_queue (
                tenant_id, sp_id, resource_type, resource_id
            ) values {", ".join(values_clauses)}
            on conflict (sp_id, resource_type, resource_id) do update set
                enqueued_at = now(),
                attempts = 0,
                next_attempt_at = null,
                last_error = null
            """,
            params,
        )
        total += affected

    return total


def list_ready_entries(
    tenant_id: TenantArg,
    sp_id: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """List queue entries ready to be processed.

    An entry is "ready" when it is not dead-lettered and either has no
    `next_attempt_at` or its `next_attempt_at` is in the past.

    Locking semantics: uses `FOR UPDATE SKIP LOCKED` so concurrent worker
    containers do not pick up the same row. `SKIP LOCKED` means "another
    transaction has already selected this row -- skip it rather than
    wait". The row locks are held for the duration of the current
    transaction; the caller is responsible for opening a tenant-scoped
    `session(tenant_id=...)` and keeping it open until the per-entry
    queue mutation (`mark_attempt_failed` / `mark_dead_letter` /
    `delete_entry`) commits. Rows visible to a stale worker (one whose
    transaction has already released the lock) are protected at the
    next-scan step too: each successful mutation either advances
    `next_attempt_at` or removes the row, so a re-read in another worker
    skips them by predicate.

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
        for update skip locked
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


def list_tenants_with_ready_entries() -> list[str]:
    """List distinct tenant ids that have at least one ready queue entry.

    Cross-tenant scan used by the push worker to discover which tenants need
    processing without iterating over every tenant unnecessarily. Uses
    UNSCOPED to bypass RLS (system task).
    """
    rows = fetchall(
        UNSCOPED,
        """
        select distinct tenant_id
        from scim_push_queue
        where dead_letter_at is null
          and (next_attempt_at is null or next_attempt_at <= now())
        """,
    )
    return [str(row["tenant_id"]) for row in rows]


def revive_dead_lettered_for_sp(tenant_id: TenantArg, sp_id: str) -> int:
    """Clear `dead_letter_at` on every dead-lettered row for one SP.

    Resets `attempts` and `next_attempt_at` on each revived row so the
    worker treats them as fresh entries. `last_error` is preserved as a
    breadcrumb. Returns the number of rows revived.
    """
    return execute(
        tenant_id,
        """
        update scim_push_queue
        set dead_letter_at = null,
            attempts = 0,
            next_attempt_at = null
        where sp_id = :sp_id and dead_letter_at is not null
        """,
        {"sp_id": sp_id},
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
