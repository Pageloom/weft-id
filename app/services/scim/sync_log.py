"""SCIM sync-log service helpers.

The push worker writes one `scim_sync_log` row per attempt, in lockstep
with mutations to `scim_push_queue`. These helpers exist so the worker
calls intention-revealing service functions instead of poking at the
database module's positional kwargs.

Sync-log writes are best-effort observability and do NOT have to be
atomic with the queue mutation: worst case the crashed-mid-attempt
worker leaves a `running` row in the log that the next pass overwrites
when it retries the same queue entry. See the iteration guidance.

Also exposes `retention_to_interval()` -- the mapping from the per-SP
`scim_log_retention` enum value (`'3' | '6' | '12' | '24' | 'forever'`)
to a Postgres interval string that the database cleanup primitive
accepts. The `'forever'` value is signaled by returning `None` so the
caller can skip the SP.
"""

from __future__ import annotations

import database


def retention_to_interval(retention: str) -> str | None:
    """Map a `scim_log_retention` enum value to a Postgres interval string.

    Returns `None` for the sentinel value `'forever'`, instructing the
    caller to skip cleanup for that SP. Unknown values raise so misconfig
    is loud instead of silently dropping rows.
    """
    if retention == "forever":
        return None
    table = {
        "3": "3 months",
        "6": "6 months",
        "12": "12 months",
        "24": "24 months",
    }
    if retention not in table:
        raise ValueError(
            f"retention must be one of '3', '6', '12', '24', 'forever', got {retention!r}"
        )
    return table[retention]


def start_attempt(
    tenant_id: str,
    sp_id: str,
    resource_type: str,
    resource_id: str,
    attempt: int,
    started_at: object,
) -> str:
    """Open a new sync-log row for a fresh attempt.

    Status starts at `running`; the caller updates it to a terminal state
    via one of the `mark_*` helpers when the attempt resolves.

    Returns the new sync-log row id.
    """
    row = database.scim_sync_log.create_entry(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        sp_id=sp_id,
        resource_type=resource_type,
        resource_id=resource_id,
        status="running",
        attempt=attempt,
        started_at=started_at,
    )
    return str(row["id"])


def mark_done(tenant_id: str, log_id: str) -> None:
    """Mark a sync-log row as successfully completed."""
    database.scim_sync_log.update_status(
        tenant_id=tenant_id,
        entry_id=log_id,
        status="done",
        error=None,
        completed=True,
    )


def mark_failed(tenant_id: str, log_id: str, error: str) -> None:
    """Mark a sync-log row as failed (retry pending)."""
    database.scim_sync_log.update_status(
        tenant_id=tenant_id,
        entry_id=log_id,
        status="failed",
        error=_truncate_error(error),
        completed=True,
    )


def mark_dead_letter(tenant_id: str, log_id: str, error: str) -> None:
    """Mark a sync-log row as dead-lettered after exhausting attempts."""
    database.scim_sync_log.update_status(
        tenant_id=tenant_id,
        entry_id=log_id,
        status="dead_letter",
        error=_truncate_error(error),
        completed=True,
    )


# The CHECK constraint on scim_sync_log.error is `length(error) <= 4000`.
# Leave some headroom for diagnostic prefixes that callers may add.
_MAX_ERROR_LENGTH = 3900


def _truncate_error(error: str | None) -> str | None:
    """Truncate error strings so they fit under the column CHECK length."""
    if error is None:
        return None
    if len(error) <= _MAX_ERROR_LENGTH:
        return error
    return error[: _MAX_ERROR_LENGTH - 3] + "..."
