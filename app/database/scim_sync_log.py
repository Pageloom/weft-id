"""Outbound SCIM push outcome log.

Append-only history of push attempts. The worker writes one row per
attempt and updates its status as the attempt progresses. A nightly
cleanup job (iteration 4) is the only code that deletes rows, based on
the per-SP `service_providers.scim_log_retention` setting.

Schema reminder: status is one of
`'pending' | 'running' | 'done' | 'failed' | 'dead_letter'`.
"""

import re
from typing import Any

from ._core import TenantArg, execute, fetchall, fetchone

# Accepted retention interval expressions for cleanup.
_INTERVAL_RE = re.compile(
    r"^\s*(\d+)\s+(seconds?|minutes?|hours?|days?|weeks?|months?|years?)\s*$",
    re.IGNORECASE,
)


def create_entry(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sp_id: str,
    resource_type: str,
    resource_id: str,
    status: str = "pending",
    attempt: int = 0,
    started_at: Any = None,
) -> dict:
    """Append a new sync-log row.

    The worker typically inserts a row with `status='running'` and
    `started_at=now()` at the top of an attempt, then updates it with
    `update_status` when the attempt resolves.

    Returns:
        Dict for the inserted row.
    """
    result = fetchone(
        tenant_id,
        """
        insert into scim_sync_log (
            tenant_id, sp_id, resource_type, resource_id,
            status, attempt, started_at
        ) values (
            :tenant_id, :sp_id, :resource_type, :resource_id,
            :status, :attempt, :started_at
        )
        returning id, tenant_id, sp_id, resource_type, resource_id,
                  status, attempt, error, started_at, completed_at,
                  created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "sp_id": sp_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "status": status,
            "attempt": attempt,
            "started_at": started_at,
        },
    )
    assert result is not None
    return result


def update_status(
    tenant_id: TenantArg,
    entry_id: str,
    status: str,
    error: str | None = None,
    completed: bool = False,
) -> int:
    """Update the status of a sync-log row.

    When `completed=True`, `completed_at` is set to now(). Use this when
    the attempt has reached a terminal state (`done`, `failed`, or
    `dead_letter`).

    Returns:
        Number of rows updated.
    """
    if completed:
        return execute(
            tenant_id,
            """
            update scim_sync_log
            set status = :status,
                error = :error,
                completed_at = now()
            where id = :id
            """,
            {"id": entry_id, "status": status, "error": error},
        )
    return execute(
        tenant_id,
        """
        update scim_sync_log
        set status = :status,
            error = :error
        where id = :id
        """,
        {"id": entry_id, "status": status, "error": error},
    )


def list_recent_for_sp(
    tenant_id: TenantArg,
    sp_id: str,
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
) -> list[dict]:
    """List recent sync-log entries for a service provider.

    Ordered with in-flight rows first (`completed_at DESC NULLS FIRST`)
    and then by recency.

    Args:
        tenant_id: Tenant scope for RLS.
        sp_id: SP to filter by.
        limit: Page size.
        offset: Offset for pagination.
        status: Optional status filter.
    """
    params: dict[str, Any] = {"sp_id": sp_id, "limit": limit, "offset": offset}
    status_filter = ""
    if status is not None:
        status_filter = "and status = :status"
        params["status"] = status

    return fetchall(
        tenant_id,
        f"""
        select id, tenant_id, sp_id, resource_type, resource_id,
               status, attempt, error, started_at, completed_at,
               created_at
        from scim_sync_log
        where sp_id = :sp_id
          {status_filter}
        order by completed_at desc nulls first, created_at desc
        limit :limit offset :offset
        """,
        params,
    )


def count_for_sp(
    tenant_id: TenantArg,
    sp_id: str,
    status: str | None = None,
) -> int:
    """Count sync-log rows for a service provider, optionally filtered by status."""
    params: dict[str, Any] = {"sp_id": sp_id}
    status_filter = ""
    if status is not None:
        status_filter = "and status = :status"
        params["status"] = status

    row = fetchone(
        tenant_id,
        f"""
        select count(*) as c
        from scim_sync_log
        where sp_id = :sp_id
          {status_filter}
        """,
        params,
    )
    if not row:
        return 0
    return int(row["c"] or 0)


def delete_older_than(
    tenant_id: TenantArg,
    sp_id: str,
    retention_interval: str,
) -> int:
    """Delete rows older than `retention_interval` for a service provider.

    Called by the nightly cleanup job. `retention_interval` is a Postgres
    interval string such as `'3 months'`. Rows whose `completed_at` is
    older than the cutoff are removed; in-flight rows (`completed_at`
    NULL) are preserved.

    Returns:
        Number of rows deleted.
    """
    # psycopg's named-param parser treats `::interval` as a named parameter,
    # so we parse the interval expression and use make_interval() instead.
    match = _INTERVAL_RE.match(retention_interval)
    if not match:
        raise ValueError(f"retention_interval must be like '3 months', got {retention_interval!r}")
    qty = int(match.group(1))
    unit = match.group(2).lower().rstrip("s")
    column = {
        "second": "secs",
        "minute": "mins",
        "hour": "hours",
        "day": "days",
        "week": "weeks",
        "month": "months",
        "year": "years",
    }[unit]
    return execute(
        tenant_id,
        f"""
        delete from scim_sync_log
        where sp_id = :sp_id
          and completed_at is not null
          and completed_at < now() - make_interval({column} => :qty)
        """,
        {"sp_id": sp_id, "qty": qty},
    )
