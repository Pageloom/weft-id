"""Back-channel logout deliveries (OpenID Connect Back-Channel Logout 1.0).

``oidc_backchannel_logout_deliveries`` is both the worker's queue and the
delivery log: one row per (ended session, client), queued by
``consume_session_clients`` and moved to ``delivered`` or ``failed`` by the
worker. ``client_id`` in the table is the client's internal UUID.

Cross-tenant reads and sweeps go through SECURITY DEFINER functions
(migration 0065); the table itself has strict tenant RLS.
"""

from database._core import UNSCOPED, TenantArg, execute, fetchall, fetchone


def list_tenants_with_due_deliveries() -> list[str]:
    """Tenant IDs that have pending deliveries whose next attempt is due."""
    rows = fetchall(
        UNSCOPED,
        "select tenant_id from list_tenants_with_due_backchannel_logouts()",
    )
    return [str(row["tenant_id"]) for row in rows]


def claim_due_deliveries(tenant_id: TenantArg, *, limit: int, lease_seconds: int) -> list[dict]:
    """Lease up to ``limit`` due deliveries and return them with their client.

    Leasing pushes ``next_attempt_at`` out by ``lease_seconds`` in the same
    statement that selects the rows (``for update skip locked``), so two
    workers never send the same delivery. The caller records the outcome with
    ``mark_delivered`` / ``mark_retry`` / ``mark_failed``; a worker that dies
    mid-send leaves the row to be retried when the lease runs out.

    Each dict has the delivery's ``id``, ``client_uuid``, ``sub``, ``sid``,
    ``issuer`` and ``attempts`` (before this one), and the client's public
    ``client_id``, ``client_type``, ``is_active``, ``oidc_enabled``,
    ``backchannel_logout_uri`` and ``backchannel_logout_session_required``.
    """
    return fetchall(
        tenant_id,
        """
        with due as (
            select id
            from oidc_backchannel_logout_deliveries
            where status = 'pending' and next_attempt_at <= now()
            order by next_attempt_at
            limit :limit
            for update skip locked
        )
        update oidc_backchannel_logout_deliveries d
        set next_attempt_at = now() + make_interval(secs => :lease_seconds)
        from due, oauth2_clients c
        where d.id = due.id and c.id = d.client_id
        returning d.id, d.client_id as client_uuid, d.sub, d.sid, d.issuer, d.attempts,
                  c.client_id, c.client_type, c.is_active, c.oidc_enabled,
                  c.backchannel_logout_uri, c.backchannel_logout_session_required
        """,
        {"limit": limit, "lease_seconds": lease_seconds},
    )


def list_client_deliveries(
    tenant_id: TenantArg,
    client_uuid: str,
    *,
    status: str | None = None,
    limit: int,
    offset: int = 0,
) -> list[dict]:
    """A client's deliveries, newest first, with the user's name and email.

    ``status`` filters to one status. The user columns are NULL when the user
    has since been deleted (``sub`` still holds their id). Each dict has
    ``id``, ``sub``, ``status``, ``attempts``, ``last_http_status``,
    ``last_error``, ``created_at``, ``last_attempt_at``, ``next_attempt_at``,
    ``completed_at``, ``user_first_name``, ``user_last_name``, ``user_email``.
    """
    return fetchall(
        tenant_id,
        """
        select d.id, d.sub, d.status, d.attempts, d.last_http_status, d.last_error,
               d.created_at, d.last_attempt_at, d.next_attempt_at, d.completed_at,
               u.first_name as user_first_name, u.last_name as user_last_name,
               ue.email as user_email
        from oidc_backchannel_logout_deliveries d
        left join users u on u.id = cast(d.sub as uuid)
        left join user_emails ue on ue.user_id = u.id and ue.is_primary
        where d.client_id = :client_id
          and (cast(:status as text) is null or d.status = :status)
        order by d.created_at desc, d.id
        limit :limit offset :offset
        """,
        {"client_id": client_uuid, "status": status, "limit": limit, "offset": offset},
    )


def count_client_deliveries_by_status(tenant_id: TenantArg, client_uuid: str) -> dict[str, int]:
    """Count a client's deliveries per status (every status key present)."""
    row = fetchone(
        tenant_id,
        """
        select count(*) filter (where status = 'pending') as pending,
               count(*) filter (where status = 'delivered') as delivered,
               count(*) filter (where status = 'failed') as failed
        from oidc_backchannel_logout_deliveries
        where client_id = :client_id
        """,
        {"client_id": client_uuid},
    )
    row = row or {}
    return {key: int(row.get(key) or 0) for key in ("pending", "delivered", "failed")}


def mark_delivered(tenant_id: TenantArg, delivery_id: str, *, http_status: int) -> int:
    """Record a successful attempt; the delivery is finished."""
    return execute(
        tenant_id,
        """
        update oidc_backchannel_logout_deliveries
        set status = 'delivered', attempts = attempts + 1, last_attempt_at = now(),
            completed_at = now(), last_http_status = :http_status, last_error = null
        where id = :id and status = 'pending'
        """,
        {"id": delivery_id, "http_status": http_status},
    )


def mark_retry(
    tenant_id: TenantArg,
    delivery_id: str,
    *,
    retry_in_seconds: int,
    error: str,
    http_status: int | None,
) -> int:
    """Record a failed attempt and schedule the next one."""
    return execute(
        tenant_id,
        """
        update oidc_backchannel_logout_deliveries
        set attempts = attempts + 1, last_attempt_at = now(),
            next_attempt_at = now() + make_interval(secs => :retry_in_seconds),
            last_http_status = :http_status, last_error = :error
        where id = :id and status = 'pending'
        """,
        {
            "id": delivery_id,
            "retry_in_seconds": retry_in_seconds,
            "http_status": http_status,
            "error": error[:1000],
        },
    )


def mark_failed(
    tenant_id: TenantArg,
    delivery_id: str,
    *,
    error: str,
    http_status: int | None,
    count_attempt: bool = True,
) -> int:
    """Give the delivery up.

    With ``count_attempt`` (the default) this records a final failed attempt;
    without it the delivery is closed without one (the client no longer takes
    part in back-channel logout).
    """
    return execute(
        tenant_id,
        """
        update oidc_backchannel_logout_deliveries
        set status = 'failed', completed_at = now(), last_error = :error,
            attempts = attempts + :increment,
            last_attempt_at = case when :increment = 1 then now() else last_attempt_at end,
            last_http_status = case when :increment = 1 then :http_status
                                    else last_http_status end
        where id = :id and status = 'pending'
        """,
        {
            "id": delivery_id,
            "http_status": http_status,
            "error": error[:1000],
            "increment": 1 if count_attempt else 0,
        },
    )


def purge_finished_deliveries(*, older_than_days: int) -> int:
    """Delete delivered/failed rows finished more than ``older_than_days`` ago.

    Cross-tenant (SECURITY DEFINER function); returns the number deleted.
    """
    rows = fetchall(
        UNSCOPED,
        "select purge_backchannel_logout_deliveries(make_interval(days => :days)) as n",
        {"days": older_than_days},
    )
    return int(rows[0]["n"]) if rows else 0


def sweep_stale_session_clients(*, older_than_days: int) -> int:
    """Delete ``oidc_session_clients`` rows last written ``older_than_days`` ago.

    These belong to sessions that ended without a logout (an expired cookie)
    and so were never consumed. Cross-tenant (SECURITY DEFINER function);
    returns the number deleted.
    """
    rows = fetchall(
        UNSCOPED,
        "select sweep_stale_oidc_session_clients(make_interval(days => :days)) as n",
        {"days": older_than_days},
    )
    return int(rows[0]["n"]) if rows else 0
