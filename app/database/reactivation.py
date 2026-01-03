"""Reactivation request database operations."""

from ._core import TenantArg, execute, fetchall, fetchone


def create_request(
    tenant_id: TenantArg,
    tenant_id_value: str,
    user_id: str,
) -> dict | None:
    """
    Create a reactivation request for an inactivated user.

    Uses UPSERT to handle case where request already exists.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        user_id: User ID requesting reactivation

    Returns:
        Dict with request details, or None if insert failed
    """
    return fetchone(
        tenant_id,
        """
        insert into reactivation_requests (tenant_id, user_id)
        values (:tenant_id, :user_id)
        on conflict (tenant_id, user_id) do update
            set requested_at = now(),
                decided_by = null,
                decided_at = null,
                decision = null
        returning id, tenant_id, user_id, requested_at, decision
        """,
        {"tenant_id": tenant_id_value, "user_id": user_id},
    )


def get_pending_request(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get a pending reactivation request for a user.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to check

    Returns:
        Dict with request details if pending, None otherwise
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, user_id, requested_at
        from reactivation_requests
        where user_id = :user_id and decision is null
        """,
        {"user_id": user_id},
    )


def get_request_by_id(tenant_id: TenantArg, request_id: str) -> dict | None:
    """
    Get a reactivation request by ID.

    Args:
        tenant_id: Tenant ID for scoping
        request_id: Request ID to fetch

    Returns:
        Dict with request details, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select r.id, r.tenant_id, r.user_id, r.requested_at, r.decision,
               r.decided_by, r.decided_at,
               u.first_name, u.last_name,
               ue.email
        from reactivation_requests r
        join users u on r.user_id = u.id
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        where r.id = :request_id
        """,
        {"request_id": request_id},
    )


def list_pending_requests(tenant_id: TenantArg) -> list[dict]:
    """
    List all pending reactivation requests for a tenant.

    Args:
        tenant_id: Tenant ID for scoping

    Returns:
        List of dicts with request and user details
    """
    return fetchall(
        tenant_id,
        """
        select r.id, r.user_id, r.requested_at,
               u.first_name, u.last_name,
               ue.email
        from reactivation_requests r
        join users u on r.user_id = u.id
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        where r.decision is null
        order by r.requested_at desc
        """,
        {},
    )


def approve_request(
    tenant_id: TenantArg,
    request_id: str,
    decided_by: str,
) -> int:
    """
    Approve a reactivation request.

    Args:
        tenant_id: Tenant ID for scoping
        request_id: Request ID to approve
        decided_by: User ID of admin approving

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update reactivation_requests
        set decision = 'approved',
            decided_by = :decided_by,
            decided_at = now()
        where id = :request_id and decision is null
        """,
        {"request_id": request_id, "decided_by": decided_by},
    )


def deny_request(
    tenant_id: TenantArg,
    request_id: str,
    decided_by: str,
) -> int:
    """
    Deny a reactivation request.

    Args:
        tenant_id: Tenant ID for scoping
        request_id: Request ID to deny
        decided_by: User ID of admin denying

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update reactivation_requests
        set decision = 'denied',
            decided_by = :decided_by,
            decided_at = now()
        where id = :request_id and decision is null
        """,
        {"request_id": request_id, "decided_by": decided_by},
    )


def delete_request(tenant_id: TenantArg, request_id: str) -> int:
    """
    Delete a reactivation request (used after decision is processed).

    Args:
        tenant_id: Tenant ID for scoping
        request_id: Request ID to delete

    Returns:
        Number of rows deleted
    """
    return execute(
        tenant_id,
        "delete from reactivation_requests where id = :request_id",
        {"request_id": request_id},
    )


def count_pending_requests(tenant_id: TenantArg) -> int:
    """
    Count pending reactivation requests for a tenant.

    Args:
        tenant_id: Tenant ID for scoping

    Returns:
        Number of pending requests
    """
    result = fetchone(
        tenant_id,
        "select count(*) as count from reactivation_requests where decision is null",
        {},
    )
    return result["count"] if result else 0


def list_decided_requests(tenant_id: TenantArg) -> list[dict]:
    """
    List all decided (approved/denied) reactivation requests for a tenant.

    Args:
        tenant_id: Tenant ID for scoping

    Returns:
        List of dicts with request, user, and decision details
    """
    return fetchall(
        tenant_id,
        """
        select r.id, r.user_id, r.requested_at, r.decision, r.decided_at,
               u.first_name, u.last_name,
               ue.email,
               d.first_name as decided_by_first_name,
               d.last_name as decided_by_last_name
        from reactivation_requests r
        join users u on r.user_id = u.id
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        left join users d on r.decided_by = d.id
        where r.decision is not null
        order by r.decided_at desc
        """,
        {},
    )
