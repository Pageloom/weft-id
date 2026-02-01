"""Group membership database operations."""

from database._core import TenantArg, execute, fetchall, fetchone


def get_group_members(
    tenant_id: TenantArg,
    group_id: str,
    page: int = 1,
    page_size: int = 50,
) -> list[dict]:
    """Get direct members of a group with user details."""
    offset = (page - 1) * page_size
    return fetchall(
        tenant_id,
        """
        select gm.id, gm.user_id, gm.created_at,
               u.first_name, u.last_name,
               ue.email
        from group_memberships gm
        join users u on gm.user_id = u.id
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        where gm.group_id = :group_id
        order by gm.created_at desc
        limit :limit offset :offset
        """,
        {"group_id": group_id, "limit": page_size, "offset": offset},
    )


def count_group_members(tenant_id: TenantArg, group_id: str) -> int:
    """Count direct members of a group."""
    result = fetchone(
        tenant_id,
        "select count(*) as count from group_memberships where group_id = :group_id",
        {"group_id": group_id},
    )
    return result["count"] if result else 0


def is_group_member(tenant_id: TenantArg, group_id: str, user_id: str) -> bool:
    """Check if a user is a direct member of a group."""
    result = fetchone(
        tenant_id,
        """
        select 1 from group_memberships
        where group_id = :group_id and user_id = :user_id
        """,
        {"group_id": group_id, "user_id": user_id},
    )
    return result is not None


def add_group_member(
    tenant_id: TenantArg,
    tenant_id_value: str,
    group_id: str,
    user_id: str,
) -> dict | None:
    """Add a user to a group."""
    return fetchone(
        tenant_id,
        """
        insert into group_memberships (tenant_id, group_id, user_id)
        values (:tenant_id, :group_id, :user_id)
        on conflict (group_id, user_id) do nothing
        returning id
        """,
        {"tenant_id": tenant_id_value, "group_id": group_id, "user_id": user_id},
    )


def remove_group_member(tenant_id: TenantArg, group_id: str, user_id: str) -> int:
    """Remove a user from a group."""
    return execute(
        tenant_id,
        "delete from group_memberships where group_id = :group_id and user_id = :user_id",
        {"group_id": group_id, "user_id": user_id},
    )


def get_user_groups(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """Get all groups a user is a direct member of."""
    return fetchall(
        tenant_id,
        """
        select g.id, g.name, g.description, g.group_type, gm.created_at as joined_at
        from group_memberships gm
        join groups g on gm.group_id = g.id
        where gm.user_id = :user_id
        order by g.name
        """,
        {"user_id": user_id},
    )
