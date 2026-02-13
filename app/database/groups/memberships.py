"""Group membership database operations."""

from typing import Any

from database._core import TenantArg, execute, fetchall, fetchone, session


def _build_member_search_clauses(
    search: str | None,
    where_clauses: list[str],
    params: dict[str, Any],
) -> None:
    """Build tokenized search WHERE clauses for group member queries.

    Splits search on whitespace. Each token must match at least one of
    first_name, last_name, or email (AND across tokens, OR within a token).
    """
    if not search:
        return

    tokens = search.split()
    for i, token in enumerate(tokens):
        param_name = f"search_{i}"
        where_clauses.append(
            f"(u.first_name ilike :{param_name}"
            f" or u.last_name ilike :{param_name}"
            f" or ue.email ilike :{param_name})"
        )
        params[param_name] = f"%{token}%"


def _build_role_clauses(
    roles: list[str] | None,
    where_clauses: list[str],
    params: dict[str, Any],
) -> None:
    """Build role filter WHERE clauses."""
    if not roles:
        return
    allowed_roles = {"member", "admin", "super_admin"}
    valid_roles = [r for r in roles if r in allowed_roles]
    if valid_roles:
        where_clauses.append("u.role = ANY(:roles)")
        params["roles"] = valid_roles


def _build_status_clauses(
    statuses: list[str] | None,
    where_clauses: list[str],
) -> None:
    """Build status filter WHERE clauses."""
    if not statuses:
        return
    status_conditions: list[str] = []
    if "active" in statuses:
        status_conditions.append("(u.is_inactivated = false and u.is_anonymized = false)")
    if "inactivated" in statuses:
        status_conditions.append("(u.is_inactivated = true and u.is_anonymized = false)")
    if "anonymized" in statuses:
        status_conditions.append("u.is_anonymized = true")
    if status_conditions:
        where_clauses.append(f"({' or '.join(status_conditions)})")


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


def bulk_add_group_members(
    tenant_id: TenantArg,
    tenant_id_value: str,
    group_id: str,
    user_ids: list[str],
) -> int:
    """Add multiple users to a single group.

    Uses ON CONFLICT DO NOTHING to skip duplicates.
    Returns the count of new memberships created.
    """
    if not user_ids:
        return 0

    with session(tenant_id=tenant_id) as cur:
        from database._core import _convert_query

        total_added = 0
        for user_id in user_ids:
            cur.execute(
                _convert_query(
                    """
                    insert into group_memberships (tenant_id, group_id, user_id)
                    values (:tenant_id, :group_id, :user_id)
                    on conflict (group_id, user_id) do nothing
                    """
                ),
                {"tenant_id": tenant_id_value, "group_id": group_id, "user_id": user_id},
            )
            total_added += cur.rowcount or 0

        return total_added


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


def search_group_members(
    tenant_id: TenantArg,
    group_id: str,
    search: str | None = None,
    roles: list[str] | None = None,
    statuses: list[str] | None = None,
    sort_field: str = "created_at",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 25,
) -> list[dict]:
    """Search group members with filtering, sorting, and pagination.

    Returns extended member info including role, is_inactivated, is_anonymized.
    """
    where_clauses: list[str] = ["gm.group_id = :group_id"]
    params: dict[str, Any] = {"group_id": group_id}

    _build_member_search_clauses(search, where_clauses, params)
    _build_role_clauses(roles, where_clauses, params)
    _build_status_clauses(statuses, where_clauses)

    where_clause = "where " + " and ".join(where_clauses)

    # Build ORDER BY clause
    status_case = """CASE
        WHEN u.is_anonymized = true THEN 3
        WHEN u.is_inactivated = true THEN 2
        ELSE 1
    END"""
    sort_field_map = {
        "name": "u.last_name {order}, u.first_name {order}",
        "email": "ue.email {order}",
        "role": "u.role {order}",
        "status": f"{status_case} {{order}}",
        "created_at": "gm.created_at {order}",
    }

    if sort_field not in sort_field_map:
        sort_field = "created_at"
    if sort_order not in ("asc", "desc"):
        sort_order = "desc"

    order_by_clause = sort_field_map[sort_field].format(order=sort_order)

    offset = (page - 1) * page_size
    params["limit"] = page_size
    params["offset"] = offset

    query = f"""
        select gm.id, gm.user_id, gm.created_at,
               u.first_name, u.last_name, u.role,
               u.is_inactivated, u.is_anonymized,
               ue.email
        from group_memberships gm
        join users u on gm.user_id = u.id
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        {where_clause}
        order by {order_by_clause}
        limit :limit offset :offset
    """

    return fetchall(tenant_id, query, params)


def count_group_members_filtered(
    tenant_id: TenantArg,
    group_id: str,
    search: str | None = None,
    roles: list[str] | None = None,
    statuses: list[str] | None = None,
) -> int:
    """Count group members with optional search and filters."""
    where_clauses: list[str] = ["gm.group_id = :group_id"]
    params: dict[str, Any] = {"group_id": group_id}

    _build_member_search_clauses(search, where_clauses, params)
    _build_role_clauses(roles, where_clauses, params)
    _build_status_clauses(statuses, where_clauses)

    where_clause = "where " + " and ".join(where_clauses)

    query = f"""
        select count(*) as count
        from group_memberships gm
        join users u on gm.user_id = u.id
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        {where_clause}
    """

    result = fetchone(tenant_id, query, params)
    return result["count"] if result else 0


def search_available_users(
    tenant_id: TenantArg,
    group_id: str,
    search: str | None = None,
    roles: list[str] | None = None,
    statuses: list[str] | None = None,
    sort_field: str = "name",
    sort_order: str = "asc",
    page: int = 1,
    page_size: int = 25,
) -> list[dict]:
    """Search users NOT in a group, with filtering, sorting, and pagination.

    Excludes service accounts (OAuth2 clients).
    """
    where_clauses: list[str] = [
        "not exists ("
        "select 1 from group_memberships gm"
        " where gm.group_id = :group_id and gm.user_id = u.id"
        ")",
        "not exists (select 1 from oauth2_clients oc where oc.service_user_id = u.id)",
    ]
    params: dict[str, Any] = {"group_id": group_id}

    _build_member_search_clauses(search, where_clauses, params)
    _build_role_clauses(roles, where_clauses, params)
    _build_status_clauses(statuses, where_clauses)

    where_clause = "where " + " and ".join(where_clauses)

    # Build ORDER BY clause
    status_case = """CASE
        WHEN u.is_anonymized = true THEN 3
        WHEN u.is_inactivated = true THEN 2
        ELSE 1
    END"""
    sort_field_map = {
        "name": "u.last_name {order}, u.first_name {order}",
        "email": "ue.email {order}",
        "role": "u.role {order}",
        "status": f"{status_case} {{order}}",
        "created_at": "u.created_at {order}",
    }

    if sort_field not in sort_field_map:
        sort_field = "name"
    if sort_order not in ("asc", "desc"):
        sort_order = "asc"

    order_by_clause = sort_field_map[sort_field].format(order=sort_order)

    offset = (page - 1) * page_size
    params["limit"] = page_size
    params["offset"] = offset

    query = f"""
        select u.id, u.first_name, u.last_name, u.role,
               u.is_inactivated, u.is_anonymized,
               ue.email
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        {where_clause}
        order by {order_by_clause}
        limit :limit offset :offset
    """

    return fetchall(tenant_id, query, params)


def count_available_users(
    tenant_id: TenantArg,
    group_id: str,
    search: str | None = None,
    roles: list[str] | None = None,
    statuses: list[str] | None = None,
) -> int:
    """Count users NOT in a group, with optional search and filters."""
    where_clauses: list[str] = [
        "not exists ("
        "select 1 from group_memberships gm"
        " where gm.group_id = :group_id and gm.user_id = u.id"
        ")",
        "not exists (select 1 from oauth2_clients oc where oc.service_user_id = u.id)",
    ]
    params: dict[str, Any] = {"group_id": group_id}

    _build_member_search_clauses(search, where_clauses, params)
    _build_role_clauses(roles, where_clauses, params)
    _build_status_clauses(statuses, where_clauses)

    where_clause = "where " + " and ".join(where_clauses)

    query = f"""
        select count(*) as count
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        {where_clause}
    """

    result = fetchone(tenant_id, query, params)
    return result["count"] if result else 0


def bulk_remove_group_members(
    tenant_id: TenantArg,
    group_id: str,
    user_ids: list[str],
) -> int:
    """Remove multiple users from a group atomically.

    Returns the count of memberships removed.
    """
    if not user_ids:
        return 0

    with session(tenant_id=tenant_id) as cur:
        from database._core import _convert_query

        total_removed = 0
        for user_id in user_ids:
            cur.execute(
                _convert_query(
                    """
                    delete from group_memberships
                    where group_id = :group_id and user_id = :user_id
                    """
                ),
                {"group_id": group_id, "user_id": user_id},
            )
            total_removed += cur.rowcount or 0

        return total_removed
