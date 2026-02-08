"""IdP group database operations."""

from database._core import TenantArg, execute, fetchall, fetchone, session


def get_idp_base_group_id(tenant_id: TenantArg, idp_id: str) -> str | None:
    """Get the base group ID for an IdP.

    The base group is the one whose name matches the IdP name.
    Uses a join to identity_providers so callers don't need the IdP name.

    Returns:
        The group ID as a string, or None if not found.
    """
    row = fetchone(
        tenant_id,
        """
        select g.id
        from groups g
        join saml_identity_providers ip on g.idp_id = ip.id and g.name = ip.name
        where g.idp_id = :idp_id
          and g.is_valid = true
        """,
        {"idp_id": idp_id},
    )
    return str(row["id"]) if row else None


def get_groups_by_idp(tenant_id: TenantArg, idp_id: str) -> list[dict]:
    """Get all groups for a specific IdP."""
    return fetchall(
        tenant_id,
        """
        select g.id, g.name, g.description, g.group_type, g.is_valid, g.created_at,
               (select count(*) from group_memberships gm where gm.group_id = g.id) as member_count
        from groups g
        where g.idp_id = :idp_id
        order by g.name
        """,
        {"idp_id": idp_id},
    )


def get_group_by_idp_and_name(tenant_id: TenantArg, idp_id: str, name: str) -> dict | None:
    """Get a specific IdP group by name."""
    return fetchone(
        tenant_id,
        """
        select g.id, g.name, g.group_type, g.idp_id, g.is_valid
        from groups g
        where g.idp_id = :idp_id and g.name = :name
        """,
        {"idp_id": idp_id, "name": name},
    )


def create_idp_group(
    tenant_id: TenantArg,
    tenant_id_value: str,
    idp_id: str,
    name: str,
    description: str | None = None,
) -> dict | None:
    """
    Create an IdP group with its self-referential lineage entry.

    This is transactional: both the group and its lineage row are created atomically.

    Returns:
        Dict with id of the created group
    """
    with session(tenant_id=tenant_id) as cur:
        # Create the group with type='idp' and idp_id set
        cur.execute(
            """
            insert into groups (tenant_id, name, description, group_type, idp_id, created_by)
            values (%(tenant_id)s, %(name)s, %(description)s, 'idp', %(idp_id)s, null)
            returning id
            """,
            {
                "tenant_id": tenant_id_value,
                "name": name,
                "description": description,
                "idp_id": idp_id,
            },
        )
        result = cur.fetchone()
        if not result:
            return None

        group_id = result["id"]

        # Create self-referential lineage entry (depth 0)
        cur.execute(
            """
            insert into group_lineage (tenant_id, ancestor_id, descendant_id, depth)
            values (%(tenant_id)s, %(group_id)s, %(group_id)s, 0)
            """,
            {"tenant_id": tenant_id_value, "group_id": group_id},
        )

        return {"id": group_id}


def invalidate_groups_by_idp(tenant_id: TenantArg, idp_id: str) -> int:
    """
    Mark all groups for an IdP as invalid.

    Called when an IdP is deleted. Groups are preserved for historical reference
    but marked as invalid so they cannot be used for future operations.

    Returns:
        Number of groups invalidated
    """
    return execute(
        tenant_id,
        """
        update groups
        set is_valid = false, updated_at = now()
        where idp_id = :idp_id and is_valid = true
        """,
        {"idp_id": idp_id},
    )


def get_user_idp_group_ids(tenant_id: TenantArg, user_id: str, idp_id: str) -> list[str]:
    """
    Get all IdP group IDs a user belongs to for a specific IdP.

    Used for membership sync to determine which groups to add/remove.
    """
    rows = fetchall(
        tenant_id,
        """
        select g.id
        from group_memberships gm
        join groups g on gm.group_id = g.id
        where gm.user_id = :user_id
          and g.idp_id = :idp_id
          and g.is_valid = true
        """,
        {"user_id": user_id, "idp_id": idp_id},
    )
    return [str(row["id"]) for row in rows]


def bulk_add_user_to_groups(
    tenant_id: TenantArg,
    tenant_id_value: str,
    user_id: str,
    group_ids: list[str],
) -> int:
    """
    Add user to multiple groups in a single transaction.

    Uses INSERT ... ON CONFLICT to handle duplicates gracefully.

    Returns:
        Number of memberships created
    """
    if not group_ids:
        return 0

    with session(tenant_id=tenant_id) as cur:
        total = 0
        for gid in group_ids:
            cur.execute(
                """
                insert into group_memberships (tenant_id, group_id, user_id)
                values (%(tenant_id)s, %(group_id)s, %(user_id)s)
                on conflict (group_id, user_id) do nothing
                """,
                {"tenant_id": tenant_id_value, "group_id": gid, "user_id": user_id},
            )
            total += cur.rowcount or 0
        return total


def bulk_remove_user_from_groups(
    tenant_id: TenantArg,
    user_id: str,
    group_ids: list[str],
) -> int:
    """
    Remove user from multiple groups in a single transaction.

    Returns:
        Number of memberships removed
    """
    if not group_ids:
        return 0

    return execute(
        tenant_id,
        """
        delete from group_memberships
        where user_id = :user_id and group_id = any(:group_ids)
        """,
        {"user_id": user_id, "group_ids": group_ids},
    )
