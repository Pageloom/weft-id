"""Group core CRUD database operations."""

from typing import Any

from database._core import TenantArg, execute, fetchone, session


def get_group_by_id(tenant_id: TenantArg, group_id: str) -> dict | None:
    """
    Get a group by ID with member/relationship counts.

    Returns:
        Dict with id, tenant_id, name, description, group_type, idp_id, idp_name,
        is_valid, created_by, created_at, updated_at, member_count,
        parent_count, child_count
    """
    return fetchone(
        tenant_id,
        """
        select g.id, g.tenant_id, g.name, g.description, g.group_type,
               g.idp_id, idp.name as idp_name, g.is_valid, g.created_by,
               g.created_at, g.updated_at,
               (select count(*) from group_memberships gm
                where gm.group_id = g.id) as member_count,
               (select count(*) from group_relationships gr
                where gr.child_group_id = g.id) as parent_count,
               (select count(*) from group_relationships gr
                where gr.parent_group_id = g.id) as child_count
        from groups g
        left join saml_identity_providers idp on g.idp_id = idp.id
        where g.id = :group_id
        """,
        {"group_id": group_id},
    )


def get_group_by_name(tenant_id: TenantArg, name: str) -> dict | None:
    """Get a group by name (for duplicate checking across all groups)."""
    return fetchone(
        tenant_id,
        "select id, name, group_type, idp_id from groups where name = :name",
        {"name": name},
    )


def get_weftid_group_by_name(tenant_id: TenantArg, name: str) -> dict | None:
    """Get a WeftID group by name (for duplicate checking within WeftID groups only)."""
    return fetchone(
        tenant_id,
        "select id, name from groups where name = :name and group_type = 'weftid'",
        {"name": name},
    )


def create_group(
    tenant_id: TenantArg,
    tenant_id_value: str,
    name: str,
    description: str | None = None,
    group_type: str = "weftid",
    created_by: str | None = None,
) -> dict | None:
    """
    Create a new group and its self-referential lineage entry.

    This is transactional: both the group and its lineage row are created atomically.

    Returns:
        Dict with id of the created group
    """
    with session(tenant_id=tenant_id) as cur:
        # Create the group
        cur.execute(
            """
            insert into groups (tenant_id, name, description, group_type, created_by)
            values (%(tenant_id)s, %(name)s, %(description)s, %(group_type)s, %(created_by)s)
            returning id
            """,
            {
                "tenant_id": tenant_id_value,
                "name": name,
                "description": description,
                "group_type": group_type,
                "created_by": created_by,
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


def update_group(
    tenant_id: TenantArg,
    group_id: str,
    name: str | None = None,
    description: str | None = None,
) -> int:
    """Update group metadata."""
    updates = []
    params: dict[str, Any] = {"group_id": group_id}

    if name is not None:
        updates.append("name = :name")
        params["name"] = name

    # Allow empty string to clear description
    if description is not None:
        updates.append("description = :description")
        params["description"] = description if description else None

    if not updates:
        return 0

    updates.append("updated_at = now()")
    update_clause = ", ".join(updates)

    return execute(
        tenant_id,
        f"update groups set {update_clause} where id = :group_id",
        params,
    )


def delete_group(tenant_id: TenantArg, group_id: str) -> int:
    """
    Delete a group.

    Cascading deletes handle:
    - group_memberships (users removed from group)
    - group_relationships (parent/child edges removed)
    - group_lineage (ancestry entries removed)

    Children become orphaned (they keep other parents if any).
    """
    return execute(
        tenant_id,
        "delete from groups where id = :group_id",
        {"group_id": group_id},
    )
