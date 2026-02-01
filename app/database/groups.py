"""Group database operations with transactional lineage maintenance."""

from typing import Any

from ._core import TenantArg, execute, fetchall, fetchone, session

# ============================================================================
# Group CRUD Operations
# ============================================================================


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


def count_groups(
    tenant_id: TenantArg,
    search: str | None = None,
    group_type: str | None = None,
) -> int:
    """Count groups, optionally filtered."""
    where_clauses: list[str] = []
    params: dict[str, Any] = {}

    if search:
        where_clauses.append("(g.name ilike :search or g.description ilike :search)")
        params["search"] = f"%{search}%"

    if group_type:
        where_clauses.append("g.group_type = :group_type")
        params["group_type"] = group_type

    where_clause = ""
    if where_clauses:
        where_clause = "where " + " and ".join(where_clauses)

    result = fetchone(
        tenant_id,
        f"select count(*) as count from groups g {where_clause}",
        params,
    )
    return result["count"] if result else 0


def list_groups(
    tenant_id: TenantArg,
    search: str | None = None,
    group_type: str | None = None,
    sort_field: str = "created_at",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 25,
) -> list[dict]:
    """List groups with pagination, sorting, and search."""
    where_clauses: list[str] = []
    params: dict[str, Any] = {}

    if search:
        where_clauses.append("(g.name ilike :search or g.description ilike :search)")
        params["search"] = f"%{search}%"

    if group_type:
        where_clauses.append("g.group_type = :group_type")
        params["group_type"] = group_type

    where_clause = ""
    if where_clauses:
        where_clause = "where " + " and ".join(where_clauses)

    # Whitelist sort fields (security)
    sort_field_map = {
        "name": "g.name {order}",
        "created_at": "g.created_at {order}",
        "member_count": "member_count {order}",
    }
    if sort_field not in sort_field_map:
        sort_field = "created_at"
    if sort_order not in ["asc", "desc"]:
        sort_order = "desc"

    order_by = sort_field_map[sort_field].format(order=sort_order)

    offset = (page - 1) * page_size
    params["limit"] = page_size
    params["offset"] = offset

    return fetchall(
        tenant_id,
        f"""
        select g.id, g.name, g.description, g.group_type, g.idp_id, g.is_valid, g.created_at,
               idp.name as idp_name,
               (select count(*) from group_memberships gm where gm.group_id = g.id) as member_count
        from groups g
        left join saml_identity_providers idp on g.idp_id = idp.id
        {where_clause}
        order by {order_by}
        limit :limit offset :offset
        """,
        params,
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


# ============================================================================
# Group Membership Operations
# ============================================================================


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


# ============================================================================
# Group Relationship Operations (with transactional lineage maintenance)
# ============================================================================


def would_create_cycle(
    tenant_id: TenantArg,
    parent_group_id: str,
    child_group_id: str,
) -> bool:
    """
    Check if adding parent_group_id -> child_group_id would create a cycle.

    A cycle exists if child_group_id is already an ancestor of parent_group_id.
    Uses the lineage table for O(1) lookup.
    """
    result = fetchone(
        tenant_id,
        """
        select 1 from group_lineage
        where ancestor_id = :child_id and descendant_id = :parent_id
        limit 1
        """,
        {"child_id": child_group_id, "parent_id": parent_group_id},
    )
    return result is not None


def relationship_exists(
    tenant_id: TenantArg,
    parent_group_id: str,
    child_group_id: str,
) -> bool:
    """Check if a direct parent-child relationship exists."""
    result = fetchone(
        tenant_id,
        """
        select 1 from group_relationships
        where parent_group_id = :parent_id and child_group_id = :child_id
        """,
        {"parent_id": parent_group_id, "child_id": child_group_id},
    )
    return result is not None


def add_group_relationship(
    tenant_id: TenantArg,
    tenant_id_value: str,
    parent_group_id: str,
    child_group_id: str,
) -> dict | None:
    """
    Add a parent-child relationship between groups (transactional).

    This atomically:
    1. Creates the direct relationship in group_relationships
    2. Updates the lineage closure table with all transitive paths

    The lineage update connects every ancestor of the parent to every
    descendant of the child, creating the transitive closure.

    Returns:
        Dict with id of the created relationship, or None if failed
    """
    with session(tenant_id=tenant_id) as cur:
        # 1. Insert the direct relationship
        cur.execute(
            """
            insert into group_relationships (tenant_id, parent_group_id, child_group_id)
            values (%(tenant_id)s, %(parent_id)s, %(child_id)s)
            on conflict (parent_group_id, child_group_id) do nothing
            returning id
            """,
            {
                "tenant_id": tenant_id_value,
                "parent_id": parent_group_id,
                "child_id": child_group_id,
            },
        )
        result = cur.fetchone()
        if not result:
            # Relationship already exists
            return None

        relationship_id = result["id"]

        # 2. Update lineage: connect all ancestors of parent to all descendants of child
        # For each (ancestor -> parent) and (child -> descendant) pair,
        # create (ancestor -> descendant) with depth = depth_to_parent + 1 + depth_from_child
        cur.execute(
            """
            insert into group_lineage (tenant_id, ancestor_id, descendant_id, depth)
            select %(tenant_id)s, p.ancestor_id, c.descendant_id, p.depth + c.depth + 1
            from group_lineage p
            cross join group_lineage c
            where p.descendant_id = %(parent_id)s
              and c.ancestor_id = %(child_id)s
            on conflict (ancestor_id, descendant_id) do update
            set depth = least(group_lineage.depth, excluded.depth)
            """,
            {
                "tenant_id": tenant_id_value,
                "parent_id": parent_group_id,
                "child_id": child_group_id,
            },
        )

        return {"id": relationship_id}


def remove_group_relationship(
    tenant_id: TenantArg,
    parent_group_id: str,
    child_group_id: str,
) -> int:
    """
    Remove a parent-child relationship and rebuild affected lineage (transactional).

    This atomically:
    1. Removes the direct relationship from group_relationships
    2. Rebuilds the lineage for all affected descendants

    The lineage rebuild is necessary because removing one edge may disconnect
    paths that were reachable through other edges (DAG allows multiple paths).

    Returns:
        Number of relationships deleted (0 or 1)
    """
    with session(tenant_id=tenant_id) as cur:
        # 1. Delete the direct relationship
        cur.execute(
            """
            delete from group_relationships
            where parent_group_id = %(parent_id)s and child_group_id = %(child_id)s
            returning id
            """,
            {"parent_id": parent_group_id, "child_id": child_group_id},
        )
        result = cur.fetchone()
        if not result:
            return 0

        # 2. Rebuild lineage for the child and all its descendants
        # First, get all descendants of the child (including itself)
        cur.execute(
            """
            select descendant_id from group_lineage
            where ancestor_id = %(child_id)s
            """,
            {"child_id": child_group_id},
        )
        descendants = [row["descendant_id"] for row in cur.fetchall()]

        if not descendants:
            return 1

        # Delete all lineage entries where these groups are descendants
        # (except self-references which we'll preserve)
        cur.execute(
            """
            delete from group_lineage
            where descendant_id = any(%(descendants)s)
              and ancestor_id != descendant_id
            """,
            {"descendants": descendants},
        )

        # Rebuild lineage from remaining relationships using recursive CTE
        # This recomputes all paths to these descendants
        cur.execute(
            """
            with recursive reachable as (
                -- Base case: direct parents of affected groups
                select gr.parent_group_id as ancestor_id,
                       gr.child_group_id as descendant_id,
                       1 as depth
                from group_relationships gr
                where gr.child_group_id = any(%(descendants)s)

                union

                -- Recursive case: ancestors of those parents
                select gr.parent_group_id,
                       r.descendant_id,
                       r.depth + 1
                from group_relationships gr
                join reachable r on gr.child_group_id = r.ancestor_id
            )
            insert into group_lineage (tenant_id, ancestor_id, descendant_id, depth)
            select distinct on (ancestor_id, descendant_id)
                   gl.tenant_id, r.ancestor_id, r.descendant_id, r.depth
            from reachable r
            join group_lineage gl on gl.descendant_id = r.descendant_id and gl.depth = 0
            order by ancestor_id, descendant_id, depth
            on conflict (ancestor_id, descendant_id) do update
            set depth = least(group_lineage.depth, excluded.depth)
            """,
            {"descendants": descendants},
        )

        return 1


def get_group_parents(tenant_id: TenantArg, group_id: str) -> list[dict]:
    """Get direct parent groups."""
    return fetchall(
        tenant_id,
        """
        select gr.id, g.id as group_id, g.name, g.group_type,
               (select count(*) from group_memberships gm where gm.group_id = g.id) as member_count,
               gr.created_at
        from group_relationships gr
        join groups g on gr.parent_group_id = g.id
        where gr.child_group_id = :group_id
        order by g.name
        """,
        {"group_id": group_id},
    )


def get_group_children(tenant_id: TenantArg, group_id: str) -> list[dict]:
    """Get direct child groups."""
    return fetchall(
        tenant_id,
        """
        select gr.id, g.id as group_id, g.name, g.group_type,
               (select count(*) from group_memberships gm where gm.group_id = g.id) as member_count,
               gr.created_at
        from group_relationships gr
        join groups g on gr.child_group_id = g.id
        where gr.parent_group_id = :group_id
        order by g.name
        """,
        {"group_id": group_id},
    )


# ============================================================================
# Group Lineage Queries (for ancestry and access control)
# ============================================================================


def get_group_ancestors(tenant_id: TenantArg, group_id: str) -> list[dict]:
    """
    Get all ancestors of a group (from lineage table).

    Returns groups ordered by depth (closest ancestors first).
    Excludes self (depth=0).
    """
    return fetchall(
        tenant_id,
        """
        select gl.ancestor_id as group_id, gl.depth, g.name, g.group_type
        from group_lineage gl
        join groups g on gl.ancestor_id = g.id
        where gl.descendant_id = :group_id and gl.depth > 0
        order by gl.depth
        """,
        {"group_id": group_id},
    )


def get_group_descendants(tenant_id: TenantArg, group_id: str) -> list[dict]:
    """
    Get all descendants of a group (from lineage table).

    Returns groups ordered by depth (closest descendants first).
    Excludes self (depth=0).
    """
    return fetchall(
        tenant_id,
        """
        select gl.descendant_id as group_id, gl.depth, g.name, g.group_type
        from group_lineage gl
        join groups g on gl.descendant_id = g.id
        where gl.ancestor_id = :group_id and gl.depth > 0
        order by gl.depth
        """,
        {"group_id": group_id},
    )


def is_ancestor_of(
    tenant_id: TenantArg,
    ancestor_group_id: str,
    descendant_group_id: str,
) -> bool:
    """Check if one group is an ancestor of another (O(1) via lineage table)."""
    result = fetchone(
        tenant_id,
        """
        select 1 from group_lineage
        where ancestor_id = :ancestor_id and descendant_id = :descendant_id
        limit 1
        """,
        {"ancestor_id": ancestor_group_id, "descendant_id": descendant_group_id},
    )
    return result is not None


# ============================================================================
# Bulk Operations
# ============================================================================


def get_groups_for_user_select(
    tenant_id: TenantArg,
    exclude_user_id: str | None = None,
) -> list[dict]:
    """
    Get groups for a user selection dropdown.

    If exclude_user_id is provided, excludes groups the user is already in.
    """
    if exclude_user_id:
        return fetchall(
            tenant_id,
            """
            select g.id, g.name, g.group_type
            from groups g
            where g.is_valid = true
              and not exists (
                  select 1 from group_memberships gm
                  where gm.group_id = g.id and gm.user_id = :user_id
              )
            order by g.name
            """,
            {"user_id": exclude_user_id},
        )
    return fetchall(
        tenant_id,
        """
        select g.id, g.name, g.group_type
        from groups g
        where g.is_valid = true
        order by g.name
        """,
        {},
    )


def get_groups_for_parent_select(
    tenant_id: TenantArg,
    child_group_id: str,
) -> list[dict]:
    """
    Get groups that can be parents of the given group.

    Excludes:
    - The group itself
    - Groups that are already parents
    - Groups that are descendants (would create cycle)
    """
    return fetchall(
        tenant_id,
        """
        select g.id, g.name, g.group_type
        from groups g
        where g.is_valid = true
          and g.id != :child_id
          -- Not already a parent
          and not exists (
              select 1 from group_relationships gr
              where gr.parent_group_id = g.id and gr.child_group_id = :child_id
          )
          -- Not a descendant (would create cycle)
          and not exists (
              select 1 from group_lineage gl
              where gl.ancestor_id = :child_id and gl.descendant_id = g.id
          )
        order by g.name
        """,
        {"child_id": child_group_id},
    )


def get_groups_for_child_select(
    tenant_id: TenantArg,
    parent_group_id: str,
) -> list[dict]:
    """
    Get groups that can be children of the given group.

    Excludes:
    - The group itself
    - Groups that are already children
    - Groups that are ancestors (would create cycle)

    Note: IdP groups CAN be children (Phase 2 change). The constraint that
    IdP groups cannot be parents is enforced at the service layer.
    """
    return fetchall(
        tenant_id,
        """
        select g.id, g.name, g.group_type
        from groups g
        where g.is_valid = true
          and g.id != :parent_id
          -- Not already a child
          and not exists (
              select 1 from group_relationships gr
              where gr.parent_group_id = :parent_id and gr.child_group_id = g.id
          )
          -- Not an ancestor (would create cycle)
          and not exists (
              select 1 from group_lineage gl
              where gl.ancestor_id = g.id and gl.descendant_id = :parent_id
          )
        order by g.name
        """,
        {"parent_id": parent_group_id},
    )


# ============================================================================
# IdP Group Operations (Phase 2)
# ============================================================================


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


def get_group_by_idp_and_name(
    tenant_id: TenantArg, idp_id: str, name: str
) -> dict | None:
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


def get_user_idp_group_ids(
    tenant_id: TenantArg, user_id: str, idp_id: str
) -> list[str]:
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
        # Build values for bulk insert
        values = ", ".join(
            f"('{tenant_id_value}', '{gid}', '{user_id}')" for gid in group_ids
        )
        cur.execute(
            f"""
            insert into group_memberships (tenant_id, group_id, user_id)
            values {values}
            on conflict (group_id, user_id) do nothing
            """
        )
        return int(cur.rowcount) if cur.rowcount else 0


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
