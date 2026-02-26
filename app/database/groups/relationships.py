"""Group relationship database operations with transactional lineage maintenance."""

from database._core import TenantArg, fetchall, fetchone, session


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
               gr.created_at,
               (logo.group_id is not null) as has_logo
        from group_relationships gr
        join groups g on gr.parent_group_id = g.id
        left join group_logos logo on logo.group_id = g.id
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
               gr.created_at,
               (logo.group_id is not null) as has_logo
        from group_relationships gr
        join groups g on gr.child_group_id = g.id
        left join group_logos logo on logo.group_id = g.id
        where gr.parent_group_id = :group_id
        order by g.name
        """,
        {"group_id": group_id},
    )
