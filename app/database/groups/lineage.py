"""Group lineage database operations (ancestry queries via closure table)."""

from database._core import TenantArg, fetchall, fetchone


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
