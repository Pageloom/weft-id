"""Group selection database operations (for dropdowns and forms)."""

from database._core import TenantArg, fetchall


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
