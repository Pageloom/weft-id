"""Effective membership queries using the group_lineage closure table."""

from database._core import TenantArg, fetchall, fetchone


def get_user_groups_with_context(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """Get user's direct groups with parent group names for hierarchy context.

    Returns groups the user is a direct member of, along with a comma-separated
    list of parent group names for each group (for display like "Parent > Group").
    """
    return fetchall(
        tenant_id,
        """
        select g.id, g.name, g.description, g.group_type, gm.created_at as joined_at,
               (
                   select string_agg(pg.name, ', ' order by pg.name)
                   from group_relationships gr
                   join groups pg on gr.parent_group_id = pg.id
                   where gr.child_group_id = g.id
               ) as parent_names
        from group_memberships gm
        join groups g on gm.group_id = g.id
        where gm.user_id = :user_id
        order by g.name
        """,
        {"user_id": user_id},
    )


def get_effective_memberships(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """Get all groups a user is effectively in (direct + ancestor groups).

    Uses the closure table to find all ancestor groups of the user's direct groups.
    Returns each group with an is_direct flag.
    """
    return fetchall(
        tenant_id,
        """
        with direct_groups as (
            select gm.group_id
            from group_memberships gm
            where gm.user_id = :user_id
        ),
        effective_groups as (
            -- Direct memberships
            select dg.group_id, true as is_direct
            from direct_groups dg
            union
            -- Ancestor groups (via lineage, depth > 0 means not self)
            select gl.ancestor_id as group_id, false as is_direct
            from direct_groups dg
            join group_lineage gl on gl.descendant_id = dg.group_id
            where gl.depth > 0
        ),
        -- Deduplicate: if a group appears as both direct and inherited, mark as direct
        deduped as (
            select group_id, bool_or(is_direct) as is_direct
            from effective_groups
            group by group_id
        )
        select g.id, g.name, g.description, g.group_type,
               g.idp_id, idp.name as idp_name,
               d.is_direct
        from deduped d
        join groups g on d.group_id = g.id
        left join saml_identity_providers idp on g.idp_id = idp.id
        order by d.is_direct desc, g.name
        """,
        {"user_id": user_id},
    )


def get_effective_members(
    tenant_id: TenantArg,
    group_id: str,
    page: int = 1,
    page_size: int = 50,
) -> list[dict]:
    """Get all effective members of a group (direct + via descendant groups).

    Uses the closure table to find all descendant groups and their members.
    Returns each user with an is_direct flag.
    """
    offset = (page - 1) * page_size
    return fetchall(
        tenant_id,
        """
        with descendant_groups as (
            select gl.descendant_id as group_id, gl.depth
            from group_lineage gl
            where gl.ancestor_id = :group_id
        ),
        effective_users as (
            select gm.user_id,
                   bool_or(dg.depth = 0) as is_direct
            from descendant_groups dg
            join group_memberships gm on gm.group_id = dg.group_id
            group by gm.user_id
        )
        select eu.user_id, eu.is_direct,
               u.first_name, u.last_name,
               ue.email
        from effective_users eu
        join users u on eu.user_id = u.id
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        order by eu.is_direct desc, u.last_name, u.first_name
        limit :limit offset :offset
        """,
        {"group_id": group_id, "limit": page_size, "offset": offset},
    )


def count_effective_members(tenant_id: TenantArg, group_id: str) -> int:
    """Count all effective members of a group (direct + via descendants)."""
    result = fetchone(
        tenant_id,
        """
        with descendant_groups as (
            select gl.descendant_id as group_id
            from group_lineage gl
            where gl.ancestor_id = :group_id
        )
        select count(distinct gm.user_id) as count
        from descendant_groups dg
        join group_memberships gm on gm.group_id = dg.group_id
        """,
        {"group_id": group_id},
    )
    return result["count"] if result else 0
