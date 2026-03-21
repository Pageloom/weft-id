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


def get_effective_group_names(tenant_id: TenantArg, user_id: str) -> list[str]:
    """Get all group names a user is effectively in (direct + inherited).

    Lightweight query returning just group names for use in SAML assertions.
    """
    rows = fetchall(
        tenant_id,
        """
        with direct_groups as (
            select gm.group_id
            from group_memberships gm
            where gm.user_id = :user_id
        ),
        effective_groups as (
            select dg.group_id
            from direct_groups dg
            union
            select gl.ancestor_id as group_id
            from direct_groups dg
            join group_lineage gl on gl.descendant_id = dg.group_id
            where gl.depth > 0
        )
        select g.name
        from effective_groups eg
        join groups g on eg.group_id = g.id
        order by g.name
        """,
        {"user_id": user_id},
    )
    return [r["name"] for r in rows]


def get_trunk_group_names(tenant_id: TenantArg, user_id: str) -> list[str]:
    """Get the user's topmost group memberships (trunk groups).

    A trunk group is one where none of the user's other effective groups is
    an ancestor of it. These represent the broadest outline of the user's
    group footprint without enumerating nested memberships.
    """
    rows = fetchall(
        tenant_id,
        """
        with direct_groups as (
            select gm.group_id
            from group_memberships gm
            where gm.user_id = :user_id
        ),
        effective_groups as (
            select dg.group_id
            from direct_groups dg
            union
            select gl.ancestor_id as group_id
            from direct_groups dg
            join group_lineage gl on gl.descendant_id = dg.group_id
            where gl.depth > 0
        ),
        -- A trunk group has no ancestor that is also in the effective set
        trunk_groups as (
            select eg.group_id
            from effective_groups eg
            where not exists (
                select 1
                from group_lineage gl
                join effective_groups eg2 on eg2.group_id = gl.ancestor_id
                where gl.descendant_id = eg.group_id
                  and gl.depth > 0
                  and eg2.group_id != eg.group_id
            )
        )
        select g.name
        from trunk_groups tg
        join groups g on tg.group_id = g.id
        order by g.name
        """,
        {"user_id": user_id},
    )
    return [r["name"] for r in rows]


def get_access_relevant_group_names(tenant_id: TenantArg, user_id: str, sp_id: str) -> list[str]:
    """Get group names that grant the user access to a specific SP.

    Returns the intersection of the user's effective groups and the groups
    assigned to the SP (via sp_group_assignments), using the closure table
    for hierarchical matching.
    """
    rows = fetchall(
        tenant_id,
        """
        with direct_groups as (
            select gm.group_id
            from group_memberships gm
            where gm.user_id = :user_id
        ),
        effective_groups as (
            select dg.group_id
            from direct_groups dg
            union
            select gl.ancestor_id as group_id
            from direct_groups dg
            join group_lineage gl on gl.descendant_id = dg.group_id
            where gl.depth > 0
        ),
        -- Groups assigned to the SP
        assigned_groups as (
            select sga.group_id
            from sp_group_assignments sga
            where sga.sp_id = :sp_id
        ),
        -- Effective groups that are assigned to the SP or are descendants
        -- of an assigned group (user's membership path that grants access)
        access_relevant as (
            select distinct eg.group_id
            from effective_groups eg
            where exists (
                select 1
                from assigned_groups ag
                where ag.group_id = eg.group_id
            )
            or exists (
                select 1
                from group_lineage gl
                join assigned_groups ag on ag.group_id = gl.ancestor_id
                where gl.descendant_id = eg.group_id
                  and gl.depth > 0
            )
        )
        select g.name
        from access_relevant ar
        join groups g on ar.group_id = g.id
        order by g.name
        """,
        {"user_id": user_id, "sp_id": sp_id},
    )
    return [r["name"] for r in rows]


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
