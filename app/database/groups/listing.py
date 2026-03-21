"""Group listing and search database operations."""

from typing import Any

from database._core import TenantArg, escape_like, fetchall, fetchone


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
        params["search"] = f"%{escape_like(search)}%"

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
        params["search"] = f"%{escape_like(search)}%"

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
        select g.id, g.name, g.description, g.acronym, g.group_type,
               g.idp_id, g.is_valid, g.created_at,
               idp.name as idp_name,
               (select count(*) from group_memberships gm where gm.group_id = g.id) as member_count,
               (select count(*) from group_relationships gr
                where gr.child_group_id = g.id) as parent_count,
               (select count(*) from group_relationships gr
                where gr.parent_group_id = g.id) as child_count,
               (select count(distinct gm.user_id)
                from group_memberships gm
                join group_lineage gl on gm.group_id = gl.descendant_id
                where gl.ancestor_id = g.id) as effective_member_count,
               (select count(*) from sp_group_assignments sga
                where sga.group_id = g.id) as sp_count,
               (logo.group_id is not null) as has_logo,
               logo.updated_at as logo_updated_at
        from groups g
        left join saml_identity_providers idp on g.idp_id = idp.id
        left join group_logos logo on logo.group_id = g.id
        {where_clause}
        order by {order_by}
        limit :limit offset :offset
        """,
        params,
    )


def list_all_groups_for_graph(tenant_id: TenantArg) -> dict:
    """Fetch all groups and relationships for graph rendering.

    Returns a dict with 'groups' (id, name, group_type, member_count,
    effective_member_count) and 'relationships' (child_group_id, parent_group_id).
    """
    groups = fetchall(
        tenant_id,
        """
        select g.id, g.name, g.acronym, g.group_type,
               (idp_match.id is not null) as is_umbrella,
               (select count(*) from group_memberships gm
                where gm.group_id = g.id) as member_count,
               (select count(distinct gm.user_id)
                from group_memberships gm
                join group_lineage gl on gm.group_id = gl.descendant_id
                where gl.ancestor_id = g.id) as effective_member_count,
               (logo.group_id is not null) as has_logo,
               logo.updated_at as logo_updated_at
        from groups g
        left join group_logos logo on logo.group_id = g.id
        left join saml_identity_providers idp_match
          on idp_match.id = g.idp_id
          and idp_match.name = g.name
        order by g.name
        """,
        {},
    )
    relationships = fetchall(
        tenant_id,
        "select child_group_id, parent_group_id from group_relationships",
        {},
    )
    return {"groups": groups, "relationships": relationships}
