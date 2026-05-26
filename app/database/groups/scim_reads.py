"""Group listing / lookup helpers for the inbound SCIM read endpoints.

Inbound SCIM exposes one group type only: `idp` groups scoped to the
authenticating IdP connection. `weftid` (manually managed) groups are
NEVER visible via inbound SCIM -- they are internal organisational
constructs, not directory state the IdP is allowed to see.

`list_groups_for_idp` and `get_group_for_idp` return only `is_valid`
groups, mirroring the existing internal helpers. Soft-deleted groups
(post-IdP-removal cleanup) are excluded.
"""

from __future__ import annotations

from database._core import TenantArg, fetchall, fetchone

_SCIM_GROUP_COLS = """
    g.id,
    g.name,
    g.idp_id,
    g.created_at,
    g.updated_at
"""


def count_groups_for_idp(
    tenant_id: TenantArg,
    idp_id: str,
    *,
    display_name: str | None = None,
) -> int:
    """Count IdP groups matching the optional `displayName eq` filter."""
    where = [
        "g.idp_id = :idp_id",
        "g.group_type = 'idp'",
        "g.is_valid = true",
    ]
    params: dict = {"idp_id": idp_id}

    if display_name is not None:
        where.append("g.name = :display_name")
        params["display_name"] = display_name

    row = fetchone(
        tenant_id,
        f"""
        select count(*) as count
        from groups g
        where {" and ".join(where)}
        """,
        params,
    )
    return int(row["count"]) if row else 0


def list_groups_for_idp(
    tenant_id: TenantArg,
    idp_id: str,
    *,
    display_name: str | None = None,
    start_index: int = 1,
    count: int = 100,
) -> list[dict]:
    """List IdP groups in SCIM shape, paginated SCIM-style (1-indexed)."""
    where = [
        "g.idp_id = :idp_id",
        "g.group_type = 'idp'",
        "g.is_valid = true",
    ]
    params: dict = {"idp_id": idp_id}

    if display_name is not None:
        where.append("g.name = :display_name")
        params["display_name"] = display_name

    offset = max(start_index - 1, 0)
    params["limit"] = count
    params["offset"] = offset

    return fetchall(
        tenant_id,
        f"""
        select {_SCIM_GROUP_COLS}
        from groups g
        where {" and ".join(where)}
        order by g.created_at asc, g.id asc
        limit :limit offset :offset
        """,
        params,
    )


def get_group_for_idp(
    tenant_id: TenantArg,
    idp_id: str,
    group_id: str,
) -> dict | None:
    """Fetch one IdP group, scoped to the authenticating IdP connection."""
    return fetchone(
        tenant_id,
        f"""
        select {_SCIM_GROUP_COLS}
        from groups g
        where g.id = :group_id
          and g.idp_id = :idp_id
          and g.group_type = 'idp'
          and g.is_valid = true
        """,
        {"group_id": group_id, "idp_id": idp_id},
    )


def list_group_members_for_scim(
    tenant_id: TenantArg,
    group_id: str,
) -> list[dict]:
    """Get group members with id + display info, scoped to one group.

    Returns all members of the group (no pagination -- SCIM 2.0
    embeds the members array inline on the Group resource). Each row
    has id, first_name, last_name, email so the SCIM payload builder
    can construct `{value, $ref, display}` triples.
    """
    return fetchall(
        tenant_id,
        """
        select u.id, u.first_name, u.last_name, ue.email
        from group_memberships gm
        join users u on gm.user_id = u.id
        left join user_emails ue on ue.user_id = u.id and ue.is_primary = true
        where gm.group_id = :group_id
        order by u.last_name asc, u.first_name asc, u.id asc
        """,
        {"group_id": group_id},
    )
