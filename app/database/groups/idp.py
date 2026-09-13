"""IdP group database operations.

IdP-type groups are sourced from one of two kinds of upstream identity
provider, selected by the ``source`` argument:

- ``"saml"`` (default): ``groups.idp_id`` references
  ``saml_identity_providers``.
- ``"oidc"``: ``groups.oidc_connection_id`` references
  ``oidc_idp_connections``.

The column and provider-table names are resolved from a fixed allowlist
(``_SOURCES``) before being interpolated into SQL; values are always
parameterized.
"""

from database._core import TenantArg, execute, fetchall, fetchone, session

# source -> (groups column holding the provider id, provider table)
_SOURCES: dict[str, tuple[str, str]] = {
    "saml": ("idp_id", "saml_identity_providers"),
    "oidc": ("oidc_connection_id", "oidc_idp_connections"),
}

IDP_SOURCES = frozenset(_SOURCES)


def _resolve_source(source: str) -> tuple[str, str]:
    """Return ``(id_column, provider_table)`` for an allowlisted source."""
    try:
        return _SOURCES[source]
    except KeyError:
        raise ValueError(f"Unknown IdP group source: {source!r}") from None


def get_idp_base_group_id(tenant_id: TenantArg, idp_id: str, source: str = "saml") -> str | None:
    """Get the base group ID for an IdP.

    The base group is the one whose name matches the IdP name.
    Uses a join to the provider table so callers don't need the IdP name.

    Returns:
        The group ID as a string, or None if not found.
    """
    id_column, provider_table = _resolve_source(source)
    row = fetchone(
        tenant_id,
        f"""
        select g.id
        from groups g
        join {provider_table} ip on g.{id_column} = ip.id and g.name = ip.name
        where g.{id_column} = :idp_id
          and g.is_valid = true
        """,
        {"idp_id": idp_id},
    )
    return str(row["id"]) if row else None


def get_groups_by_idp(tenant_id: TenantArg, idp_id: str, source: str = "saml") -> list[dict]:
    """Get all groups for a specific IdP."""
    id_column, _ = _resolve_source(source)
    return fetchall(
        tenant_id,
        f"""
        select g.id, g.name, g.description, g.group_type, g.is_valid, g.created_at,
               (select count(*) from group_memberships gm where gm.group_id = g.id) as member_count
        from groups g
        where g.{id_column} = :idp_id
        order by g.name
        """,
        {"idp_id": idp_id},
    )


def get_group_by_idp_and_name(
    tenant_id: TenantArg, idp_id: str, name: str, source: str = "saml"
) -> dict | None:
    """Get a specific IdP group by name."""
    id_column, _ = _resolve_source(source)
    return fetchone(
        tenant_id,
        f"""
        select g.id, g.name, g.group_type, g.idp_id, g.oidc_connection_id, g.is_valid
        from groups g
        where g.{id_column} = :idp_id and g.name = :name
        """,
        {"idp_id": idp_id, "name": name},
    )


def create_idp_group(
    tenant_id: TenantArg,
    tenant_id_value: str,
    idp_id: str,
    name: str,
    description: str | None = None,
    source: str = "saml",
) -> dict | None:
    """
    Create an IdP group with its self-referential lineage entry.

    This is transactional: both the group and its lineage row are created atomically.

    Returns:
        Dict with id of the created group
    """
    id_column, _ = _resolve_source(source)
    with session(tenant_id=tenant_id) as cur:
        # Create the group with type='idp' and the source id column set
        cur.execute(
            f"""
            insert into groups (tenant_id, name, description, group_type, {id_column}, created_by)
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


def invalidate_groups_by_idp(tenant_id: TenantArg, idp_id: str, source: str = "saml") -> int:
    """
    Mark all groups for an IdP as invalid.

    Called when an IdP is deleted. Groups are preserved for historical reference
    but marked as invalid so they cannot be used for future operations.

    Returns:
        Number of groups invalidated
    """
    id_column, _ = _resolve_source(source)
    return execute(
        tenant_id,
        f"""
        update groups
        set is_valid = false, updated_at = now()
        where {id_column} = :idp_id and is_valid = true
        """,
        {"idp_id": idp_id},
    )


def delete_groups_by_idp(tenant_id: TenantArg, idp_id: str, source: str = "saml") -> int:
    """
    Delete all groups for an IdP.

    Called before an IdP is deleted to avoid unique constraint violations.
    The SAML groups FK has ON DELETE SET NULL, which would set idp_id to NULL
    and collide with existing weftid groups sharing the same name. The OIDC FK
    cascades, but deleting here first lets the service layer audit each removal.

    Cascading deletes handle memberships, relationships, and lineage.

    Returns:
        Number of groups deleted
    """
    id_column, _ = _resolve_source(source)
    return execute(
        tenant_id,
        f"delete from groups where {id_column} = :idp_id",
        {"idp_id": idp_id},
    )


def get_user_idp_group_ids(
    tenant_id: TenantArg, user_id: str, idp_id: str, source: str = "saml"
) -> list[str]:
    """
    Get all IdP group IDs a user belongs to for a specific IdP.

    Used for membership sync to determine which groups to add/remove.
    """
    id_column, _ = _resolve_source(source)
    rows = fetchall(
        tenant_id,
        f"""
        select g.id
        from group_memberships gm
        join groups g on gm.group_id = g.id
        where gm.user_id = :user_id
          and g.{id_column} = :idp_id
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
