"""OIDC upstream user-link database operations.

Maps an upstream OIDC subject (``sub``, or a per-connection correlation claim
such as Entra's ``oid``) to a WeftID user. One row per (idp_id, sub), UNIQUE
(idp_id, sub). Written by the auth flow (Iteration 3); this module exists now
so the data model is testable at the database layer.

Every query is RLS-scoped via the ``tenant_id`` argument to the database
helpers.
"""

from database._core import TenantArg, execute, fetchall, fetchone

_COLUMNS = "id, tenant_id, idp_id, sub, user_id, created_at, last_used_at"


def create_link(
    tenant_id: TenantArg,
    tenant_id_value: str,
    idp_id: str,
    sub: str,
    user_id: str,
) -> dict | None:
    """Create a user link for an (idp_id, sub) pair.

    Returns the created row. Raises a UniqueViolation if a link for the same
    (idp_id, sub) already exists (the UNIQUE constraint is enforced by the
    database, not by this function).
    """
    return fetchone(
        tenant_id,
        f"""
        insert into oidc_idp_user_links (tenant_id, idp_id, sub, user_id)
        values (:tenant_id, :idp_id, :sub, :user_id)
        returning {_COLUMNS}
        """,
        {
            "tenant_id": tenant_id_value,
            "idp_id": idp_id,
            "sub": sub,
            "user_id": user_id,
        },
    )


def get_link(tenant_id: TenantArg, link_id: str) -> dict | None:
    """Get a user link by ID, or None if not found."""
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_user_links
        where id = :link_id
        """,
        {"link_id": link_id},
    )


def get_link_by_idp_sub(tenant_id: TenantArg, idp_id: str, sub: str) -> dict | None:
    """Get a user link by (idp_id, sub), or None if not found."""
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_user_links
        where idp_id = :idp_id and sub = :sub
        """,
        {"idp_id": idp_id, "sub": sub},
    )


def get_user_id_by_sub(tenant_id: TenantArg, idp_id: str, sub: str) -> str | None:
    """Return the WeftID user id bound to (idp_id, sub), or None."""
    row = fetchone(
        tenant_id,
        """
        select user_id
        from oidc_idp_user_links
        where idp_id = :idp_id and sub = :sub
        """,
        {"idp_id": idp_id, "sub": sub},
    )
    return str(row["user_id"]) if row else None


def list_links_for_user(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """Return every OIDC link a user holds, joined to its connection.

    Ordered most recently used first (never-used links last, then newest
    created), so the auth-routing decision point can take the first link
    whose connection is enabled. Rows carry the link columns plus
    ``connection_name``, ``provider_type`` and ``connection_enabled``.
    """
    return fetchall(
        tenant_id,
        """
        select l.id, l.tenant_id, l.idp_id, l.sub, l.user_id, l.created_at,
               l.last_used_at,
               c.name as connection_name, c.provider_type,
               c.is_enabled as connection_enabled
        from oidc_idp_user_links l
        join oidc_idp_connections c on c.id = l.idp_id
        where l.user_id = :user_id
        order by l.last_used_at desc nulls last, l.created_at desc, l.id desc
        """,
        {"user_id": user_id},
    )


def get_link_for_user_idp(
    tenant_id: TenantArg,
    user_id: str,
    idp_id: str,
) -> dict | None:
    """Return a user's link to one connection, or None.

    UNIQUE (idp_id, user_id) means a user holds at most one link per
    connection.
    """
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_user_links
        where user_id = :user_id and idp_id = :idp_id
        """,
        {"user_id": user_id, "idp_id": idp_id},
    )


def touch_link(tenant_id: TenantArg, idp_id: str, sub: str) -> int:
    """Set ``last_used_at`` to now on the (idp_id, sub) link. Returns row count."""
    return execute(
        tenant_id,
        """
        update oidc_idp_user_links
        set last_used_at = now()
        where idp_id = :idp_id and sub = :sub
        """,
        {"idp_id": idp_id, "sub": sub},
    )


def delete_link(tenant_id: TenantArg, link_id: str) -> int:
    """Delete a user link by ID. Returns the number of rows deleted."""
    return execute(
        tenant_id,
        "delete from oidc_idp_user_links where id = :link_id",
        {"link_id": link_id},
    )


def delete_link_for_user_idp(
    tenant_id: TenantArg,
    user_id: str,
    idp_id: str,
) -> int:
    """Delete a user's link to one connection. Returns the number of rows deleted."""
    return execute(
        tenant_id,
        """
        delete from oidc_idp_user_links
        where user_id = :user_id and idp_id = :idp_id
        """,
        {"user_id": user_id, "idp_id": idp_id},
    )


def count_links_for_connection(tenant_id: TenantArg, connection_id: str) -> int:
    """Count user links bound to a connection (delete-guard support)."""
    result = fetchone(
        tenant_id,
        """
        select count(*) as count
        from oidc_idp_user_links
        where idp_id = :connection_id
        """,
        {"connection_id": connection_id},
    )
    return result["count"] if result else 0


def list_links_for_connection(tenant_id: TenantArg, connection_id: str) -> list[dict]:
    """List all user links for a connection, joined to user + primary email.

    Used by the admin disconnect surface (connection danger tab) to show which
    users are linked and offer an unlink action. Returns rows with link id,
    sub, user id, first/last name, and primary email.
    """
    return fetchall(
        tenant_id,
        """
        select l.id, l.sub, l.user_id, l.created_at,
               u.first_name, u.last_name,
               ue.email
        from oidc_idp_user_links l
        join users u on u.id = l.user_id
        left join user_emails ue
          on ue.user_id = u.id and ue.is_primary = true
        where l.idp_id = :connection_id
        order by l.created_at asc
        """,
        {"connection_id": connection_id},
    )
