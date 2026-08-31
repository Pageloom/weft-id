"""OIDC upstream user-link database operations.

Maps an upstream OIDC subject (``sub``, or a per-connection correlation claim
such as Entra's ``oid``) to a WeftID user. One row per (idp_id, sub), UNIQUE
(idp_id, sub). Written by the auth flow (Iteration 3); this module exists now
so the data model is testable at the database layer.

Every query is RLS-scoped via the ``tenant_id`` argument to the database
helpers.
"""

from database._core import TenantArg, execute, fetchone

_COLUMNS = "id, tenant_id, idp_id, sub, user_id, created_at"


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


def delete_link(tenant_id: TenantArg, link_id: str) -> int:
    """Delete a user link by ID. Returns the number of rows deleted."""
    return execute(
        tenant_id,
        "delete from oidc_idp_user_links where id = :link_id",
        {"link_id": link_id},
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
