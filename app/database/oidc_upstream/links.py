"""OIDC upstream user-link database operations.

Maps an upstream OIDC subject (``sub``, or a per-connection correlation claim
such as Entra's ``oid``) to a WeftID user. One row per (idp_id, sub), UNIQUE
(idp_id, sub). Written by the auth flow (Iteration 3); this module exists now
so the data model is testable at the database layer.

Every query is RLS-scoped via the ``tenant_id`` argument to the database
helpers.
"""

from database._core import TenantArg, execute, fetchall, fetchone

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


def get_link_for_user(tenant_id: TenantArg, user_id: str) -> dict | None:
    """Return the first OIDC user link for a user, or None.

    Used by the auth-routing decision point to detect that a user is an OIDC
    user. A user has at most one OIDC link in practice (one upstream subject),
    but this returns the first match ordered by created_at for determinism.
    """
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_user_links
        where user_id = :user_id
        order by created_at asc
        limit 1
        """,
        {"user_id": user_id},
    )


def get_links_for_user_idp(
    tenant_id: TenantArg,
    user_id: str,
    idp_id: str,
) -> list[dict]:
    """Return all OIDC user links for a (user_id, idp_id) pair, ordered by created_at.

    Unlike ``get_link_for_user`` (which returns only the first link for a user,
    used by the auth-routing decision point), this returns every link a user
    holds against a single connection. A user can legitimately accumulate
    multiple links against one connection (e.g. the email-linking path creates
    a link without an existing-link check), so the disconnect path must remove
    all of them, not just the first.
    """
    return fetchall(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_user_links
        where user_id = :user_id and idp_id = :idp_id
        order by created_at asc
        """,
        {"user_id": user_id, "idp_id": idp_id},
    )


def delete_link(tenant_id: TenantArg, link_id: str) -> int:
    """Delete a user link by ID. Returns the number of rows deleted."""
    return execute(
        tenant_id,
        "delete from oidc_idp_user_links where id = :link_id",
        {"link_id": link_id},
    )


def delete_links_for_user_idp(
    tenant_id: TenantArg,
    user_id: str,
    idp_id: str,
) -> int:
    """Delete all user links for a (user_id, idp_id) pair. Returns row count.

    Used by the per-user disconnect path, which must remove every link a user
    holds against a connection (not just the first), since the schema has no
    uniqueness on ``user_id``.
    """
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


def list_links_for_user(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """List all OIDC user links for a user, ordered by created_at.

    Used by the admin disconnect surface to show which connections a user is
    linked to. A user has at most one link in practice, but this returns all
    of them for completeness.
    """
    return fetchall(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_user_links
        where user_id = :user_id
        order by created_at asc
        """,
        {"user_id": user_id},
    )


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
