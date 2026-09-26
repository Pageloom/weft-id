"""OAuth2 / OIDC consent grant database operations.

A grant is one row per (client, user) holding the union of the scopes the
user has allowed for that client. ``client_id`` here is always the client's
internal UUID (``oauth2_clients.id``), never the public ``client_id`` string.
"""

from database._core import TenantArg, execute, fetchall, fetchone

_GRANT_COLUMNS = "id, tenant_id, client_id, user_id, scopes, granted_at, updated_at"


def get_consent_grant(tenant_id: TenantArg, client_id: str, user_id: str) -> dict | None:
    """Return the grant for ``(client, user)``, or ``None``."""
    return fetchone(
        tenant_id,
        f"""
        select {_GRANT_COLUMNS}
        from oauth2_consent_grants
        where client_id = :client_id and user_id = :user_id
        """,
        {"client_id": client_id, "user_id": user_id},
    )


def get_consent_grant_by_id(tenant_id: TenantArg, grant_id: str) -> dict | None:
    """Return a grant by its own id, or ``None``."""
    return fetchone(
        tenant_id,
        f"select {_GRANT_COLUMNS} from oauth2_consent_grants where id = :grant_id",
        {"grant_id": grant_id},
    )


def upsert_consent_grant(
    tenant_id: TenantArg,
    tenant_id_value: str,
    client_id: str,
    user_id: str,
    scopes: list[str],
) -> dict:
    """Create the grant for ``(client, user)`` or widen it with ``scopes``.

    The stored set is the sorted union of the existing scopes and the new
    ones, so a grant only ever grows until it is revoked. Returns the row.
    """
    row = fetchone(
        tenant_id,
        f"""
        insert into oauth2_consent_grants (tenant_id, client_id, user_id, scopes)
        values (:tenant_id, :client_id, :user_id, :scopes)
        on conflict (client_id, user_id) do update
            set scopes = (
                    select coalesce(array_agg(distinct s order by s), '{{}}')
                    from unnest(oauth2_consent_grants.scopes || excluded.scopes) as s
                ),
                updated_at = now()
        returning {_GRANT_COLUMNS}
        """,
        {
            "tenant_id": tenant_id_value,
            "client_id": client_id,
            "user_id": user_id,
            "scopes": sorted(set(scopes)),
        },
    )
    assert row is not None  # insert ... returning always yields a row
    return row


def list_consent_grants_for_user(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """List a user's grants joined with the client's public details, by client name."""
    return fetchall(
        tenant_id,
        """
        select g.id, g.tenant_id, g.client_id, g.user_id, g.scopes, g.granted_at,
               g.updated_at, c.client_id as client_public_id, c.name as client_name,
               c.description as client_description, c.is_active as client_is_active
        from oauth2_consent_grants g
        join oauth2_clients c on c.id = g.client_id
        where g.user_id = :user_id
        order by lower(c.name), g.granted_at
        """,
        {"user_id": user_id},
    )


def list_consent_grants_for_client(tenant_id: TenantArg, client_id: str) -> list[dict]:
    """List a client's grants joined with the user's name and primary email."""
    return fetchall(
        tenant_id,
        """
        select g.id, g.tenant_id, g.client_id, g.user_id, g.scopes, g.granted_at,
               g.updated_at, u.first_name as user_first_name, u.last_name as user_last_name,
               ue.email as user_email
        from oauth2_consent_grants g
        join users u on u.id = g.user_id
        left join user_emails ue on ue.user_id = u.id and ue.is_primary
        where g.client_id = :client_id
        order by lower(u.last_name), lower(u.first_name), g.granted_at
        """,
        {"client_id": client_id},
    )


def delete_consent_grant(tenant_id: TenantArg, grant_id: str) -> int:
    """Delete one grant by id. Returns the number of rows deleted (0 or 1)."""
    return execute(
        tenant_id,
        "delete from oauth2_consent_grants where id = :grant_id",
        {"grant_id": grant_id},
    )


def delete_consent_grants_for_user(tenant_id: TenantArg, user_id: str) -> int:
    """Delete every grant a user has given. Returns the number of rows deleted."""
    return execute(
        tenant_id,
        "delete from oauth2_consent_grants where user_id = :user_id",
        {"user_id": user_id},
    )


def delete_consent_grants_for_client(tenant_id: TenantArg, client_id: str) -> int:
    """Delete every grant given to a client. Returns the number of rows deleted."""
    return execute(
        tenant_id,
        "delete from oauth2_consent_grants where client_id = :client_id",
        {"client_id": client_id},
    )
