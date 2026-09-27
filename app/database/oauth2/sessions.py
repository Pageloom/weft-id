"""Which OAuth2 clients received an ID token in which WeftID session.

One row per (session, client), keyed by the session identifier that the ID
token carries as its ``sid`` claim. Logout reads and deletes a session's rows
to notify the relying parties (front-channel iframes; back-channel later).
``client_id`` here is the client's internal UUID (``oauth2_clients.id``).
"""

from database._core import TenantArg, execute, fetchall


def upsert_session_client(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sid: str,
    client_id: str,
    user_id: str,
) -> int:
    """Record that ``client_id`` received an ID token in session ``sid``.

    A repeat issuance in the same session only refreshes ``last_issued_at``.
    """
    return execute(
        tenant_id,
        """
        insert into oidc_session_clients (tenant_id, sid, client_id, user_id)
        values (:tenant_id, :sid, :client_id, :user_id)
        on conflict (tenant_id, sid, client_id) do update
            set last_issued_at = now(), user_id = excluded.user_id
        """,
        {
            "tenant_id": tenant_id_value,
            "sid": sid,
            "client_id": client_id,
            "user_id": user_id,
        },
    )


def delete_session_clients(tenant_id: TenantArg, sid: str) -> list[dict]:
    """Delete every row for session ``sid`` and return the clients they named.

    Each returned dict has the client's internal ``id``, public ``client_id``,
    ``client_type``, ``is_active``, ``oidc_enabled``, ``frontchannel_logout_uri``
    and ``frontchannel_logout_session_required``, plus the row's ``user_id``,
    ordered by when the client first received a token in the session.
    """
    return fetchall(
        tenant_id,
        """
        delete from oidc_session_clients s
        using oauth2_clients c
        where s.sid = :sid and c.id = s.client_id
        returning c.id, c.client_id, c.client_type, c.is_active, c.oidc_enabled,
                  c.frontchannel_logout_uri, c.frontchannel_logout_session_required,
                  s.user_id, s.created_at
        """,
        {"sid": sid},
    )
