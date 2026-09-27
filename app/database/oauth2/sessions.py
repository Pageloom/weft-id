"""Which OAuth2 clients received an ID token in which WeftID session.

One row per (session, client), keyed by the session identifier that the ID
token carries as its ``sid`` claim. Logout reads and deletes a session's rows
to notify the relying parties (front-channel iframes, back-channel logout
tokens queued in ``oidc_backchannel_logout_deliveries``).
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


def consume_session_clients(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sid: str,
    *,
    issuer: str,
    exclude_client_id: str | None = None,
) -> list[dict]:
    """Delete every row for session ``sid`` and queue its back-channel logouts.

    One statement, so the rows can never be gone without their deliveries
    queued. A delivery (``oidc_backchannel_logout_deliveries``) is queued for
    each client that registered a ``backchannel_logout_uri`` and is an active,
    normal, OIDC-enabled client, except ``exclude_client_id`` (internal UUID),
    whose row is still deleted.

    Each returned dict has the client's internal ``id``, public ``client_id``,
    ``client_type``, ``is_active``, ``oidc_enabled``, ``frontchannel_logout_uri``,
    ``frontchannel_logout_session_required`` and ``backchannel_logout_uri``, the
    row's ``user_id`` and ``created_at``, and ``backchannel_queued``. Order is
    unspecified.
    """
    return fetchall(
        tenant_id,
        """
        with consumed as (
            delete from oidc_session_clients s
            using oauth2_clients c
            where s.sid = :sid and c.id = s.client_id
            returning c.id, c.client_id, c.client_type, c.is_active, c.oidc_enabled,
                      c.frontchannel_logout_uri, c.frontchannel_logout_session_required,
                      c.backchannel_logout_uri, s.user_id, s.created_at
        ),
        queued as (
            insert into oidc_backchannel_logout_deliveries (tenant_id, client_id, sub, sid, issuer)
            select :tenant_id, consumed.id, cast(consumed.user_id as text), :sid, :issuer
            from consumed
            where consumed.backchannel_logout_uri is not null
              and consumed.client_type = 'normal'
              and consumed.is_active
              and consumed.oidc_enabled
              and consumed.id is distinct from cast(:exclude_client_id as uuid)
            returning client_id
        )
        select consumed.*,
               exists (select 1 from queued q where q.client_id = consumed.id)
                   as backchannel_queued
        from consumed
        """,
        {
            "tenant_id": tenant_id_value,
            "sid": sid,
            "issuer": issuer,
            "exclude_client_id": exclude_client_id,
        },
    )
