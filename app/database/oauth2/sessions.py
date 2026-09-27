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
    *,
    issuer: str | None = None,
) -> int:
    """Record that ``client_id`` received an ID token in session ``sid``.

    ``issuer`` is the ID token's ``iss``, kept so a logout token can repeat it
    when the session ends without a request (user deactivation). A repeat
    issuance in the same session refreshes ``last_issued_at`` and the issuer.
    """
    return execute(
        tenant_id,
        """
        insert into oidc_session_clients (tenant_id, sid, client_id, user_id, issuer)
        values (:tenant_id, :sid, :client_id, :user_id, :issuer)
        on conflict (tenant_id, sid, client_id) do update
            set last_issued_at = now(), user_id = excluded.user_id,
                issuer = coalesce(excluded.issuer, oidc_session_clients.issuer)
        """,
        {
            "tenant_id": tenant_id_value,
            "sid": sid,
            "client_id": client_id,
            "user_id": user_id,
            "issuer": issuer,
        },
    )


# Deletes the matching session rows and queues their back-channel deliveries
# in one statement, so rows can never be gone without their deliveries queued.
# ``{match}`` selects the rows (by session or by user). Each delivery carries
# the row's own sid and the issuer recorded at ID-token issuance, falling back
# to :issuer for rows written before the issuer was recorded.
_CONSUME_SQL = """
    with consumed as (
        delete from oidc_session_clients s
        using oauth2_clients c
        where {match} and c.id = s.client_id
        returning c.id, c.client_id, c.client_type, c.is_active, c.oidc_enabled,
                  c.frontchannel_logout_uri, c.frontchannel_logout_session_required,
                  c.backchannel_logout_uri, s.sid, s.user_id, s.created_at,
                  coalesce(s.issuer, :issuer) as issuer
    ),
    queued as (
        insert into oidc_backchannel_logout_deliveries (tenant_id, client_id, sub, sid, issuer)
        select :tenant_id, consumed.id, cast(consumed.user_id as text), consumed.sid,
               consumed.issuer
        from consumed
        where consumed.backchannel_logout_uri is not null
          and consumed.client_type = 'normal'
          and consumed.is_active
          and consumed.oidc_enabled
          and consumed.id is distinct from cast(:exclude_client_id as uuid)
        returning client_id, sid
    )
    select consumed.*,
           exists (
               select 1 from queued q where q.client_id = consumed.id and q.sid = consumed.sid
           ) as backchannel_queued
    from consumed
"""


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
    whose row is still deleted. The delivery's issuer is the one recorded with
    the row, or ``issuer`` for rows that have none.

    Each returned dict has the client's internal ``id``, public ``client_id``,
    ``client_type``, ``is_active``, ``oidc_enabled``, ``frontchannel_logout_uri``,
    ``frontchannel_logout_session_required`` and ``backchannel_logout_uri``, the
    row's ``sid``, ``user_id``, ``created_at`` and effective ``issuer``, and
    ``backchannel_queued``. Order is unspecified.
    """
    return fetchall(
        tenant_id,
        _CONSUME_SQL.format(match="s.sid = :sid"),
        {
            "tenant_id": tenant_id_value,
            "sid": sid,
            "issuer": issuer,
            "exclude_client_id": exclude_client_id,
        },
    )


def consume_user_session_clients(
    tenant_id: TenantArg,
    tenant_id_value: str,
    user_id: str,
    *,
    issuer: str,
) -> list[dict]:
    """Delete every row of ``user_id`` (all sessions) and queue their logouts.

    Same statement and return shape as ``consume_session_clients``, matched by
    user instead of session: one delivery per (session, back-channel client).
    ``issuer`` is the fallback for rows recorded without one.
    """
    return fetchall(
        tenant_id,
        _CONSUME_SQL.format(match="s.user_id = :user_id"),
        {
            "tenant_id": tenant_id_value,
            "user_id": user_id,
            "issuer": issuer,
            "exclude_client_id": None,
        },
    )
