"""Upstream OIDC sessions: which upstream sign-in created which WeftID session.

One row per WeftID session (``sid``) that began with a sign-in at an upstream
OIDC connection, holding the upstream ``sub`` and, when the IdP sent one, the
upstream ``sid``. A back-channel logout token from that IdP names the upstream
session; these rows map it to the WeftID sessions to revoke.

Also the replay store for accepted logout tokens (``jti`` until expiry).

Every query is RLS-scoped via the ``tenant_id`` argument, except the
retention sweeps, which run cross-tenant through SECURITY DEFINER functions.
"""

from datetime import datetime

from database._core import UNSCOPED, TenantArg, execute, fetchall, fetchone

_COLUMNS = "tenant_id, sid, idp_id, user_id, upstream_sub, upstream_sid, created_at"


def record_idp_session(
    tenant_id: TenantArg,
    tenant_id_value: str,
    *,
    sid: str,
    idp_id: str,
    user_id: str,
    upstream_sub: str,
    upstream_sid: str | None,
) -> int:
    """Record that WeftID session ``sid`` began with this upstream sign-in.

    A session is created by exactly one sign-in, so a repeat for the same sid
    replaces the row.
    """
    return execute(
        tenant_id,
        """
        insert into oidc_idp_sessions
            (tenant_id, sid, idp_id, user_id, upstream_sub, upstream_sid)
        values (:tenant_id, :sid, :idp_id, :user_id, :upstream_sub, :upstream_sid)
        on conflict (tenant_id, sid) do update
            set idp_id = excluded.idp_id, user_id = excluded.user_id,
                upstream_sub = excluded.upstream_sub,
                upstream_sid = excluded.upstream_sid, created_at = now()
        """,
        {
            "tenant_id": tenant_id_value,
            "sid": sid,
            "idp_id": idp_id,
            "user_id": user_id,
            "upstream_sub": upstream_sub,
            "upstream_sid": upstream_sid,
        },
    )


def find_idp_sessions(
    tenant_id: TenantArg,
    idp_id: str,
    *,
    upstream_sid: str | None,
    upstream_sub: str | None,
) -> list[dict]:
    """WeftID sessions linked to an upstream session or subject.

    With ``upstream_sid``, the sessions created by that upstream session
    (narrowed to ``upstream_sub`` when both are given). With only
    ``upstream_sub``, every session of that subject at this connection.
    Neither returns nothing.
    """
    if not upstream_sid and not upstream_sub:
        return []
    return fetchall(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_sessions
        where idp_id = :idp_id
          and (cast(:upstream_sid as text) is null or upstream_sid = :upstream_sid)
          and (cast(:upstream_sub as text) is null or upstream_sub = :upstream_sub)
        order by created_at
        """,
        {"idp_id": idp_id, "upstream_sid": upstream_sid, "upstream_sub": upstream_sub},
    )


def get_idp_session(tenant_id: TenantArg, sid: str) -> dict | None:
    """The upstream sign-in behind WeftID session ``sid``, or None."""
    return fetchone(
        tenant_id,
        f"select {_COLUMNS} from oidc_idp_sessions where sid = :sid",
        {"sid": sid},
    )


def delete_idp_session(tenant_id: TenantArg, sid: str) -> int:
    """Forget the upstream link of WeftID session ``sid`` (it has ended)."""
    return execute(
        tenant_id,
        "delete from oidc_idp_sessions where sid = :sid",
        {"sid": sid},
    )


def sweep_stale_idp_sessions(*, older_than_days: int) -> int:
    """Delete links created more than ``older_than_days`` ago.

    These belong to sessions that ended by cookie expiry, which nothing
    announces. Cross-tenant (SECURITY DEFINER function).
    """
    rows = fetchall(
        UNSCOPED,
        "select sweep_stale_oidc_idp_sessions(make_interval(days => :days)) as n",
        {"days": older_than_days},
    )
    return int(rows[0]["n"]) if rows else 0


def consume_logout_token_jti(
    tenant_id: TenantArg,
    tenant_id_value: str,
    *,
    idp_id: str,
    jti: str,
    expires_at: datetime,
) -> bool:
    """Record an accepted logout token's ``jti``; False when already seen.

    A single conditional insert, so two concurrent deliveries of one token
    cannot both be accepted.
    """
    row = fetchone(
        tenant_id,
        """
        insert into oidc_idp_logout_token_jtis (tenant_id, idp_id, jti, expires_at)
        values (:tenant_id, :idp_id, :jti, :expires_at)
        on conflict (tenant_id, idp_id, jti) do nothing
        returning jti
        """,
        {"tenant_id": tenant_id_value, "idp_id": idp_id, "jti": jti, "expires_at": expires_at},
    )
    return row is not None


def purge_expired_logout_token_jtis() -> int:
    """Delete replay records of expired logout tokens. Cross-tenant."""
    rows = fetchall(UNSCOPED, "select purge_expired_oidc_idp_logout_token_jtis() as n")
    return int(rows[0]["n"]) if rows else 0
