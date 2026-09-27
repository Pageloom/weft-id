"""Server-side revocation of WeftID sessions.

WeftID sessions are signed cookies; nothing on the server can delete one. A
session that must end from the server (an upstream IdP's logout token, or a
local logout that must also defeat a copied cookie) is listed here by its
session identifier (``sid``), and every authenticated request checks the list.

Rows are kept for ``older_than_days`` by the retention sweep: the cookie is
refused once idle longer than its max_age, so an older row can never match a
live cookie.
"""

from database._core import UNSCOPED, TenantArg, execute, fetchall, fetchone


def revoke_session(tenant_id: TenantArg, tenant_id_value: str, sid: str) -> int:
    """List ``sid`` as revoked. Idempotent; returns 1 when newly listed."""
    return execute(
        tenant_id,
        """
        insert into revoked_sessions (tenant_id, sid)
        values (:tenant_id, :sid)
        on conflict (tenant_id, sid) do nothing
        """,
        {"tenant_id": tenant_id_value, "sid": sid},
    )


def is_session_revoked(tenant_id: TenantArg, sid: str) -> bool:
    """True when ``sid`` has been revoked in this tenant."""
    row = fetchone(
        tenant_id,
        "select 1 as revoked from revoked_sessions where sid = :sid",
        {"sid": sid},
    )
    return row is not None


def purge_revoked_sessions(*, older_than_days: int) -> int:
    """Delete rows revoked more than ``older_than_days`` ago.

    Cross-tenant (SECURITY DEFINER function); returns the number deleted.
    """
    rows = fetchall(
        UNSCOPED,
        "select purge_revoked_sessions(make_interval(days => :days)) as n",
        {"days": older_than_days},
    )
    return int(rows[0]["n"]) if rows else 0
