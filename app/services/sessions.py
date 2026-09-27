"""Server-side revocation of WeftID sessions.

Sessions are signed cookies, so ending one on the server means listing its
identifier (``sid``) as revoked; ``utils.auth.get_current_user`` checks the
list on every authenticated request and signs a revoked session out.

Every logout revokes the session it ends (so a copied cookie dies with the
logout), and an upstream IdP's back-channel logout revokes the sessions it
names, which is the only way that logout can reach a browser WeftID never
sees.
"""

from __future__ import annotations

import database

# Starlette refuses a session cookie idle longer than its max_age (14 days)
# and re-signs it on every response. A revoked sid is presented within that
# window or never again; one day of margin on top.
REVOKED_SESSION_RETENTION_DAYS = 15

# Upstream session links of sessions that ended by cookie expiry (nothing
# announces those). Same horizon as the downstream session records.
STALE_UPSTREAM_SESSION_DAYS = 90


def revoke_session(*, tenant_id: str, sid: str) -> None:
    """Revoke WeftID session ``sid`` and forget its upstream sign-in link.

    Authorization: none -- called while the session itself is being ended
    (logout, forced re-authentication) or by the upstream back-channel logout
    receiver after the IdP's logout token verified.

    No audit of its own: the caller's ``user_signed_out`` event records the
    logout.
    """
    database.revoked_sessions.revoke_session(tenant_id, tenant_id, sid)
    database.oidc_upstream.delete_idp_session(tenant_id, sid)


def cleanup_session_state() -> dict[str, int]:
    """Purge old revocations, stale upstream links, and expired jti records.

    Authorization: none -- worker entry point. No audit: retention
    bookkeeping of rows that can no longer match anything.
    """
    return {
        "revoked_sessions_purged": database.revoked_sessions.purge_revoked_sessions(
            older_than_days=REVOKED_SESSION_RETENTION_DAYS
        ),
        "upstream_sessions_swept": database.oidc_upstream.sweep_stale_idp_sessions(
            older_than_days=STALE_UPSTREAM_SESSION_DAYS
        ),
        "logout_token_jtis_purged": database.oidc_upstream.purge_expired_logout_token_jtis(),
    }
