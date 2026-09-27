"""Retention sweep for OIDC logout and session-revocation bookkeeping.

Purges finished back-channel logout deliveries past their retention, and
session records (``oidc_session_clients``) of sessions that ended without a
logout (an expired cookie), which nothing else would ever consume. Also purges
server-side session revocations that can no longer match a live cookie,
upstream session links of long-gone sessions, and replay records of expired
upstream logout tokens.
"""

import logging
from typing import Any

from services.oidc import cleanup_backchannel_logout_state
from services.sessions import cleanup_session_state
from utils.request_context import system_context

logger = logging.getLogger(__name__)


def cleanup_oidc_backchannel_logouts() -> dict[str, Any]:
    """Purge old deliveries, stale session records, and revocation state.

    Called directly by the worker's periodic timer (daily), not as a queued
    job. Idempotent.

    Returns:
        Dict with ``deliveries_purged``, ``session_records_swept``,
        ``revoked_sessions_purged``, ``upstream_sessions_swept`` and
        ``logout_token_jtis_purged``.
    """
    with system_context():
        result = {**cleanup_backchannel_logout_state(), **cleanup_session_state()}
    logger.info(
        "OIDC logout cleanup: %d deliveries purged, %d stale session records swept, "
        "%d revoked sessions purged, %d upstream session links swept, "
        "%d logout token jtis purged",
        result["deliveries_purged"],
        result["session_records_swept"],
        result["revoked_sessions_purged"],
        result["upstream_sessions_swept"],
        result["logout_token_jtis_purged"],
    )
    return result
