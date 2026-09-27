"""Retention sweep for OIDC back-channel logout bookkeeping.

Purges finished back-channel logout deliveries past their retention, and
session records (``oidc_session_clients``) of sessions that ended without a
logout (an expired cookie), which nothing else would ever consume.
"""

import logging
from typing import Any

from services.oidc import cleanup_backchannel_logout_state
from utils.request_context import system_context

logger = logging.getLogger(__name__)


def cleanup_oidc_backchannel_logouts() -> dict[str, Any]:
    """Purge old deliveries and stale session records.

    Called directly by the worker's periodic timer (daily), not as a queued
    job. Idempotent.

    Returns:
        Dict with ``deliveries_purged`` and ``session_records_swept``.
    """
    with system_context():
        result = cleanup_backchannel_logout_state()
    logger.info(
        "OIDC back-channel cleanup: %d deliveries purged, %d stale session records swept",
        result["deliveries_purged"],
        result["session_records_swept"],
    )
    return result
