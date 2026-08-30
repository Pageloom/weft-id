"""Periodic cleanup of expired forward-auth handshake nonces.

The forward-auth handshake records a single-use nonce at `/authorize` and
consumes it at `/callback`. A handshake the user abandons (closes the tab
before `/callback`) leaves an unconsumed, soon-expired row behind. This sweep
purges expired rows so the `forward_auth_nonces` table does not accumulate
dead rows over time.
"""

import logging
from typing import Any

from services.forward_auth import cleanup_expired_nonces
from utils.request_context import system_context

logger = logging.getLogger(__name__)


def cleanup_forward_auth_nonces() -> dict[str, Any]:
    """Purge expired forward-auth nonce rows.

    Called directly by the worker's periodic timer (hourly), not as a queued
    job. Idempotent: rows already purged (or still unexpired) are untouched.

    Returns:
        Dict with deleted count.
    """
    with system_context():
        deleted = cleanup_expired_nonces()

    logger.info("Forward-auth nonce cleanup: %d expired nonce(s) purged", deleted)
    return {"deleted": deleted}
