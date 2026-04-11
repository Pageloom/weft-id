"""SAML debug entry cleanup job.

Deletes debug entries older than 24 hours. Called by the worker's
periodic timer (not a queued job).
"""

import logging
from typing import Any

import database

logger = logging.getLogger(__name__)


def cleanup_saml_debug_entries() -> dict[str, Any]:
    """Delete SAML debug entries older than 24 hours."""
    deleted = database.saml.delete_old_debug_entries(hours=24)
    if deleted:
        logger.info("SAML debug cleanup: deleted %d entries", deleted)
    return {"deleted": deleted}
