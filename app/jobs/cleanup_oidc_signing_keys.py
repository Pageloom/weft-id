"""Periodic cleanup of retired OIDC signing keys.

After a signing-key rotation, the retired key stays published in the
tenant's JWKS for a grace period so relying parties can verify in-flight
ID tokens. This sweep finds tenants whose grace period has ended and clears
the retired key material via the service layer (which emits the
``oidc_signing_key_cleanup_completed`` event).
"""

import logging
from typing import Any

from services.oidc import cleanup_previous_signing_key, list_signing_keys_needing_cleanup
from utils.request_context import system_context

logger = logging.getLogger(__name__)


def cleanup_oidc_signing_keys() -> dict[str, Any]:
    """Clear retired OIDC signing keys whose rotation grace period has ended.

    Called directly by the worker's periodic timer (hourly), not as a queued
    job. Idempotent: a key already cleared (or still within grace) is skipped.

    Returns:
        Dict with cleaned_up count and errors list.
    """
    rows = list_signing_keys_needing_cleanup()
    if not rows:
        logger.info("No retired OIDC signing keys need cleanup")
        return {"cleaned_up": 0, "errors": []}

    logger.info("OIDC signing keys: %d retired key(s) past grace period", len(rows))

    cleaned_up = 0
    errors: list[dict[str, Any]] = []

    with system_context():
        for row in rows:
            tenant_id = str(row["tenant_id"])
            try:
                if cleanup_previous_signing_key(tenant_id):
                    cleaned_up += 1
                    logger.info(
                        "Cleaned up retired OIDC signing key %s for tenant %s",
                        row["previous_kid"],
                        tenant_id,
                    )
            except Exception as e:
                logger.exception(
                    "Failed to clean up retired OIDC signing key for tenant %s: %s",
                    tenant_id,
                    e,
                )
                errors.append(
                    {
                        "tenant_id": tenant_id,
                        "previous_kid": row["previous_kid"],
                        "error": str(e),
                    }
                )

    logger.info(
        "OIDC signing-key cleanup completed: %d cleaned up, %d errors",
        cleaned_up,
        len(errors),
    )
    return {"cleaned_up": cleaned_up, "errors": errors}
