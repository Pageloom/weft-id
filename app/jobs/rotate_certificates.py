"""Automatic SP signing certificate rotation and cleanup.

This module provides the scheduled job that:
1. Auto-rotates per-SP signing certificates expiring within 90 days.
2. Cleans up previous certificates after their grace period has expired.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import database
from database._core import session
from services.event_log import SYSTEM_ACTOR_ID, log_event
from utils.request_context import system_context
from utils.saml import (
    encrypt_private_key,
    generate_sp_certificate,
    get_certificate_expiry,
)

logger = logging.getLogger(__name__)

ROTATION_GRACE_PERIOD_DAYS = 90


def rotate_and_cleanup_certificates() -> dict[str, Any]:
    """
    Check all SP signing certificates for rotation or cleanup needs.

    This function is called directly by the worker's periodic timer (daily),
    not as a queued job.

    For each certificate needing rotation (expires within 90 days):
    - Generate a new certificate using the tenant's configured lifetime
    - Rotate with a 90-day grace period for SP migration
    - Log auto-rotation event

    For each certificate needing cleanup (grace period expired):
    - Clear previous certificate data
    - Log cleanup event

    Returns:
        Dict with rotated, cleaned_up counts and errors list
    """
    logger.info("Starting SP signing certificate rotation/cleanup check...")

    certs = database.sp_signing_certificates.get_certificates_needing_rotation_or_cleanup()

    if not certs:
        logger.info("No SP signing certificates need rotation or cleanup")
        return {"rotated": 0, "cleaned_up": 0, "errors": []}

    rotate_certs = [c for c in certs if c["action"] == "rotate"]
    cleanup_certs = [c for c in certs if c["action"] == "cleanup"]

    logger.info(
        "Found %d certificates needing rotation, %d needing cleanup",
        len(rotate_certs),
        len(cleanup_certs),
    )

    rotated = 0
    cleaned_up = 0
    errors: list[dict[str, Any]] = []

    with system_context():
        for cert in rotate_certs:
            try:
                if _rotate_certificate(cert):
                    rotated += 1
            except Exception as e:
                logger.exception(
                    "Failed to auto-rotate certificate %s (sp=%s, tenant=%s): %s",
                    cert["id"],
                    cert["sp_id"],
                    cert["tenant_id"],
                    e,
                )
                errors.append(
                    {
                        "action": "rotate",
                        "cert_id": str(cert["id"]),
                        "sp_id": str(cert["sp_id"]),
                        "tenant_id": str(cert["tenant_id"]),
                        "error": str(e),
                    }
                )

        for cert in cleanup_certs:
            try:
                if _cleanup_certificate(cert):
                    cleaned_up += 1
            except Exception as e:
                logger.exception(
                    "Failed to clean up certificate %s (sp=%s, tenant=%s): %s",
                    cert["id"],
                    cert["sp_id"],
                    cert["tenant_id"],
                    e,
                )
                errors.append(
                    {
                        "action": "cleanup",
                        "cert_id": str(cert["id"]),
                        "sp_id": str(cert["sp_id"]),
                        "tenant_id": str(cert["tenant_id"]),
                        "error": str(e),
                    }
                )

    logger.info(
        "Certificate rotation/cleanup completed: %d rotated, %d cleaned up, %d errors",
        rotated,
        cleaned_up,
        len(errors),
    )

    return {"rotated": rotated, "cleaned_up": cleaned_up, "errors": errors}


def _rotate_certificate(cert: dict[str, Any]) -> bool:
    """Auto-rotate a single SP signing certificate.

    Generates a new certificate, stores it via the database rotation
    function, and logs an event.

    Returns True if rotation was performed, False if skipped.
    """
    tenant_id = str(cert["tenant_id"])
    sp_id = str(cert["sp_id"])

    with session(tenant_id=tenant_id):
        # Get tenant's configured certificate lifetime
        lifetime = database.security.get_certificate_lifetime(tenant_id)

        # Generate new certificate
        new_cert_pem, new_key_pem = generate_sp_certificate(tenant_id, validity_years=lifetime)
        new_encrypted_key = encrypt_private_key(new_key_pem)
        new_expires_at = get_certificate_expiry(new_cert_pem)

        # Get current certificate for previous_* fields
        current = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
        if current is None:
            logger.warning(
                "Certificate disappeared for sp=%s tenant=%s, skipping",
                sp_id,
                tenant_id,
            )
            return False

        grace_period_ends = datetime.now(UTC) + timedelta(days=ROTATION_GRACE_PERIOD_DAYS)

        result = database.sp_signing_certificates.rotate_signing_certificate(
            tenant_id=tenant_id,
            sp_id=sp_id,
            new_certificate_pem=new_cert_pem,
            new_private_key_pem_enc=new_encrypted_key,
            new_expires_at=new_expires_at,
            previous_certificate_pem=current["certificate_pem"],
            previous_private_key_pem_enc=current["private_key_pem_enc"],
            previous_expires_at=current["expires_at"],
            rotation_grace_period_ends_at=grace_period_ends,
        )

        if result is None:
            raise RuntimeError(f"rotate_signing_certificate returned None for sp={sp_id}")

        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="sp_signing_certificate",
            artifact_id=str(result["id"]),
            event_type="sp_signing_certificate_auto_rotated",
            metadata={
                "sp_id": sp_id,
                "grace_period_days": ROTATION_GRACE_PERIOD_DAYS,
                "grace_period_ends_at": str(grace_period_ends),
                "new_expires_at": str(new_expires_at),
                "old_expires_at": str(cert["expires_at"]),
                "validity_years": lifetime,
            },
        )

    logger.info(
        "Auto-rotated certificate for sp=%s tenant=%s (expires %s -> %s)",
        sp_id,
        tenant_id,
        cert["expires_at"],
        new_expires_at,
    )
    return True


def _cleanup_certificate(cert: dict[str, Any]) -> bool:
    """Clean up previous certificate data after grace period expiry.

    Returns True if cleanup was performed, False if skipped.
    """
    tenant_id = str(cert["tenant_id"])
    sp_id = str(cert["sp_id"])

    with session(tenant_id=tenant_id):
        result = database.sp_signing_certificates.clear_previous_signing_certificate(
            tenant_id, sp_id
        )

        if result is None:
            logger.warning(
                "Certificate disappeared for sp=%s tenant=%s, skipping",
                sp_id,
                tenant_id,
            )
            return False

        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="sp_signing_certificate",
            artifact_id=str(result["id"]),
            event_type="sp_signing_certificate_cleanup_completed",
            metadata={
                "sp_id": sp_id,
                "grace_period_ended_at": str(cert["rotation_grace_period_ends_at"]),
            },
        )

    logger.info(
        "Cleaned up previous certificate for sp=%s tenant=%s",
        sp_id,
        tenant_id,
    )
    return True
