"""Automatic certificate rotation and cleanup.

This module provides the scheduled job that:
1. Auto-rotates per-SP signing certificates based on the tenant's configured rotation window.
2. Cleans up previous SP signing certificates after their grace period has expired.
3. Auto-rotates per-IdP SP certificates based on the tenant's configured rotation window.
4. Cleans up previous per-IdP SP certificates after their grace period has expired.
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


def rotate_and_cleanup_certificates() -> dict[str, Any]:
    """
    Check all certificates (SP signing and per-IdP SP) for rotation or cleanup needs.

    This function is called directly by the worker's periodic timer (daily),
    not as a queued job.

    For each certificate needing rotation (expires within the tenant's configured window):
    - Generate a new certificate using the tenant's configured lifetime
    - Rotate with a grace period matching the tenant's rotation window
    - Log auto-rotation event

    For each certificate needing cleanup (grace period expired):
    - Clear previous certificate data
    - Log cleanup event

    Returns:
        Dict with rotated, cleaned_up counts (totals and per-type) and errors list
    """
    logger.info("Starting certificate rotation/cleanup check...")

    sp_rotated = 0
    sp_cleaned = 0
    idp_sp_rotated = 0
    idp_sp_cleaned = 0
    errors: list[dict[str, Any]] = []

    # --- SP signing certificates ---
    sp_certs = database.sp_signing_certificates.get_certificates_needing_rotation_or_cleanup()

    if sp_certs:
        sp_rotate = [c for c in sp_certs if c["action"] == "rotate"]
        sp_cleanup = [c for c in sp_certs if c["action"] == "cleanup"]

        logger.info(
            "SP signing: %d needing rotation, %d needing cleanup",
            len(sp_rotate),
            len(sp_cleanup),
        )

        with system_context():
            for cert in sp_rotate:
                try:
                    if _rotate_certificate(cert):
                        sp_rotated += 1
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
                            "cert_type": "sp_signing",
                            "cert_id": str(cert["id"]),
                            "sp_id": str(cert["sp_id"]),
                            "tenant_id": str(cert["tenant_id"]),
                            "error": str(e),
                        }
                    )

            for cert in sp_cleanup:
                try:
                    if _cleanup_certificate(cert):
                        sp_cleaned += 1
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
                            "cert_type": "sp_signing",
                            "cert_id": str(cert["id"]),
                            "sp_id": str(cert["sp_id"]),
                            "tenant_id": str(cert["tenant_id"]),
                            "error": str(e),
                        }
                    )
    else:
        logger.info("No SP signing certificates need rotation or cleanup")

    # --- Per-IdP SP certificates ---
    idp_sp_certs = database.saml.get_idp_sp_certificates_needing_rotation_or_cleanup()

    if idp_sp_certs:
        idp_sp_rotate = [c for c in idp_sp_certs if c["action"] == "rotate"]
        idp_sp_cleanup = [c for c in idp_sp_certs if c["action"] == "cleanup"]

        logger.info(
            "Per-IdP SP: %d needing rotation, %d needing cleanup",
            len(idp_sp_rotate),
            len(idp_sp_cleanup),
        )

        with system_context():
            for cert in idp_sp_rotate:
                try:
                    if _rotate_idp_sp_certificate(cert):
                        idp_sp_rotated += 1
                except Exception as e:
                    logger.exception(
                        "Failed to auto-rotate IdP SP certificate %s (idp=%s, tenant=%s): %s",
                        cert["id"],
                        cert["idp_id"],
                        cert["tenant_id"],
                        e,
                    )
                    errors.append(
                        {
                            "action": "rotate",
                            "cert_type": "idp_sp",
                            "cert_id": str(cert["id"]),
                            "idp_id": str(cert["idp_id"]),
                            "tenant_id": str(cert["tenant_id"]),
                            "error": str(e),
                        }
                    )

            for cert in idp_sp_cleanup:
                try:
                    if _cleanup_idp_sp_certificate(cert):
                        idp_sp_cleaned += 1
                except Exception as e:
                    logger.exception(
                        "Failed to clean up IdP SP certificate %s (idp=%s, tenant=%s): %s",
                        cert["id"],
                        cert["idp_id"],
                        cert["tenant_id"],
                        e,
                    )
                    errors.append(
                        {
                            "action": "cleanup",
                            "cert_type": "idp_sp",
                            "cert_id": str(cert["id"]),
                            "idp_id": str(cert["idp_id"]),
                            "tenant_id": str(cert["tenant_id"]),
                            "error": str(e),
                        }
                    )
    else:
        logger.info("No per-IdP SP certificates need rotation or cleanup")

    total_rotated = sp_rotated + idp_sp_rotated
    total_cleaned = sp_cleaned + idp_sp_cleaned

    logger.info(
        "Certificate rotation/cleanup completed: %d rotated, %d cleaned up, %d errors",
        total_rotated,
        total_cleaned,
        len(errors),
    )

    return {
        "rotated": total_rotated,
        "cleaned_up": total_cleaned,
        "errors": errors,
        "sp_rotated": sp_rotated,
        "sp_cleaned_up": sp_cleaned,
        "idp_sp_rotated": idp_sp_rotated,
        "idp_sp_cleaned_up": idp_sp_cleaned,
    }


# ---------------------------------------------------------------------------
# SP signing certificate helpers
# ---------------------------------------------------------------------------


def _rotate_certificate(cert: dict[str, Any]) -> bool:
    """Auto-rotate a single SP signing certificate.

    Generates a new certificate, stores it via the database rotation
    function, and logs an event.

    Returns True if rotation was performed, False if skipped.
    """
    tenant_id = str(cert["tenant_id"])
    sp_id = str(cert["sp_id"])

    with session(tenant_id=tenant_id):
        # Get tenant's configured certificate lifetime and rotation window
        lifetime = database.security.get_certificate_lifetime(tenant_id)
        rotation_window = database.security.get_certificate_rotation_window(tenant_id)

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

        grace_period_ends = datetime.now(UTC) + timedelta(days=rotation_window)

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
                "grace_period_days": rotation_window,
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


# ---------------------------------------------------------------------------
# Per-IdP SP certificate helpers
# ---------------------------------------------------------------------------


def _rotate_idp_sp_certificate(cert: dict[str, Any]) -> bool:
    """Auto-rotate a single per-IdP SP certificate.

    Generates a new certificate, stores it via the database rotation
    function, and logs an event.

    Returns True if rotation was performed, False if skipped.
    """
    tenant_id = str(cert["tenant_id"])
    idp_id = str(cert["idp_id"])

    with session(tenant_id=tenant_id):
        # Get tenant's configured certificate lifetime and rotation window
        lifetime = database.security.get_certificate_lifetime(tenant_id)
        rotation_window = database.security.get_certificate_rotation_window(tenant_id)

        # Generate new certificate
        new_cert_pem, new_key_pem = generate_sp_certificate(tenant_id, validity_years=lifetime)
        new_encrypted_key = encrypt_private_key(new_key_pem)
        new_expires_at = get_certificate_expiry(new_cert_pem)

        # Get current certificate for previous_* fields
        current = database.saml.get_idp_sp_certificate(tenant_id, idp_id)
        if current is None:
            logger.warning(
                "Certificate disappeared for idp=%s tenant=%s, skipping",
                idp_id,
                tenant_id,
            )
            return False

        grace_period_ends = datetime.now(UTC) + timedelta(days=rotation_window)

        result = database.saml.rotate_idp_sp_certificate(
            tenant_id=tenant_id,
            idp_id=idp_id,
            new_certificate_pem=new_cert_pem,
            new_private_key_pem_enc=new_encrypted_key,
            new_expires_at=new_expires_at,
            previous_certificate_pem=current["certificate_pem"],
            previous_private_key_pem_enc=current["private_key_pem_enc"],
            previous_expires_at=current["expires_at"],
            rotation_grace_period_ends_at=grace_period_ends,
        )

        if result is None:
            raise RuntimeError(f"rotate_idp_sp_certificate returned None for idp={idp_id}")

        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="saml_idp_sp_certificate",
            artifact_id=str(result["id"]),
            event_type="saml_idp_sp_certificate_auto_rotated",
            metadata={
                "idp_id": idp_id,
                "grace_period_days": rotation_window,
                "grace_period_ends_at": str(grace_period_ends),
                "new_expires_at": str(new_expires_at),
                "old_expires_at": str(cert["expires_at"]),
                "validity_years": lifetime,
            },
        )

    logger.info(
        "Auto-rotated certificate for idp=%s tenant=%s (expires %s -> %s)",
        idp_id,
        tenant_id,
        cert["expires_at"],
        new_expires_at,
    )
    return True


def _cleanup_idp_sp_certificate(cert: dict[str, Any]) -> bool:
    """Clean up previous per-IdP SP certificate data after grace period expiry.

    Returns True if cleanup was performed, False if skipped.
    """
    tenant_id = str(cert["tenant_id"])
    idp_id = str(cert["idp_id"])

    with session(tenant_id=tenant_id):
        result = database.saml.clear_previous_idp_sp_certificate(tenant_id, idp_id)

        if result is None:
            logger.warning(
                "Certificate disappeared for idp=%s tenant=%s, skipping",
                idp_id,
                tenant_id,
            )
            return False

        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="saml_idp_sp_certificate",
            artifact_id=str(result["id"]),
            event_type="saml_idp_sp_certificate_cleanup_completed",
            metadata={
                "idp_id": idp_id,
                "grace_period_ended_at": str(cert["rotation_grace_period_ends_at"]),
            },
        )

    logger.info(
        "Cleaned up previous certificate for idp=%s tenant=%s",
        idp_id,
        tenant_id,
    )
    return True
