"""IdP certificate management for multi-cert support.

This module handles operations for IdP signing certificates,
enabling certificate rotation without SSO downtime. Certificates
are managed exclusively through metadata sync.
"""

import logging

import database
from schemas.saml import IdPCertificate
from services.activity import track_activity
from services.auth import require_super_admin
from services.exceptions import NotFoundError
from services.types import RequestingUser
from utils.saml import get_certificate_expiry, get_certificate_fingerprint

logger = logging.getLogger(__name__)


def _cert_row_to_schema(row: dict) -> IdPCertificate:
    """Convert a database row to IdPCertificate schema."""
    return IdPCertificate(
        id=str(row["id"]),
        idp_id=str(row["idp_id"]),
        certificate_pem=row["certificate_pem"],
        fingerprint=row["fingerprint"],
        expires_at=row.get("expires_at"),
        created_at=row["created_at"],
    )


def _backfill_fingerprint(tenant_id: str, row: dict) -> dict:
    """Backfill fingerprint for migrated certificates with empty fingerprint."""
    if row["fingerprint"] == "":
        try:
            fingerprint = get_certificate_fingerprint(row["certificate_pem"])
            expires_at = get_certificate_expiry(row["certificate_pem"])
            updated = database.saml.update_idp_certificate_fingerprint(
                tenant_id, str(row["id"]), fingerprint, expires_at
            )
            if updated:
                return updated
        except Exception:
            logger.warning("Failed to backfill fingerprint for cert %s", row["id"])
    return row


def list_idp_certificates(requesting_user: RequestingUser, idp_id: str) -> list[IdPCertificate]:
    """List all certificates for an IdP.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="idp_certificates")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists
    idp = database.saml.get_identity_provider(tenant_id, idp_id)
    if idp is None:
        raise NotFoundError(message="Identity provider not found", code="idp_not_found")

    rows = database.saml.list_idp_certificates(tenant_id, idp_id)
    rows = [_backfill_fingerprint(tenant_id, r) for r in rows]
    return [_cert_row_to_schema(r) for r in rows]


def get_certificates_for_validation(tenant_id: str, idp_id: str) -> list[str]:
    """Get certificate PEM strings for SAML validation.

    No authorization required (called during SAML login flow).
    Backfills fingerprints for migrated certs.

    Returns:
        List of PEM certificate strings.
    """
    rows = database.saml.list_idp_certificates(tenant_id, idp_id)
    rows = [_backfill_fingerprint(tenant_id, r) for r in rows]
    return [r["certificate_pem"] for r in rows]


def sync_certificates_from_metadata(tenant_id: str, idp_id: str, certs: list[str]) -> None:
    """Sync certificates from metadata. Adds new certs, removes certs no longer in metadata.

    No authorization required (called during metadata import/refresh).
    """
    if not certs:
        return

    existing = database.saml.list_idp_certificates(tenant_id, idp_id)

    # Build set of existing fingerprints (backfill if needed)
    existing_fingerprints: dict[str, dict] = {}
    for row in existing:
        row = _backfill_fingerprint(tenant_id, row)
        fp = row["fingerprint"]
        if fp:
            existing_fingerprints[fp] = row

    # Compute fingerprints for incoming certs
    incoming_fingerprints: set[str] = set()
    for pem in certs:
        try:
            fp = get_certificate_fingerprint(pem.strip())
            incoming_fingerprints.add(fp)

            # Add new certs
            if fp not in existing_fingerprints:
                try:
                    expires_at = get_certificate_expiry(pem.strip())
                except Exception:
                    expires_at = None
                database.saml.create_idp_certificate(
                    tenant_id=tenant_id,
                    idp_id=idp_id,
                    tenant_id_value=tenant_id,
                    certificate_pem=pem.strip(),
                    fingerprint=fp,
                    expires_at=expires_at,
                )
        except Exception:
            logger.warning("Failed to process certificate during metadata sync for IdP %s", idp_id)

    # Remove certs no longer in metadata
    for fp, row in existing_fingerprints.items():
        if fp and fp not in incoming_fingerprints:
            database.saml.delete_idp_certificate(tenant_id, str(row["id"]))
