"""Outbound SCIM push queue processor.

Scans every tenant with ready queue entries, opens an RLS-scoped session
per tenant, and runs `services.scim.worker.process_pending_pushes()` for
the tenant slice. The actual draining logic lives in the service layer
(`app/services/scim/worker.py`); this file is a thin shell that handles:

- Cross-tenant discovery (UNSCOPED query for distinct tenant ids that
  have ready work).
- Tenant-scoped session setup for the worker.
- Per-tenant error isolation: a failure on one tenant must not block the
  others.

The worker container schedules this periodically (every minute, per the
worker config in `app/worker.py`). Per-tenant parallelism is supplied by
multiple worker containers; within a single worker run the tenant
iteration is sequential -- on the assumption that the cadence (minute-
level) and the 500-row drain cap keep individual runs short.
"""

from __future__ import annotations

import logging
from typing import Any

import database
from database._core import session
from services.scim import worker as scim_worker
from utils.scim_crypto import InvalidToken, decrypt_token

logger = logging.getLogger(__name__)


def _resolve_outbound_token(tenant_id: str, sp_id: str) -> tuple[str, str] | None:
    """Production token resolver for the SCIM push worker.

    Looks up the most-recent non-revoked credential row for the SP whose
    `encrypted_plaintext` is set, decrypts the value with the Fernet key
    derived from `SECRET_KEY`, and returns `(credential_id, plaintext)`.
    Returns None (the safe failure path) when:

    - No active credential exists for this SP.
    - The active row is from before iteration 5 (no plaintext stored).
    - The ciphertext fails Fernet validation (key rotation without a
      re-encrypt, corrupted bytes, etc.).

    The worker dead-letters the queue entry on a None return with reason
    `no_credential_source`. The credential id is returned alongside the
    plaintext so the worker can call `update_last_used()` after a
    successful push without re-querying. The tenant-scoped session is
    already active when this is called.
    """
    try:
        row = database.scim_credentials.get_active_credential_for_outbound(tenant_id, sp_id)
    except Exception:  # noqa: BLE001
        logger.exception(
            "SCIM token_resolver: lookup failed (tenant=%s sp=%s)",
            tenant_id,
            sp_id,
        )
        return None

    if row is None:
        return None

    ciphertext = row.get("encrypted_plaintext")
    if ciphertext is None:
        return None

    try:
        plaintext = decrypt_token(bytes(ciphertext))
    except InvalidToken:
        logger.error(
            "SCIM token_resolver: ciphertext invalid (tenant=%s sp=%s credential=%s)",
            tenant_id,
            sp_id,
            row.get("id"),
        )
        return None

    return (str(row["id"]), plaintext)


def process_scim_push_queue() -> dict[str, Any]:
    """Run one drain pass for every tenant that has ready queue entries.

    Returns a summary dict suitable for the periodic-job logger:
    `tenants_processed`, `entries_processed`, `succeeded`, `retried`,
    `dead_lettered`, `skipped`, plus a per-tenant `details` list.
    """
    tenant_ids = database.scim_push_queue.list_tenants_with_ready_entries()
    if not tenant_ids:
        return _empty_summary()

    logger.info("SCIM push queue: %d tenant(s) have ready entries", len(tenant_ids))

    summary = _empty_summary()
    summary["tenants_processed"] = len(tenant_ids)

    for tenant_id in tenant_ids:
        try:
            with session(tenant_id=tenant_id):
                tenant_summary = scim_worker.process_pending_pushes(
                    tenant_id,
                    token_resolver=_resolve_outbound_token,
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("SCIM push queue: tenant %s failed: %s", tenant_id, exc)
            summary["details"].append({"tenant_id": tenant_id, "error": str(exc)})
            continue

        summary["entries_processed"] += tenant_summary["entries_processed"]
        summary["succeeded"] += tenant_summary["succeeded"]
        summary["retried"] += tenant_summary["retried"]
        summary["dead_lettered"] += tenant_summary["dead_lettered"]
        summary["skipped"] += tenant_summary["skipped"]
        summary["details"].append({"tenant_id": tenant_id, **tenant_summary})

    logger.info(
        "SCIM push queue: processed %d entries across %d tenants "
        "(succeeded=%d, retried=%d, dead_lettered=%d, skipped=%d)",
        summary["entries_processed"],
        summary["tenants_processed"],
        summary["succeeded"],
        summary["retried"],
        summary["dead_lettered"],
        summary["skipped"],
    )
    return summary


def _empty_summary() -> dict[str, Any]:
    return {
        "tenants_processed": 0,
        "entries_processed": 0,
        "succeeded": 0,
        "retried": 0,
        "dead_lettered": 0,
        "skipped": 0,
        "details": [],
    }
