"""Nightly cleanup of `scim_sync_log` rows past their retention window.

Each SCIM-enabled SP has a per-SP `scim_log_retention` setting (one of
`'3' | '6' | '12' | '24' | 'forever'`). This job walks every SCIM-
enabled SP across every tenant, maps the enum to a Postgres interval
(or skips on `'forever'`), and deletes completed log rows older than
the cutoff.

Pruning runs only against rows with `completed_at IS NOT NULL`; in-
flight rows (`running`/`pending`) are preserved regardless of their
created_at, so a stuck row is still visible to admins.

The job is scheduled daily by the worker (`app/worker.py`).
"""

from __future__ import annotations

import logging
from typing import Any

import database
from database._core import session
from services.scim.sync_log import retention_to_interval

logger = logging.getLogger(__name__)


def cleanup_scim_sync_log() -> dict[str, Any]:
    """Delete `scim_sync_log` rows past their per-SP retention window.

    Returns a summary with `sps_processed`, `sps_skipped` (forever-
    retention or misconfigured), `rows_deleted`, plus a per-SP `details`
    list with the disposition of each SP.
    """
    sps = database.service_providers.list_scim_enabled_sps_all_tenants()
    if not sps:
        return _empty_summary()

    logger.info("SCIM sync-log cleanup: scanning %d SCIM-enabled SP(s)", len(sps))

    summary = _empty_summary()

    # Group by tenant so we open one RLS session per tenant rather than
    # one per SP.
    by_tenant: dict[str, list[dict]] = {}
    for sp in sps:
        by_tenant.setdefault(str(sp["tenant_id"]), []).append(sp)

    for tenant_id, sp_rows in by_tenant.items():
        try:
            with session(tenant_id=tenant_id):
                _process_tenant(tenant_id, sp_rows, summary)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "SCIM sync-log cleanup: tenant %s failed: %s",
                tenant_id,
                exc,
            )
            summary["details"].append({"tenant_id": tenant_id, "error": str(exc)})

    logger.info(
        "SCIM sync-log cleanup: deleted %d rows from %d SP(s) (skipped %d)",
        summary["rows_deleted"],
        summary["sps_processed"],
        summary["sps_skipped"],
    )
    return summary


def _process_tenant(tenant_id: str, sp_rows: list[dict], summary: dict[str, Any]) -> None:
    for sp in sp_rows:
        sp_id = str(sp["id"])
        retention = str(sp["scim_log_retention"])
        try:
            interval = retention_to_interval(retention)
        except ValueError as exc:
            logger.warning(
                "SCIM sync-log cleanup: SP %s has invalid retention %r: %s",
                sp_id,
                retention,
                exc,
            )
            summary["sps_skipped"] += 1
            summary["details"].append(
                {
                    "tenant_id": tenant_id,
                    "sp_id": sp_id,
                    "skipped": "invalid_retention",
                }
            )
            continue

        if interval is None:
            # 'forever' retention -- do not delete anything for this SP.
            summary["sps_skipped"] += 1
            summary["details"].append(
                {"tenant_id": tenant_id, "sp_id": sp_id, "skipped": "forever"}
            )
            continue

        try:
            deleted = database.scim_sync_log.delete_older_than(tenant_id, sp_id, interval)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "SCIM sync-log cleanup: SP %s delete failed: %s",
                sp_id,
                exc,
            )
            summary["sps_skipped"] += 1
            summary["details"].append(
                {
                    "tenant_id": tenant_id,
                    "sp_id": sp_id,
                    "error": str(exc),
                }
            )
            continue
        summary["sps_processed"] += 1
        summary["rows_deleted"] += deleted
        summary["details"].append(
            {
                "tenant_id": tenant_id,
                "sp_id": sp_id,
                "retention": retention,
                "deleted": deleted,
            }
        )


def _empty_summary() -> dict[str, Any]:
    return {
        "sps_processed": 0,
        "sps_skipped": 0,
        "rows_deleted": 0,
        "details": [],
    }
