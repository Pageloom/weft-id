"""Delivery of queued OIDC back-channel logout tokens.

Ending a WeftID session queues one delivery per relying party that registered
a back-channel logout URI. This job, run by the worker's periodic timer every
few seconds, finds the tenants with deliveries due and sends them through the
service layer (``services.oidc.deliver_due_backchannel_logouts``), which
mints each logout token, POSTs it, and records the outcome.

A failure for one tenant is logged and does not stop the others.
"""

import logging
from typing import Any

from services.oidc import (
    deliver_due_backchannel_logouts,
    list_tenants_with_due_backchannel_logouts,
)
from utils.request_context import system_context

logger = logging.getLogger(__name__)


def deliver_oidc_backchannel_logouts() -> dict[str, Any]:
    """Send every due back-channel logout delivery, tenant by tenant.

    Called directly by the worker's periodic timer, not as a queued job.
    Quiet when there is nothing to do (it runs every few seconds).

    Returns:
        Totals of ``delivered``, ``retried``, ``failed`` and ``skipped``, and
        the tenant IDs whose pass raised.
    """
    totals: dict[str, Any] = {"delivered": 0, "retried": 0, "failed": 0, "skipped": 0}
    errors: list[str] = []
    with system_context():
        for tenant_id in list_tenants_with_due_backchannel_logouts():
            try:
                counts = deliver_due_backchannel_logouts(tenant_id)
            except Exception:
                logger.exception("Back-channel logout delivery failed for tenant %s", tenant_id)
                errors.append(tenant_id)
                continue
            for key, value in counts.items():
                totals[key] += value
    if any(totals.values()) or errors:
        logger.info("OIDC back-channel logout deliveries: %s, errors: %s", totals, errors)
    totals["errors"] = errors
    return totals
