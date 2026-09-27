"""OpenID Connect Back-Channel Logout 1.0: logout tokens and their delivery.

Ending a WeftID session queues one delivery per client that registered a
``backchannel_logout_uri`` (``end_oidc_session``). The worker drains the queue
every few seconds with ``deliver_due_backchannel_logouts``: it mints a logout
token and POSTs it to the RP, form-encoded as ``logout_token`` (section 2.5).

The token is minted per attempt, so a retry never carries a stale ``iat`` or a
reused ``jti``. Claims (section 2.4): ``iss`` (the issuer captured when the
session ended, equal to the ID tokens' ``iss``), ``aud`` (the client_id),
``iat``, ``exp``, ``jti``, ``events`` with the back-channel logout member,
``sub`` always, ``sid`` when the client requires it, and never ``nonce``. The
JOSE header carries ``typ: logout+jwt`` and the signing key's ``kid``.

Outcomes: any 2xx is delivered. A 4xx other than 408/429 means the RP refused
the token (section 2.8: it returns 400 when logout failed); resending the same
claims will not change that, so the delivery fails at once. Network errors,
5xx, 408 and 429 are retried on ``RETRY_SCHEDULE``; after the last retry the
delivery fails. A failed delivery logs ``oidc_backchannel_logout_failed``.

Finished rows stay as the delivery log for ``DELIVERY_RETENTION_DAYS``;
``cleanup_backchannel_logout_state`` purges them and sweeps session records
of sessions that ended without a logout.
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import database
import httpx
import jwt
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.oidc.keys import get_active_signing_key
from utils.safe_http import build_safe_client

logger = logging.getLogger(__name__)

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

# A logout token is consumed on arrival; two minutes (the spec's example)
# covers clock skew without leaving a replay window worth having.
LOGOUT_TOKEN_LIFETIME = timedelta(minutes=2)

# Seconds to wait before each retry. The first attempt plus these five: the
# last retry happens about seven hours after the logout.
RETRY_SCHEDULE = (30, 120, 600, 3600, 21600)
MAX_ATTEMPTS = 1 + len(RETRY_SCHEDULE)

# Deliveries are claimed in small batches; a claimed delivery is hidden from
# other workers for LEASE_SECONDS, which exceeds a whole batch at the HTTP
# timeout (10 x 5 s), so a slow RP cannot cause a second send.
HTTP_TIMEOUT_SECONDS = 5.0
BATCH_SIZE = 10
LEASE_SECONDS = 120

DELIVERY_RETENTION_DAYS = 30
# Session records last written this long ago belong to sessions that ended
# without a logout (sessions have no hard maximum lifetime; see migration 0065).
STALE_SESSION_RECORD_DAYS = 90

# The OIDC conformance suite serves its back-channel endpoint from a docker
# service on the dev network with a self-signed certificate. Dev only: both
# escape hatches are inert when IS_DEV is false.
_DEV_HOSTNAME_ALLOWLIST = frozenset({"localhost.emobix.co.uk"})

_RETRYABLE_4XX = frozenset({408, 429})


def build_logout_token(
    *,
    tenant_id: str,
    issuer: str,
    client_id: str,
    sub: str,
    sid: str | None,
) -> str:
    """Mint a signed logout token for one client.

    Authorization: none -- called only by the delivery worker for a queued
    delivery. No audit: minting is not an event; the outcome is recorded on
    the delivery row.
    """
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "iss": issuer,
        "aud": client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + LOGOUT_TOKEN_LIFETIME).timestamp()),
        "jti": secrets.token_urlsafe(24),
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
        "sub": sub,
    }
    if sid:
        payload["sid"] = sid
    signing_key = get_active_signing_key(tenant_id)
    return jwt.encode(
        payload,
        signing_key.private_key_pem,
        algorithm=signing_key.algorithm,
        headers={"kid": signing_key.kid, "typ": "logout+jwt"},
    )


def _build_http_client() -> httpx.Client:
    return build_safe_client(
        timeout=HTTP_TIMEOUT_SECONDS,
        dev_hostname_allowlist=_DEV_HOSTNAME_ALLOWLIST,
        dev_skip_tls_verify=True,
        dev_base_domain_rewrite=True,
    )


def _still_eligible(delivery: dict) -> bool:
    return bool(
        delivery.get("backchannel_logout_uri")
        and delivery.get("client_type") == "normal"
        and delivery.get("is_active")
        and delivery.get("oidc_enabled")
    )


def _send(client: httpx.Client, delivery: dict, tenant_id: str) -> tuple[int | None, str | None]:
    """POST the logout token. Returns (HTTP status or None, error or None)."""
    token = build_logout_token(
        tenant_id=tenant_id,
        issuer=delivery["issuer"],
        client_id=delivery["client_id"],
        sub=delivery["sub"],
        sid=delivery["sid"] if delivery.get("backchannel_logout_session_required") else None,
    )
    try:
        response = client.post(
            delivery["backchannel_logout_uri"],
            data={"logout_token": token},
            headers={"Cache-Control": "no-store"},
        )
    except httpx.HTTPError as exc:
        return None, f"network_error: {type(exc).__name__}: {str(exc)[:200]}"
    if 200 <= response.status_code < 300:
        return response.status_code, None
    return response.status_code, f"http_{response.status_code}"


def _record_failure(tenant_id: str, delivery: dict, *, error: str, http_status: int | None) -> None:
    attempts = delivery["attempts"] + 1
    database.oauth2.mark_failed(
        tenant_id, str(delivery["id"]), error=error, http_status=http_status
    )
    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="oauth2_client",
        artifact_id=str(delivery["client_uuid"]),
        event_type="oidc_backchannel_logout_failed",
        metadata={
            "client_id": delivery["client_id"],
            "attempts": attempts,
            "http_status": http_status,
            "error": error,
        },
    )


def deliver_due_backchannel_logouts(
    tenant_id: str, *, http_client: httpx.Client | None = None
) -> dict[str, int]:
    """Send every due back-channel logout delivery of one tenant.

    Authorization: none -- worker entry point (system context).

    Logs: ``oidc_backchannel_logout_failed`` when a delivery is given up.
    Deliveries for a client that no longer takes part (deactivated, OIDC
    disabled, URI removed) are closed as failed without an attempt or event.

    Returns:
        Counts: ``delivered``, ``retried``, ``failed``, ``skipped``.
    """
    counts = {"delivered": 0, "retried": 0, "failed": 0, "skipped": 0}
    owns_client = http_client is None
    client: httpx.Client | None = http_client
    try:
        while True:
            deliveries = database.oauth2.claim_due_deliveries(
                tenant_id, limit=BATCH_SIZE, lease_seconds=LEASE_SECONDS
            )
            if deliveries and client is None:
                client = _build_http_client()
            for delivery in deliveries:
                assert client is not None
                counts[_deliver_one(client, delivery, tenant_id)] += 1
            if len(deliveries) < BATCH_SIZE:
                break
    finally:
        if owns_client and client is not None:
            client.close()
    return counts


def _deliver_one(client: httpx.Client, delivery: dict, tenant_id: str) -> str:
    """Attempt one claimed delivery, record the outcome, return its count key."""
    delivery_id = str(delivery["id"])
    if not _still_eligible(delivery):
        database.oauth2.mark_failed(
            tenant_id,
            delivery_id,
            error="client_no_longer_eligible",
            http_status=None,
            count_attempt=False,
        )
        return "skipped"

    http_status, error = _send(client, delivery, tenant_id)
    if error is None:
        database.oauth2.mark_delivered(tenant_id, delivery_id, http_status=http_status or 200)
        return "delivered"

    attempt = delivery["attempts"] + 1
    logger.warning(
        "Back-channel logout to client %s failed (attempt %d): %s",
        delivery["client_id"],
        attempt,
        error,
    )
    permanent = (
        http_status is not None and 400 <= http_status < 500 and http_status not in _RETRYABLE_4XX
    )
    if permanent or attempt >= MAX_ATTEMPTS:
        _record_failure(tenant_id, delivery, error=error, http_status=http_status)
        return "failed"
    database.oauth2.mark_retry(
        tenant_id,
        delivery_id,
        retry_in_seconds=RETRY_SCHEDULE[attempt - 1],
        error=error,
        http_status=http_status,
    )
    return "retried"


def list_tenants_with_due_backchannel_logouts() -> list[str]:
    """Tenants with deliveries due now. Worker entry point; no audit."""
    return database.oauth2.list_tenants_with_due_deliveries()


def cleanup_backchannel_logout_state() -> dict[str, int]:
    """Purge old finished deliveries and stale session records.

    Authorization: none -- worker entry point. No audit: retention
    bookkeeping of rows that are themselves the record.
    """
    return {
        "deliveries_purged": database.oauth2.purge_finished_deliveries(
            older_than_days=DELIVERY_RETENTION_DAYS
        ),
        "session_records_swept": database.oauth2.sweep_stale_session_clients(
            older_than_days=STALE_SESSION_RECORD_DAYS
        ),
    }
