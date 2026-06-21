"""Generic SCIM 2.0 client (transport + retry).

Public API:
    push_user(sp, user_resource, *, token, http_client=None) -> PushResult
    push_group(sp, group_resource, *, token, http_client=None) -> PushResult
    put_user(sp, remote_id, user_resource, *, token, http_client=None) -> PushResult
    put_group(sp, remote_id, group_resource, *, token, http_client=None) -> PushResult
    delete_user(sp, remote_id, *, token, http_client=None) -> PushResult
    delete_group(sp, remote_id, *, token, http_client=None) -> PushResult

This module is pure transport: it sends spec-correct requests, applies the
matching quirk module's transforms, retries on transient errors, and reports
a structured result. It does not touch the database, the queue, or the audit
log -- the worker (iteration 4) owns all of that.

`sp` is a row-shaped dict from `database.service_providers` -- the client
only reads `scim_target_url` and `scim_kind`. The plaintext bearer token is
passed by keyword; the worker is responsible for sourcing it.

POST vs PUT:
    The worker decides which to call based on whether it has a recorded
    `remote_id` mapping (see `services.scim.worker`). POST creates the
    resource and the receiver mints the canonical id; PUT updates an
    existing resource at the receiver's `id`. This client just forwards
    the verb -- it has no state of its own.

Retry policy (transport-level, distinct from worker-level queue retry):
    - Up to 3 attempts per call (initial + 2 retries).
    - Sleep 1s before retry 2, 4s before retry 3.
    - Retry on network errors (httpx connect / read timeouts / transport
      errors) and any response the quirk module flags retryable. The
      generic quirk treats 5xx and 429 as retryable, 404-on-DELETE as
      `absent` (success-like), other 4xx as permanent.
    - `absent` and `permanent` return immediately without further retries.

The function constructs and closes an `httpx.Client` when none is supplied;
otherwise it uses the caller's client without closing it (tests, shared
pools).
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from types import ModuleType
from typing import Literal

import httpx
from utils.safe_http import build_safe_client

from ._sanitise import redact_bearer
from .quirks import get_quirk_module

# Re-export so the worker can introspect quirk capability flags without
# adding a direct dependency on the quirks package layout.
__all__ = [
    "PushResult",
    "PushStatus",
    "delete_group",
    "delete_user",
    "get_quirk_module",
    "push_group",
    "push_user",
    "put_group",
    "put_user",
]

_logger = logging.getLogger(__name__)

# HTTP attempts per call (initial + retries).
_MAX_ATTEMPTS = 3
# Sleep before retry N (index 1 == sleep before retry 2, etc.). The first
# attempt has no preceding sleep; this list is consulted starting at index 1.
_BACKOFF_SECONDS = [0.0, 1.0, 4.0]
# Per-call HTTP timeout. The worker is a background process; long timeouts
# are fine, we'd rather wait than spuriously declare failure.
_HTTP_TIMEOUT_SECONDS = 30.0

# Dev-only hostnames that resolve to private docker-bridge addresses and are
# intentionally permitted on the SCIM path (the external Authentik testbed at
# `host.docker.internal`, the in-stack loopback E2E target `app`). Mirrors
# `_DEV_HOSTNAME_ALLOWLIST` in `services.scim.admin`; production never uses
# these names and `IS_DEV` is false, so the allowlist is inert there.
_DEV_HOSTNAME_ALLOWLIST = frozenset({"host.docker.internal", "app"})

PushStatus = Literal["success", "retryable", "permanent", "absent"]


@dataclass(frozen=True)
class PushResult:
    """Outcome of a single client call.

    Fields:
        status: One of "success", "retryable", "permanent", "absent". The
            worker maps "retryable" to a queue retry, "permanent" to a
            dead-letter, "absent" to a queue-drop with a sync-log marker
            (the resource was already gone at the receiver), and
            "success" to a queue-drop with a normal `done` sync-log row.
        http_status: The HTTP status code from the final attempt, if any.
            None when the call never produced a response (e.g., all attempts
            raised network errors).
        reason: Short human-readable summary; non-None for non-success.
        scim_id: The SP-assigned resource id parsed from a successful POST
            or PUT response, if present. None for DELETEs and for any
            response that does not return an `id`.
    """

    status: PushStatus
    http_status: int | None
    reason: str | None
    scim_id: str | None


def _bearer_headers(token: str) -> dict[str, str]:
    """Standard SCIM 2.0 request headers with bearer auth."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/scim+json",
        "Accept": "application/scim+json",
    }


def _target_for(sp: dict, *segments: str) -> str:
    """Join the SP's base URL with one or more path segments.

    The base URL may or may not end with `/`; we normalize to one slash
    between joined segments and trim the result so doubled slashes do not
    appear in the wire request. Empty segments are skipped.
    """
    base = str(sp["scim_target_url"]).rstrip("/")
    pieces = [s.strip("/") for s in segments if s]
    if not pieces:
        return base
    return base + "/" + "/".join(pieces)


def _extract_scim_id(response: httpx.Response) -> str | None:
    """Best-effort parse of the SCIM `id` from a JSON response body."""
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError):
        return None
    if isinstance(body, dict):
        scim_id = body.get("id")
        if isinstance(scim_id, str):
            return scim_id
    return None


def _success(response: httpx.Response) -> PushResult:
    """Build a success `PushResult` from a 2xx response."""
    return PushResult(
        status="success",
        http_status=response.status_code,
        reason=None,
        scim_id=_extract_scim_id(response),
    )


def _classify_response(
    response: httpx.Response,
    quirk: ModuleType,
    method: str,
) -> PushResult:
    """Map a non-2xx response through the quirk module into a `PushResult`.

    The reason string is sanitised through `redact_bearer()` so any echoed
    `Authorization: Bearer <token>` header in the SP's response body does
    not leak back into our sync-log or queue error columns. The scrub
    happens here -- at the boundary where quirk output crosses into the
    worker's persistence layer -- so every quirk benefits without having
    to remember to redact in its own `interpret_error`.

    The `method` is forwarded so the quirk can treat status codes
    differently per verb -- notably, 404 on DELETE is `absent` rather
    than permanent.
    """
    disposition, reason = quirk.interpret_error(response, method)
    if disposition not in ("retryable", "permanent", "absent"):
        # Defensive: a misbehaving quirk module returned something we don't
        # understand. Treat as permanent so the entry dead-letters with a
        # clear breadcrumb instead of looping forever.
        _logger.error(
            "quirk %s returned unknown disposition %r; treating as permanent",
            quirk.__name__,
            disposition,
        )
        disposition = "permanent"
    status: PushStatus = disposition  # type: ignore[assignment]
    return PushResult(
        status=status,
        http_status=response.status_code,
        reason=redact_bearer(reason),
        scim_id=None,
    )


def _send_with_retry(
    method: str,
    url: str,
    *,
    token: str,
    json_body: dict | None,
    quirk: ModuleType,
    http_client: httpx.Client | None,
) -> PushResult:
    """Send an HTTP request with the transport-level retry policy.

    A returned `PushResult` is always populated. The function never raises
    for SCIM-shaped failures (4xx/5xx/network); only programmer errors
    propagate.
    """
    owns_client = http_client is None
    # When the caller supplies no client we build an SSRF-hardened one that
    # re-resolves and IP-pins the target per request (DNS-rebinding defense)
    # and refuses redirects. See `_safe_transport`.
    client = http_client or build_safe_client(
        timeout=_HTTP_TIMEOUT_SECONDS,
        dev_hostname_allowlist=_DEV_HOSTNAME_ALLOWLIST,
    )
    headers = _bearer_headers(token)

    last_result: PushResult = PushResult(
        status="retryable",
        http_status=None,
        reason="no_attempts_made",
        scim_id=None,
    )

    try:
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            if attempt > 1:
                time.sleep(_BACKOFF_SECONDS[attempt - 1])
            try:
                response = client.request(
                    method,
                    url,
                    headers=headers,
                    json=json_body,
                )
            except httpx.RequestError as exc:
                # Network-level failures: connect timeout, read timeout,
                # connection error, etc. Always retryable at this layer.
                _logger.warning(
                    "SCIM %s %s attempt %d/%d failed: %s",
                    method,
                    url,
                    attempt,
                    _MAX_ATTEMPTS,
                    exc,
                )
                last_result = PushResult(
                    status="retryable",
                    http_status=None,
                    reason=f"network_error: {type(exc).__name__}",
                    scim_id=None,
                )
                continue

            if 200 <= response.status_code < 300:
                return _success(response)

            result = _classify_response(response, quirk, method)
            last_result = result
            if result.status in ("permanent", "absent"):
                return result
            # retryable -- loop and try again unless out of attempts.

        return last_result
    finally:
        if owns_client:
            client.close()


def push_user(
    sp: dict,
    user_resource: dict,
    *,
    token: str,
    http_client: httpx.Client | None = None,
) -> PushResult:
    """Create a user on the downstream SP via SCIM POST `/Users`.

    Used when the worker has no recorded `remote_id` mapping for this
    user against this SP. The receiver mints the canonical `id` and
    returns it in the response body; the worker captures it via
    `PushResult.scim_id` and persists the mapping. Quirk modules may
    rewrite the payload via `transform_user_payload` before send.
    """
    quirk = get_quirk_module(sp.get("scim_kind"))
    payload = quirk.transform_user_payload(user_resource)
    url = _target_for(sp, "Users")
    return _send_with_retry(
        "POST",
        url,
        token=token,
        json_body=payload,
        quirk=quirk,
        http_client=http_client,
    )


def push_group(
    sp: dict,
    group_resource: dict,
    *,
    token: str,
    http_client: httpx.Client | None = None,
) -> PushResult:
    """Create a group on the downstream SP via SCIM POST `/Groups`.

    See `push_user` for the create-vs-update note. Quirk modules may rewrite
    the payload via `transform_group_payload` before send.
    """
    quirk = get_quirk_module(sp.get("scim_kind"))
    payload = quirk.transform_group_payload(group_resource)
    url = _target_for(sp, "Groups")
    return _send_with_retry(
        "POST",
        url,
        token=token,
        json_body=payload,
        quirk=quirk,
        http_client=http_client,
    )


def put_user(
    sp: dict,
    remote_id: str,
    user_resource: dict,
    *,
    token: str,
    http_client: httpx.Client | None = None,
) -> PushResult:
    """Replace a user on the downstream SP via SCIM PUT `/Users/<remote_id>`.

    Used when the worker has a recorded `remote_id` mapping. `remote_id` is
    the SP's canonical id (the value the receiver returned on the original
    POST). A 404 here means the receiver no longer recognises the id; the
    worker's caller treats that as an invalidation signal (clear the
    mapping and re-POST on the next attempt).
    """
    quirk = get_quirk_module(sp.get("scim_kind"))
    payload = quirk.transform_user_payload(user_resource)
    url = _target_for(sp, "Users", remote_id)
    return _send_with_retry(
        "PUT",
        url,
        token=token,
        json_body=payload,
        quirk=quirk,
        http_client=http_client,
    )


def put_group(
    sp: dict,
    remote_id: str,
    group_resource: dict,
    *,
    token: str,
    http_client: httpx.Client | None = None,
) -> PushResult:
    """Replace a group on the downstream SP via SCIM PUT `/Groups/<remote_id>`.

    See `put_user` for the 404-as-invalidation note.
    """
    quirk = get_quirk_module(sp.get("scim_kind"))
    payload = quirk.transform_group_payload(group_resource)
    url = _target_for(sp, "Groups", remote_id)
    return _send_with_retry(
        "PUT",
        url,
        token=token,
        json_body=payload,
        quirk=quirk,
        http_client=http_client,
    )


def delete_user(
    sp: dict,
    remote_id: str,
    *,
    token: str,
    http_client: httpx.Client | None = None,
) -> PushResult:
    """Delete a user on the downstream SP via SCIM DELETE `/Users/<remote_id>`.

    `remote_id` is the SP-side id when a mapping has been recorded;
    otherwise the worker falls back to WeftID's UUID (the externalId)
    for backwards compatibility with pre-mapping rows. 404 is classified
    as `absent` by the generic quirk so deprovisioning a resource that
    the downstream never saw drains the queue cleanly instead of
    dead-lettering.
    """
    quirk = get_quirk_module(sp.get("scim_kind"))
    url = _target_for(sp, "Users", remote_id)
    return _send_with_retry(
        "DELETE",
        url,
        token=token,
        json_body=None,
        quirk=quirk,
        http_client=http_client,
    )


def delete_group(
    sp: dict,
    remote_id: str,
    *,
    token: str,
    http_client: httpx.Client | None = None,
) -> PushResult:
    """Delete a group on the downstream SP via SCIM DELETE `/Groups/<remote_id>`."""
    quirk = get_quirk_module(sp.get("scim_kind"))
    url = _target_for(sp, "Groups", remote_id)
    return _send_with_retry(
        "DELETE",
        url,
        token=token,
        json_body=None,
        quirk=quirk,
        http_client=http_client,
    )
