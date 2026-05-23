"""Generic SCIM 2.0 quirk baseline.

This module defines the contract every per-vendor quirk module must implement.
Vendor modules `import` these functions from `generic` and selectively override
them; anything they don't override falls back to spec-correct SCIM 2.0
behavior implemented here.

Contract (all quirk modules expose these as module-level functions):

    transform_user_payload(payload: dict) -> dict
        Adjust an outbound SCIM User resource (or sub-resource) just before
        send. The generic implementation passes it through unchanged.

    transform_group_payload(payload: dict) -> dict
        Adjust an outbound SCIM Group resource just before send. Generic
        implementation passes through unchanged.

    transform_patch_ops(ops: list[dict]) -> list[dict]
        Adjust the `Operations` array of a SCIM PATCH request. Generic
        implementation passes through unchanged.

    interpret_error(response: httpx.Response, method: str) -> tuple[Disposition, str]
        Map an HTTP response to (disposition, reason). `method` is the HTTP
        verb of the request (POST/PUT/PATCH/DELETE) so quirks can decide
        e.g. "404 on DELETE = already absent, success". The generic
        implementation treats `5xx` and `429` as retryable, `404 on DELETE`
        as `absent` (the resource is already gone -- success-like), other
        `4xx` as permanent.

Disposition values:
    "retryable" -- transient failure; worker re-queues with backoff
    "permanent" -- fatal failure; worker dead-letters
    "absent"    -- the target resource is already gone at the receiver.
                   Worker treats this as success (drops the queue row,
                   marks the sync_log row `done`) but records a note so
                   admins see "skipped: not present" rather than implying
                   a real push happened.

Quirk modules are looked up by `service_providers.scim_kind`. Unknown kinds
fall back to this module via the registry (with a logged warning).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    import httpx

# Disposition tags returned by `interpret_error`. The client maps "absent"
# onto its own `PushStatus = "absent"` literal; the worker turns that into
# a queue-drop + sync_log marker.
Disposition = Literal["retryable", "permanent", "absent"]


# Per-quirk verb used to update an existing Group resource. Generic SCIM
# 2.0 accepts PUT; some vendors do not (notably GitHub, which returns 405
# on PUT /Groups/<id> and requires PATCH instead). When set to "POST" a
# quirk opts out of PUT-based group updates -- the worker keeps POSTing
# even when it has a recorded `remote_id`. The receiver will typically
# return 409 uniqueness on the second POST and the entry dead-letters;
# this is the same broken-but-deterministic behavior as before the
# remote-id iteration, and the long-term fix is a PATCH-rewriting layer
# (out of scope here).
GROUP_UPDATE_VERB = "PUT"


def transform_user_payload(payload: dict) -> dict:
    """Return the user payload unchanged. Override per-vendor as needed."""
    return payload


def transform_group_payload(payload: dict) -> dict:
    """Return the group payload unchanged. Override per-vendor as needed."""
    return payload


def transform_patch_ops(ops: list[dict]) -> list[dict]:
    """Return PATCH `Operations` unchanged. Override per-vendor as needed."""
    return ops


def interpret_error(response: httpx.Response, method: str) -> tuple[Disposition, str]:
    """Map an HTTP response to (disposition, reason).

    Spec-correct defaults:
    - `2xx` is not an error and never reaches this function via the client,
      but if it does we report it as permanent for safety (so the worker
      sees an explicit signal rather than treating it as success).
    - `404` on `DELETE` is `absent` (the resource is already gone). Treated
      as success-like by the worker so deprovisioning a resource the
      downstream never saw does not generate dead-letter noise.
    - `429` (rate limited) is retryable.
    - `5xx` is retryable.
    - Other `4xx` is permanent. (404 on PUT/PATCH is permanent here; the
      worker may take corrective action *before* calling the client when
      it has a stale id mapping -- see `services.scim.worker`.)
    """
    status = response.status_code
    if status == 429:
        return "retryable", f"rate_limited (HTTP {status})"
    if 500 <= status < 600:
        return "retryable", f"server_error (HTTP {status})"
    if status == 404 and method.upper() == "DELETE":
        return "absent", "already_absent (HTTP 404 on DELETE)"
    if 400 <= status < 500:
        return "permanent", f"client_error (HTTP {status})"
    # 1xx/2xx/3xx: shouldn't normally hit this function via the client.
    return "permanent", f"unexpected_status (HTTP {status})"
