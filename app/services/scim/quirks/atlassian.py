"""Atlassian SCIM quirks.

Source: <https://support.atlassian.com/provisioning-users/docs/about-scim-provisioning/>

Atlassian's SCIM endpoint (used by Atlassian Guard / Atlassian Access) has
a handful of well-known divergences:

- **Empty PATCH `value` arrays are rejected with 400.** A `replace` or `add`
  op with `value: []` returns an error. We filter ops whose `value` is an
  empty list before send so the worker does not waste an attempt on a
  payload Atlassian guarantees to reject.
- **Group naming constraints.** Atlassian rejects group `displayName`
  containing leading/trailing whitespace or empty names with a 400. The
  transform trims `displayName` and leaves it to the caller to decide what
  to do when the trimmed value is empty (the request will fail at
  Atlassian, surfaced as a permanent error).
- **Tolerant of partial `meta` fields.** Atlassian returns `meta` with
  `created`/`lastModified`/`location`; some tenants omit `resourceType`.
  The transform does not need to do anything for this -- noted for
  completeness.
- **404 on `/Users/<id>` for an already-deprovisioned user is normal.**
  Atlassian returns 404 when DELETE targets a user that's already gone.
  We classify that as a *non-failure* permanent so the worker does not
  treat "already done" as an error worth alerting on.

Synthetic-fixture notice: fixtures in `tests/fixtures/scim/atlassian/` are
based on the public Atlassian provisioning docs; replace with real
recordings when an Atlassian Guard tenant is available.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .generic import (
    interpret_error as _generic_interpret_error,
)
from .generic import (
    transform_user_payload,
)

if TYPE_CHECKING:
    import httpx


def transform_group_payload(payload: dict) -> dict:
    """Trim leading/trailing whitespace from `displayName`."""
    if not isinstance(payload, dict):
        return payload
    display_name = payload.get("displayName")
    if isinstance(display_name, str):
        trimmed = display_name.strip()
        if trimmed != display_name:
            return {**payload, "displayName": trimmed}
    return payload


def transform_patch_ops(ops: list[dict]) -> list[dict]:
    """Drop ops with empty `value` arrays (Atlassian rejects them with 400)."""
    if not isinstance(ops, list):
        return ops
    return [
        op
        for op in ops
        if not (
            isinstance(op, dict) and isinstance(op.get("value"), list) and len(op["value"]) == 0
        )
    ]


def interpret_error(response: httpx.Response) -> tuple[bool, str]:
    """Atlassian-specific error classification.

    - 404 is a *non-retryable, non-alerting* result -- the resource is
      already gone. The worker records this as permanent (no retry) but
      operators should not treat it as an incident.
    - Otherwise fall through to the generic classifier.
    """
    if response.status_code == 404:
        return False, "not_found (HTTP 404, resource already absent)"
    return _generic_interpret_error(response)


__all__ = [
    "interpret_error",
    "transform_group_payload",
    "transform_patch_ops",
    "transform_user_payload",
]
