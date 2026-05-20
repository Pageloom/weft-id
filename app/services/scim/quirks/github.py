"""GitHub Enterprise Cloud SCIM quirks.

Source: <https://docs.github.com/en/enterprise-cloud@latest/rest/scim>

GitHub diverges from spec-correct SCIM 2.0 in a few load-bearing ways:

- **`externalId` is required and must match the SAML NameID** that the user
  authenticates with. The generic payload builder already emits `externalId`
  set to WeftID's user id; the SP integration is responsible for ensuring
  that value matches whatever NameID format the SAML IdP issues. The
  transform does not synthesize one when missing -- it raises via the empty
  payload reaching GitHub and getting a 400.
- **Group membership uses strict PATCH path syntax**. To remove a member,
  the path must be `members[value eq "<user-id>"]`, not the generic
  `path=members, op=remove, value=[{value: <id>}]`. We rewrite that shape
  on the way out.
- **No PUT on Groups.** GitHub rejects PUT `/Groups/<id>` (returns 405) and
  requires PATCH for membership changes. The worker today only POSTs
  (create) and DELETEs Groups -- it never PUTs -- so no transform-level
  guard is needed. If a future worker change introduces PUT on Groups, it
  must route through `transform_patch_ops` against GitHub instead. The
  per-vendor tests pin the current "POST/DELETE/PATCH-only" expectation.
- **`uniqueness` errors are permanent**, not retryable. GitHub returns 409
  with a SCIM error body `{"scimType": "uniqueness", ...}` when a user
  already exists. Generic classification already treats 409 as permanent;
  we keep that and surface the `scimType` in the reason so operators can
  see the cause without opening the SP's response body.
- **Rate limit returns 403 with a `x-ratelimit-remaining: 0` header**, not
  429. We treat that specific shape as retryable.

Synthetic-fixture notice: fixtures in `tests/fixtures/scim/github/` are
based on the public GitHub Enterprise Cloud SCIM docs; replace with real
recordings when an Enterprise Cloud tenant is available.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from .generic import (
    interpret_error as _generic_interpret_error,
)
from .generic import (
    transform_group_payload,
    transform_user_payload,
)

if TYPE_CHECKING:
    import httpx


def transform_patch_ops(ops: list[dict]) -> list[dict]:
    """Rewrite generic `remove`/`add` member ops into GitHub's strict path form.

    Generic SCIM 2.0 accepts:
        {"op": "remove", "path": "members", "value": [{"value": "u-1"}]}

    GitHub requires the value to be filter-encoded into the path:
        {"op": "remove", "path": 'members[value eq "u-1"]'}

    For `add` ops, GitHub accepts the generic shape, so we leave them alone.
    Any op whose path is already a filtered `members[...]` expression is left
    alone (idempotent rewrite).
    """
    if not isinstance(ops, list):
        return ops
    rewritten: list[dict] = []
    for op in ops:
        if not isinstance(op, dict):
            rewritten.append(op)
            continue
        op_name = (op.get("op") or "").lower()
        path = op.get("path")
        value = op.get("value")
        if op_name == "remove" and path == "members" and isinstance(value, list) and value:
            for entry in value:
                if not isinstance(entry, dict):
                    continue
                user_id = entry.get("value")
                if user_id is None:
                    continue
                # Escape embedded quotes defensively; SCIM filters use
                # double-quoted string literals.
                safe = str(user_id).replace('"', r"\"")
                rewritten.append({"op": "remove", "path": f'members[value eq "{safe}"]'})
        else:
            rewritten.append(op)
    return rewritten


def _extract_scim_type(response: httpx.Response) -> str | None:
    """Return the `scimType` from a SCIM error body, if present."""
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError):
        return None
    if isinstance(body, dict):
        scim_type = body.get("scimType")
        if isinstance(scim_type, str):
            return scim_type
    return None


def interpret_error(response: httpx.Response) -> tuple[bool, str]:
    """GitHub-specific error classification.

    - 403 with `x-ratelimit-remaining: 0` is rate-limit -> retryable.
    - 409 with `scimType: uniqueness` is permanent (user/group already
      exists); we surface the scimType in the reason.
    - Otherwise fall through to the generic classifier, but enrich the
      reason with the SCIM `scimType` when present.
    """
    status = response.status_code
    if status == 403:
        remaining = response.headers.get("x-ratelimit-remaining") or response.headers.get(
            "X-RateLimit-Remaining"
        )
        if remaining == "0":
            return True, "rate_limited (HTTP 403, x-ratelimit-remaining: 0)"
    if status == 409:
        scim_type = _extract_scim_type(response)
        if scim_type == "uniqueness":
            return False, "uniqueness (HTTP 409, resource already exists)"
    # Generic classification, optionally enriched with scimType.
    retryable, reason = _generic_interpret_error(response)
    scim_type = _extract_scim_type(response)
    if scim_type and scim_type not in reason:
        reason = f"{reason} scimType={scim_type}"
    return retryable, reason


__all__ = [
    "interpret_error",
    "transform_group_payload",
    "transform_patch_ops",
    "transform_user_payload",
]
