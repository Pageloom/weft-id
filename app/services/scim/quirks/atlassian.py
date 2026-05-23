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
- **404 on `DELETE /Users/<id>` for an already-deprovisioned user is normal.**
  Atlassian returns 404 when DELETE targets a user that's already gone.
  This now matches the generic policy (404 on DELETE = `absent`), so no
  per-vendor override is needed for the success path. A 404 on PUT/PATCH
  remains permanent (the worker handles stale-id invalidation upstream of
  the client call).
- **`id` vs `externalId`.** Atlassian uses its own server-minted `id` for
  every subsequent reference, with `externalId` as a non-canonical
  back-pointer to WeftID's UUID. The shared remote-id mapping table
  (`sp_scim_remote_ids`) covers Atlassian without a per-vendor override.

Synthetic-fixture notice: fixtures in `tests/fixtures/scim/atlassian/` are
based on the public Atlassian provisioning docs; replace with real
recordings when an Atlassian Guard tenant is available.
"""

from __future__ import annotations

from .generic import (
    interpret_error,
    transform_user_payload,
)


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


__all__ = [
    "interpret_error",
    "transform_group_payload",
    "transform_patch_ops",
    "transform_user_payload",
]
