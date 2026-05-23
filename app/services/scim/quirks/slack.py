"""Slack SCIM quirks.

Source: <https://api.slack.com/scim>

Slack's SCIM API is mostly spec-compliant with a few well-known divergences:

- **Spec-correct core User URN, no Slack-specific extension required.** Slack
  accepts the standard `urn:ietf:params:scim:schemas:core:2.0:User` schema
  URN and does not require a `urn:scim:schemas:extension:slack:*` extension.
  The generic payload builder emits only the core URN; the transform
  preserves it (and would not synthesize a Slack extension URN even if a
  future caller asked).
- **`userName` is the user's email.** Slack uses email as the canonical
  username; the generic payload builder already emits `userName = email`, so
  no transform is needed.
- **Drops unknown attributes server-side.** Slack silently ignores attributes
  it does not recognize, so we do not need to scrub most payload fields.
  However, some operators have reported that older Slack Enterprise Grid
  endpoints reject `$ref` on Group members as "unknown attribute"; we strip
  `$ref` defensively from both Group payloads and PATCH `value` entries.
  Dropping `$ref` is spec-safe (SCIM 2.0 does not require clients to send
  it).
- **Rate limit (429) carries a `Retry-After` header.** The generic handler
  already classifies 429 as retryable; we surface the header in the reason
  string so operators can see the requested cool-down.
- **5xx is retryable; 4xx is permanent.** Same as generic, no override.

Synthetic-fixture notice: the fixtures in `tests/fixtures/scim/slack/` are
constructed from the public Slack SCIM docs and known divergences, not
captured from a live Slack Enterprise Grid tenant. Replace with real
recordings when a customer tenant is available.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .generic import interpret_error as _generic_interpret_error
from .generic import transform_user_payload

if TYPE_CHECKING:
    import httpx


def transform_group_payload(payload: dict) -> dict:
    """Drop `$ref` from each member entry; leave the rest untouched.

    Slack accepts spec-correct group payloads but a subset of legacy Slack
    Enterprise Grid endpoints reject `$ref` as an unknown attribute. Dropping
    it is safe everywhere: SCIM clients are not required to send `$ref`.
    """
    if not isinstance(payload, dict):
        return payload
    members = payload.get("members")
    if not isinstance(members, list):
        return payload
    new_members = []
    for member in members:
        if isinstance(member, dict) and "$ref" in member:
            new_members.append({k: v for k, v in member.items() if k != "$ref"})
        else:
            new_members.append(member)
    return {**payload, "members": new_members}


def transform_patch_ops(ops: list[dict]) -> list[dict]:
    """Strip `$ref` from PATCH `value` entries that look like member refs.

    Slack PATCHes for group membership accept `{op, path: "members", value:
    [{value, display}]}`. The `$ref` key is harmless on most tenants but
    rejected on some; drop it to match `transform_group_payload`.
    """
    if not isinstance(ops, list):
        return ops
    cleaned: list[dict] = []
    for op in ops:
        if not isinstance(op, dict):
            cleaned.append(op)
            continue
        value = op.get("value")
        if isinstance(value, list):
            new_value = []
            for entry in value:
                if isinstance(entry, dict) and "$ref" in entry:
                    new_value.append({k: v for k, v in entry.items() if k != "$ref"})
                else:
                    new_value.append(entry)
            cleaned.append({**op, "value": new_value})
        else:
            cleaned.append(op)
    return cleaned


def interpret_error(response: httpx.Response, method: str) -> tuple[str, str]:
    """Slack-specific error classification.

    Overrides the generic handler only for 429: surface the `Retry-After`
    header so operators understand why we backed off. 5xx and other 4xx
    (including 404-on-DELETE -> `absent`) fall through to the generic
    classification.
    """
    if response.status_code == 429:
        retry_after = response.headers.get("Retry-After") or response.headers.get("retry-after")
        if retry_after:
            return "retryable", f"rate_limited (HTTP 429, Retry-After: {retry_after})"
        return "retryable", "rate_limited (HTTP 429)"
    return _generic_interpret_error(response, method)


__all__ = [
    "interpret_error",
    "transform_group_payload",
    "transform_patch_ops",
    "transform_user_payload",
]
