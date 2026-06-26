"""GitLab SCIM quirks.

Source: <https://docs.gitlab.com/ee/user/group/saml_sso/scim_setup.html>

GitLab's group-SAML SCIM endpoint (`https://gitlab.com/api/scim/v2/groups/<id>`)
has the following divergences:

- **`externalId` couples to SAML NameID.** GitLab uses `externalId` as the
  durable link between the SCIM user and the SAML identity; it must be
  stable across re-provisioning. The generic payload already sets
  `externalId = WeftID user id`, which is stable. The transform makes the
  coupling explicit (and raises only if a caller passes a payload missing
  `externalId`, since GitLab will 400 on it anyway -- we surface the issue
  earlier with a `KeyError`).
- **PATCH membership uses `operations` lowercased** historically in some
  GitLab versions; modern releases accept the spec-correct `Operations`.
  We do not rewrite case (spec wins; if a vendor regresses we'll log a
  retryable error and a human will notice).
- **GitLab proxy returns 502 on transient back-end issues.** The generic
  classifier already retries 5xx; we keep that and enrich the reason so
  the breadcrumb in `scim_sync_log` mentions GitLab's proxy explicitly.
- **403 with body `{"detail": "License does not allow SCIM"}` is permanent.**
  This is an account-level configuration issue, not something a retry will
  fix. The generic classifier already returns permanent for 403; we
  enrich the reason for this specific message.

Synthetic-fixture notice: fixtures in `tests/fixtures/scim/gitlab/` are
based on the public GitLab SCIM setup docs; replace with real recordings
when a GitLab.com group-SAML tenant is available.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from .generic import (
    interpret_error as _generic_interpret_error,
)
from .generic import (
    transform_group_payload,
    transform_patch_ops,
)

if TYPE_CHECKING:
    import httpx


def transform_user_payload(payload: dict) -> dict:
    """Pass through, but assert `externalId` is present.

    GitLab requires `externalId` for the SAML/SCIM coupling. The generic
    payload always sets it; this transform raises `KeyError` if a caller
    bypasses the builder and forgets it, so the failure is local and
    actionable rather than a remote 400.
    """
    if not isinstance(payload, dict):
        return payload
    if "externalId" not in payload or not payload["externalId"]:
        raise KeyError(
            "GitLab SCIM requires `externalId` (coupled to SAML NameID); "
            "payload did not include one"
        )
    return payload


def _extract_detail(response: httpx.Response) -> str | None:
    """Return the `detail` field from a GitLab error body, if present."""
    try:
        body = response.json()
    except ValueError, json.JSONDecodeError:
        return None
    if isinstance(body, dict):
        detail = body.get("detail")
        if isinstance(detail, str):
            return detail
    return None


def interpret_error(response: httpx.Response, method: str) -> tuple[str, str]:
    """GitLab-specific error classification.

    - 502 from GitLab's proxy: retryable (generic also retries; we enrich
      the reason).
    - 403 with `detail: "License does not allow ..."`: permanent
      (configuration issue, retrying will not help).
    - 404 on DELETE -> `absent` via the generic classifier.
    - Otherwise fall through to the generic classifier.
    """
    status = response.status_code
    if status == 502:
        return "retryable", "proxy_error (HTTP 502, GitLab upstream)"
    if status == 403:
        detail = _extract_detail(response)
        if detail and "license" in detail.lower():
            return "permanent", f"license_error (HTTP 403, {detail})"
    return _generic_interpret_error(response, method)


__all__ = [
    "interpret_error",
    "transform_group_payload",
    "transform_patch_ops",
    "transform_user_payload",
]
