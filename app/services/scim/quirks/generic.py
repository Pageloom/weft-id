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

    interpret_error(response: httpx.Response) -> tuple[bool, str]
        Map an HTTP response to (retryable, reason). The generic
        implementation treats `5xx` and `429` as retryable and `4xx` as
        permanent, with a short reason string.

Quirk modules are looked up by `service_providers.scim_kind`. Unknown kinds
fall back to this module via the registry (with a logged warning).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx


def transform_user_payload(payload: dict) -> dict:
    """Return the user payload unchanged. Override per-vendor as needed."""
    return payload


def transform_group_payload(payload: dict) -> dict:
    """Return the group payload unchanged. Override per-vendor as needed."""
    return payload


def transform_patch_ops(ops: list[dict]) -> list[dict]:
    """Return PATCH `Operations` unchanged. Override per-vendor as needed."""
    return ops


def interpret_error(response: httpx.Response) -> tuple[bool, str]:
    """Map an HTTP response to (retryable, reason).

    Spec-correct defaults:
    - `2xx` is not an error and never reaches this function via the client,
      but if it does we report it as non-retryable success-ish for safety.
    - `429` (rate limited) is retryable.
    - `5xx` is retryable.
    - Other `4xx` is permanent.
    """
    status = response.status_code
    if status == 429:
        return True, f"rate_limited (HTTP {status})"
    if 500 <= status < 600:
        return True, f"server_error (HTTP {status})"
    if 400 <= status < 500:
        return False, f"client_error (HTTP {status})"
    # 1xx/2xx/3xx: shouldn't normally hit this function via the client.
    return False, f"unexpected_status (HTTP {status})"
