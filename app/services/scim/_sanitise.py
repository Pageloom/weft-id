"""Sanitisers for strings that flow into SCIM sync-log / queue error fields.

A misbehaving downstream SP can echo the inbound `Authorization: Bearer ...`
header in the 4xx/5xx response body. That body lands in `scim_sync_log.error`
(and `scim_push_queue.last_error`), where it is rendered in the admin UI's
sync-activity panel and exported via the API. Bearer plaintext must never
leak back into our own logs.

Centralised here so EVERY quirk module benefits, including future ones. The
client layer (`services.scim.client`) calls `redact_bearer()` on quirk-
returned reason strings before the worker writes them to the database.
"""

from __future__ import annotations

import re

# Match `Authorization: Bearer <token>` (case-insensitive, any whitespace
# between the header name and value) AND bare `Bearer <token>` occurrences.
# `\S+` captures the token (no whitespace). Quoted variants ("Bearer abc")
# are not matched separately because the quotes are not part of the token
# itself; the inner `Bearer <token>` substring still matches.
_AUTH_HEADER_RE = re.compile(
    r"Authorization\s*:\s*Bearer\s+\S+",
    re.IGNORECASE,
)
_BARE_BEARER_RE = re.compile(
    r"Bearer\s+\S+",
    re.IGNORECASE,
)

_REDACTED = "[REDACTED]"


def redact_bearer(text: str | None) -> str | None:
    """Replace any bearer-token occurrence with `[REDACTED]`.

    Handles both `Authorization: Bearer <token>` (the canonical HTTP
    header form, including indentation/multi-line bodies) and bare
    `Bearer <token>` substrings. Non-bearer text passes through
    unchanged. `None` is returned as-is.
    """
    if text is None:
        return None
    # Order matters: the header form is a superset of the bare form, so
    # match it first to avoid the bare-bearer regex chewing into the
    # `Authorization:` prefix and leaving `Authorization: [REDACTED]`
    # adjacent dangling text.
    scrubbed = _AUTH_HEADER_RE.sub(f"Authorization: Bearer {_REDACTED}", text)
    scrubbed = _BARE_BEARER_RE.sub(f"Bearer {_REDACTED}", scrubbed)
    return scrubbed
