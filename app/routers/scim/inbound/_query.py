"""Shared query-string parsing for the inbound SCIM read endpoints.

SCIM 2.0 uses a small, well-defined query grammar for read endpoints
(RFC 7644 §3.4.2):

- `filter=<attr> eq "<value>"` -- restricted to `eq` on a small
  attribute allowlist for this iteration. Anything else returns
  `400 invalidFilter`.
- `startIndex=<int>` -- 1-indexed page start.
- `count=<int>` -- page size. Clamped to a documented maximum.

This module is independent of FastAPI so unit tests can exercise the
parser without spinning up a request.
"""

from __future__ import annotations

import re

# Matches: <attr> eq "<value>" (with surrounding whitespace tolerated).
# Captures the attribute name and the quoted value (no escape handling
# needed -- we only support equality and reject the value if it contains
# an embedded double quote rather than supporting RFC 7644's escape
# rules. SCIM clients never need to send embedded quotes for the
# attributes we accept.).
_FILTER_PATTERN = re.compile(r'^\s*([A-Za-z][A-Za-z0-9_]*)\s+eq\s+"([^"]*)"\s*$')

DEFAULT_COUNT = 100
MAX_COUNT = 200


class FilterParseError(Exception):
    """Raised when a `filter=` query parameter is not parseable.

    Carries the SCIM `scimType` (`invalidFilter`) and a human-readable
    detail so the router can build the SCIM error envelope without
    repeating itself.
    """

    def __init__(self, detail: str, scim_type: str = "invalidFilter"):
        super().__init__(detail)
        self.detail = detail
        self.scim_type = scim_type


def parse_eq_filter(
    raw: str | None,
    *,
    allowed_attributes: list[str],
) -> tuple[str, str] | None:
    """Parse a `filter=<attr> eq "<value>"` expression.

    Returns `(attribute, value)` on success, or None if `raw` is None
    / empty. Raises `FilterParseError` for any expression we don't
    understand (other operators, unknown attributes, malformed
    syntax).
    """
    if raw is None or raw.strip() == "":
        return None

    match = _FILTER_PATTERN.match(raw)
    if not match:
        raise FilterParseError('Only `eq` filters are supported (e.g. `userName eq "alice@x"`).')

    attr, value = match.group(1), match.group(2)
    if attr not in allowed_attributes:
        raise FilterParseError(
            f"Filter attribute `{attr}` not supported. Supported: {', '.join(allowed_attributes)}."
        )
    return attr, value


def parse_pagination(
    start_index: int | None,
    count: int | None,
    *,
    default_count: int = DEFAULT_COUNT,
    max_count: int = MAX_COUNT,
) -> tuple[int, int]:
    """Parse and validate SCIM pagination parameters.

    Returns `(start_index, count)` normalised to safe values:
    - `start_index` floored to 1 (SCIM 2.0 says values < 1 are
      interpreted as 1; we follow that).
    - `count` clamped to `[0, max_count]`; `None` => `default_count`.
    """
    si = 1 if start_index is None or start_index < 1 else start_index
    if count is None:
        c = default_count
    elif count < 0:
        c = 0
    elif count > max_count:
        c = max_count
    else:
        c = count
    return si, c
