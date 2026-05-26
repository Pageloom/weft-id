"""Recorded vendor SCIM request fixtures.

These JSON files are real (or shape-faithful) payloads as captured from
Okta and Microsoft Entra. Tests load them via the `load_fixture` helper
and feed them straight into the inbound SCIM endpoints to verify that
vendor quirks round-trip through WeftID's parser without manual tweaks.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES_ROOT = Path(__file__).parent


def load_fixture(vendor: str, name: str) -> dict:
    """Load a recorded SCIM request body by vendor + filename (no .json).

    Example: `load_fixture("okta", "create_user")` returns the parsed
    contents of `tests/fixtures/scim/inbound/okta/create_user.json`.
    """
    path = FIXTURES_ROOT / vendor / f"{name}.json"
    with path.open() as fh:
        return json.load(fh)
