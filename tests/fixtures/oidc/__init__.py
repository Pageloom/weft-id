"""Recorded OIDC upstream fixtures.

These JSON files are shape-faithful discovery documents and JWKS documents
used to test the connector core without live network calls. Tests load them
via the ``load_fixture`` helper and feed them into the discovery/JWKS/ID-token
modules, which are patched to return the fixture bytes instead of dialing the
network.

The JWKS/private-key pair in this directory is a throwaway RSA-2048 key
generated solely for tests; it is not used anywhere in production.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES_ROOT = Path(__file__).parent


def load_fixture(name: str) -> dict:
    """Load a recorded OIDC fixture by filename (no .json).

    Example: ``load_fixture("discovery")`` returns the parsed contents of
    ``tests/fixtures/oidc/discovery.json``.
    """
    path = FIXTURES_ROOT / f"{name}.json"
    with path.open() as fh:
        return json.load(fh)


def load_fixture_text(name: str) -> str:
    """Load a raw text fixture (e.g. the private key PEM)."""
    path = FIXTURES_ROOT / name
    with path.open() as fh:
        return fh.read()
