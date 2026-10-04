"""Facebook Graph API fixtures.

Response bodies follow the shapes in Meta's Facebook Login (manual flow) and
Graph API User documentation (``/oauth/access_token``, ``/me``), with
made-up ids. Facebook sign-in cannot be recorded in CI (no test account), so
these stand in. :func:`facebook_api` serves them without a network.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
from services.oidc_upstream.facebook import GRAPH_API_VERSION

from tests.fixtures.oauth2_api import load_json, mock_provider_api

FIXTURES_ROOT = Path(__file__).parent

TOKEN_PATH = f"/{GRAPH_API_VERSION}/oauth/access_token"
ME_PATH = f"/{GRAPH_API_VERSION}/me"


def load(name: str):
    """Load a fixture by filename (no .json)."""
    return load_json(FIXTURES_ROOT, name)


@contextmanager
def facebook_api(
    overrides: dict[str, object] | None = None,
) -> Iterator[list[httpx.Request]]:
    """Serve the Facebook fixtures; yield the list of requests made.

    ``overrides`` maps a path to a replacement (see
    :func:`tests.fixtures.oauth2_api.mock_provider_api`).
    """
    routes: dict[str, object] = {TOKEN_PATH: load("token"), ME_PATH: load("me")}
    routes.update(overrides or {})
    with mock_provider_api(routes) as requests:
        yield requests
