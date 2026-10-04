"""Discord API fixtures.

Response bodies follow the shapes in Discord's OAuth2 and user resource
documentation (``/api/oauth2/token``, ``/api/v10/users/@me``), with made-up
ids. Discord sign-in cannot be recorded in CI (no test account), so these
stand in. :func:`discord_api` serves them without a network.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx

from tests.fixtures.oauth2_api import load_json, mock_provider_api

FIXTURES_ROOT = Path(__file__).parent

TOKEN_PATH = "/api/oauth2/token"
USERS_ME_PATH = "/api/v10/users/@me"


def load(name: str):
    """Load a fixture by filename (no .json)."""
    return load_json(FIXTURES_ROOT, name)


@contextmanager
def discord_api(
    overrides: dict[str, object] | None = None,
) -> Iterator[list[httpx.Request]]:
    """Serve the Discord fixtures; yield the list of requests made.

    ``overrides`` maps a path to a replacement (see
    :func:`tests.fixtures.oauth2_api.mock_provider_api`).
    """
    routes: dict[str, object] = {TOKEN_PATH: load("token"), USERS_ME_PATH: load("users_me")}
    routes.update(overrides or {})
    with mock_provider_api(routes) as requests:
        yield requests
