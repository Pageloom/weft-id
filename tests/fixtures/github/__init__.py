"""GitHub REST API fixtures.

Response bodies follow the shapes in GitHub's REST API documentation
(``/login/oauth/access_token``, ``/user``, ``/user/emails``, ``/user/orgs``,
``/user/teams``), trimmed to the fields that matter and with made-up ids.
GitHub sign-in cannot be recorded in CI (no test account), so these stand in.

:func:`github_api` serves them through an ``httpx.MockTransport`` patched in
for ``build_safe_client`` in the OAuth2 adapter plumbing and the token exchange, so
tests exercise the real request code without a network.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx

from tests.fixtures.oauth2_api import load_json, mock_provider_api

FIXTURES_ROOT = Path(__file__).parent


def load(name: str):
    """Load a fixture by filename (no .json)."""
    return load_json(FIXTURES_ROOT, name)


# Path -> fixture served by default.
_DEFAULT_ROUTES = {
    "/login/oauth/access_token": "token",
    "/user": "user",
    "/user/emails": "user_emails",
    "/user/orgs": "user_orgs",
    "/user/teams": "user_teams",
}


@contextmanager
def github_api(
    overrides: dict[str, object] | None = None,
) -> Iterator[list[httpx.Request]]:
    """Serve the GitHub fixtures; yield the list of requests made.

    ``overrides`` maps a path to a replacement: an ``httpx.Response``, a
    JSON-able body (served with 200), or a callable taking the request and
    returning an ``httpx.Response``.
    """
    routes: dict[str, object] = {path: load(name) for path, name in _DEFAULT_ROUTES.items()}
    routes.update(overrides or {})
    with mock_provider_api(routes) as requests:
        yield requests
