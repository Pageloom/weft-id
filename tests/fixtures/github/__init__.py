"""GitHub REST API fixtures.

Response bodies follow the shapes in GitHub's REST API documentation
(``/login/oauth/access_token``, ``/user``, ``/user/emails``, ``/user/orgs``,
``/user/teams``), trimmed to the fields that matter and with made-up ids.
GitHub sign-in cannot be recorded in CI (no test account), so these stand in.

:func:`github_api` serves them through an ``httpx.MockTransport`` patched in
for ``build_safe_client`` in the GitHub adapter and the token exchange, so
tests exercise the real request code without a network.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import httpx

FIXTURES_ROOT = Path(__file__).parent


def load(name: str):
    """Load a fixture by filename (no .json)."""
    with (FIXTURES_ROOT / f"{name}.json").open() as fh:
        return json.load(fh)


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
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        route = routes.get(request.url.path)
        if route is None:
            return httpx.Response(404, json={"message": "Not Found"})
        if isinstance(route, httpx.Response):
            return route
        if callable(route):
            responder: Callable[[httpx.Request], httpx.Response] = route
            return responder(request)
        return httpx.Response(200, json=route)

    def client_factory(**kwargs) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(handler))

    with (
        patch("services.oidc_upstream.github.build_safe_client", side_effect=client_factory),
        patch(
            "services.oidc_upstream.token_exchange.build_safe_client",
            side_effect=client_factory,
        ),
    ):
        yield requests
