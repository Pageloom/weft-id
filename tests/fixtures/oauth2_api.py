"""Serve recorded OAuth2 provider API responses without a network.

:func:`mock_provider_api` patches ``build_safe_client`` in the shared OAuth2
adapter plumbing and in the token exchange with an ``httpx.MockTransport``,
so tests run the real request code. Requests are routed on the URL path; an
unrouted path answers 404, so a new live call fails the test that makes it.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import httpx


def load_json(directory: Path, name: str):
    """Load ``<directory>/<name>.json``."""
    with (directory / f"{name}.json").open() as fh:
        return json.load(fh)


@contextmanager
def mock_provider_api(routes: dict[str, object]) -> Iterator[list[httpx.Request]]:
    """Serve ``routes``; yield the list of requests made.

    ``routes`` maps a URL path to an ``httpx.Response``, a JSON-able body
    (served with 200), or a callable taking the request and returning an
    ``httpx.Response``.
    """
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
        patch("services.oidc_upstream._oauth2.build_safe_client", side_effect=client_factory),
        patch(
            "services.oidc_upstream.token_exchange.build_safe_client",
            side_effect=client_factory,
        ),
    ):
        yield requests
