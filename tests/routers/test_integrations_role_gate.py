"""Defense in depth for the Applications admin routes.

The routers already require admin (router-level dependency). Each handler
also checks page access itself; with the router-level check bypassed, a plain
user posting to any of these routes is sent to /dashboard and no service is
called.
"""

from unittest.mock import MagicMock

import pytest
from fastapi.routing import APIRoute
from main import app
from routers import integrations

from tests.helpers.client import TestClient

_SERVICE_ATTRS = [
    name for name in dir(integrations) if name.endswith("_service") and not name.startswith("_")
]

_PATH_VALUES = {
    "client_id": "weft-id_client_gate",
    "group_id": "00000000-0000-0000-0000-000000000001",
    "grant_id": "00000000-0000-0000-0000-000000000002",
    "token_id": "00000000-0000-0000-0000-000000000003",
}


def _post_paths() -> list[str]:
    paths = []
    for router in (
        integrations.apps_router,
        integrations.b2b_router,
        integrations.registration_router,
    ):
        for route in router.routes:
            if isinstance(route, APIRoute) and "POST" in route.methods:
                paths.append(route.path.format(**_PATH_VALUES))
    return sorted(paths)


def test_every_post_route_is_listed():
    paths = _post_paths()
    assert "/applications/oauth/weft-id_client_gate/subject" in paths
    assert "/applications/service-accounts/weft-id_client_gate/role" in paths
    assert len(paths) >= 25


@pytest.mark.parametrize("path", _post_paths())
def test_member_redirected_without_calling_a_service(path, monkeypatch, test_user, override_auth):
    mocks = {}
    for name in _SERVICE_ATTRS:
        mocks[name] = MagicMock()
        monkeypatch.setattr(integrations, name, mocks[name])
    # Bypass the router-level admin dependency to reach the handler's own check.
    override_auth(test_user, level="admin")
    client = TestClient(app)

    response = client.post(path, data={}, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert {name: m.mock_calls for name, m in mocks.items() if m.mock_calls} == {}
