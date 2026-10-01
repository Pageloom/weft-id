"""OIDC apps in My Apps (third-party-initiated login), real database.

An OIDC-enabled client with an ``initiate_login_uri`` that the user may access
appears on the dashboard and in ``GET /api/v1/my-apps``, launching at that URI
with ``iss`` set to the tenant's issuer (the request host, as in discovery).
"""

from urllib.parse import parse_qs, urlsplit

import database
import pytest
from main import app

from tests.helpers.client import TestClient

LOGIN_URI = "https://wiki.example.com/login"


@pytest.fixture
def launchable_client(test_tenant, test_admin_user):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Team Wiki",
        redirect_uris=["https://wiki.example.com/cb"],
        created_by=str(test_admin_user["id"]),
        description="Where the docs live",
        initiate_login_uri=LOGIN_URI,
    )
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], client["client_id"], oidc_enabled=True, available_to_all=True
    )
    return client


def _launch_url(test_tenant_host):
    return f"{LOGIN_URI}?iss=https%3A%2F%2F{test_tenant_host}"


def test_my_apps_api_lists_oidc_app(
    client, test_tenant_host, oauth2_authorization_header, launchable_client
):
    headers = {"Host": test_tenant_host, **oauth2_authorization_header}
    response = client.get("/api/v1/my-apps", headers=headers)

    assert response.status_code == 200
    items = [i for i in response.json()["items"] if i["kind"] == "oidc"]
    assert len(items) == 1
    item = items[0]
    assert item["id"] == str(launchable_client["id"])
    assert item["name"] == "Team Wiki"
    assert item["description"] == "Where the docs live"
    assert item["launch_url"] == _launch_url(test_tenant_host)

    # iss is the issuer the client finds in discovery.
    issuer = client.get("/.well-known/openid-configuration", headers=headers).json()["issuer"]
    assert parse_qs(urlsplit(item["launch_url"]).query)["iss"] == [issuer]


def test_my_apps_api_omits_oidc_app_without_access(
    client, test_tenant, test_tenant_host, oauth2_authorization_header, launchable_client
):
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], launchable_client["client_id"], available_to_all=False
    )
    response = client.get(
        "/api/v1/my-apps", headers={"Host": test_tenant_host, **oauth2_authorization_header}
    )

    assert response.status_code == 200
    assert [i for i in response.json()["items"] if i["kind"] == "oidc"] == []


def test_dashboard_shows_oidc_app(test_tenant, test_tenant_host, test_user, mocker):
    from dependencies import get_tenant_id_from_request

    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Team Wiki",
        redirect_uris=["https://wiki.example.com/cb"],
        created_by=str(test_user["id"]),
        initiate_login_uri=LOGIN_URI,
    )
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], client["client_id"], oidc_enabled=True, available_to_all=True
    )
    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]
    mocker.patch("routers.auth.dashboard.get_current_user", return_value=dict(test_user))

    response = TestClient(app).get("/dashboard", headers={"Host": test_tenant_host})

    assert response.status_code == 200
    expected_href = _launch_url(test_tenant_host).replace("&", "&amp;")
    assert f'href="{expected_href}"' in response.text
    assert "Team Wiki" in response.text
    # No hot-linked logo on the dashboard: the generated acronym is used.
    assert f'data-acronym="{client["id"]}"' in response.text
