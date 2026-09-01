"""Tests for the OIDC upstream disconnect API/admin surface (Iteration 8).

Covers the per-user disconnect endpoints deferred from Iteration 7:

- ``GET /api/v1/oidc-upstream/connections/{id}/users`` (200 + list shape)
- ``DELETE /api/v1/oidc-upstream/connections/{id}/users/{user_id}`` (204 then
  link gone)
- 404 for unknown user / connection / link
- 403 for non-super-admin
- admin ``POST .../unlink-user/{user_id}`` redirects with
  ``success=user_unlinked``
- the danger tab renders the linked-users table
"""

import os
import uuid
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def oauth2_super_admin_access_token(test_tenant, normal_oauth2_client, test_super_admin_user):
    import database

    refresh_token, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
    )
    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
        parent_token_id=refresh_token_id,
    )
    yield access_token


@pytest.fixture
def oauth2_super_admin_header(oauth2_super_admin_access_token):
    return {"Authorization": f"Bearer {oauth2_super_admin_access_token}"}


def _make_connection(test_tenant, test_super_admin_user, **overrides):
    import database

    kwargs = {"issuer": "https://idp.example.com", "is_enabled": False}
    kwargs.update(overrides)
    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Disconnect OIDC",
        provider_type="generic",
        created_by=str(test_super_admin_user["id"]),
        **kwargs,
    )


def _link(test_tenant, connection, user, sub="subject-123"):
    import database

    return database.oidc_upstream.create_link(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        idp_id=str(connection["id"]),
        sub=sub,
        user_id=str(user["id"]),
    )


# =============================================================================
# API: list linked users
# =============================================================================


def test_list_linked_users_200_and_shape(
    client,
    test_tenant_host,
    oauth2_super_admin_header,
    test_tenant,
    test_super_admin_user,
    test_user,
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    _link(test_tenant, conn, test_user)

    response = client.get(
        f"/api/v1/oidc-upstream/connections/{conn['id']}/users",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["user_id"] == str(test_user["id"])
    assert data[0]["sub"] == "subject-123"
    assert "link_id" in data[0]


def test_list_linked_users_unknown_connection_404(
    client, test_tenant_host, oauth2_super_admin_header
):
    response = client.get(
        f"/api/v1/oidc-upstream/connections/{uuid.uuid4()}/users",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 404


def test_list_linked_users_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = client.get(
        f"/api/v1/oidc-upstream/connections/{conn['id']}/users",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 403


# =============================================================================
# API: unlink user
# =============================================================================


def test_unlink_user_204_then_link_gone(
    client,
    test_tenant_host,
    oauth2_super_admin_header,
    test_tenant,
    test_super_admin_user,
    test_user,
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user)
    _link(test_tenant, conn, test_user)

    response = client.delete(
        f"/api/v1/oidc-upstream/connections/{conn['id']}/users/{test_user['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 204

    assert (
        database.oidc_upstream.get_user_id_by_sub(test_tenant["id"], str(conn["id"]), "subject-123")
        is None
    )


def test_unlink_user_unknown_connection_404(
    client, test_tenant_host, oauth2_super_admin_header, test_user
):
    response = client.delete(
        f"/api/v1/oidc-upstream/connections/{uuid.uuid4()}/users/{test_user['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 404


def test_unlink_user_unknown_user_404(
    client,
    test_tenant_host,
    oauth2_super_admin_header,
    test_tenant,
    test_super_admin_user,
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = client.delete(
        f"/api/v1/oidc-upstream/connections/{conn['id']}/users/{uuid.uuid4()}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 404


def test_unlink_user_not_linked_404(
    client,
    test_tenant_host,
    oauth2_super_admin_header,
    test_tenant,
    test_super_admin_user,
    test_user,
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = client.delete(
        f"/api/v1/oidc-upstream/connections/{conn['id']}/users/{test_user['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 404


def test_unlink_user_as_admin_forbidden(
    client,
    test_tenant_host,
    oauth2_admin_authorization_header,
    test_tenant,
    test_super_admin_user,
    test_user,
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    _link(test_tenant, conn, test_user)
    response = client.delete(
        f"/api/v1/oidc-upstream/connections/{conn['id']}/users/{test_user['id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 403


# =============================================================================
# Admin UI: unlink-user POST + danger tab
# =============================================================================


@pytest.fixture
def super_admin_session(client, test_tenant_host, test_super_admin_user, override_auth):
    override_auth(test_super_admin_user, level="super_admin")
    yield client


def test_admin_unlink_user_redirects_success(
    super_admin_session,
    test_tenant_host,
    test_tenant,
    test_super_admin_user,
    test_user,
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user)
    _link(test_tenant, conn, test_user)

    response = super_admin_session.post(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/unlink-user/{test_user['id']}",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=user_unlinked" in response.headers["location"]

    assert (
        database.oidc_upstream.get_user_id_by_sub(test_tenant["id"], str(conn["id"]), "subject-123")
        is None
    )


def test_danger_tab_renders_linked_users_table(
    super_admin_session,
    test_tenant_host,
    test_tenant,
    test_super_admin_user,
    test_user,
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    _link(test_tenant, conn, test_user)

    response = super_admin_session.get(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/danger",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "Linked Users" in response.text
    assert "subject-123" in response.text
    assert f"/unlink-user/{test_user['id']}" in response.text
