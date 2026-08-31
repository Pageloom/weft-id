"""Tests for the OIDC upstream admin UI routes.

Covers the list page, create form, detail tabs (details / danger), the
test-connection action, and the POST handlers (edit, settings, toggle,
set-default, delete). Authz (non-super-admin refused) and the "secret never
rendered" guarantee are asserted.
"""

import os
from pathlib import Path
from unittest.mock import patch

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
def super_admin_session(client, test_tenant_host, test_super_admin_user, override_auth):
    """Create a client with super_admin session."""
    override_auth(test_super_admin_user, level="super_admin")
    yield client


@pytest.fixture
def admin_session(client, test_tenant_host, test_admin_user, override_auth):
    """Create a client with admin session (should be refused)."""
    override_auth(test_admin_user, level="admin")
    yield client


def _make_connection(test_tenant, test_super_admin_user, **overrides):
    """Create a real OIDC connection row via the database layer."""
    import database

    kwargs = {
        "issuer": "https://idp.example.com",
        "client_id": "client-123",
        "is_enabled": False,
    }
    kwargs.update(overrides)
    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test OIDC",
        provider_type="generic",
        created_by=str(test_super_admin_user["id"]),
        **kwargs,
    )


# =============================================================================
# List + New form
# =============================================================================


def test_list_connections_as_super_admin(super_admin_session, test_tenant_host):
    response = super_admin_session.get(
        "/admin/settings/oidc-identity-providers",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200


def test_list_connections_as_admin_forbidden(admin_session, test_tenant_host):
    response = admin_session.get(
        "/admin/settings/oidc-identity-providers",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code in (303, 403)


def test_new_connection_form_as_super_admin(super_admin_session, test_tenant_host):
    response = super_admin_session.get(
        "/admin/settings/oidc-identity-providers/new",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    # The preset picker must offer all three vendors.
    assert "Generic OIDC" in response.text
    assert "Google" in response.text
    assert "Entra ID" in response.text


def test_new_connection_form_as_admin_forbidden(admin_session, test_tenant_host):
    response = admin_session.get(
        "/admin/settings/oidc-identity-providers/new",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code in (303, 403)


# =============================================================================
# Create
# =============================================================================


def test_create_connection_success(super_admin_session, test_tenant_host):
    response = super_admin_session.post(
        "/admin/settings/oidc-identity-providers/new",
        data={
            "name": "New OIDC",
            "provider_type": "generic",
            "issuer": "https://idp.example.com",
            "client_id": "client-123",
            "client_secret": "super-secret-value",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=created" in response.headers["location"]


def test_create_connection_entra_composes_issuer(super_admin_session, test_tenant_host):
    response = super_admin_session.post(
        "/admin/settings/oidc-identity-providers/new",
        data={
            "name": "Entra OIDC",
            "provider_type": "entra",
            "entra_tenant_id": "contoso.onmicrosoft.com",
            "client_id": "client-123",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=created" in response.headers["location"]


def test_create_connection_missing_name(super_admin_session, test_tenant_host):
    response = super_admin_session.post(
        "/admin/settings/oidc-identity-providers/new",
        data={"provider_type": "generic", "issuer": "https://idp.example.com"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    # Missing required name -> 422 (Form validation).
    assert response.status_code == 422


def test_create_connection_invalid_provider_type(super_admin_session, test_tenant_host):
    response = super_admin_session.post(
        "/admin/settings/oidc-identity-providers/new",
        data={
            "name": "Evil OIDC",
            "provider_type": "evil",
            "issuer": "https://idp.example.com",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    # Invalid provider type must not 500; redirect back with a generic error.
    assert response.status_code == 303
    assert "error=invalid_input" in response.headers["location"]


def test_create_connection_empty_issuer(super_admin_session, test_tenant_host):
    response = super_admin_session.post(
        "/admin/settings/oidc-identity-providers/new",
        data={
            "name": "No Issuer",
            "provider_type": "generic",
            "issuer": "",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    # Empty issuer must not 500; redirect back with a generic error.
    assert response.status_code == 303
    assert "error=invalid_input" in response.headers["location"]


def test_new_connection_form_prefills_google_issuer(super_admin_session, test_tenant_host):
    response = super_admin_session.get(
        "/admin/settings/oidc-identity-providers/new",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    # The preset JSON must carry the Google issuer so the picker can pre-fill it.
    assert "https://accounts.google.com" in response.text


# =============================================================================
# Detail tabs
# =============================================================================


def test_detail_redirects_to_details_tab(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.get(
        f"/admin/settings/oidc-identity-providers/{conn['id']}",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert (
        f"/admin/settings/oidc-identity-providers/{conn['id']}/details"
        in response.headers["location"]
    )


def test_details_tab_renders_and_hides_secret(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    from services.oidc_upstream.connections import _encrypt_secret

    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        client_secret_enc=_encrypt_secret("super-secret-value"),
    )
    response = super_admin_session.get(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/details",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    # The callback URL is displayed for pasting into the IdP console.
    assert f"/auth/oidc/{conn['id']}/callback" in response.text
    # The secret is never rendered.
    assert "super-secret-value" not in response.text


def test_danger_tab_renders(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.get(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/danger",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200


def test_details_tab_not_found_redirects(super_admin_session, test_tenant_host):
    import uuid

    response = super_admin_session.get(
        f"/admin/settings/oidc-identity-providers/{uuid.uuid4()}/details",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


# =============================================================================
# POST handlers
# =============================================================================


def test_edit_name(super_admin_session, test_tenant_host, test_tenant, test_super_admin_user):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.post(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/edit",
        data={"name": "Renamed OIDC"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=updated" in response.headers["location"]


def test_edit_settings(super_admin_session, test_tenant_host, test_tenant, test_super_admin_user):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.post(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/edit-settings",
        data={"is_enabled": "on", "jit_provisioning": "on"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=settings_updated" in response.headers["location"]


def test_toggle_connection(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.post(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/toggle",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=enabled" in response.headers["location"]


def test_set_default(super_admin_session, test_tenant_host, test_tenant, test_super_admin_user):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.post(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/set-default",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=set_default" in response.headers["location"]


def test_delete_connection(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.post(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/delete",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=deleted" in response.headers["location"]


def test_delete_enabled_connection_conflict(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user, is_enabled=True)
    response = super_admin_session.post(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/delete",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=" in response.headers["location"]


# =============================================================================
# Test connection
# =============================================================================


@patch("routers.oidc_upstream.admin.oidc_service.run_discovery")
def test_test_connection_success(
    mock_discovery,
    super_admin_session,
    test_tenant_host,
    test_tenant,
    test_super_admin_user,
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    mock_discovery.return_value = {}
    response = super_admin_session.post(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/test-connection",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "test=success" in response.headers["location"]
    mock_discovery.assert_called_once()


@patch("routers.oidc_upstream.admin.oidc_service.run_discovery")
def test_test_connection_failure(
    mock_discovery,
    super_admin_session,
    test_tenant_host,
    test_tenant,
    test_super_admin_user,
):
    from services.oidc_upstream.errors import DiscoveryError

    conn = _make_connection(test_tenant, test_super_admin_user)
    mock_discovery.side_effect = DiscoveryError("boom")
    response = super_admin_session.post(
        f"/admin/settings/oidc-identity-providers/{conn['id']}/test-connection",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "test=error" in response.headers["location"]
