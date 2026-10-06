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
        "provider_type": "generic",
        "issuer": "https://idp.example.com",
        "client_id": "client-123",
        "is_enabled": False,
    }
    kwargs.update(overrides)
    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test OIDC",
        created_by=str(test_super_admin_user["id"]),
        **kwargs,
    )


# =============================================================================
# List + New form
# =============================================================================


def test_list_connections_as_super_admin(super_admin_session, test_tenant_host):
    response = super_admin_session.get(
        "/identity-providers/oidc",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200


def test_list_connections_as_admin_forbidden(admin_session, test_tenant_host):
    response = admin_session.get(
        "/identity-providers/oidc",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code in (303, 403)


def test_new_connection_form_as_super_admin(super_admin_session, test_tenant_host):
    response = super_admin_session.get(
        "/identity-providers/oidc/new",
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
        "/identity-providers/oidc/new",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code in (303, 403)


# =============================================================================
# Create
# =============================================================================


def test_create_connection_success(super_admin_session, test_tenant_host):
    response = super_admin_session.post(
        "/identity-providers/oidc/new",
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
        "/identity-providers/oidc/new",
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
        "/identity-providers/oidc/new",
        data={"provider_type": "generic", "issuer": "https://idp.example.com"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    # Missing required name -> 422 (Form validation).
    assert response.status_code == 422


def test_create_connection_invalid_provider_type(super_admin_session, test_tenant_host):
    response = super_admin_session.post(
        "/identity-providers/oidc/new",
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
        "/identity-providers/oidc/new",
        data={
            "name": "No Issuer",
            "provider_type": "generic",
            "issuer": "",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    # Empty issuer for a generic connection must not 500; the service layer
    # rejects it and redirects back with a specific error.
    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert "issuer" in response.headers["location"]


def test_new_connection_form_prefills_google_issuer(super_admin_session, test_tenant_host):
    response = super_admin_session.get(
        "/identity-providers/oidc/new",
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
        f"/identity-providers/oidc/{conn['id']}",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert f"/identity-providers/oidc/{conn['id']}/details" in response.headers["location"]


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
        f"/identity-providers/oidc/{conn['id']}/details",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    # The callback URL is displayed for pasting into the IdP console.
    assert f"/auth/oidc/{conn['id']}/callback" in response.text
    # So is the back-channel logout URL, with its own copy button.
    assert f"/auth/oidc/{conn['id']}/backchannel-logout" in response.text
    assert 'id="copy-backchannel-logout-url"' in response.text
    # And the post-logout redirect URI for provider sign-out.
    assert "/logout/complete" in response.text
    assert 'id="copy-post-logout-redirect-uri"' in response.text
    assert "End Session Endpoint" in response.text
    assert 'id="sign_out_at_idp"' in response.text
    # The secret is never rendered.
    assert "super-secret-value" not in response.text


def test_danger_tab_renders(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/danger",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200


def test_danger_tab_delete_enabled_when_disabled_and_unlinked(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/danger",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert f'action="/identity-providers/oidc/{conn["id"]}/delete"' in response.text
    assert "Unlink all users before deleting." not in response.text


def test_danger_tab_delete_disabled_while_users_linked(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user, test_user
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user)
    database.oidc_upstream.create_link(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        idp_id=str(conn["id"]),
        sub="linked-sub",
        user_id=str(test_user["id"]),
    )
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/danger",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "Unlink all users before deleting." in response.text
    assert f'action="/identity-providers/oidc/{conn["id"]}/delete"' not in response.text


def test_danger_tab_surfaces_linked_user_listing_failure(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user, caplog
):
    """A linked-user listing failure must not silently pass (criterion #4).

    The danger tab catches ``ServiceError`` from ``list_connection_linked_users``
    and logs a warning rather than rendering an empty (misleading) table. This
    asserts the page still renders 200 and the warning is emitted.
    """
    from services.exceptions import ServiceError

    conn = _make_connection(test_tenant, test_super_admin_user)

    with patch(
        "services.oidc_upstream.list_connection_linked_users",
        side_effect=ServiceError(message="boom", code="boom"),
    ):
        response = super_admin_session.get(
            f"/identity-providers/oidc/{conn['id']}/danger",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert any("Failed to list linked users" in record.message for record in caplog.records)


def test_details_tab_not_found_redirects(super_admin_session, test_tenant_host):
    import uuid

    response = super_admin_session.get(
        f"/identity-providers/oidc/{uuid.uuid4()}/details",
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
        f"/identity-providers/oidc/{conn['id']}/edit",
        data={"name": "Renamed OIDC"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=updated" in response.headers["location"]


def test_edit_settings(super_admin_session, test_tenant_host, test_tenant, test_super_admin_user):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-settings",
        data={"is_enabled": "on", "jit_provisioning": "on"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=settings_updated" in response.headers["location"]


def test_edit_settings_unchecking_default_clears_it(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user)
    url = f"/identity-providers/oidc/{conn['id']}/edit-settings"
    super_admin_session.post(
        url,
        data={"is_default": "on"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])["is_default"]

    # An unchecked box is absent from the form: the connection stops being the default.
    response = super_admin_session.post(
        url, data={}, headers={"Host": test_tenant_host}, follow_redirects=False
    )
    assert response.status_code == 303
    assert "success=settings_updated" in response.headers["location"]
    row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
    assert row["is_default"] is False


def test_edit_settings_turns_provider_sign_out_on_and_off(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user)
    url = f"/identity-providers/oidc/{conn['id']}/edit-settings"
    super_admin_session.post(
        url,
        data={"sign_out_at_idp": "on"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])["sign_out_at_idp"]

    # An unchecked box is absent from the form: off.
    super_admin_session.post(
        url, data={}, headers={"Host": test_tenant_host}, follow_redirects=False
    )
    row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
    assert row["sign_out_at_idp"] is False


def test_details_tab_warns_when_provider_publishes_no_end_session_endpoint(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user)
    database.oidc_upstream.update_connection(test_tenant["id"], conn["id"], sign_out_at_idp=True)
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/details", headers={"Host": test_tenant_host}
    )
    assert "publishes no end session endpoint" in response.text

    database.oidc_upstream.update_connection(
        test_tenant["id"], conn["id"], end_session_endpoint="https://idp.example.com/logout"
    )
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/details", headers={"Host": test_tenant_host}
    )
    assert "publishes no end session endpoint" not in response.text
    assert "https://idp.example.com/logout" in response.text


def test_toggle_connection(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/toggle",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=enabled" in response.headers["location"]


def test_set_default(super_admin_session, test_tenant_host, test_tenant, test_super_admin_user):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/set-default",
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
        f"/identity-providers/oidc/{conn['id']}/delete",
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
        f"/identity-providers/oidc/{conn['id']}/delete",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=" in response.headers["location"]


# =============================================================================
# Test connection
# =============================================================================


@patch("routers.oidc_upstream.admin.oidc_service.test_connection")
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
        f"/identity-providers/oidc/{conn['id']}/test-connection",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "test=success" in response.headers["location"]
    mock_discovery.assert_called_once()


def test_test_connection_failure_shows_reason(
    super_admin_session,
    test_tenant_host,
    test_tenant,
    test_super_admin_user,
):
    """Real service, failing discovery: the reason reaches the details tab."""
    from services.oidc_upstream.errors import DiscoveryError

    conn = _make_connection(test_tenant, test_super_admin_user)
    with patch(
        "services.oidc_upstream.discovery.run_discovery",
        side_effect=DiscoveryError("boom & bust"),
    ):
        response = super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/test-connection",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )
    assert response.status_code == 303
    location = response.headers["location"]
    assert "test=error" in location
    assert "test_detail=Discovery%20failed%3A%20boom%20%26%20bust" in location

    page = super_admin_session.get(location, headers={"Host": test_tenant_host})
    assert "Discovery failed: boom &amp; bust" in page.text


def test_test_connection_unknown_connection(super_admin_session, test_tenant_host):
    from uuid import uuid4

    response = super_admin_session.post(
        f"/identity-providers/oidc/{uuid4()}/test-connection",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


# =============================================================================
# Manual endpoints (providers without discovery)
# =============================================================================


def test_new_connection_form_renders_manual_endpoint_fields(super_admin_session, test_tenant_host):
    response = super_admin_session.get(
        "/identity-providers/oidc/new",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "Advanced: manual endpoints" in response.text
    for field in (
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "end_session_endpoint",
    ):
        assert f'name="{field}"' in response.text


def test_create_connection_with_manual_endpoints(
    super_admin_session, test_tenant_host, test_tenant
):
    import database

    response = super_admin_session.post(
        "/identity-providers/oidc/new",
        data={
            "name": "No Discovery IdP",
            "provider_type": "generic",
            "issuer": "https://idp.example.com",
            "client_id": "client-123",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "userinfo_endpoint": "https://idp.example.com/userinfo",
            "jwks_uri": "https://idp.example.com/keys",
            "end_session_endpoint": "https://idp.example.com/logout",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert "success=created" in location

    connection_id = location.split("/identity-providers/oidc/")[1].split("/")[0]
    row = database.oidc_upstream.get_connection(test_tenant["id"], connection_id)
    assert row["authorization_endpoint"] == "https://idp.example.com/authorize"
    assert row["token_endpoint"] == "https://idp.example.com/token"
    assert row["userinfo_endpoint"] == "https://idp.example.com/userinfo"
    assert row["end_session_endpoint"] == "https://idp.example.com/logout"
    assert row["jwks_uri"] == "https://idp.example.com/keys"


def test_create_connection_rejects_insecure_manual_endpoint(super_admin_session, test_tenant_host):
    with patch("services.oidc_upstream.connections.settings.IS_DEV", False):
        response = super_admin_session.post(
            "/identity-providers/oidc/new",
            data={
                "name": "Plaintext IdP",
                "provider_type": "generic",
                "issuer": "https://idp.example.com",
                "token_endpoint": "http://idp.example.com/token",
            },
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert "/new?error=" in response.headers["location"]
    assert "https" in response.headers["location"]


def test_details_tab_shows_endpoint_editor_for_generic(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        authorization_endpoint="https://idp.example.com/authorize",
    )
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/details",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert 'id="edit-endpoints-btn"' in response.text
    assert 'id="edit-endpoints-modal"' in response.text
    # The modal is prefilled with the stored value.
    assert 'value="https://idp.example.com/authorize"' in response.text


def test_details_tab_hides_endpoint_editor_for_google(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Google OIDC",
        provider_type="google",
        created_by=str(test_super_admin_user["id"]),
        issuer="https://accounts.google.com",
        client_id="client-123",
        is_enabled=False,
    )
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/details",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert 'id="edit-endpoints-btn"' not in response.text
    assert 'id="edit-endpoints-modal"' not in response.text


def test_edit_endpoints(super_admin_session, test_tenant_host, test_tenant, test_super_admin_user):
    import database

    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        userinfo_endpoint="https://idp.example.com/userinfo",
    )
    response = super_admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-endpoints",
        data={
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "jwks_uri": "https://idp.example.com/keys",
            "end_session_endpoint": "https://idp.example.com/logout",
            # Blank keeps the stored value.
            "userinfo_endpoint": "",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=endpoints_updated" in response.headers["location"]

    row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
    assert row["authorization_endpoint"] == "https://idp.example.com/authorize"
    assert row["token_endpoint"] == "https://idp.example.com/token"
    assert row["jwks_uri"] == "https://idp.example.com/keys"
    assert row["userinfo_endpoint"] == "https://idp.example.com/userinfo"
    assert row["end_session_endpoint"] == "https://idp.example.com/logout"


def test_edit_endpoints_rejects_insecure_url(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user)
    with patch("services.oidc_upstream.connections.settings.IS_DEV", False):
        response = super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/edit-endpoints",
            data={"jwks_uri": "http://idp.example.com/keys"},
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert f"/{conn['id']}/details?error=" in response.headers["location"]

    row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
    assert row["jwks_uri"] is None


def test_edit_endpoints_not_found(super_admin_session, test_tenant_host):
    from uuid import uuid4

    response = super_admin_session.post(
        f"/identity-providers/oidc/{uuid4()}/edit-endpoints",
        data={"jwks_uri": "https://idp.example.com/keys"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_edit_endpoints_as_admin_forbidden(
    admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-endpoints",
        data={"jwks_uri": "https://idp.example.com/keys"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code in (303, 403)


# =============================================================================
# Credentials (details tab)
# =============================================================================


def test_details_tab_shows_credentials_editor(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        scopes="openid profile email groups",
        client_secret_enc="encrypted-secret-value",
    )
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/details",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    html = response.text
    assert 'id="edit-credentials-btn"' in html
    assert 'id="edit-credentials-modal"' in html
    assert "openid profile email groups" in html
    for field in ("issuer", "discovery_url", "client_id", "client_secret", "correlation_claim"):
        assert f'name="{field}"' in html
    assert 'name="hosted_domain"' not in html
    assert 'name="entra_tenant_id"' not in html
    # The secret is write-only.
    assert "encrypted-secret-value" not in html


def test_details_tab_credentials_editor_for_google(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        provider_type="google",
        issuer="https://accounts.google.com",
        hosted_domain="example.com",
    )
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/details",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    html = response.text
    assert 'name="hosted_domain"' in html
    assert 'value="example.com"' in html
    assert 'name="issuer"' not in html
    assert 'name="correlation_claim"' not in html


def test_details_tab_credentials_editor_for_entra(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        provider_type="entra",
        issuer="https://login.microsoftonline.com/contoso.com/v2.0",
        entra_tenant_id="contoso.com",
    )
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/details",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    html = response.text
    assert 'name="entra_tenant_id"' in html
    assert 'value="contoso.com"' in html
    assert 'name="issuer"' not in html


def test_details_tab_credentials_editor_for_apple_has_no_secret(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        provider_type="apple",
        issuer="https://appleid.apple.com",
    )
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/details",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    html = response.text
    assert 'id="edit-credentials-modal"' in html
    assert 'name="client_secret"' not in html


def test_edit_credentials_rotates_secret(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user, scopes="openid")
    response = super_admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-credentials",
        data={
            "client_id": " client-456 ",
            "client_secret": "rotated-secret",
            "scopes": "openid   profile email",
            "issuer": "https://idp.example.com",
            "discovery_url": "",
            "correlation_claim": "sub",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=credentials_updated" in response.headers["location"]

    row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
    assert row["client_id"] == "client-456"
    assert row["scopes"] == "openid profile email"
    assert row["client_secret_enc"]
    assert "rotated-secret" not in row["client_secret_enc"]


def test_edit_credentials_blank_keeps_values(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        scopes="openid",
        client_secret_enc="encrypted-secret-value",
    )
    response = super_admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-credentials",
        data={"client_id": "", "client_secret": "", "scopes": "", "issuer": ""},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303

    row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
    assert row["client_id"] == "client-123"
    assert row["client_secret_enc"] == "encrypted-secret-value"
    assert row["scopes"] == "openid"
    assert row["issuer"] == "https://idp.example.com"


def test_edit_credentials_clears_hosted_domain(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        provider_type="google",
        issuer="https://accounts.google.com",
        hosted_domain="example.com",
    )
    response = super_admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-credentials",
        data={"client_id": "client-123", "hosted_domain": ""},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
    assert row["hosted_domain"] is None


def test_edit_credentials_rejects_multi_tenant_entra(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        provider_type="entra",
        issuer="https://login.microsoftonline.com/contoso.com/v2.0",
        entra_tenant_id="contoso.com",
    )
    response = super_admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-credentials",
        data={"entra_tenant_id": "organizations"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert f"/{conn['id']}/details?error=Multi-tenant" in response.headers["location"]
    row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
    assert row["entra_tenant_id"] == "contoso.com"


def test_edit_credentials_not_found(super_admin_session, test_tenant_host):
    from uuid import uuid4

    response = super_admin_session.post(
        f"/identity-providers/oidc/{uuid4()}/edit-credentials",
        data={"client_id": "x"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_edit_credentials_as_admin_forbidden(
    admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user)
    response = admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-credentials",
        data={"client_id": "hijacked"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code in (303, 403)
    row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
    assert row["client_id"] == "client-123"


# =============================================================================
# Group claim settings (claim-mapping tab)
# =============================================================================


def test_claim_mapping_tab_renders_group_claim_settings(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(
        test_tenant,
        test_super_admin_user,
        group_claim_source="https://example.com/groups",
        group_claim_name_key="displayName",
    )
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/claim-mapping",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    body = response.text
    assert "Group Claim" in body
    assert 'name="group_claim_source"' in body
    assert 'value="https://example.com/groups"' in body
    assert 'value="displayName"' in body
    assert "edit-group-claim" in body


def test_claim_mapping_tab_entra_shows_guid_note(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user)
    database.execute(
        test_tenant["id"],
        "update oidc_idp_connections set provider_type = 'entra' where id = :id",
        {"id": str(conn["id"])},
    )
    response = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/claim-mapping",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "directory object IDs" in response.text


def test_edit_group_claim_saves(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(test_tenant, test_super_admin_user)
    response = super_admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-group-claim",
        data={"group_claim_source": " groups ", "group_claim_name_key": "name"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=group_claim_updated" in response.headers["location"]

    row = database.oidc_upstream.get_connection(test_tenant["id"], str(conn["id"]))
    assert row is not None
    assert row["group_claim_source"] == "groups"
    assert row["group_claim_name_key"] == "name"


def test_edit_group_claim_blank_clears(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    import database

    conn = _make_connection(
        test_tenant, test_super_admin_user, group_claim_source="groups", group_claim_name_key="n"
    )
    response = super_admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-group-claim",
        data={"group_claim_source": "", "group_claim_name_key": ""},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303

    row = database.oidc_upstream.get_connection(test_tenant["id"], str(conn["id"]))
    assert row is not None
    assert row["group_claim_source"] is None
    assert row["group_claim_name_key"] is None


def test_edit_group_claim_not_found(super_admin_session, test_tenant_host):
    import uuid

    response = super_admin_session.post(
        f"/identity-providers/oidc/{uuid.uuid4()}/edit-group-claim",
        data={"group_claim_source": "groups"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_edit_group_claim_as_admin_forbidden(
    admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user)
    response = admin_session.post(
        f"/identity-providers/oidc/{conn['id']}/edit-group-claim",
        data={"group_claim_source": "groups"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code in (303, 403)


# =============================================================================
# Social presets (Microsoft personal, LinkedIn, GitLab)
# =============================================================================


def test_new_connection_form_offers_social_presets(super_admin_session, test_tenant_host):
    response = super_admin_session.get(
        "/identity-providers/oidc/new",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 200
    for provider_type, label in (
        ("microsoft", "Microsoft (personal accounts)"),
        ("linkedin", "LinkedIn"),
        ("gitlab", "GitLab"),
        ("github", "GitHub"),
        ("discord", "Discord"),
        ("facebook", "Facebook"),
        ("apple", "Apple"),
    ):
        assert f'<option value="{provider_type}">{label}</option>' in response.text


@pytest.mark.parametrize(
    ("provider_type", "issuer"),
    [
        (
            "microsoft",
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
        ),
        ("linkedin", "https://www.linkedin.com/oauth"),
        ("gitlab", "https://gitlab.com"),
    ],
)
def test_create_social_preset_connection(
    super_admin_session, test_tenant_host, test_tenant, provider_type, issuer
):
    import database

    response = super_admin_session.post(
        "/identity-providers/oidc/new",
        data={
            "name": f"{provider_type} sign-in",
            "provider_type": provider_type,
            "client_id": "client-123",
            "client_secret": "super-secret-value",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=created" in response.headers["location"]
    row = next(
        c
        for c in database.oidc_upstream.list_connections(test_tenant["id"])
        if c["name"] == f"{provider_type} sign-in"
    )
    assert row["provider_type"] == provider_type
    assert row["issuer"] == issuer
    assert row["correlation_claim"] == "sub"


def test_create_self_managed_gitlab(super_admin_session, test_tenant_host, test_tenant):
    import database

    response = super_admin_session.post(
        "/identity-providers/oidc/new",
        data={
            "name": "Acme GitLab",
            "provider_type": "gitlab",
            "issuer": "https://gitlab.acme.example",
            "client_id": "client-123",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    row = next(
        c
        for c in database.oidc_upstream.list_connections(test_tenant["id"])
        if c["name"] == "Acme GitLab"
    )
    assert row["issuer"] == "https://gitlab.acme.example"
    assert row["discovery_url"] is None


def test_create_unknown_provider_type_rejected(super_admin_session, test_tenant_host):
    response = super_admin_session.post(
        "/identity-providers/oidc/new",
        data={"name": "MySpace", "provider_type": "myspace", "client_id": "client-123"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=invalid_input" in response.headers["location"]


def test_list_and_details_show_provider_label(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    conn = _make_connection(test_tenant, test_super_admin_user, provider_type="linkedin")
    listing = super_admin_session.get(
        "/identity-providers/oidc", headers={"Host": test_tenant_host}
    )
    assert "LinkedIn" in listing.text
    details = super_admin_session.get(
        f"/identity-providers/oidc/{conn['id']}/details", headers={"Host": test_tenant_host}
    )
    assert details.status_code == 200
    assert "LinkedIn" in details.text
