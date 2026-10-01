"""Tests for routers/integrations.py endpoints (mounted at /applications/*).

The module is still named integrations.py for historical reasons -- see its
docstring and .claude/ITERATION_nav_restructure.md.
"""

import re
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.responses import HTMLResponse
from main import app

from tests.helpers.client import TestClient

# Module path constants for cleaner patch targets
ROUTERS_INTEGRATIONS = "routers.integrations"
SERVICES_OAUTH2 = "services.oauth2"

# =============================================================================
# Index Redirect Tests
# =============================================================================


def test_applications_index_redirects_to_oauth(test_admin_user, override_auth):
    """Test the /applications/ index redirects a plain admin to OAuth2 / OIDC.

    A plain admin can't see SAML/Forward Auth/Service Accounts (super_admin
    only), so OAuth2 / OIDC -- the only child they have access to -- must be
    the fallback destination.
    """
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.get("/applications/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/applications/oauth"


def test_applications_index_redirects_super_admin_to_saml(test_super_admin_user, override_auth):
    """Test the /applications/ index redirects a super_admin to SAML."""
    override_auth(test_super_admin_user, level="super_admin")

    client = TestClient(app)
    response = client.get("/applications/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/applications/saml"


def test_applications_index_without_trailing_slash(test_admin_user, override_auth):
    """Applications index works without a trailing slash (no 307 hop)."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.get("/applications", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/applications/oauth"


def test_applications_index_fallback_to_dashboard(test_admin_user, override_auth, mocker):
    """Test the /applications/ index falls back to dashboard with no accessible children."""
    override_auth(test_admin_user, level="admin")

    mock_first = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_first_accessible_child")
    mock_first.return_value = None

    client = TestClient(app)
    response = client.get("/applications/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_forward_auth_index_redirects_to_domains(test_super_admin_user, override_auth):
    """Test the /applications/forward-auth index redirects to the Domains tab."""
    override_auth(test_super_admin_user, level="super_admin")

    client = TestClient(app)
    response = client.get("/applications/forward-auth", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/applications/forward-auth/domains"


def test_forward_auth_index_non_super_admin_fallback_to_dashboard(test_admin_user, override_auth):
    """Test the /applications/forward-auth index falls back to dashboard for a plain admin."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.get("/applications/forward-auth", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# Apps List Tests
# =============================================================================


def test_apps_list_renders(test_admin_user, override_auth, mocker):
    """Test apps list page renders successfully."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_all_clients")
    mock_ctx = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTERS_INTEGRATIONS}.templates.TemplateResponse")

    mock_get.return_value = []
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>apps</html>")

    client = TestClient(app)
    response = client.get("/applications/oauth")

    assert response.status_code == 200
    mock_get.assert_called_once_with(str(test_admin_user["tenant_id"]), client_type="normal")
    mock_tmpl.assert_called_once()
    template_name = mock_tmpl.call_args[0][1]
    assert template_name == "integrations_apps.html"


def test_apps_list_with_clients(test_admin_user, override_auth, mocker):
    """Test apps list page renders with client data."""
    override_auth(test_admin_user, level="admin")

    mock_clients = [
        {
            "id": str(uuid4()),
            "client_id": "weft-id_client_abc123",
            "client_type": "normal",
            "name": "Test App",
            "description": "A test app",
            "redirect_uris": ["https://example.com/callback"],
            "service_user_id": None,
            "is_active": True,
            "created_at": "2026-01-01T00:00:00",
            "service_role": None,
        }
    ]

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_all_clients")
    mock_ctx = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTERS_INTEGRATIONS}.templates.TemplateResponse")

    mock_get.return_value = mock_clients
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>apps</html>")

    client = TestClient(app)
    response = client.get("/applications/oauth")

    assert response.status_code == 200
    # Verify clients passed to template context
    ctx_call = mock_ctx.call_args
    assert ctx_call[1]["clients"] == mock_clients


def test_apps_list_non_admin_redirects(test_user, override_auth):
    """Test non-admin user gets redirected from apps list."""
    override_auth(test_user, level="admin")

    client = TestClient(app)
    response = client.get("/applications/oauth", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# Apps Create Tests
# =============================================================================


def test_apps_create_success(test_admin_user, override_auth, mocker):
    """Test creating a normal OAuth2 client succeeds."""
    override_auth(test_admin_user, level="admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_new123",
        "client_secret": "secret_abc123",
        "client_type": "normal",
        "name": "New App",
        "description": None,
        "redirect_uris": ["https://example.com/callback"],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_create = mocker.patch(f"{SERVICES_OAUTH2}.create_normal_client")
    mock_create.return_value = mock_client

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/create",
        data={
            "name": "New App",
            "redirect_uris": "https://example.com/callback",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/applications/oauth" in response.headers["location"]
    assert "success=created" in response.headers["location"]

    mock_create.assert_called_once_with(
        tenant_id=str(test_admin_user["tenant_id"]),
        name="New App",
        redirect_uris=["https://example.com/callback"],
        created_by=str(test_admin_user["id"]),
        description=None,
        is_public=False,
    )


def test_apps_create_with_description(test_admin_user, override_auth, mocker):
    """Test creating a client with description passes it through."""
    override_auth(test_admin_user, level="admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_new123",
        "client_secret": "secret_abc123",
        "client_type": "normal",
        "name": "Described App",
        "description": "My custom description",
        "redirect_uris": ["https://example.com/callback"],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_create = mocker.patch(f"{SERVICES_OAUTH2}.create_normal_client")
    mock_create.return_value = mock_client

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/create",
        data={
            "name": "Described App",
            "redirect_uris": "https://example.com/callback",
            "description": "My custom description",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    mock_create.assert_called_once()
    assert mock_create.call_args[1]["description"] == "My custom description"


def test_apps_create_multiple_redirect_uris(test_admin_user, override_auth, mocker):
    """Test creating an app with multiple redirect URIs parses them correctly."""
    override_auth(test_admin_user, level="admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_multi",
        "client_secret": "secret_multi",
        "client_type": "normal",
        "name": "Multi URI App",
        "description": None,
        "redirect_uris": [
            "https://example.com/callback",
            "https://example.com/auth/redirect",
        ],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_create = mocker.patch(f"{SERVICES_OAUTH2}.create_normal_client")
    mock_create.return_value = mock_client

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/create",
        data={
            "name": "Multi URI App",
            "redirect_uris": "https://example.com/callback\nhttps://example.com/auth/redirect",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    mock_create.assert_called_once()
    call_kwargs = mock_create.call_args[1]
    assert call_kwargs["redirect_uris"] == [
        "https://example.com/callback",
        "https://example.com/auth/redirect",
    ]


@pytest.mark.parametrize(
    "form_data,expected_error",
    [
        (
            {
                "name": "   ",
                "redirect_uris": "https://example.com/callback",
                "description": "",
                "csrf_token": "test-token",
            },
            "error=name_required",
        ),
        (
            {
                "name": "Test App",
                "redirect_uris": "",
                "description": "",
                "csrf_token": "test-token",
            },
            "error=redirect_uris_required",
        ),
    ],
    ids=["empty_name", "empty_redirect_uris"],
)
def test_apps_create_validation_error(test_admin_user, override_auth, form_data, expected_error):
    """Test creating an app with invalid data returns appropriate error."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/create",
        data=form_data,
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert expected_error in response.headers["location"]


def test_apps_create_service_error(test_admin_user, override_auth, mocker):
    """Test that service errors during creation are handled gracefully."""
    override_auth(test_admin_user, level="admin")

    from services.exceptions import ValidationError

    mock_create = mocker.patch(f"{SERVICES_OAUTH2}.create_normal_client")
    mock_create.side_effect = ValidationError("failed", code="test")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/create",
        data={
            "name": "Fail App",
            "redirect_uris": "https://example.com/callback",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=creation_failed" in response.headers["location"]


def test_apps_create_non_admin_redirects(test_user, override_auth):
    """Test non-admin cannot create apps."""
    override_auth(test_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/create",
        data={
            "name": "Test",
            "redirect_uris": "https://example.com/callback",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# B2B List Tests
# =============================================================================


def test_b2b_list_renders(test_super_admin_user, override_auth, mocker):
    """Test B2B list page renders successfully."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_all_clients")
    mock_ctx = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTERS_INTEGRATIONS}.templates.TemplateResponse")

    mock_get.return_value = []
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>b2b</html>")

    client = TestClient(app)
    response = client.get("/applications/service-accounts")

    assert response.status_code == 200
    mock_get.assert_called_once_with(str(test_super_admin_user["tenant_id"]), client_type="b2b")
    mock_tmpl.assert_called_once()
    template_name = mock_tmpl.call_args[0][1]
    assert template_name == "integrations_b2b.html"


def test_b2b_list_admin_redirects(test_admin_user, override_auth):
    """Test admin user gets redirected from B2B list (requires super_admin)."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.get("/applications/service-accounts", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_b2b_list_non_admin_redirects(test_user, override_auth):
    """Test non-admin user gets redirected from B2B list."""
    override_auth(test_user, level="admin")

    client = TestClient(app)
    response = client.get("/applications/service-accounts", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# B2B Create Tests
# =============================================================================


def test_b2b_create_success(test_super_admin_user, override_auth, mocker):
    """Test creating a B2B client succeeds."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_new123",
        "client_secret": "secret_b2b123",
        "client_type": "b2b",
        "name": "New B2B Client",
        "description": None,
        "redirect_uris": None,
        "service_user_id": str(uuid4()),
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_create = mocker.patch(f"{SERVICES_OAUTH2}.create_b2b_client")
    mock_create.return_value = mock_client

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/create",
        data={
            "name": "New B2B Client",
            "role": "admin",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/applications/service-accounts" in response.headers["location"]
    assert "success=created" in response.headers["location"]

    mock_create.assert_called_once_with(
        tenant_id=str(test_super_admin_user["tenant_id"]),
        name="New B2B Client",
        role="admin",
        created_by=str(test_super_admin_user["id"]),
        description=None,
    )


def test_b2b_create_with_description(test_super_admin_user, override_auth, mocker):
    """Test creating a B2B client with description passes it through."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_desc",
        "client_secret": "secret_desc",
        "client_type": "b2b",
        "name": "Described B2B",
        "description": "Service for syncing",
        "redirect_uris": None,
        "service_user_id": str(uuid4()),
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_create = mocker.patch(f"{SERVICES_OAUTH2}.create_b2b_client")
    mock_create.return_value = mock_client

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/create",
        data={
            "name": "Described B2B",
            "role": "member",
            "description": "Service for syncing",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    mock_create.assert_called_once()
    assert mock_create.call_args[1]["description"] == "Service for syncing"


def test_b2b_create_empty_name_redirects_with_error(test_super_admin_user, override_auth):
    """Test creating a B2B client with empty name returns error."""
    override_auth(test_super_admin_user, level="super_admin")

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/create",
        data={
            "name": "",
            "role": "member",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=name_required" in response.headers["location"]


def test_b2b_create_invalid_role_redirects_with_error(test_super_admin_user, override_auth):
    """Test creating a B2B client with invalid role returns error."""
    override_auth(test_super_admin_user, level="super_admin")

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/create",
        data={
            "name": "Test B2B",
            "role": "invalid_role",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=invalid_role" in response.headers["location"]


def test_b2b_create_service_error(test_super_admin_user, override_auth, mocker):
    """Test that service errors during B2B creation are handled gracefully."""
    override_auth(test_super_admin_user, level="super_admin")

    from services.exceptions import ValidationError

    mock_create = mocker.patch(f"{SERVICES_OAUTH2}.create_b2b_client")
    mock_create.side_effect = ValidationError("failed", code="test")

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/create",
        data={
            "name": "Fail B2B",
            "role": "member",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=creation_failed" in response.headers["location"]


def test_b2b_create_non_admin_redirects(test_user, override_auth):
    """Test non-admin cannot create B2B clients."""
    override_auth(test_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/create",
        data={
            "name": "Test",
            "role": "member",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# Credentials Session Flow Tests
# =============================================================================


def test_apps_list_pops_pending_credentials(test_admin_user, override_auth, mocker):
    """Test that apps list page pops pending credentials from session."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_all_clients")
    mock_ctx = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTERS_INTEGRATIONS}.templates.TemplateResponse")

    mock_get.return_value = []
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>apps</html>")

    # Verify template context is called with pending_credentials
    client = TestClient(app)
    response = client.get("/applications/oauth?success=created")

    assert response.status_code == 200
    # The pending_credentials should be passed to template context
    ctx_kwargs = mock_ctx.call_args[1]
    # It will be None since session is empty in test
    assert "pending_credentials" in ctx_kwargs


def test_b2b_list_pops_pending_credentials(test_super_admin_user, override_auth, mocker):
    """Test that B2B list page pops pending credentials from session."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_all_clients")
    mock_ctx = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTERS_INTEGRATIONS}.templates.TemplateResponse")

    mock_get.return_value = []
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>b2b</html>")

    client = TestClient(app)
    response = client.get("/applications/service-accounts?success=created")

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert "pending_credentials" in ctx_kwargs


# =============================================================================
# App Detail Tests
# =============================================================================


def test_app_detail_renders(test_admin_user, override_auth, mocker):
    """Test app detail page renders successfully."""
    override_auth(test_admin_user, level="admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_detail123",
        "client_type": "normal",
        "name": "Detail Test App",
        "description": "A test app",
        "redirect_uris": ["https://example.com/callback"],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_ctx = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTERS_INTEGRATIONS}.templates.TemplateResponse")
    # app_detail now also loads OIDC management context via the OIDC client service.
    mock_oidc = mocker.patch(f"{ROUTERS_INTEGRATIONS}.oidc_client_service")
    mock_oidc.get_client_discovery_info.return_value = MagicMock()
    mock_oidc.list_client_group_assignments.return_value = MagicMock(items=[])
    mock_oidc.list_available_groups_for_client.return_value = []
    mocker.patch(f"{ROUTERS_INTEGRATIONS}.consent_service.list_client_grants", return_value=[])
    mocker.patch(f"{ROUTERS_INTEGRATIONS}.backchannel_service.list_backchannel_logout_deliveries")

    mock_get.return_value = mock_client
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>detail</html>")

    client = TestClient(app)
    response = client.get("/applications/oauth/weft-id_client_detail123")

    assert response.status_code == 200
    mock_tmpl.assert_called_once()
    template_name = mock_tmpl.call_args[0][1]
    assert template_name == "integrations_app_detail.html"
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["client"] == mock_client


def test_app_detail_not_found_redirects(test_admin_user, override_auth, mocker):
    """Test app detail page redirects when client not found."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = None

    client = TestClient(app)
    response = client.get("/applications/oauth/nonexistent", follow_redirects=False)

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_app_detail_wrong_type_redirects(test_admin_user, override_auth, mocker):
    """Test app detail page redirects when client is B2B type."""
    override_auth(test_admin_user, level="admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_wrong",
        "client_type": "b2b",  # Wrong type
        "name": "B2B Client",
        "description": None,
        "redirect_uris": None,
        "service_user_id": str(uuid4()),
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = mock_client

    client = TestClient(app)
    response = client.get("/applications/oauth/weft-id_b2b_wrong", follow_redirects=False)

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


# =============================================================================
# App Edit Tests
# =============================================================================


def test_app_edit_success(test_admin_user, override_auth, mocker):
    """Test editing an app succeeds."""
    override_auth(test_admin_user, level="admin")

    mock_updated_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_edit123",
        "client_type": "normal",
        "name": "Updated Name",
        "description": "Updated desc",
        "redirect_uris": ["https://new.example.com/callback"],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = mock_updated_client
    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")
    mock_update.return_value = mock_updated_client

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_client_edit123/edit",
        data={
            "name": "Updated Name",
            "description": "Updated desc",
            "redirect_uris": "https://new.example.com/callback",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=updated" in response.headers["location"]
    mock_update.assert_called_once()


def test_app_edit_empty_name_returns_error(test_admin_user, override_auth):
    """Test editing an app with empty name returns error."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_client_edit123/edit",
        data={
            "name": "",
            "description": "",
            "redirect_uris": "https://example.com/callback",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=name_required" in response.headers["location"]


def test_app_edit_empty_uris_returns_error(test_admin_user, override_auth, mocker):
    """Test editing an app with empty redirect URIs returns error."""
    override_auth(test_admin_user, level="admin")
    mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id").return_value = {
        "client_id": "weft-id_client_edit123",
        "client_type": "normal",
        "is_public": False,
    }

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_client_edit123/edit",
        data={
            "name": "Test",
            "description": "",
            "redirect_uris": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=redirect_uris_required" in response.headers["location"]


# =============================================================================
# App Regenerate Secret Tests
# =============================================================================


def test_app_regenerate_secret_success(test_admin_user, override_auth, mocker):
    """Test regenerating app secret succeeds."""
    override_auth(test_admin_user, level="admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_regen123",
        "client_type": "normal",
        "name": "Regen App",
        "description": None,
        "redirect_uris": ["https://example.com/callback"],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_regen = mocker.patch(f"{SERVICES_OAUTH2}.regenerate_client_secret")
    mock_get.return_value = mock_client
    mock_regen.return_value = "new_secret_xyz"

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_client_regen123/regenerate-secret",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=secret_regenerated" in response.headers["location"]


def test_app_regenerate_secret_not_found(test_admin_user, override_auth, mocker):
    """Test regenerating secret for non-existent app redirects with error."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = None

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/nonexistent/regenerate-secret",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


# =============================================================================
# App Deactivate/Reactivate Tests
# =============================================================================


def test_app_deactivate_success(test_admin_user, override_auth, mocker):
    """Test deactivating an app succeeds."""
    override_auth(test_admin_user, level="admin")

    mock_deactivated = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_deact123",
        "client_type": "normal",
        "name": "Deact App",
        "description": None,
        "redirect_uris": ["https://example.com/callback"],
        "service_user_id": None,
        "is_active": False,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = mock_deactivated
    mock_deact = mocker.patch(f"{SERVICES_OAUTH2}.deactivate_client")
    mock_deact.return_value = mock_deactivated

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_client_deact123/deactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=deactivated" in response.headers["location"]


def test_app_reactivate_success(test_admin_user, override_auth, mocker):
    """Test reactivating an app succeeds."""
    override_auth(test_admin_user, level="admin")

    mock_reactivated = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_react123",
        "client_type": "normal",
        "name": "React App",
        "description": None,
        "redirect_uris": ["https://example.com/callback"],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = mock_reactivated
    mock_react = mocker.patch(f"{SERVICES_OAUTH2}.reactivate_client")
    mock_react.return_value = mock_reactivated

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_client_react123/reactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=reactivated" in response.headers["location"]


def test_app_deactivate_b2b_client_redirects_not_found(test_admin_user, override_auth, mocker):
    """Test an admin cannot deactivate a B2B client via the Apps route."""
    override_auth(test_admin_user, level="admin")

    mock_b2b = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_deact123",
        "client_type": "b2b",
        "name": "B2B Service Account",
        "description": None,
        "redirect_uris": None,
        "service_user_id": str(uuid4()),
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = mock_b2b
    mock_deact = mocker.patch(f"{SERVICES_OAUTH2}.deactivate_client")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_b2b_deact123/deactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]
    mock_deact.assert_not_called()


def test_app_reactivate_b2b_client_redirects_not_found(test_admin_user, override_auth, mocker):
    """Test an admin cannot reactivate a B2B client via the Apps route."""
    override_auth(test_admin_user, level="admin")

    mock_b2b = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_react123",
        "client_type": "b2b",
        "name": "B2B Service Account",
        "description": None,
        "redirect_uris": None,
        "service_user_id": str(uuid4()),
        "is_active": False,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = mock_b2b
    mock_react = mocker.patch(f"{SERVICES_OAUTH2}.reactivate_client")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_b2b_react123/reactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]
    mock_react.assert_not_called()


def test_app_edit_b2b_client_redirects_not_found(test_admin_user, override_auth, mocker):
    """Test an admin cannot edit a B2B client via the Apps route."""
    override_auth(test_admin_user, level="admin")

    mock_b2b = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_edit123",
        "client_type": "b2b",
        "name": "B2B Service Account",
        "description": None,
        "redirect_uris": None,
        "service_user_id": str(uuid4()),
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = mock_b2b
    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_b2b_edit123/edit",
        data={
            "name": "Updated Name",
            "description": "",
            "redirect_uris": "https://example.com/callback",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]
    mock_update.assert_not_called()


# =============================================================================
# B2B Detail Tests
# =============================================================================


def test_b2b_detail_renders(test_super_admin_user, override_auth, mocker):
    """Test B2B detail page renders successfully."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_detail123",
        "client_type": "b2b",
        "name": "Detail Test B2B",
        "description": "A B2B client",
        "redirect_uris": None,
        "service_user_id": str(uuid4()),
        "service_role": "admin",
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_ctx = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTERS_INTEGRATIONS}.templates.TemplateResponse")

    mock_get.return_value = mock_client
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>b2b detail</html>")

    client = TestClient(app)
    response = client.get("/applications/service-accounts/weft-id_b2b_detail123")

    assert response.status_code == 200
    mock_tmpl.assert_called_once()
    template_name = mock_tmpl.call_args[0][1]
    assert template_name == "integrations_b2b_detail.html"


def test_b2b_detail_not_found_redirects(test_super_admin_user, override_auth, mocker):
    """Test B2B detail page redirects when client not found."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = None

    client = TestClient(app)
    response = client.get("/applications/service-accounts/nonexistent", follow_redirects=False)

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


# =============================================================================
# B2B Edit Tests
# =============================================================================


def test_b2b_edit_success(test_super_admin_user, override_auth, mocker):
    """Test editing a B2B client succeeds."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_updated = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_edit123",
        "client_type": "b2b",
        "name": "Updated B2B Name",
        "description": "Updated desc",
        "redirect_uris": None,
        "service_user_id": str(uuid4()),
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")
    mock_update.return_value = mock_updated

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_edit123/edit",
        data={
            "name": "Updated B2B Name",
            "description": "Updated desc",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=updated" in response.headers["location"]


# =============================================================================
# B2B Role Change Tests
# =============================================================================


def test_b2b_role_change_success(test_super_admin_user, override_auth, mocker):
    """Test changing B2B client role succeeds."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_updated = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_role123",
        "client_type": "b2b",
        "name": "Role Test B2B",
        "description": None,
        "redirect_uris": None,
        "service_user_id": str(uuid4()),
        "service_role": "super_admin",
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_b2b_client_role")
    mock_update.return_value = mock_updated

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_role123/role",
        data={
            "role": "super_admin",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=role_changed" in response.headers["location"]


def test_b2b_role_change_invalid_role(test_super_admin_user, override_auth):
    """Test changing to invalid role returns error."""
    override_auth(test_super_admin_user, level="super_admin")

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_role123/role",
        data={
            "role": "invalid_role",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=invalid_role" in response.headers["location"]


# =============================================================================
# B2B Regenerate/Deactivate/Reactivate Tests
# =============================================================================


def test_b2b_regenerate_secret_success(test_super_admin_user, override_auth, mocker):
    """Test regenerating B2B client secret succeeds."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_regen123",
        "client_type": "b2b",
        "name": "Regen B2B",
        "description": None,
        "redirect_uris": None,
        "service_user_id": str(uuid4()),
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_regen = mocker.patch(f"{SERVICES_OAUTH2}.regenerate_client_secret")
    mock_get.return_value = mock_client
    mock_regen.return_value = "new_b2b_secret"

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_regen123/regenerate-secret",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=secret_regenerated" in response.headers["location"]


def test_b2b_deactivate_success(test_super_admin_user, override_auth, mocker):
    """Test deactivating a B2B client succeeds."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_deactivated = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_deact123",
        "client_type": "b2b",
        "name": "Deact B2B",
        "is_active": False,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_deact = mocker.patch(f"{SERVICES_OAUTH2}.deactivate_client")
    mock_deact.return_value = mock_deactivated

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_deact123/deactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=deactivated" in response.headers["location"]


def test_b2b_reactivate_success(test_super_admin_user, override_auth, mocker):
    """Test reactivating a B2B client succeeds."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_reactivated = {
        "id": str(uuid4()),
        "client_id": "weft-id_b2b_react123",
        "client_type": "b2b",
        "name": "React B2B",
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_react = mocker.patch(f"{SERVICES_OAUTH2}.reactivate_client")
    mock_react.return_value = mock_reactivated

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_react123/reactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=reactivated" in response.headers["location"]


# =============================================================================
# Additional Error Handling Tests
# =============================================================================


def test_app_edit_not_found(test_admin_user, override_auth, mocker):
    """Test editing a non-existent app redirects with not_found error."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = None
    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_client_missing/edit",
        data={
            "name": "Updated Name",
            "description": "",
            "redirect_uris": "https://example.com/callback",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]
    mock_update.assert_not_called()


def test_app_edit_service_error(test_admin_user, override_auth, mocker):
    """Test editing an app when service raises error."""
    override_auth(test_admin_user, level="admin")

    from services.exceptions import ServiceError

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = {"client_type": "normal"}
    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")
    mock_update.side_effect = ServiceError("update failed")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_client_edit123/edit",
        data={
            "name": "Updated Name",
            "description": "",
            "redirect_uris": "https://example.com/callback",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=update_failed" in response.headers["location"]


def test_app_deactivate_not_found(test_admin_user, override_auth, mocker):
    """Test deactivating non-existent app redirects with not_found error."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = None
    mock_deact = mocker.patch(f"{SERVICES_OAUTH2}.deactivate_client")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/nonexistent/deactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]
    mock_deact.assert_not_called()


def test_app_reactivate_not_found(test_admin_user, override_auth, mocker):
    """Test reactivating non-existent app redirects with not_found error."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = None
    mock_react = mocker.patch(f"{SERVICES_OAUTH2}.reactivate_client")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/nonexistent/reactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]
    mock_react.assert_not_called()


def test_b2b_edit_empty_name(test_super_admin_user, override_auth):
    """Test editing B2B client with empty name returns error."""
    override_auth(test_super_admin_user, level="super_admin")

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_edit123/edit",
        data={
            "name": "   ",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=name_required" in response.headers["location"]


def test_b2b_edit_not_found(test_super_admin_user, override_auth, mocker):
    """Test editing B2B client that returns None redirects with not_found error."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")
    mock_update.return_value = None

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_missing/edit",
        data={
            "name": "Updated Name",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_edit_service_error(test_super_admin_user, override_auth, mocker):
    """Test editing B2B client when service raises error."""
    override_auth(test_super_admin_user, level="super_admin")

    from services.exceptions import ServiceError

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")
    mock_update.side_effect = ServiceError("update failed")

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_edit123/edit",
        data={
            "name": "Updated Name",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=update_failed" in response.headers["location"]


def test_b2b_role_change_not_found(test_super_admin_user, override_auth, mocker):
    """Test role change for B2B client that returns None."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_b2b_client_role")
    mock_update.return_value = None

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_role123/role",
        data={
            "role": "admin",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_role_change_service_error(test_super_admin_user, override_auth, mocker):
    """Test role change when service raises error."""
    override_auth(test_super_admin_user, level="super_admin")

    from services.exceptions import ServiceError

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_b2b_client_role")
    mock_update.side_effect = ServiceError("role change failed")

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_b2b_role123/role",
        data={
            "role": "admin",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=role_change_failed" in response.headers["location"]


def test_b2b_regenerate_secret_wrong_type(test_super_admin_user, override_auth, mocker):
    """Test regenerating secret for B2B client that's actually normal type."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_normal",
        "client_type": "normal",  # Wrong type for B2B route
        "name": "Normal Client",
        "description": None,
        "redirect_uris": ["https://example.com/callback"],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = mock_client

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/weft-id_client_normal/regenerate-secret",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_regenerate_secret_not_found(test_super_admin_user, override_auth, mocker):
    """Test regenerating secret for non-existent B2B client."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = None

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/nonexistent/regenerate-secret",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_deactivate_not_found(test_super_admin_user, override_auth, mocker):
    """Test deactivating non-existent B2B client."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_deact = mocker.patch(f"{SERVICES_OAUTH2}.deactivate_client")
    mock_deact.return_value = None

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/nonexistent/deactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_reactivate_not_found(test_super_admin_user, override_auth, mocker):
    """Test reactivating non-existent B2B client."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_react = mocker.patch(f"{SERVICES_OAUTH2}.reactivate_client")
    mock_react.return_value = None

    client = TestClient(app)
    response = client.post(
        "/applications/service-accounts/nonexistent/reactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_detail_wrong_type(test_super_admin_user, override_auth, mocker):
    """Test B2B detail page redirects when client is normal type."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_normal",
        "client_type": "normal",  # Wrong type for B2B route
        "name": "Normal Client",
        "description": None,
        "redirect_uris": ["https://example.com/callback"],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = mock_client

    client = TestClient(app)
    response = client.get(
        "/applications/service-accounts/weft-id_client_normal", follow_redirects=False
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


# =============================================================================
# App Consent Revocation
# =============================================================================


def test_app_revoke_consent_success(test_admin_user, override_auth, mocker):
    """Revoking a user's consent redirects back to the app with a success flag."""
    override_auth(test_admin_user, level="admin")
    mock_revoke = mocker.patch(f"{ROUTERS_INTEGRATIONS}.consent_service.revoke_client_grant")

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_client_abc/consents/grant-1/revoke", follow_redirects=False
    )

    assert response.status_code == 303
    assert (
        response.headers["location"]
        == "/applications/oauth/weft-id_client_abc?success=consent_revoked"
    )
    args = mock_revoke.call_args[0]
    assert args[0]["id"] == str(test_admin_user["id"])
    assert args[1] == "weft-id_client_abc"
    assert args[2] == "grant-1"


def test_app_revoke_consent_service_error(test_admin_user, override_auth, mocker):
    """A service error (unknown grant) redirects back with an error flag."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")
    mocker.patch(
        f"{ROUTERS_INTEGRATIONS}.consent_service.revoke_client_grant",
        side_effect=NotFoundError(message="nope", code="consent_grant_not_found"),
    )

    client = TestClient(app)
    response = client.post(
        "/applications/oauth/weft-id_client_abc/consents/grant-1/revoke", follow_redirects=False
    )

    assert response.status_code == 303
    assert (
        response.headers["location"]
        == "/applications/oauth/weft-id_client_abc?error=consent_revoke_failed"
    )


def test_app_revoke_consent_requires_csrf(test_admin_user, override_auth, mocker):
    override_auth(test_admin_user, level="admin")
    mock_revoke = mocker.patch(f"{ROUTERS_INTEGRATIONS}.consent_service.revoke_client_grant")

    client = TestClient(app)
    with client.without_csrf():
        response = client.post(
            "/applications/oauth/weft-id_client_abc/consents/grant-1/revoke",
            follow_redirects=False,
        )
    assert response.status_code == 403
    mock_revoke.assert_not_called()


def test_app_detail_passes_consent_grants(test_admin_user, override_auth, mocker):
    """The detail page hands the client's consent grants to the template."""
    override_auth(test_admin_user, level="admin")
    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_consents",
        "client_type": "normal",
        "name": "Consent App",
        "description": None,
        "redirect_uris": ["https://example.com/callback"],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }
    mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id", return_value=mock_client)
    mock_ctx = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTERS_INTEGRATIONS}.templates.TemplateResponse")
    mock_oidc = mocker.patch(f"{ROUTERS_INTEGRATIONS}.oidc_client_service")
    mock_oidc.get_client_discovery_info.return_value = MagicMock()
    mock_oidc.list_client_group_assignments.return_value = MagicMock(items=[])
    mock_oidc.list_available_groups_for_client.return_value = []
    grants = [MagicMock(id="g1")]
    mock_list = mocker.patch(
        f"{ROUTERS_INTEGRATIONS}.consent_service.list_client_grants", return_value=grants
    )
    mocker.patch(f"{ROUTERS_INTEGRATIONS}.backchannel_service.list_backchannel_logout_deliveries")
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>detail</html>")

    client = TestClient(app)
    response = client.get("/applications/oauth/weft-id_client_consents")

    assert response.status_code == 200
    assert mock_ctx.call_args[1]["consent_grants"] == grants
    assert mock_list.call_args[0][1] == "weft-id_client_consents"


# =============================================================================
# Post-logout redirect URIs (RP-initiated logout), real database
# =============================================================================


def _edit_form(client_row: dict, **extra: str) -> dict:
    data = {
        "name": client_row["name"],
        "description": "",
        "redirect_uris": "\n".join(client_row["redirect_uris"]),
        "csrf_token": "test-token",
    }
    data.update(extra)
    return data


def test_app_edit_saves_post_logout_redirect_uris(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    override_auth(test_admin_user, level="admin")
    response = TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(
            normal_oauth2_client,
            post_logout_redirect_uris="https://rp.example/bye\n\n  https://rp.example/bye2  \n",
        ),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=updated" in response.headers["location"]
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["post_logout_redirect_uris"] == [
        "https://rp.example/bye",
        "https://rp.example/bye2",
    ]


def test_app_edit_blank_post_logout_field_clears_them(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    database.oauth2.update_client(
        test_tenant["id"],
        normal_oauth2_client["client_id"],
        post_logout_redirect_uris=["https://rp.example/bye"],
    )
    override_auth(test_admin_user, level="admin")
    TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(normal_oauth2_client, post_logout_redirect_uris=""),
        follow_redirects=False,
    )
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["post_logout_redirect_uris"] == []


def test_app_edit_invalid_post_logout_uri_shows_error(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    override_auth(test_admin_user, level="admin")
    response = TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(normal_oauth2_client, post_logout_redirect_uris="not-a-uri"),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=invalid_post_logout_redirect_uri" in response.headers["location"]
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["post_logout_redirect_uris"] == []


def test_app_detail_renders_post_logout_uris_and_end_session_url(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    database.oauth2.update_client(
        test_tenant["id"],
        normal_oauth2_client["client_id"],
        post_logout_redirect_uris=["https://rp.example/bye"],
    )
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], normal_oauth2_client["client_id"], oidc_enabled=True
    )
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}")
    assert response.status_code == 200
    assert 'name="post_logout_redirect_uris"' in response.text
    assert "https://rp.example/bye</textarea>" in response.text
    assert "/oauth2/logout</code>" in response.text


# =============================================================================
# Front-channel logout (real database)
# =============================================================================


def test_app_edit_saves_frontchannel_logout(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    override_auth(test_admin_user, level="admin")
    response = TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(
            normal_oauth2_client,
            frontchannel_logout_uri="  http://localhost:3000/fc  ",
            frontchannel_logout_session_required="true",
        ),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=updated" in response.headers["location"]
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["frontchannel_logout_uri"] == "http://localhost:3000/fc"
    assert saved["frontchannel_logout_session_required"] is True


def test_app_edit_unchecked_box_and_blank_uri_clear_frontchannel_logout(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    database.oauth2.update_client(
        test_tenant["id"],
        normal_oauth2_client["client_id"],
        frontchannel_logout_uri="http://localhost:3000/fc",
        frontchannel_logout_session_required=True,
    )
    override_auth(test_admin_user, level="admin")
    TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(normal_oauth2_client),
        follow_redirects=False,
    )
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["frontchannel_logout_uri"] is None
    assert saved["frontchannel_logout_session_required"] is False


def test_app_edit_cross_origin_frontchannel_uri_shows_error(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    override_auth(test_admin_user, level="admin")
    response = TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(normal_oauth2_client, frontchannel_logout_uri="https://evil.example/fc"),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=invalid_frontchannel_logout_uri" in response.headers["location"]
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["frontchannel_logout_uri"] is None


def test_app_detail_renders_frontchannel_logout_settings(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    database.oauth2.update_client(
        test_tenant["id"],
        normal_oauth2_client["client_id"],
        frontchannel_logout_uri="http://localhost:3000/fc",
        frontchannel_logout_session_required=True,
    )
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}")
    assert response.status_code == 200
    assert 'value="http://localhost:3000/fc"' in response.text
    assert re.search(r'id="frontchannel_logout_session_required"[^>]*\s+checked', response.text), (
        "session-required box should be checked"
    )


def test_app_detail_error_banner_for_frontchannel_uri(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(
        f"/applications/oauth/{normal_oauth2_client['client_id']}"
        "?error=invalid_frontchannel_logout_uri"
    )
    assert "same scheme, host and port as one of the redirect URIs" in response.text


# =============================================================================
# Back-channel logout (real database)
# =============================================================================


def test_app_edit_saves_backchannel_logout(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    override_auth(test_admin_user, level="admin")
    response = TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(
            normal_oauth2_client,
            backchannel_logout_uri="  https://api.rp.example/bc  ",
            backchannel_logout_session_required="true",
        ),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=updated" in response.headers["location"]
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["backchannel_logout_uri"] == "https://api.rp.example/bc"
    assert saved["backchannel_logout_session_required"] is True


def test_app_edit_unchecked_box_and_blank_uri_clear_backchannel_logout(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    database.oauth2.update_client(
        test_tenant["id"],
        normal_oauth2_client["client_id"],
        backchannel_logout_uri="https://rp.example/bc",
        backchannel_logout_session_required=True,
    )
    override_auth(test_admin_user, level="admin")
    TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(normal_oauth2_client),
        follow_redirects=False,
    )
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["backchannel_logout_uri"] is None
    assert saved["backchannel_logout_session_required"] is False


def test_app_edit_bad_backchannel_uri_shows_error(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    override_auth(test_admin_user, level="admin")
    response = TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(normal_oauth2_client, backchannel_logout_uri="https://rp.example/bc#x"),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=invalid_backchannel_logout_uri" in response.headers["location"]
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["backchannel_logout_uri"] is None


def test_app_detail_renders_backchannel_logout_settings(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    database.oauth2.update_client(
        test_tenant["id"],
        normal_oauth2_client["client_id"],
        backchannel_logout_uri="https://api.rp.example/bc",
        backchannel_logout_session_required=True,
    )
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}")
    assert response.status_code == 200
    assert 'value="https://api.rp.example/bc"' in response.text
    assert re.search(r'id="backchannel_logout_session_required"[^>]*\s+checked', response.text), (
        "sid box should be checked"
    )


def test_app_detail_error_banner_for_backchannel_uri(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(
        f"/applications/oauth/{normal_oauth2_client['client_id']}"
        "?error=invalid_backchannel_logout_uri"
    )
    assert "The back-channel logout URI must be an absolute http or https URI" in response.text


# =============================================================================
# Back-channel logout deliveries on the App detail page (real database)
# =============================================================================


def _bc_app_with_deliveries(test_tenant, oauth_client, user, errors):
    """Back-channel on, one failed delivery per entry of ``errors``."""
    import database

    tid = str(test_tenant["id"])
    database.oauth2.update_client(
        tid, oauth_client["client_id"], backchannel_logout_uri="https://rp.example/bc"
    )
    database.oauth2.update_client_oidc_settings(tid, oauth_client["client_id"], oidc_enabled=True)
    for i, (error, http_status) in enumerate(errors):
        sid = f"s-{i}"
        database.oauth2.upsert_session_client(
            tid, tid, sid=sid, client_id=str(oauth_client["id"]), user_id=str(user["id"])
        )
        database.oauth2.consume_session_clients(tid, tid, sid, issuer="https://t.example")
        database.execute(
            tid,
            """
            update oidc_backchannel_logout_deliveries
            set status = 'failed', attempts = 1, last_error = :e, last_http_status = :h
            where sid = :sid
            """,
            {"e": error, "h": http_status, "sid": sid},
        )


def test_app_detail_shows_backchannel_deliveries(
    test_tenant, test_admin_user, test_user, override_auth, normal_oauth2_client
):
    _bc_app_with_deliveries(
        test_tenant,
        normal_oauth2_client,
        test_user,
        [
            ("blocked_destination", None),
            ("http_400", 400),
            ("network_error: ConnectTimeout: timed out", None),
            ("client_no_longer_eligible", None),
        ],
    )
    override_auth(test_admin_user, level="admin")

    response = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}")

    assert response.status_code == 200
    text = response.text
    assert "Back-channel Logout Deliveries" in text
    assert "0 delivered, 0 pending, 4 failed." in text
    assert "Address not allowed or not found" in text
    assert "The app responded with HTTP 400" in text
    assert "Could not connect" in text
    assert "App no longer uses back-channel logout" in text
    assert f'href="/users/{test_user["id"]}"' in text


def test_app_detail_hides_backchannel_section_when_unused(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}")
    assert response.status_code == 200
    assert "Back-channel Logout Deliveries" not in response.text


def test_app_detail_backchannel_section_empty_state(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    database.oauth2.update_client(
        test_tenant["id"],
        normal_oauth2_client["client_id"],
        backchannel_logout_uri="https://rp.example/bc",
    )
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}")
    assert "No logout tokens have been sent to this app yet." in response.text


def test_app_detail_backchannel_shows_most_recent_only(
    test_tenant, test_admin_user, test_user, override_auth, normal_oauth2_client, mocker
):
    mocker.patch(f"{ROUTERS_INTEGRATIONS}.BACKCHANNEL_DELIVERIES_SHOWN", 2)
    _bc_app_with_deliveries(test_tenant, normal_oauth2_client, test_user, [("http_500", 500)] * 3)
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}")
    assert "Showing the 2 most recent of 3." in response.text


# =============================================================================
# Login initiation URI (real database)
# =============================================================================


def test_app_edit_saves_and_clears_initiate_login_uri(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    override_auth(test_admin_user, level="admin")
    url = f"/applications/oauth/{normal_oauth2_client['client_id']}/edit"
    response = TestClient(app).post(
        url,
        data=_edit_form(normal_oauth2_client, initiate_login_uri="  https://rp.example/login  "),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=updated" in response.headers["location"]
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["initiate_login_uri"] == "https://rp.example/login"

    TestClient(app).post(url, data=_edit_form(normal_oauth2_client), follow_redirects=False)
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["initiate_login_uri"] is None


def test_app_edit_http_initiate_login_uri_shows_error(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    override_auth(test_admin_user, level="admin")
    response = TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(normal_oauth2_client, initiate_login_uri="http://rp.example/login"),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=invalid_initiate_login_uri" in response.headers["location"]
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["initiate_login_uri"] is None


def test_app_edit_initiate_login_uri_member_blocked(
    test_tenant, test_user, override_auth, normal_oauth2_client
):
    import database

    # The edit route reads get_current_user; a member gets through auth and is
    # stopped by the page check.
    override_auth(test_user, level="admin")
    response = TestClient(app).post(
        f"/applications/oauth/{normal_oauth2_client['client_id']}/edit",
        data=_edit_form(normal_oauth2_client, initiate_login_uri="https://rp.example/login"),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["initiate_login_uri"] is None


def test_app_detail_renders_initiate_login_uri_and_error(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    database.oauth2.update_client(
        test_tenant["id"],
        normal_oauth2_client["client_id"],
        initiate_login_uri="https://rp.example/login",
    )
    override_auth(test_admin_user, level="admin")
    page = f"/applications/oauth/{normal_oauth2_client['client_id']}"
    response = TestClient(app).get(page)
    assert response.status_code == 200
    assert re.search(
        r'id="initiate_login_uri" name="initiate_login_uri"[^>]*value="https://rp.example/login"',
        response.text,
    )

    response = TestClient(app).get(f"{page}?error=invalid_initiate_login_uri")
    assert "The login initiation URI must be an absolute https URI" in response.text


# =============================================================================
# Device authorization grant switch (real database)
# =============================================================================


def test_app_edit_turns_device_grant_on_and_off(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    override_auth(test_admin_user, level="admin")
    url = f"/applications/oauth/{normal_oauth2_client['client_id']}/edit"
    response = TestClient(app).post(
        url,
        data=_edit_form(normal_oauth2_client, device_grant_enabled="true"),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=updated" in response.headers["location"]
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["device_grant_enabled"] is True

    # An unchecked box is absent from the form: off.
    TestClient(app).post(url, data=_edit_form(normal_oauth2_client), follow_redirects=False)
    saved = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert saved["device_grant_enabled"] is False


def test_app_detail_renders_device_grant_checkbox_and_endpoint(
    test_tenant, test_admin_user, override_auth, normal_oauth2_client
):
    import database

    database.oauth2.update_client(
        test_tenant["id"], normal_oauth2_client["client_id"], device_grant_enabled=True
    )
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], normal_oauth2_client["client_id"], oidc_enabled=True
    )
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}")
    assert response.status_code == 200
    assert re.search(
        r'id="device_grant_enabled" name="device_grant_enabled" value="true"\s+checked',
        response.text,
    )
    assert re.search(r'id="oidc-device"[^>]*>[^<]*/oauth2/device_authorization<', response.text)


# =============================================================================
# Public clients (real database)
# =============================================================================


@pytest.fixture
def public_app(test_tenant, test_admin_user):
    import database

    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="TV App",
        redirect_uris=[],
        created_by=str(test_admin_user["id"]),
        device_grant_enabled=True,
        is_public=True,
    )


def test_apps_create_public_client(test_tenant, test_admin_user, override_auth):
    import database

    override_auth(test_admin_user, level="admin")
    response = TestClient(app).post(
        "/applications/oauth/create",
        data={
            "name": "TV App",
            "redirect_uris": "https://ignored.example/cb",
            "description": "",
            "is_public": "true",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/applications/oauth/weft-id_client_")
    assert location.endswith("?success=created")

    client_id = location.split("/")[-1].split("?")[0]
    saved = database.oauth2.get_client_by_client_id(test_tenant["id"], client_id)
    assert saved["is_public"] is True
    assert saved["device_grant_enabled"] is True
    assert saved["redirect_uris"] == []


def test_apps_create_public_client_does_not_need_redirect_uris(
    test_admin_user, override_auth, mocker
):
    override_auth(test_admin_user, level="admin")
    mock_create = mocker.patch(f"{SERVICES_OAUTH2}.create_normal_client")
    mock_create.return_value = {"client_id": "weft-id_client_pub", "name": "TV"}

    response = TestClient(app).post(
        "/applications/oauth/create",
        data={"name": "TV", "redirect_uris": "", "is_public": "true", "csrf_token": "t"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error" not in response.headers["location"]
    assert mock_create.call_args.kwargs["is_public"] is True
    assert mock_create.call_args.kwargs["redirect_uris"] == []


def test_app_detail_public_client(test_admin_user, override_auth, public_app):
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(f"/applications/oauth/{public_app['client_id']}?success=created")
    assert response.status_code == 200
    text = response.text
    assert "Public client (device sign-in only)" in text
    assert "A public client has no secret" in text
    # No browser-redirect fields, no secret to regenerate, no introspection.
    assert 'id="redirect_uris"' not in text
    assert 'id="frontchannel_logout_uri"' not in text
    assert 'id="initiate_login_uri"' not in text
    assert 'id="device_grant_enabled"' not in text
    assert 'id="show-regenerate-btn"' not in text
    assert "/introspection" not in text
    # Back-channel logout stays.
    assert 'id="backchannel_logout_uri"' in text


def test_app_detail_confidential_client_unchanged(
    test_admin_user, override_auth, normal_oauth2_client
):
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}")
    text = response.text
    assert 'id="redirect_uris"' in text
    assert 'id="show-regenerate-btn"' in text
    assert "Public client (device sign-in only)" not in text


def test_app_edit_public_client(test_tenant, test_admin_user, override_auth, public_app):
    import database

    override_auth(test_admin_user, level="admin")
    response = TestClient(app).post(
        f"/applications/oauth/{public_app['client_id']}/edit",
        data={
            "name": "Living Room TV",
            "description": "Lounge",
            "backchannel_logout_uri": "https://rp.example/bc",
            # Fields the public form does not have are ignored, not saved.
            "redirect_uris": "https://evil.example/cb",
            "initiate_login_uri": "https://evil.example/login",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "success=updated" in response.headers["location"]
    saved = database.oauth2.get_client_by_client_id(test_tenant["id"], public_app["client_id"])
    assert saved["name"] == "Living Room TV"
    assert saved["backchannel_logout_uri"] == "https://rp.example/bc"
    assert saved["redirect_uris"] == []
    assert saved["initiate_login_uri"] is None
    # The form has no device checkbox; the grant stays on.
    assert saved["device_grant_enabled"] is True


def test_app_regenerate_secret_public_client(
    test_tenant, test_admin_user, override_auth, public_app
):
    import database

    override_auth(test_admin_user, level="admin")
    before = database.oauth2.get_client_by_client_id(test_tenant["id"], public_app["client_id"])
    response = TestClient(app).post(
        f"/applications/oauth/{public_app['client_id']}/regenerate-secret",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=public_client_no_secret" in response.headers["location"]
    after = database.oauth2.get_client_by_client_id(test_tenant["id"], public_app["client_id"])
    assert after["client_secret_hash"] == before["client_secret_hash"]


def test_app_set_introspection_public_client(test_admin_user, override_auth, public_app):
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).post(
        f"/applications/oauth/{public_app['client_id']}/introspection",
        data={"enabled": "true", "csrf_token": "test-token"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=introspection_update_failed" in response.headers["location"]


def test_apps_list_marks_public_clients(test_admin_user, override_auth, public_app):
    override_auth(test_admin_user, level="admin")
    response = TestClient(app).get("/applications/oauth")
    assert response.status_code == 200
    assert 'title="Public client: no secret, device sign-in only">Public</span>' in response.text
    assert 'id="is_public" name="is_public" value="true"' in response.text
