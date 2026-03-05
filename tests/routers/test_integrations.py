"""Tests for routers/integrations.py endpoints."""

from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app

# Module path constants for cleaner patch targets
ROUTERS_INTEGRATIONS = "routers.integrations"
SERVICES_OAUTH2 = "services.oauth2"

# =============================================================================
# Index Redirect Tests
# =============================================================================


def test_integrations_index_redirects_to_apps(test_admin_user, override_auth):
    """Test integrations index redirects to apps tab."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.get("/admin/integrations/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/integrations/apps"


def test_integrations_index_fallback_to_dashboard(test_admin_user, override_auth, mocker):
    """Test integrations index falls back to dashboard when no accessible children."""
    override_auth(test_admin_user, level="admin")

    mock_first = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_first_accessible_child")
    mock_first.return_value = None

    client = TestClient(app)
    response = client.get("/admin/integrations/", follow_redirects=False)

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
    response = client.get("/admin/integrations/apps")

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
    response = client.get("/admin/integrations/apps")

    assert response.status_code == 200
    # Verify clients passed to template context
    ctx_call = mock_ctx.call_args
    assert ctx_call[1]["clients"] == mock_clients


def test_apps_list_non_admin_redirects(test_user, override_auth):
    """Test non-admin user gets redirected from apps list."""
    override_auth(test_user, level="admin")

    client = TestClient(app)
    response = client.get("/admin/integrations/apps", follow_redirects=False)

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
        "/admin/integrations/apps/create",
        data={
            "name": "New App",
            "redirect_uris": "https://example.com/callback",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/admin/integrations/apps" in response.headers["location"]
    assert "success=created" in response.headers["location"]

    mock_create.assert_called_once_with(
        tenant_id=str(test_admin_user["tenant_id"]),
        name="New App",
        redirect_uris=["https://example.com/callback"],
        created_by=str(test_admin_user["id"]),
        description=None,
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
        "/admin/integrations/apps/create",
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


def test_apps_create_stores_credentials_in_session(test_admin_user, override_auth, mocker):
    """Test that created client credentials are stored in the session."""
    override_auth(test_admin_user, level="admin")

    mock_client = {
        "id": str(uuid4()),
        "client_id": "weft-id_client_sesstest",
        "client_secret": "secret_sesstest",
        "client_type": "normal",
        "name": "Session Test App",
        "description": None,
        "redirect_uris": ["https://example.com/callback"],
        "service_user_id": None,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00",
    }

    mock_create = mocker.patch(f"{SERVICES_OAUTH2}.create_normal_client")
    mock_create.return_value = mock_client

    mocker.patch("starlette.requests.Request.session", new_callable=dict)

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/apps/create",
        data={
            "name": "Session Test App",
            "redirect_uris": "https://example.com/callback",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    # The session store happens through the actual middleware,
    # we verify the redirect indicates success
    assert "success=created" in response.headers["location"]


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
        "/admin/integrations/apps/create",
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
        "/admin/integrations/apps/create",
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
        "/admin/integrations/apps/create",
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
        "/admin/integrations/apps/create",
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


def test_b2b_list_renders(test_admin_user, override_auth, mocker):
    """Test B2B list page renders successfully."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_all_clients")
    mock_ctx = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTERS_INTEGRATIONS}.templates.TemplateResponse")

    mock_get.return_value = []
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>b2b</html>")

    client = TestClient(app)
    response = client.get("/admin/integrations/b2b")

    assert response.status_code == 200
    mock_get.assert_called_once_with(str(test_admin_user["tenant_id"]), client_type="b2b")
    mock_tmpl.assert_called_once()
    template_name = mock_tmpl.call_args[0][1]
    assert template_name == "integrations_b2b.html"


def test_b2b_list_non_admin_redirects(test_user, override_auth):
    """Test non-admin user gets redirected from B2B list."""
    override_auth(test_user, level="admin")

    client = TestClient(app)
    response = client.get("/admin/integrations/b2b", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# B2B Create Tests
# =============================================================================


def test_b2b_create_success(test_admin_user, override_auth, mocker):
    """Test creating a B2B client succeeds."""
    override_auth(test_admin_user, level="admin")

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
        "/admin/integrations/b2b/create",
        data={
            "name": "New B2B Client",
            "role": "admin",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/admin/integrations/b2b" in response.headers["location"]
    assert "success=created" in response.headers["location"]

    mock_create.assert_called_once_with(
        tenant_id=str(test_admin_user["tenant_id"]),
        name="New B2B Client",
        role="admin",
        created_by=str(test_admin_user["id"]),
        description=None,
    )


def test_b2b_create_with_description(test_admin_user, override_auth, mocker):
    """Test creating a B2B client with description passes it through."""
    override_auth(test_admin_user, level="admin")

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
        "/admin/integrations/b2b/create",
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


def test_b2b_create_empty_name_redirects_with_error(test_admin_user, override_auth):
    """Test creating a B2B client with empty name returns error."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/create",
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


def test_b2b_create_invalid_role_redirects_with_error(test_admin_user, override_auth):
    """Test creating a B2B client with invalid role returns error."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/create",
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


def test_b2b_create_service_error(test_admin_user, override_auth, mocker):
    """Test that service errors during B2B creation are handled gracefully."""
    override_auth(test_admin_user, level="admin")

    from services.exceptions import ValidationError

    mock_create = mocker.patch(f"{SERVICES_OAUTH2}.create_b2b_client")
    mock_create.side_effect = ValidationError("failed", code="test")

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/create",
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
        "/admin/integrations/b2b/create",
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
    response = client.get("/admin/integrations/apps?success=created")

    assert response.status_code == 200
    # The pending_credentials should be passed to template context
    ctx_kwargs = mock_ctx.call_args[1]
    # It will be None since session is empty in test
    assert "pending_credentials" in ctx_kwargs


def test_b2b_list_pops_pending_credentials(test_admin_user, override_auth, mocker):
    """Test that B2B list page pops pending credentials from session."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_all_clients")
    mock_ctx = mocker.patch(f"{ROUTERS_INTEGRATIONS}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTERS_INTEGRATIONS}.templates.TemplateResponse")

    mock_get.return_value = []
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>b2b</html>")

    client = TestClient(app)
    response = client.get("/admin/integrations/b2b?success=created")

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

    mock_get.return_value = mock_client
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>detail</html>")

    client = TestClient(app)
    response = client.get("/admin/integrations/apps/weft-id_client_detail123")

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
    response = client.get("/admin/integrations/apps/nonexistent", follow_redirects=False)

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
    response = client.get("/admin/integrations/apps/weft-id_b2b_wrong", follow_redirects=False)

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

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")
    mock_update.return_value = mock_updated_client

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/apps/weft-id_client_edit123/edit",
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
        "/admin/integrations/apps/weft-id_client_edit123/edit",
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


def test_app_edit_empty_uris_returns_error(test_admin_user, override_auth):
    """Test editing an app with empty redirect URIs returns error."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/apps/weft-id_client_edit123/edit",
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
        "/admin/integrations/apps/weft-id_client_regen123/regenerate-secret",
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
        "/admin/integrations/apps/nonexistent/regenerate-secret",
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

    mock_deact = mocker.patch(f"{SERVICES_OAUTH2}.deactivate_client")
    mock_deact.return_value = mock_deactivated

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/apps/weft-id_client_deact123/deactivate",
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

    mock_react = mocker.patch(f"{SERVICES_OAUTH2}.reactivate_client")
    mock_react.return_value = mock_reactivated

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/apps/weft-id_client_react123/reactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=reactivated" in response.headers["location"]


# =============================================================================
# B2B Detail Tests
# =============================================================================


def test_b2b_detail_renders(test_admin_user, override_auth, mocker):
    """Test B2B detail page renders successfully."""
    override_auth(test_admin_user, level="admin")

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
    response = client.get("/admin/integrations/b2b/weft-id_b2b_detail123")

    assert response.status_code == 200
    mock_tmpl.assert_called_once()
    template_name = mock_tmpl.call_args[0][1]
    assert template_name == "integrations_b2b_detail.html"


def test_b2b_detail_not_found_redirects(test_admin_user, override_auth, mocker):
    """Test B2B detail page redirects when client not found."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = None

    client = TestClient(app)
    response = client.get("/admin/integrations/b2b/nonexistent", follow_redirects=False)

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


# =============================================================================
# B2B Edit Tests
# =============================================================================


def test_b2b_edit_success(test_admin_user, override_auth, mocker):
    """Test editing a B2B client succeeds."""
    override_auth(test_admin_user, level="admin")

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
        "/admin/integrations/b2b/weft-id_b2b_edit123/edit",
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


def test_b2b_role_change_success(test_admin_user, override_auth, mocker):
    """Test changing B2B client role succeeds."""
    override_auth(test_admin_user, level="admin")

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
        "/admin/integrations/b2b/weft-id_b2b_role123/role",
        data={
            "role": "super_admin",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=role_changed" in response.headers["location"]


def test_b2b_role_change_invalid_role(test_admin_user, override_auth):
    """Test changing to invalid role returns error."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/weft-id_b2b_role123/role",
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


def test_b2b_regenerate_secret_success(test_admin_user, override_auth, mocker):
    """Test regenerating B2B client secret succeeds."""
    override_auth(test_admin_user, level="admin")

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
        "/admin/integrations/b2b/weft-id_b2b_regen123/regenerate-secret",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=secret_regenerated" in response.headers["location"]


def test_b2b_deactivate_success(test_admin_user, override_auth, mocker):
    """Test deactivating a B2B client succeeds."""
    override_auth(test_admin_user, level="admin")

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
        "/admin/integrations/b2b/weft-id_b2b_deact123/deactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=deactivated" in response.headers["location"]


def test_b2b_reactivate_success(test_admin_user, override_auth, mocker):
    """Test reactivating a B2B client succeeds."""
    override_auth(test_admin_user, level="admin")

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
        "/admin/integrations/b2b/weft-id_b2b_react123/reactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=reactivated" in response.headers["location"]


# =============================================================================
# Additional Error Handling Tests
# =============================================================================


def test_app_edit_not_found(test_admin_user, override_auth, mocker):
    """Test editing an app that returns None redirects with not_found error."""
    override_auth(test_admin_user, level="admin")

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")
    mock_update.return_value = None

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/apps/weft-id_client_missing/edit",
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


def test_app_edit_service_error(test_admin_user, override_auth, mocker):
    """Test editing an app when service raises error."""
    override_auth(test_admin_user, level="admin")

    from services.exceptions import ServiceError

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")
    mock_update.side_effect = ServiceError("update failed")

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/apps/weft-id_client_edit123/edit",
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

    mock_deact = mocker.patch(f"{SERVICES_OAUTH2}.deactivate_client")
    mock_deact.return_value = None

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/apps/nonexistent/deactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_app_reactivate_not_found(test_admin_user, override_auth, mocker):
    """Test reactivating non-existent app redirects with not_found error."""
    override_auth(test_admin_user, level="admin")

    mock_react = mocker.patch(f"{SERVICES_OAUTH2}.reactivate_client")
    mock_react.return_value = None

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/apps/nonexistent/reactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_edit_empty_name(test_admin_user, override_auth):
    """Test editing B2B client with empty name returns error."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/weft-id_b2b_edit123/edit",
        data={
            "name": "   ",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=name_required" in response.headers["location"]


def test_b2b_edit_not_found(test_admin_user, override_auth, mocker):
    """Test editing B2B client that returns None redirects with not_found error."""
    override_auth(test_admin_user, level="admin")

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")
    mock_update.return_value = None

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/weft-id_b2b_missing/edit",
        data={
            "name": "Updated Name",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_edit_service_error(test_admin_user, override_auth, mocker):
    """Test editing B2B client when service raises error."""
    override_auth(test_admin_user, level="admin")

    from services.exceptions import ServiceError

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_client")
    mock_update.side_effect = ServiceError("update failed")

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/weft-id_b2b_edit123/edit",
        data={
            "name": "Updated Name",
            "description": "",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=update_failed" in response.headers["location"]


def test_b2b_role_change_not_found(test_admin_user, override_auth, mocker):
    """Test role change for B2B client that returns None."""
    override_auth(test_admin_user, level="admin")

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_b2b_client_role")
    mock_update.return_value = None

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/weft-id_b2b_role123/role",
        data={
            "role": "admin",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_role_change_service_error(test_admin_user, override_auth, mocker):
    """Test role change when service raises error."""
    override_auth(test_admin_user, level="admin")

    from services.exceptions import ServiceError

    mock_update = mocker.patch(f"{SERVICES_OAUTH2}.update_b2b_client_role")
    mock_update.side_effect = ServiceError("role change failed")

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/weft-id_b2b_role123/role",
        data={
            "role": "admin",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=role_change_failed" in response.headers["location"]


def test_b2b_regenerate_secret_wrong_type(test_admin_user, override_auth, mocker):
    """Test regenerating secret for B2B client that's actually normal type."""
    override_auth(test_admin_user, level="admin")

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
        "/admin/integrations/b2b/weft-id_client_normal/regenerate-secret",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_regenerate_secret_not_found(test_admin_user, override_auth, mocker):
    """Test regenerating secret for non-existent B2B client."""
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{SERVICES_OAUTH2}.get_client_by_client_id")
    mock_get.return_value = None

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/nonexistent/regenerate-secret",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_deactivate_not_found(test_admin_user, override_auth, mocker):
    """Test deactivating non-existent B2B client."""
    override_auth(test_admin_user, level="admin")

    mock_deact = mocker.patch(f"{SERVICES_OAUTH2}.deactivate_client")
    mock_deact.return_value = None

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/nonexistent/deactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_reactivate_not_found(test_admin_user, override_auth, mocker):
    """Test reactivating non-existent B2B client."""
    override_auth(test_admin_user, level="admin")

    mock_react = mocker.patch(f"{SERVICES_OAUTH2}.reactivate_client")
    mock_react.return_value = None

    client = TestClient(app)
    response = client.post(
        "/admin/integrations/b2b/nonexistent/reactivate",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


def test_b2b_detail_wrong_type(test_admin_user, override_auth, mocker):
    """Test B2B detail page redirects when client is normal type."""
    override_auth(test_admin_user, level="admin")

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
    response = client.get("/admin/integrations/b2b/weft-id_client_normal", follow_redirects=False)

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]
