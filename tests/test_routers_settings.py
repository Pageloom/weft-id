"""Tests for routers/settings.py endpoints."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from main import app


def test_settings_index_redirects_to_first_child(test_admin_user):
    """Test settings index redirects to first accessible child page."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch('routers.settings.get_first_accessible_child') as mock_first_child:
        mock_first_child.return_value = "/settings/privileged-domains"

        client = TestClient(app)
        response = client.get("/settings/", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/settings/privileged-domains"


def test_settings_index_fallback_to_dashboard(test_admin_user):
    """Test settings index falls back to dashboard when no accessible children."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch('routers.settings.get_first_accessible_child') as mock_first_child:
        mock_first_child.return_value = None  # No accessible children

        client = TestClient(app)
        response = client.get("/settings/", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"


def test_privileged_domains_list(test_admin_user):
    """Test privileged domains page displays list."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch('database.settings.list_privileged_domains') as mock_list:
        with patch('utils.template_context.get_template_context') as mock_context:
            with patch('routers.settings.templates.TemplateResponse') as mock_template:
                mock_list.return_value = [
                    {"id": "1", "domain": "example.com"},
                    {"id": "2", "domain": "test.org"}
                ]
                mock_context.return_value = {"request": Mock(), "domains": mock_list.return_value}
                mock_template.return_value = HTMLResponse(content="<html>domains</html>")

                client = TestClient(app)
                response = client.get("/settings/privileged-domains")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_list.assert_called_once_with(test_admin_user["tenant_id"])


def test_privileged_domains_with_error_param(test_admin_user):
    """Test privileged domains page with error parameter."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch('database.settings.list_privileged_domains') as mock_list:
        with patch('utils.template_context.get_template_context') as mock_context:
            with patch('routers.settings.templates.TemplateResponse') as mock_template:
                mock_list.return_value = []
                mock_context.return_value = {"request": Mock(), "domains": [], "error": "invalid_domain"}
                mock_template.return_value = HTMLResponse(content="<html>error</html>")

                client = TestClient(app)
                response = client.get("/settings/privileged-domains?error=invalid_domain")

                app.dependency_overrides.clear()

                assert response.status_code == 200


def test_add_privileged_domain_success(test_admin_user):
    """Test adding a valid privileged domain."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch('database.settings.privileged_domain_exists') as mock_exists:
        with patch('database.settings.add_privileged_domain') as mock_add:
            mock_exists.return_value = False

            client = TestClient(app)
            response = client.post(
                "/settings/privileged-domains/add",
                data={"domain": "example.com"},
                follow_redirects=False
            )

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert response.headers["location"] == "/settings/privileged-domains"
            mock_add.assert_called_once_with(
                test_admin_user["tenant_id"],
                "example.com",
                test_admin_user["id"],
                test_admin_user["tenant_id"]
            )


def test_add_privileged_domain_with_at_prefix(test_admin_user):
    """Test adding domain with @ prefix (should be stripped)."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch('database.settings.privileged_domain_exists') as mock_exists:
        with patch('database.settings.add_privileged_domain') as mock_add:
            mock_exists.return_value = False

            client = TestClient(app)
            response = client.post(
                "/settings/privileged-domains/add",
                data={"domain": "@example.com"},
                follow_redirects=False
            )

            app.dependency_overrides.clear()

            assert response.status_code == 303
            # @ should be stripped
            mock_add.assert_called_once()
            assert mock_add.call_args[0][1] == "example.com"


def test_add_privileged_domain_empty(test_admin_user):
    """Test adding empty domain."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    client = TestClient(app)
    response = client.post(
        "/settings/privileged-domains/add",
        data={"domain": "   "},  # Empty after strip
        follow_redirects=False
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_domain" in response.headers["location"]


def test_add_privileged_domain_with_spaces(test_admin_user):
    """Test adding domain with spaces."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    client = TestClient(app)
    response = client.post(
        "/settings/privileged-domains/add",
        data={"domain": "exam ple.com"},
        follow_redirects=False
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_domain" in response.headers["location"]


def test_add_privileged_domain_no_dot(test_admin_user):
    """Test adding domain without dot."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    client = TestClient(app)
    response = client.post(
        "/settings/privileged-domains/add",
        data={"domain": "localhost"},
        follow_redirects=False
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_domain" in response.headers["location"]


def test_add_privileged_domain_too_long(test_admin_user):
    """Test adding domain that's too long."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    client = TestClient(app)
    response = client.post(
        "/settings/privileged-domains/add",
        data={"domain": "a" * 250 + ".com"},  # > 253 chars
        follow_redirects=False
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_domain" in response.headers["location"]


def test_add_privileged_domain_too_short(test_admin_user):
    """Test adding domain that's too short."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    client = TestClient(app)
    response = client.post(
        "/settings/privileged-domains/add",
        data={"domain": "a."},  # Only 2 chars
        follow_redirects=False
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_domain" in response.headers["location"]


def test_add_privileged_domain_already_exists(test_admin_user):
    """Test adding duplicate domain."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch('database.settings.privileged_domain_exists') as mock_exists:
        mock_exists.return_value = True

        client = TestClient(app)
        response = client.post(
            "/settings/privileged-domains/add",
            data={"domain": "example.com"},
            follow_redirects=False
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=domain_exists" in response.headers["location"]


def test_delete_privileged_domain(test_admin_user):
    """Test deleting a privileged domain."""
    from dependencies import get_tenant_id_from_request, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch('database.settings.delete_privileged_domain') as mock_delete:
        client = TestClient(app)
        response = client.post(
            "/settings/privileged-domains/delete/domain-id-123",
            follow_redirects=False
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/settings/privileged-domains"
        mock_delete.assert_called_once_with(test_admin_user["tenant_id"], "domain-id-123")


def test_tenant_security_page(test_super_admin_user):
    """Test tenant security settings page."""
    from dependencies import get_tenant_id_from_request, require_super_admin, require_admin
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_super_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_super_admin_user
    app.dependency_overrides[require_super_admin] = lambda: test_super_admin_user

    with patch('database.security.get_security_settings') as mock_get:
        with patch('utils.template_context.get_template_context') as mock_context:
            with patch('routers.settings.templates.TemplateResponse') as mock_template:
                mock_get.return_value = {
                    "session_timeout_seconds": 1800,
                    "persistent_sessions": False,
                    "allow_users_edit_profile": True,
                    "allow_users_add_emails": False
                }
                mock_context.return_value = {"request": Mock()}
                mock_template.return_value = HTMLResponse(content="<html>security</html>")

                client = TestClient(app)
                response = client.get("/settings/tenant-security")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_get.assert_called_once_with(test_super_admin_user["tenant_id"])


def test_tenant_security_page_no_settings(test_super_admin_user):
    """Test tenant security page when no settings exist (defaults)."""
    from dependencies import get_tenant_id_from_request, require_super_admin, require_admin
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_super_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_super_admin_user
    app.dependency_overrides[require_super_admin] = lambda: test_super_admin_user

    with patch('database.security.get_security_settings') as mock_get:
        with patch('utils.template_context.get_template_context') as mock_context:
            with patch('routers.settings.templates.TemplateResponse') as mock_template:
                mock_get.return_value = None  # No settings row
                mock_context.return_value = {"request": Mock()}
                mock_template.return_value = HTMLResponse(content="<html>security</html>")

                client = TestClient(app)
                response = client.get("/settings/tenant-security")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Just verify the response was successful
                # The defaults are handled in the route logic


def test_update_tenant_security(test_super_admin_user):
    """Test updating tenant security settings."""
    from dependencies import get_tenant_id_from_request, require_super_admin, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_super_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_super_admin_user
    app.dependency_overrides[require_super_admin] = lambda: test_super_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_super_admin_user

    with patch('database.security.update_security_settings') as mock_update:
        client = TestClient(app)
        response = client.post(
            "/settings/tenant-security/update",
            data={
                "session_timeout": "3600",
                "persistent_sessions": "true",
                "allow_users_edit_profile": "true",
                "allow_users_add_emails": ""  # Unchecked
            },
            follow_redirects=False
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "success=1" in response.headers["location"]
        mock_update.assert_called_once_with(
            test_super_admin_user["tenant_id"],
            3600,  # timeout
            True,  # persistent
            True,  # allow_edit_profile
            False,  # allow_add_emails
            test_super_admin_user["id"],
            test_super_admin_user["tenant_id"]
        )


def test_update_tenant_security_no_timeout(test_super_admin_user):
    """Test updating security with no timeout (indefinite)."""
    from dependencies import get_tenant_id_from_request, require_super_admin, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_super_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_super_admin_user
    app.dependency_overrides[require_super_admin] = lambda: test_super_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_super_admin_user

    with patch('database.security.update_security_settings') as mock_update:
        client = TestClient(app)
        response = client.post(
            "/settings/tenant-security/update",
            data={
                "session_timeout": "",  # Empty = indefinite
                "persistent_sessions": "",
                "allow_users_edit_profile": "",
                "allow_users_add_emails": ""
            },
            follow_redirects=False
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        # timeout_seconds should be None
        mock_update.assert_called_once()
        assert mock_update.call_args[0][1] is None


def test_update_tenant_security_invalid_timeout_non_numeric(test_super_admin_user):
    """Test updating security with non-numeric timeout."""
    from dependencies import get_tenant_id_from_request, require_super_admin, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_super_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_super_admin_user
    app.dependency_overrides[require_super_admin] = lambda: test_super_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_super_admin_user

    client = TestClient(app)
    response = client.post(
        "/settings/tenant-security/update",
        data={
            "session_timeout": "invalid",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true"
        },
        follow_redirects=False
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_timeout" in response.headers["location"]


def test_update_tenant_security_invalid_timeout_negative(test_super_admin_user):
    """Test updating security with negative timeout."""
    from dependencies import get_tenant_id_from_request, require_super_admin, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_super_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_super_admin_user
    app.dependency_overrides[require_super_admin] = lambda: test_super_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_super_admin_user

    client = TestClient(app)
    response = client.post(
        "/settings/tenant-security/update",
        data={
            "session_timeout": "-100",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true"
        },
        follow_redirects=False
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_timeout" in response.headers["location"]


def test_update_tenant_security_invalid_timeout_zero(test_super_admin_user):
    """Test updating security with zero timeout."""
    from dependencies import get_tenant_id_from_request, require_super_admin, require_admin, get_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_super_admin_user["tenant_id"]
    app.dependency_overrides[require_admin] = lambda: test_super_admin_user
    app.dependency_overrides[require_super_admin] = lambda: test_super_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_super_admin_user

    client = TestClient(app)
    response = client.post(
        "/settings/tenant-security/update",
        data={
            "session_timeout": "0",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true"
        },
        follow_redirects=False
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_timeout" in response.headers["location"]
