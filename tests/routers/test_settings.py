"""Tests for routers/settings.py endpoints."""

from unittest.mock import Mock

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app

# Module path constants for cleaner patch targets
ROUTERS_SETTINGS = "routers.settings"
DB_SETTINGS = "database.settings"
DB_SECURITY = "database.security"
UTILS_TEMPLATE = "utils.template_context"
UTILS_ERRORS = "utils.service_errors"


def test_settings_index_redirects_to_first_child(test_admin_user, override_auth, mocker):
    """Test settings index redirects to first accessible child page."""
    override_auth(test_admin_user, level="admin")

    mock_first_child = mocker.patch(f"{ROUTERS_SETTINGS}.get_first_accessible_child")
    mock_first_child.return_value = "/admin/settings/privileged-domains"

    client = TestClient(app)
    response = client.get("/admin/settings/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/settings/privileged-domains"


def test_privileged_domains_list(test_admin_user, override_auth, mocker):
    """Test privileged domains page displays list."""
    from datetime import UTC, datetime

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch(f"{DB_SETTINGS}.list_privileged_domains")
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>domains</html>"),
    )

    mock_list.return_value = [
        {
            "id": "1",
            "domain": "example.com",
            "created_at": datetime.now(UTC),
            "first_name": "Admin",
            "last_name": "User",
        },
        {
            "id": "2",
            "domain": "test.org",
            "created_at": datetime.now(UTC),
            "first_name": None,
            "last_name": None,
        },
    ]

    client = TestClient(app)
    response = client.get("/admin/settings/privileged-domains")

    assert response.status_code == 200
    mock_list.assert_called_once_with(str(test_admin_user["tenant_id"]))


def test_privileged_domains_with_error_param(test_admin_user, override_auth, mocker):
    """Test privileged domains page with error parameter."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{DB_SETTINGS}.list_privileged_domains", return_value=[])
    mocker.patch(
        f"{UTILS_TEMPLATE}.get_template_context",
        return_value={"request": Mock(), "domains": [], "error": "invalid_domain"},
    )
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>error</html>"),
    )

    client = TestClient(app)
    response = client.get("/admin/settings/privileged-domains?error=invalid_domain")

    assert response.status_code == 200


def test_add_privileged_domain_success(test_admin_user, override_auth, mocker):
    """Test adding a valid privileged domain."""
    from datetime import UTC, datetime

    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{DB_SETTINGS}.privileged_domain_exists", return_value=False)
    mock_add = mocker.patch(f"{DB_SETTINGS}.add_privileged_domain")
    mocker.patch(
        f"{DB_SETTINGS}.list_privileged_domains",
        return_value=[
            {
                "id": "1",
                "domain": "example.com",
                "created_at": datetime.now(UTC),
                "first_name": "Admin",
                "last_name": "User",
            },
        ],
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/privileged-domains/add",
        data={"domain": "example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/settings/privileged-domains"
    mock_add.assert_called_once()


def test_add_privileged_domain_with_at_prefix(test_admin_user, override_auth, mocker):
    """Test adding domain with @ prefix (should be stripped)."""
    from datetime import UTC, datetime

    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{DB_SETTINGS}.privileged_domain_exists", return_value=False)
    mock_add = mocker.patch(f"{DB_SETTINGS}.add_privileged_domain")
    mocker.patch(
        f"{DB_SETTINGS}.list_privileged_domains",
        return_value=[
            {
                "id": "1",
                "domain": "example.com",
                "created_at": datetime.now(UTC),
                "first_name": None,
                "last_name": None,
            },
        ],
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/privileged-domains/add",
        data={"domain": "@example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    # @ should be stripped - check add was called with example.com
    mock_add.assert_called_once()
    call_kwargs = mock_add.call_args.kwargs
    assert call_kwargs["domain"] == "example.com"


def test_add_privileged_domain_invalid_shows_error_page(test_admin_user, override_auth, mocker):
    """Test adding invalid domain shows error page (service layer behavior)."""
    override_auth(test_admin_user, level="admin")

    mock_template = mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(
            content="<html>Invalid Input: cannot be empty</html>", status_code=400
        ),
    )

    client = TestClient(app)
    # Empty domain after strip - shows error page
    response = client.post(
        "/admin/settings/privileged-domains/add",
        data={"domain": "   "},
        follow_redirects=False,
    )

    # Service layer returns error pages for validation errors
    assert response.status_code == 400
    mock_template.assert_called_once()


def test_add_privileged_domain_no_dot_shows_error_page(test_admin_user, override_auth, mocker):
    """Test adding domain without dot shows error page."""
    override_auth(test_admin_user, level="admin")

    mock_template = mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(
            content="<html>Invalid Input: must contain a dot</html>", status_code=400
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/privileged-domains/add",
        data={"domain": "localhost"},
        follow_redirects=False,
    )

    # Service layer returns error page for validation errors
    assert response.status_code == 400
    mock_template.assert_called_once()


def test_add_privileged_domain_already_exists_shows_error_page(
    test_admin_user, override_auth, mocker
):
    """Test adding duplicate domain shows error page."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{DB_SETTINGS}.privileged_domain_exists", return_value=True)
    mock_template = mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(
            content="<html>Conflict: domain already exists</html>", status_code=409
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/privileged-domains/add",
        data={"domain": "example.com"},
        follow_redirects=False,
    )

    # Service layer returns error page for conflict errors
    assert response.status_code == 409
    mock_template.assert_called_once()


def test_delete_privileged_domain(test_admin_user, override_auth, mocker):
    """Test deleting a privileged domain."""
    from datetime import UTC, datetime

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{DB_SETTINGS}.list_privileged_domains",
        return_value=[
            {
                "id": "domain-id-123",
                "domain": "example.com",
                "created_at": datetime.now(UTC),
                "first_name": None,
                "last_name": None,
            },
        ],
    )
    mock_delete = mocker.patch(f"{DB_SETTINGS}.delete_privileged_domain")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/privileged-domains/delete/domain-id-123", follow_redirects=False
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/settings/privileged-domains"
    mock_delete.assert_called_once()


def test_delete_privileged_domain_not_found_shows_error(test_admin_user, override_auth, mocker):
    """Test deleting non-existent domain shows error page."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{DB_SETTINGS}.list_privileged_domains", return_value=[])
    mock_template = mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(
            content="<html>Not Found: domain not found</html>", status_code=404
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/privileged-domains/delete/nonexistent-id", follow_redirects=False
    )

    assert response.status_code == 404
    mock_template.assert_called_once()


def test_tenant_security_redirects_to_sessions(test_super_admin_user, override_auth):
    """Test /security redirects to /security/sessions."""
    override_auth(test_super_admin_user, level="super_admin")

    client = TestClient(app)
    response = client.get("/admin/settings/security", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/settings/security/sessions"


def test_tenant_security_sessions_page(test_super_admin_user, override_auth, mocker):
    """Test tenant security sessions tab page."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_get = mocker.patch(f"{DB_SECURITY}.get_security_settings")
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>security sessions</html>"),
    )

    mock_get.return_value = {
        "session_timeout_seconds": 1800,
        "persistent_sessions": False,
        "allow_users_edit_profile": True,
        "allow_users_add_emails": False,
    }

    client = TestClient(app)
    response = client.get("/admin/settings/security/sessions")

    assert response.status_code == 200
    mock_get.assert_called_once_with(str(test_super_admin_user["tenant_id"]))


def test_tenant_security_certificates_page(test_super_admin_user, override_auth, mocker):
    """Test tenant security certificates tab page."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>security certificates</html>"),
    )

    client = TestClient(app)
    response = client.get("/admin/settings/security/certificates")

    assert response.status_code == 200


def test_tenant_security_permissions_page(test_super_admin_user, override_auth, mocker):
    """Test tenant security permissions tab page."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>security permissions</html>"),
    )

    client = TestClient(app)
    response = client.get("/admin/settings/security/permissions")

    assert response.status_code == 200


def test_tenant_security_sessions_page_no_settings(test_super_admin_user, override_auth, mocker):
    """Test tenant security sessions page when no settings exist (defaults)."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>security</html>"),
    )

    client = TestClient(app)
    response = client.get("/admin/settings/security/sessions")

    assert response.status_code == 200


def test_update_tenant_security_sessions(test_super_admin_user, override_auth, mocker):
    """Test updating tenant session security settings."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/sessions/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=1" in response.headers["location"]
    mock_update.assert_called_once()


def test_update_tenant_security_sessions_no_timeout(test_super_admin_user, override_auth, mocker):
    """Test updating sessions with no timeout (indefinite)."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/sessions/update",
        data={
            "session_timeout": "",  # Empty = indefinite
            "persistent_sessions": "",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    # timeout_seconds should be None
    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["timeout_seconds"] is None


def test_update_tenant_security_sessions_invalid_timeout_shows_error_page(
    test_super_admin_user, override_auth, mocker
):
    """Test updating sessions with invalid timeout shows error page."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_template = mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(
            content="<html>Invalid Input: timeout must be positive</html>", status_code=400
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/sessions/update",
        data={
            "session_timeout": "0",  # Zero is invalid
            "persistent_sessions": "true",
        },
        follow_redirects=False,
    )

    # Route validates timeout and returns error page
    assert response.status_code == 400
    mock_template.assert_called_once()


def test_update_tenant_security_permissions(test_super_admin_user, override_auth, mocker):
    """Test updating tenant permission security settings."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/permissions/update",
        data={
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "",  # Unchecked
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=1" in response.headers["location"]
    mock_update.assert_called_once()


def test_security_tab_form_action_urls_are_correct():
    """Test that each security tab template form posts to the correct URL.

    Regression test for bug where form posted to wrong URL causing 404.
    """
    import os

    templates_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app", "templates")

    # Sessions tab
    with open(os.path.join(templates_dir, "settings_security_tab_sessions.html")) as f:
        content = f.read()
    assert 'action="/admin/settings/security/sessions/update"' in content

    # Certificates tab
    with open(os.path.join(templates_dir, "settings_security_tab_certificates.html")) as f:
        content = f.read()
    assert 'action="/admin/settings/security/certificates/update"' in content

    # Permissions tab
    with open(os.path.join(templates_dir, "settings_security_tab_permissions.html")) as f:
        content = f.read()
    assert 'action="/admin/settings/security/permissions/update"' in content


# =============================================================================
# Domain-to-IdP Binding Route Tests
# =============================================================================


def test_bind_domain_to_idp_success(test_super_admin_user, override_auth, mocker):
    """Test binding a domain to an IdP redirects with success."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_bind = mocker.patch(f"{ROUTERS_SETTINGS}.saml_service.bind_domain_to_idp")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/privileged-domains/domain-123/bind",
        data={"idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/admin/settings/privileged-domains?success=domain_bound" in response.headers["location"]
    mock_bind.assert_called_once()
    call_kwargs = mock_bind.call_args[1]
    assert call_kwargs["domain_id"] == "domain-123"
    assert call_kwargs["idp_id"] == "idp-456"


def test_bind_domain_to_idp_service_error(test_super_admin_user, override_auth, mocker):
    """Test binding domain with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_bind = mocker.patch(f"{ROUTERS_SETTINGS}.saml_service.bind_domain_to_idp")
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")

    mock_bind.side_effect = ServiceError(message="IdP not found")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/privileged-domains/domain-123/bind",
        data={"idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_unbind_domain_from_idp_success(test_super_admin_user, override_auth, mocker):
    """Test unbinding a domain from IdP redirects with success."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_unbind = mocker.patch(f"{ROUTERS_SETTINGS}.saml_service.unbind_domain_from_idp")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/privileged-domains/domain-123/unbind",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert (
        "/admin/settings/privileged-domains?success=domain_unbound" in response.headers["location"]
    )
    mock_unbind.assert_called_once()
    call_kwargs = mock_unbind.call_args[1]
    assert call_kwargs["domain_id"] == "domain-123"


def test_unbind_domain_from_idp_service_error(test_super_admin_user, override_auth, mocker):
    """Test unbinding domain with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_unbind = mocker.patch(f"{ROUTERS_SETTINGS}.saml_service.unbind_domain_from_idp")
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")

    mock_unbind.side_effect = ServiceError(message="Domain not bound")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/privileged-domains/domain-123/unbind",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


# =============================================================================
# Settings Index Fallback Test
# =============================================================================


def test_settings_index_fallback_to_dashboard(override_auth, mocker):
    """Test settings index falls back to dashboard when no children are accessible.

    This tests the fallback path (line 47) when get_first_accessible_child returns None.
    We need a user with a role that has NO accessible admin children.
    """
    # Create a mock user with a role that has no accessible admin pages
    mock_user = {
        "id": "test-id",
        "tenant_id": "test-tenant",
        "role": "nonexistent_role",  # Role with no access
        "first_name": "Test",
        "last_name": "User",
    }

    override_auth(mock_user, level="admin")

    mocker.patch(f"{ROUTERS_SETTINGS}.get_first_accessible_child", return_value=None)

    client = TestClient(app)
    response = client.get("/admin/settings/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# Privileged Domains with Super Admin IdP Fetching Test
# =============================================================================


def test_privileged_domains_super_admin_fetches_idps(test_super_admin_user, override_auth, mocker):
    """Test super_admin user fetches IdPs for domain binding dropdown."""
    override_auth(test_super_admin_user, level="admin")

    mocker.patch(f"{DB_SETTINGS}.list_privileged_domains", return_value=[])
    mock_idps = mocker.patch(f"{ROUTERS_SETTINGS}.saml_service.list_identity_providers")
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>domains</html>"),
    )

    mock_idps.return_value = Mock(items=[{"id": "idp-1", "name": "Test IdP"}])

    client = TestClient(app)
    response = client.get("/admin/settings/privileged-domains")

    assert response.status_code == 200
    # Verify IdPs were fetched for super_admin
    mock_idps.assert_called_once()


def test_privileged_domains_regular_admin_no_idps(test_admin_user, override_auth, mocker):
    """Test regular admin user does not fetch IdPs (not super_admin)."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{DB_SETTINGS}.list_privileged_domains", return_value=[])
    mock_idps = mocker.patch(f"{ROUTERS_SETTINGS}.saml_service.list_identity_providers")
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>domains</html>"),
    )

    client = TestClient(app)
    response = client.get("/admin/settings/privileged-domains")

    assert response.status_code == 200
    # Verify IdPs were NOT fetched for regular admin
    mock_idps.assert_not_called()


# =============================================================================
# Security Settings Error Handling Tests
# =============================================================================


def test_admin_security_sessions_service_error(test_super_admin_user, override_auth, mocker):
    """Test security sessions page shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_get = mocker.patch(f"{ROUTERS_SETTINGS}.settings_service.get_security_settings")
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")

    mock_get.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.get("/admin/settings/security/sessions")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_update_security_non_numeric_timeout_error(test_super_admin_user, override_auth, mocker):
    """Test updating sessions with non-numeric timeout shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/sessions/update",
        data={
            "session_timeout": "not-a-number",  # Non-numeric
            "persistent_sessions": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_update_security_non_numeric_inactivity_error(test_super_admin_user, override_auth, mocker):
    """Test updating sessions with non-numeric inactivity threshold shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/sessions/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
            "inactivity_threshold": "not-a-number",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_update_security_sessions_service_error(test_super_admin_user, override_auth, mocker):
    """Test updating sessions with service error shows error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_update = mocker.patch(f"{ROUTERS_SETTINGS}.settings_service.update_security_settings")
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")

    mock_update.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/sessions/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


# =============================================================================
# Certificate Lifetime Route Tests
# =============================================================================


def test_update_tenant_security_with_certificate_lifetime(
    test_super_admin_user, override_auth, mocker
):
    """Test updating certificates with certificate lifetime form field."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/certificates/update",
        data={
            "certificate_lifetime": "3",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=1" in response.headers["location"]
    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["max_certificate_lifetime_years"] == 3


def test_update_tenant_security_empty_certificate_lifetime(
    test_super_admin_user, override_auth, mocker
):
    """Test that empty certificate lifetime keeps the default."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/certificates/update",
        data={
            "certificate_lifetime": "",  # Empty = keep default
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    mock_update.assert_called_once()
    # Certificate lifetime should be the default (10) since not provided
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["max_certificate_lifetime_years"] == 10


def test_update_tenant_security_non_numeric_certificate_lifetime_error(
    test_super_admin_user, override_auth, mocker
):
    """Test updating certificates with non-numeric certificate lifetime shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/certificates/update",
        data={
            "certificate_lifetime": "not-a-number",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_security_certificates_template_has_certificate_lifetime_field():
    """Test that the certificates tab template includes certificate lifetime dropdown."""
    import os

    template_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "app",
        "templates",
        "settings_security_tab_certificates.html",
    )
    with open(template_path) as f:
        template_content = f.read()

    assert 'name="certificate_lifetime"' in template_content
    assert "Validity period" in template_content


# =============================================================================
# Certificate Rotation Window Route Tests
# =============================================================================


def test_update_tenant_security_with_rotation_window(test_super_admin_user, override_auth, mocker):
    """Test updating certificates with rotation window form field."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/certificates/update",
        data={
            "rotation_window": "30",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=1" in response.headers["location"]
    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["certificate_rotation_window_days"] == 30


def test_update_tenant_security_empty_rotation_window(test_super_admin_user, override_auth, mocker):
    """Test that empty rotation window keeps the default."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/certificates/update",
        data={
            "rotation_window": "",  # Empty = keep default
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["certificate_rotation_window_days"] == 90


def test_update_tenant_security_invalid_rotation_window_error(
    test_super_admin_user, override_auth, mocker
):
    """Test updating certificates with invalid rotation window shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/certificates/update",
        data={
            "rotation_window": "45",  # Invalid: not in [14, 30, 60, 90]
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_security_certificates_template_has_rotation_window_field():
    """Test that the certificates tab template includes rotation window dropdown."""
    import os

    template_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "app",
        "templates",
        "settings_security_tab_certificates.html",
    )
    with open(template_path) as f:
        template_content = f.read()

    assert 'name="rotation_window"' in template_content
    assert "Rotation window" in template_content


# =============================================================================
# Privileged Domains ServiceError Test
# =============================================================================


def test_privileged_domains_service_error(test_admin_user, override_auth, mocker):
    """Test privileged domains page shows error when service call fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch(f"{ROUTERS_SETTINGS}.settings_service.list_privileged_domains")
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")

    mock_list.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.get("/admin/settings/privileged-domains")

    assert response.status_code == 500
    mock_error.assert_called_once()


# =============================================================================
# Inactivity Threshold Validation Tests
# =============================================================================


def test_update_security_negative_inactivity_threshold_error(
    test_super_admin_user, override_auth, mocker
):
    """Test updating sessions with negative inactivity threshold shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/sessions/update",
        data={
            "session_timeout": "",
            "persistent_sessions": "",
            "inactivity_threshold": "-5",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_update_security_zero_inactivity_threshold_error(
    test_super_admin_user, override_auth, mocker
):
    """Test updating sessions with zero inactivity threshold shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/sessions/update",
        data={
            "session_timeout": "",
            "persistent_sessions": "",
            "inactivity_threshold": "0",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


# =============================================================================
# Certificate Lifetime Invalid Numeric Value Test
# =============================================================================


def test_update_security_invalid_certificate_lifetime_value_error(
    test_super_admin_user, override_auth, mocker
):
    """Test updating certificates with numeric but disallowed certificate lifetime (e.g. 4)."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/certificates/update",
        data={
            "certificate_lifetime": "4",  # Valid int, but not in [1,2,3,5,10]
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


# =============================================================================
# Security Settings PydanticValidationError Test
# =============================================================================


def test_update_security_pydantic_validation_error(test_super_admin_user, override_auth, mocker):
    """Test PydanticValidationError during schema construction shows error page."""
    from pydantic import BaseModel
    from pydantic import ValidationError as PydanticValidationError

    override_auth(test_super_admin_user, level="super_admin")

    # Create a real PydanticValidationError to use as side_effect
    class _Dummy(BaseModel):
        x: int

    saved_err = None
    try:
        _Dummy(x="bad")  # type: ignore[arg-type]
    except PydanticValidationError as e:
        saved_err = e

    assert saved_err is not None

    mocker.patch(
        f"{ROUTERS_SETTINGS}.TenantSecuritySettingsUpdate",
        side_effect=saved_err,
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/sessions/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


# =============================================================================
# Branding Route Tests
# =============================================================================


def _mock_branding_settings():
    """Create a mock BrandingSettings response."""
    from schemas.branding import BrandingSettings, GroupAvatarStyle, LogoMode

    return BrandingSettings(
        logo_mode=LogoMode.MANDALA,
        use_logo_as_favicon=False,
        site_title=None,
        show_title_in_nav=True,
        has_logo_light=False,
        has_logo_dark=False,
        group_avatar_style=GroupAvatarStyle.ACRONYM,
    )


def test_branding_redirect(test_admin_user, override_auth):
    """Test /branding redirects to /branding/global."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.get("/admin/settings/branding", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/settings/branding/global"


def test_branding_global_page(test_admin_user, override_auth, mocker):
    """Test branding global settings page renders."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.get_branding_settings",
        return_value=_mock_branding_settings(),
    )
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>branding</html>"),
    )

    client = TestClient(app)
    response = client.get("/admin/settings/branding/global")

    assert response.status_code == 200


def test_branding_global_service_error(test_admin_user, override_auth, mocker):
    """Test branding global page shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.get_branding_settings",
        side_effect=ServiceError(message="DB error"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.get("/admin/settings/branding/global")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_branding_groups_page(test_admin_user, override_auth, mocker):
    """Test branding groups settings page renders."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.get_branding_settings",
        return_value=_mock_branding_settings(),
    )
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>groups branding</html>"),
    )

    client = TestClient(app)
    response = client.get("/admin/settings/branding/groups")

    assert response.status_code == 200


def test_branding_groups_service_error(test_admin_user, override_auth, mocker):
    """Test branding groups page shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.get_branding_settings",
        side_effect=ServiceError(message="DB error"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.get("/admin/settings/branding/groups")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_upload_branding_logo_success(test_admin_user, override_auth, mocker):
    """Test uploading a branding logo redirects with success."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.upload_logo",
        return_value=_mock_branding_settings(),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/global/upload/light",
        files={"file": ("logo.png", b"fake-png-data", "image/png")},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=logo_uploaded" in response.headers["location"]


def test_upload_branding_logo_service_error(test_admin_user, override_auth, mocker):
    """Test uploading a branding logo shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.upload_logo",
        side_effect=ServiceError(message="Invalid image"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/global/upload/light",
        files={"file": ("logo.png", b"bad", "image/png")},
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


def test_delete_branding_logo_success(test_admin_user, override_auth, mocker):
    """Test deleting a branding logo redirects with success."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.delete_logo",
        return_value=_mock_branding_settings(),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/global/delete/dark",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=logo_deleted" in response.headers["location"]


def test_delete_branding_logo_service_error(test_admin_user, override_auth, mocker):
    """Test deleting a branding logo shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.delete_logo",
        side_effect=ServiceError(message="Logo not found"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=404)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/global/delete/light",
        follow_redirects=False,
    )

    assert response.status_code == 404
    mock_error.assert_called_once()


def test_update_branding_settings_success(test_admin_user, override_auth, mocker):
    """Test updating branding settings redirects with success."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.get_branding_settings",
        return_value=_mock_branding_settings(),
    )
    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.update_branding_settings",
        return_value=_mock_branding_settings(),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/global/settings",
        data={
            "logo_mode": "custom",
            "use_logo_as_favicon": "true",
            "site_title": "My Site",
            "show_title_in_nav": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=settings_updated" in response.headers["location"]


def test_update_branding_settings_invalid_logo_mode(test_admin_user, override_auth, mocker):
    """Test updating branding with invalid logo_mode shows error."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.get_branding_settings",
        return_value=_mock_branding_settings(),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/global/settings",
        data={
            "logo_mode": "invalid_mode",
            "site_title": "",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


def test_update_branding_settings_get_current_error(test_admin_user, override_auth, mocker):
    """Test updating branding settings fails when fetching current settings fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.get_branding_settings",
        side_effect=ServiceError(message="DB error"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/global/settings",
        data={"logo_mode": "mandala"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_update_branding_settings_update_service_error(test_admin_user, override_auth, mocker):
    """Test updating branding settings fails when update service call fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.get_branding_settings",
        return_value=_mock_branding_settings(),
    )
    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.update_branding_settings",
        side_effect=ServiceError(message="Update failed"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/global/settings",
        data={
            "logo_mode": "mandala",
            "site_title": "",
        },
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_upload_group_logo_success(test_admin_user, override_auth, mocker):
    """Test uploading a group logo redirects with success."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{ROUTERS_SETTINGS}.branding_service.upload_group_logo")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/groups/upload/group-123",
        files={"file": ("logo.png", b"fake-png", "image/png")},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=logo_uploaded" in response.headers["location"]


def test_upload_group_logo_service_error(test_admin_user, override_auth, mocker):
    """Test uploading a group logo shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.upload_group_logo",
        side_effect=ServiceError(message="Invalid image"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/groups/upload/group-123",
        files={"file": ("logo.png", b"bad", "image/png")},
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


def test_delete_group_logo_success(test_admin_user, override_auth, mocker):
    """Test deleting a group logo redirects with success."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{ROUTERS_SETTINGS}.branding_service.delete_group_logo")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/groups/delete/group-123",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=logo_deleted" in response.headers["location"]


def test_delete_group_logo_service_error(test_admin_user, override_auth, mocker):
    """Test deleting a group logo shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS}.branding_service.delete_group_logo",
        side_effect=ServiceError(message="Group not found"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=404)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/branding/groups/delete/group-123",
        follow_redirects=False,
    )

    assert response.status_code == 404
    mock_error.assert_called_once()
