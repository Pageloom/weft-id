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


def test_tenant_security_page(test_super_admin_user, override_auth, mocker):
    """Test tenant security settings page."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_get = mocker.patch(f"{DB_SECURITY}.get_security_settings")
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>security</html>"),
    )

    mock_get.return_value = {
        "session_timeout_seconds": 1800,
        "persistent_sessions": False,
        "allow_users_edit_profile": True,
        "allow_users_add_emails": False,
    }

    client = TestClient(app)
    response = client.get("/admin/settings/security")

    assert response.status_code == 200
    mock_get.assert_called_once_with(str(test_super_admin_user["tenant_id"]))


def test_tenant_security_page_no_settings(test_super_admin_user, override_auth, mocker):
    """Test tenant security page when no settings exist (defaults)."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>security</html>"),
    )

    client = TestClient(app)
    response = client.get("/admin/settings/security")

    assert response.status_code == 200


def test_update_tenant_security(test_super_admin_user, override_auth, mocker):
    """Test updating tenant security settings."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "",  # Unchecked
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=1" in response.headers["location"]
    mock_update.assert_called_once()


def test_update_tenant_security_no_timeout(test_super_admin_user, override_auth, mocker):
    """Test updating security with no timeout (indefinite)."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/update",
        data={
            "session_timeout": "",  # Empty = indefinite
            "persistent_sessions": "",
            "allow_users_edit_profile": "",
            "allow_users_add_emails": "",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    # timeout_seconds should be None
    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["timeout_seconds"] is None


def test_update_tenant_security_invalid_timeout_shows_error_page(
    test_super_admin_user, override_auth, mocker
):
    """Test updating security with invalid timeout shows error page."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_template = mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(
            content="<html>Invalid Input: timeout must be positive</html>", status_code=400
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/update",
        data={
            "session_timeout": "0",  # Zero is invalid
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true",
        },
        follow_redirects=False,
    )

    # Route validates timeout and returns error page
    assert response.status_code == 400
    mock_template.assert_called_once()


def test_tenant_security_form_action_url_is_correct():
    """Test that the security settings template form posts to the correct URL.

    This test reads the template file directly and verifies the form
    action attribute points to the correct endpoint.
    Regression test for bug where form posted to wrong URL causing 404.
    """
    import os

    # Read the template file directly
    template_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "app", "templates", "settings_tenant_security.html"
    )
    with open(template_path) as f:
        template_content = f.read()

    # Verify the form action points to the correct route
    assert 'action="/admin/settings/security/update"' in template_content, (
        "Form should POST to /admin/settings/security/update to match the route at "
        "app/routers/settings.py:143 (router prefix='/admin', route='/security/update'). "
        "Found form action does not match the actual route endpoint."
    )


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


def test_admin_security_service_error(test_super_admin_user, override_auth, mocker):
    """Test security settings page shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_get = mocker.patch(f"{ROUTERS_SETTINGS}.settings_service.get_security_settings")
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")

    mock_get.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.get("/admin/settings/security")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_update_security_non_numeric_timeout_error(test_super_admin_user, override_auth, mocker):
    """Test updating security with non-numeric timeout shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/update",
        data={
            "session_timeout": "not-a-number",  # Non-numeric
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_update_security_non_numeric_inactivity_error(test_super_admin_user, override_auth, mocker):
    """Test updating security with non-numeric inactivity threshold shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true",
            "inactivity_threshold": "not-a-number",  # Correct field name
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_update_security_service_error(test_super_admin_user, override_auth, mocker):
    """Test updating security with service error shows error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_update = mocker.patch(f"{ROUTERS_SETTINGS}.settings_service.update_security_settings")
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS}.render_error_page")

    mock_update.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true",
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
    """Test updating security with certificate lifetime form field."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true",
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
        "/admin/settings/security/update",
        data={
            "session_timeout": "",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true",
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
    """Test updating security with non-numeric certificate lifetime shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true",
            "certificate_lifetime": "not-a-number",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_security_template_has_certificate_lifetime_field():
    """Test that the security settings template includes certificate lifetime dropdown."""
    import os

    template_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "app", "templates", "settings_tenant_security.html"
    )
    with open(template_path) as f:
        template_content = f.read()

    assert 'name="certificate_lifetime"' in template_content
    assert "Certificate Lifetime" in template_content


# =============================================================================
# Certificate Rotation Window Route Tests
# =============================================================================


def test_update_tenant_security_with_rotation_window(test_super_admin_user, override_auth, mocker):
    """Test updating security with rotation window form field."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true",
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
        "/admin/settings/security/update",
        data={
            "session_timeout": "",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true",
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
    """Test updating security with invalid rotation window shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/admin/settings/security/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
            "allow_users_edit_profile": "true",
            "allow_users_add_emails": "true",
            "rotation_window": "45",  # Invalid: not in [14, 30, 60, 90]
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_security_template_has_rotation_window_field():
    """Test that the security settings template includes rotation window dropdown."""
    import os

    template_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "app", "templates", "settings_tenant_security.html"
    )
    with open(template_path) as f:
        template_content = f.read()

    assert 'name="rotation_window"' in template_content
    assert "Certificate Rotation Window" in template_content
