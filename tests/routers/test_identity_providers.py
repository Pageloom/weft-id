"""Tests for routers/identity_providers.py endpoints (Domain Routing).

Domain Routing (formerly Privileged Domains) moved here from
routers/settings.py as part of the nav restructure -- see
.claude/ITERATION_nav_restructure.md.
"""

from unittest.mock import Mock

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app

# Module path constants for cleaner patch targets
ROUTERS_IDENTITY_PROVIDERS = "routers.identity_providers"
DB_SETTINGS = "database.settings"
UTILS_TEMPLATE = "utils.template_context"
UTILS_ERRORS = "utils.service_errors"


def test_privileged_domains_list(test_admin_user, override_auth, mocker):
    """Test privileged domains page displays list."""
    from datetime import UTC, datetime

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch(f"{DB_SETTINGS}.list_privileged_domains")
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_IDENTITY_PROVIDERS}.templates.TemplateResponse",
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
    response = client.get("/identity-providers/domain-routing")

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
        f"{ROUTERS_IDENTITY_PROVIDERS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>error</html>"),
    )

    client = TestClient(app)
    response = client.get("/identity-providers/domain-routing?error=invalid_domain")

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
        "/identity-providers/domain-routing/add",
        data={"domain": "example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/identity-providers/domain-routing"
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
        "/identity-providers/domain-routing/add",
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
        "/identity-providers/domain-routing/add",
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
        "/identity-providers/domain-routing/add",
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
        "/identity-providers/domain-routing/add",
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
        "/identity-providers/domain-routing/delete/domain-id-123", follow_redirects=False
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/identity-providers/domain-routing"
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
        "/identity-providers/domain-routing/delete/nonexistent-id", follow_redirects=False
    )

    assert response.status_code == 404
    mock_template.assert_called_once()


# =============================================================================
# Domain-to-IdP Binding Route Tests
# =============================================================================


def test_bind_domain_to_idp_success(test_super_admin_user, override_auth, mocker):
    """Test binding a domain to an IdP redirects with success."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_bind = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.saml_service.bind_domain_to_idp")

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/bind",
        data={"idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/identity-providers/domain-routing?success=domain_bound" in response.headers["location"]
    mock_bind.assert_called_once()
    call_kwargs = mock_bind.call_args[1]
    assert call_kwargs["domain_id"] == "domain-123"
    assert call_kwargs["idp_id"] == "idp-456"


def test_bind_domain_to_idp_service_error(test_super_admin_user, override_auth, mocker):
    """Test binding domain with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_bind = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.saml_service.bind_domain_to_idp")
    mock_error = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.render_error_page")

    mock_bind.side_effect = ServiceError(message="IdP not found")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/bind",
        data={"idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_unbind_domain_from_idp_success(test_super_admin_user, override_auth, mocker):
    """Test unbinding a domain from IdP redirects with success."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_unbind = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.saml_service.unbind_domain_from_idp")

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/unbind",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert (
        "/identity-providers/domain-routing?success=domain_unbound" in response.headers["location"]
    )
    mock_unbind.assert_called_once()
    call_kwargs = mock_unbind.call_args[1]
    assert call_kwargs["domain_id"] == "domain-123"


def test_unbind_domain_from_idp_service_error(test_super_admin_user, override_auth, mocker):
    """Test unbinding domain with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_unbind = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.saml_service.unbind_domain_from_idp")
    mock_error = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.render_error_page")

    mock_unbind.side_effect = ServiceError(message="Domain not bound")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/unbind",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


# =============================================================================
# Privileged Domains with Super Admin IdP Fetching Test
# =============================================================================


def test_privileged_domains_super_admin_fetches_idps(test_super_admin_user, override_auth, mocker):
    """Test super_admin user fetches IdPs for domain binding dropdown."""
    override_auth(test_super_admin_user, level="admin")

    mocker.patch(f"{DB_SETTINGS}.list_privileged_domains", return_value=[])
    mock_idps = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.saml_service.list_identity_providers")
    mocker.patch(
        f"{ROUTERS_IDENTITY_PROVIDERS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>domains</html>"),
    )

    mock_idps.return_value = Mock(items=[{"id": "idp-1", "name": "Test IdP"}])

    client = TestClient(app)
    response = client.get("/identity-providers/domain-routing")

    assert response.status_code == 200
    # Verify IdPs were fetched for super_admin
    mock_idps.assert_called_once()


def test_privileged_domains_regular_admin_no_idps(test_admin_user, override_auth, mocker):
    """Test regular admin user does not fetch IdPs (not super_admin)."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{DB_SETTINGS}.list_privileged_domains", return_value=[])
    mock_idps = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.saml_service.list_identity_providers")
    mocker.patch(
        f"{ROUTERS_IDENTITY_PROVIDERS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>domains</html>"),
    )

    client = TestClient(app)
    response = client.get("/identity-providers/domain-routing")

    assert response.status_code == 200
    # Verify IdPs were NOT fetched for regular admin
    mock_idps.assert_not_called()


# =============================================================================
# Privileged Domains ServiceError Test
# =============================================================================


def test_privileged_domains_service_error(test_admin_user, override_auth, mocker):
    """Test privileged domains page shows error when service call fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch(
        f"{ROUTERS_IDENTITY_PROVIDERS}.settings_service.list_privileged_domains"
    )
    mock_error = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.render_error_page")

    mock_list.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.get("/identity-providers/domain-routing")

    assert response.status_code == 500
    mock_error.assert_called_once()


# =============================================================================
# Domain Group Linking Tests
# =============================================================================


def test_link_group_to_domain_success(test_admin_user, override_auth, mocker):
    """Test linking a group to a privileged domain redirects with success."""
    override_auth(test_admin_user, level="admin")

    mock_add = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.settings_service.add_domain_group_link")

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/link-group",
        data={"group_id": "group-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=group_linked" in response.headers["location"]
    mock_add.assert_called_once()


def test_link_group_to_domain_service_error(test_admin_user, override_auth, mocker):
    """Test linking group with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mock_add = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.settings_service.add_domain_group_link")
    mock_error = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.render_error_page")

    mock_add.side_effect = ServiceError(message="Group not found")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/link-group",
        data={"group_id": "group-456"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_unlink_group_from_domain_success(test_admin_user, override_auth, mocker):
    """Test unlinking a group from a privileged domain redirects with success."""
    override_auth(test_admin_user, level="admin")

    mock_delete = mocker.patch(
        f"{ROUTERS_IDENTITY_PROVIDERS}.settings_service.delete_domain_group_link"
    )

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/unlink-group/link-789",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=group_unlinked" in response.headers["location"]
    mock_delete.assert_called_once()


def test_unlink_group_from_domain_service_error(test_admin_user, override_auth, mocker):
    """Test unlinking group with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mock_delete = mocker.patch(
        f"{ROUTERS_IDENTITY_PROVIDERS}.settings_service.delete_domain_group_link"
    )
    mock_error = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.render_error_page")

    mock_delete.side_effect = ServiceError(message="Link not found")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/unlink-group/link-789",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


# =============================================================================
# Domain-to-OIDC-Connection Binding Route Tests
# =============================================================================


def test_bind_domain_to_oidc_connection_success(test_super_admin_user, override_auth, mocker):
    """Test binding a domain to an OIDC connection redirects with success."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_bind = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.oidc_service.bind_domain_to_connection")

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/bind-oidc",
        data={"connection_id": "conn-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert (
        "/identity-providers/domain-routing?success=domain_bound_oidc"
        in response.headers["location"]
    )
    mock_bind.assert_called_once()
    call_kwargs = mock_bind.call_args[1]
    assert call_kwargs["domain_id"] == "domain-123"
    assert call_kwargs["connection_id"] == "conn-456"


def test_bind_domain_to_oidc_connection_requires_super_admin(
    test_admin_user, override_auth, mocker
):
    """Test a regular admin is redirected, not allowed, to bind a domain to OIDC.

    require_super_admin is a router-layer *authentication* dependency in this
    codebase (see app/dependencies.py): it redirects rather than raising a
    403. The exact location varies between `/dashboard`
    (logged-in-but-wrong-role) and `/login` (the real dependency cannot see
    the test's `get_current_user` override at the "admin" level -- see
    test_saml_idp_scim_admin.py::test_scim_tab_redirects_non_super_admin for
    the same precedent), so both are accepted.
    """
    override_auth(test_admin_user, level="admin")

    mock_bind = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.oidc_service.bind_domain_to_connection")

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/bind-oidc",
        data={"connection_id": "conn-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] in ("/dashboard", "/login")
    mock_bind.assert_not_called()


def test_bind_domain_to_oidc_connection_service_error(test_super_admin_user, override_auth, mocker):
    """Test binding domain to OIDC connection with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_bind = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.oidc_service.bind_domain_to_connection")
    mock_error = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.render_error_page")

    mock_bind.side_effect = ServiceError(message="Connection not found")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/bind-oidc",
        data={"connection_id": "conn-456"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_unbind_domain_from_oidc_connection_success(test_super_admin_user, override_auth, mocker):
    """Test unbinding a domain from an OIDC connection redirects with success."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_unbind = mocker.patch(
        f"{ROUTERS_IDENTITY_PROVIDERS}.oidc_service.unbind_domain_from_connection"
    )

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/unbind-oidc",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert (
        "/identity-providers/domain-routing?success=domain_unbound" in response.headers["location"]
    )
    mock_unbind.assert_called_once()
    call_kwargs = mock_unbind.call_args[1]
    assert call_kwargs["domain_id"] == "domain-123"


def test_unbind_domain_from_oidc_connection_requires_super_admin(
    test_admin_user, override_auth, mocker
):
    """Test a regular admin is redirected, not allowed, to unbind a domain from OIDC.

    See test_bind_domain_to_oidc_connection_requires_super_admin for why the
    expected outcome is a redirect (to either /dashboard or /login) rather
    than a 403.
    """
    override_auth(test_admin_user, level="admin")

    mock_unbind = mocker.patch(
        f"{ROUTERS_IDENTITY_PROVIDERS}.oidc_service.unbind_domain_from_connection"
    )

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/unbind-oidc",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] in ("/dashboard", "/login")
    mock_unbind.assert_not_called()


def test_unbind_domain_from_oidc_connection_service_error(
    test_super_admin_user, override_auth, mocker
):
    """Test unbinding domain from OIDC connection with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_unbind = mocker.patch(
        f"{ROUTERS_IDENTITY_PROVIDERS}.oidc_service.unbind_domain_from_connection"
    )
    mock_error = mocker.patch(f"{ROUTERS_IDENTITY_PROVIDERS}.render_error_page")

    mock_unbind.side_effect = ServiceError(message="Connection not bound")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/identity-providers/domain-routing/domain-123/unbind-oidc",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


# =============================================================================
# Index Redirect Tests
# =============================================================================


def test_index_redirects_super_admin_to_saml(test_super_admin_user, override_auth):
    """Test the /identity-providers/ index redirects a super_admin to SAML."""
    override_auth(test_super_admin_user, level="super_admin")

    client = TestClient(app)
    response = client.get("/identity-providers/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/identity-providers/saml"


def test_index_redirects_admin_to_domain_routing(test_admin_user, override_auth):
    """Test the /identity-providers/ index redirects a plain admin to Domain Routing.

    A plain admin can't see SAML/OIDC (super_admin-only), so Domain Routing --
    the only child they have access to -- must be the fallback destination.
    """
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.get("/identity-providers/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/identity-providers/domain-routing"
