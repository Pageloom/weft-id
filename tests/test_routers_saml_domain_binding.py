"""Tests for SAML router domain binding endpoints.

This test file covers the domain binding feature:
- Bind domain to IdP success and error paths
- Unbind domain from IdP success and error paths
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from services.exceptions import NotFoundError, ServiceError


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def super_admin_session(client, test_tenant_host, test_super_admin_user):
    """Create a client with super_admin session."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_super_admin
    from main import app

    tenant_id = str(test_super_admin_user["tenant_id"])

    app.dependency_overrides[get_current_user] = lambda: test_super_admin_user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id
    app.dependency_overrides[require_super_admin] = lambda: test_super_admin_user

    yield client

    app.dependency_overrides.clear()


# =============================================================================
# Bind Domain Tests
# =============================================================================


@patch("routers.saml.saml_service.bind_domain_to_idp")
def test_bind_domain_success(mock_bind, super_admin_session, test_tenant_host):
    """Test bind domain returns redirect with success on successful binding."""
    mock_bind.return_value = None  # Success returns nothing

    response = super_admin_session.post(
        "/admin/identity-providers/idp-123/bind-domain",
        data={"domain_id": "domain-456"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/idp-123" in location
    assert "success=domain_bound" in location
    mock_bind.assert_called_once()


@patch("routers.saml.saml_service.bind_domain_to_idp")
def test_bind_domain_not_found(mock_bind, super_admin_session, test_tenant_host):
    """Test bind domain returns redirect with error on NotFoundError."""
    mock_bind.side_effect = NotFoundError("IdP or domain not found")

    response = super_admin_session.post(
        "/admin/identity-providers/non-existent-idp/bind-domain",
        data={"domain_id": "domain-456"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/non-existent-idp" in location
    assert "error=" in location


@patch("routers.saml.saml_service.bind_domain_to_idp")
def test_bind_domain_service_error(mock_bind, super_admin_session, test_tenant_host):
    """Test bind domain returns redirect with error on ServiceError."""
    mock_bind.side_effect = ServiceError("Domain already bound to another IdP")

    response = super_admin_session.post(
        "/admin/identity-providers/idp-123/bind-domain",
        data={"domain_id": "domain-456"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/idp-123" in location
    assert "error=" in location


# =============================================================================
# Unbind Domain Tests
# =============================================================================


@patch("routers.saml.saml_service.unbind_domain_from_idp")
def test_unbind_domain_success(mock_unbind, super_admin_session, test_tenant_host):
    """Test unbind domain returns redirect with success on successful unbinding."""
    mock_unbind.return_value = None  # Success returns nothing

    response = super_admin_session.post(
        "/admin/identity-providers/idp-123/unbind-domain/domain-456",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/idp-123" in location
    assert "success=domain_unbound" in location
    mock_unbind.assert_called_once()


@patch("routers.saml.saml_service.unbind_domain_from_idp")
def test_unbind_domain_not_found(mock_unbind, super_admin_session, test_tenant_host):
    """Test unbind domain returns redirect with error on NotFoundError."""
    mock_unbind.side_effect = NotFoundError("Domain binding not found")

    response = super_admin_session.post(
        "/admin/identity-providers/idp-123/unbind-domain/non-existent-domain",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/idp-123" in location
    assert "error=" in location


@patch("routers.saml.saml_service.unbind_domain_from_idp")
def test_unbind_domain_service_error(mock_unbind, super_admin_session, test_tenant_host):
    """Test unbind domain returns redirect with error on ServiceError."""
    mock_unbind.side_effect = ServiceError("Cannot unbind domain with active users")

    response = super_admin_session.post(
        "/admin/identity-providers/idp-123/unbind-domain/domain-456",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/idp-123" in location
    assert "error=" in location
