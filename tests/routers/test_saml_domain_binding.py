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
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def super_admin_session(client, test_tenant_host, test_super_admin_user, override_auth):
    """Create a client with super_admin session."""
    override_auth(test_super_admin_user, level="super_admin")
    yield client


# =============================================================================
# Bind Domain Tests
# =============================================================================


@patch("routers.saml.admin.domains.saml_service.bind_domain_to_idp")
def test_bind_domain_success(mock_bind, super_admin_session, test_tenant_host):
    """Test bind domain returns redirect with success on successful binding."""
    mock_bind.return_value = None  # Success returns nothing

    response = super_admin_session.post(
        "/admin/settings/identity-providers/idp-123/bind-domain",
        data={"domain_id": "domain-456"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/settings/identity-providers/idp-123" in location
    assert "success=domain_bound" in location
    mock_bind.assert_called_once()


@pytest.mark.parametrize(
    "exception,message",
    [
        (NotFoundError, "IdP or domain not found"),
        (ServiceError, "Domain already bound to another IdP"),
    ],
    ids=["not_found", "service_error"],
)
@patch("routers.saml.admin.domains.saml_service.bind_domain_to_idp")
def test_bind_domain_error(mock_bind, super_admin_session, test_tenant_host, exception, message):
    """Test bind domain returns redirect with error on service exceptions."""
    mock_bind.side_effect = exception(message)

    response = super_admin_session.post(
        "/admin/settings/identity-providers/idp-123/bind-domain",
        data={"domain_id": "domain-456"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/settings/identity-providers/idp-123" in location
    assert "error=" in location


# =============================================================================
# Unbind Domain Tests
# =============================================================================


@patch("routers.saml.admin.domains.saml_service.unbind_domain_from_idp")
def test_unbind_domain_success(mock_unbind, super_admin_session, test_tenant_host):
    """Test unbind domain returns redirect with success on successful unbinding."""
    mock_unbind.return_value = None  # Success returns nothing

    response = super_admin_session.post(
        "/admin/settings/identity-providers/idp-123/unbind-domain/domain-456",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/settings/identity-providers/idp-123" in location
    assert "success=domain_unbound" in location
    mock_unbind.assert_called_once()


@pytest.mark.parametrize(
    "exception,message",
    [
        (NotFoundError, "Domain binding not found"),
        (ServiceError, "Cannot unbind domain with active users"),
    ],
    ids=["not_found", "service_error"],
)
@patch("routers.saml.admin.domains.saml_service.unbind_domain_from_idp")
def test_unbind_domain_error(
    mock_unbind, super_admin_session, test_tenant_host, exception, message
):
    """Test unbind domain returns redirect with error on service exceptions."""
    mock_unbind.side_effect = exception(message)

    response = super_admin_session.post(
        "/admin/settings/identity-providers/idp-123/unbind-domain/domain-456",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/settings/identity-providers/idp-123" in location
    assert "error=" in location
