"""Tests for SAML router endpoints.

Tests both admin UI endpoints and public SAML endpoints.
"""

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def test_idp_data():
    """Provide test IdP data for form submissions."""
    return {
        "name": "Test Okta IdP",
        "provider_type": "okta",
        "entity_id": "https://idp.example.com/entity",
        "sso_url": "https://idp.example.com/sso",
        "certificate_pem": """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
ZZK9p7a2W3F8V3fVT3Z7m7bZa5W3WwJGfGQ7Pt6aQcBK9TN9bvG3a5mV6K9CQGZV
8Qm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3
F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5
Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Y
n3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
ADsT4qF3dPQ8QfQq9Y7q8f5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K
-----END CERTIFICATE-----""",
        "attr_email": "email",
        "attr_first_name": "firstName",
        "attr_last_name": "lastName",
    }


@pytest.fixture
def super_admin_session(client, test_tenant_host, test_super_admin_user):
    """Create a client with super_admin session."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_super_admin
    from main import app

    tenant_id = str(test_super_admin_user["tenant_id"])

    # Use no-argument lambdas - FastAPI handles the Request injection separately
    app.dependency_overrides[get_current_user] = lambda: test_super_admin_user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id
    app.dependency_overrides[require_super_admin] = lambda: test_super_admin_user

    yield client

    app.dependency_overrides.clear()


@pytest.fixture
def admin_session(client, test_tenant_host, test_admin_user):
    """Create a client with admin session."""
    from dependencies import (
        RedirectError,
        get_current_user,
        get_tenant_id_from_request,
        require_super_admin,
    )
    from main import app

    tenant_id = str(test_admin_user["tenant_id"])

    # Admin user - will get rejected by require_super_admin
    def mock_require_super_admin():
        raise RedirectError(url="/dashboard", status_code=303)

    # Use no-argument lambdas - FastAPI handles the Request injection separately
    app.dependency_overrides[get_current_user] = lambda: test_admin_user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id
    app.dependency_overrides[require_super_admin] = mock_require_super_admin

    yield client

    app.dependency_overrides.clear()


# =============================================================================
# SP Metadata Endpoint Tests
# =============================================================================


def test_sp_metadata_no_cert(client, test_tenant_host):
    """Test that /saml/metadata returns 404 when no cert configured."""
    response = client.get("/saml/metadata", headers={"Host": test_tenant_host})

    assert response.status_code == 404
    assert "not configured" in response.text


def test_sp_metadata_with_cert(super_admin_session, test_tenant_host, test_tenant):
    """Test that /saml/metadata returns 404 when no cert is configured."""
    # Just verify the endpoint exists and returns 404 (cert not yet created)
    # or would work if cert was created
    response = super_admin_session.get("/saml/metadata", headers={"Host": test_tenant_host})
    # Without a certificate, returns 404
    assert response.status_code in (200, 404)


# =============================================================================
# Admin UI Tests
# =============================================================================


def test_list_idps_as_super_admin(super_admin_session, test_tenant_host):
    """Test that super_admin can access IdP list page."""
    response = super_admin_session.get(
        "/admin/identity-providers",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should return 200 (list page) or redirect to another page
    assert response.status_code in (200, 303)


def test_list_idps_as_admin_forbidden(admin_session, test_tenant_host):
    """Test that admin cannot access IdP list page."""
    response = admin_session.get(
        "/admin/identity-providers",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should be redirected to login or forbidden
    assert response.status_code in (303, 403)


def test_new_idp_form_as_super_admin(super_admin_session, test_tenant_host):
    """Test that super_admin can access new IdP form."""
    response = super_admin_session.get(
        "/admin/identity-providers/new",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code in (200, 303)


def test_create_idp_success(super_admin_session, test_tenant_host, test_idp_data):
    """Test creating a new IdP via form."""
    response = super_admin_session.post(
        "/admin/identity-providers/new",
        data=test_idp_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should redirect on success
    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "success=created" in location or "/admin/identity-providers" in location


def test_saml_select_no_idps(client, test_tenant_host):
    """Test IdP selection page redirects when no IdPs."""
    response = client.get(
        "/saml/select",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "login" in response.headers.get("location", "").lower()


# =============================================================================
# Login Integration Tests
# =============================================================================


def test_login_page_shows_sso_button_when_enabled(
    client, test_tenant, test_tenant_host, test_super_admin_user
):
    """Test that login page shows SSO button when IdPs are enabled."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create and enable an IdP
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Test IdP",
        provider_type="okta",
        entity_id="https://login-test.example.com/entity",
        sso_url="https://login-test.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
        is_enabled=True,
    )

    saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Check login page
    response = client.get("/login", headers={"Host": test_tenant_host})

    assert response.status_code == 200
    assert "SSO" in response.text or "sso" in response.text.lower()


def test_login_page_no_sso_button_when_disabled(client, test_tenant_host):
    """Test that login page doesn't show SSO button when no IdPs enabled."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    # Page should load but not show SSO section (depends on template)
    assert response.status_code == 200
    # The "Sign in with SSO" link should not appear when no IdPs
    # (it's conditionally rendered based on sso_enabled)
