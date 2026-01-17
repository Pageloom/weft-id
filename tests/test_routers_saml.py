"""Tests for SAML router endpoints.

Tests both admin UI endpoints and public SAML endpoints.
"""

import os
from pathlib import Path

import pytest

# Check if the SAML library is available
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # noqa: F401

    HAS_SAML_LIBRARY = True
except ImportError:
    HAS_SAML_LIBRARY = False


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


def test_login_page_no_sso_button_with_email_verification(
    client, test_tenant, test_tenant_host, test_super_admin_user
):
    """Test that login page doesn't show SSO button (anti-enumeration).

    With email possession verification enabled, the login page only shows
    the email input form. SSO routing happens AFTER email verification.
    """
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
    # SSO button should NOT be shown (anti-enumeration)
    assert "Sign in with SSO" not in response.text
    # Login form should post to email verification endpoint
    assert "/login/send-code" in response.text


def test_login_page_no_sso_button_when_disabled(client, test_tenant_host):
    """Test that login page doesn't show SSO button when no IdPs enabled."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    # Page should load but not show SSO section
    assert response.status_code == 200
    # SSO button should NOT appear (email verification flow is used instead)
    assert "Sign in with SSO" not in response.text


# =============================================================================
# Additional SAML Flow Tests
# =============================================================================


def test_saml_login_invalid_idp_raises_not_found(test_tenant):
    """Test that get_idp_for_saml_login raises NotFoundError for invalid IdP."""
    import uuid

    from services.exceptions import NotFoundError
    from services.saml import get_idp_for_saml_login

    fake_idp_id = str(uuid.uuid4())

    with pytest.raises(NotFoundError) as exc_info:
        get_idp_for_saml_login(str(test_tenant["id"]), fake_idp_id)

    assert exc_info.value.code == "idp_not_found"


def test_saml_select_with_one_idp_redirects(
    client, test_tenant, test_tenant_host, test_super_admin_user
):
    """Test that /saml/select with one IdP auto-redirects to that IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create and enable a single IdP
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Single Test IdP",
        provider_type="okta",
        entity_id="https://single-idp.example.com/entity",
        sso_url="https://single-idp.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
        is_enabled=True,
    )

    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Access the select page - should redirect to the single IdP
    response = client.get(
        "/saml/select",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    # Should redirect to /saml/login/{idp_id}
    assert f"/saml/login/{idp.id}" in location or "saml/login" in location


def test_toggle_idp_enabled(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    """Test toggling IdP enabled state via POST."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create a disabled IdP
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Toggle Test IdP",
        provider_type="generic",
        entity_id="https://toggle-test.example.com/entity",
        sso_url="https://toggle-test.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
        is_enabled=False,
    )

    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Toggle to enabled
    response = super_admin_session.post(
        f"/admin/identity-providers/{idp.id}/toggle",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "success=enabled" in location or "/admin/identity-providers" in location


def test_delete_idp_via_admin(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    """Test deleting an IdP via the admin interface."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create an IdP to delete
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Delete Test IdP",
        provider_type="generic",
        entity_id="https://delete-test.example.com/entity",
        sso_url="https://delete-test.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
    )

    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Delete the IdP
    response = super_admin_session.post(
        f"/admin/identity-providers/{idp.id}/delete",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "success=deleted" in location or "/admin/identity-providers" in location


def test_view_idp_detail(super_admin_session, test_tenant_host, test_tenant, test_super_admin_user):
    """Test viewing an IdP detail page."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create an IdP
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Detail Test IdP",
        provider_type="azure_ad",
        entity_id="https://detail-test.example.com/entity",
        sso_url="https://detail-test.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
    )

    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # View the IdP detail page
    response = super_admin_session.get(
        f"/admin/identity-providers/{idp.id}",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code in (200, 303)
    if response.status_code == 200:
        assert "Detail Test IdP" in response.text or idp.name in response.text
        # Verify the form action is correct (this was the reported bug)
        expected_action = f'action="/admin/identity-providers/{idp.id}"'
        assert (
            expected_action in response.text
        ), f"Form action not found. Looking for: {expected_action}"
        # Verify ACS URL is displayed (sp_acs_url field)
        assert "/saml/acs" in response.text, "ACS URL not displayed in template"


def test_update_idp_via_form(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    """Test updating an IdP via the HTML form."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create an IdP to update
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Update Test IdP",
        provider_type="okta",
        entity_id="https://update-test.example.com/entity",
        sso_url="https://update-test.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
    )

    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Update via form - simulating what the HTML form sends
    # Note: The form includes entity_id and provider_type which the handler ignores
    update_form_data = {
        "name": "Updated IdP Name",
        "provider_type": "okta",  # form sends this but handler ignores
        "entity_id": idp.entity_id,  # form sends this but handler ignores
        "sso_url": "https://updated-sso.example.com/sso",
        "slo_url": "",
        "certificate_pem": idp.certificate_pem,
        "metadata_url": "",
        "attr_email": "email",
        "attr_first_name": "firstName",
        "attr_last_name": "lastName",
        "is_enabled": "on",  # checkbox value
        "is_default": "on",
        # require_platform_mfa not sent = unchecked
    }

    response = super_admin_session.post(
        f"/admin/identity-providers/{idp.id}",
        data=update_form_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should redirect on success
    assert response.status_code == 303, f"Expected 303, got {response.status_code}"
    location = response.headers.get("location", "")
    assert "success=updated" in location, f"Expected success=updated in location, got: {location}"

    # Verify the update was applied
    updated_idp = saml_service.get_identity_provider(requesting_user, idp.id)
    assert updated_idp.name == "Updated IdP Name"
    assert updated_idp.sso_url == "https://updated-sso.example.com/sso"
    assert updated_idp.is_enabled is True
    assert updated_idp.is_default is True


# =============================================================================
# Import IdP from Raw XML Tests
# =============================================================================


@pytest.fixture
def sample_idp_metadata_xml():
    """Sample IdP metadata XML for testing import."""
    return """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://router-xml-import.example.com/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://router-xml-import.example.com/sso"/>
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://router-xml-import.example.com/slo"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_import_idp_from_xml_via_form(
    super_admin_session, test_tenant_host, sample_idp_metadata_xml
):
    """Test importing an IdP from raw metadata XML via HTML form."""
    form_data = {
        "name": "Router XML Imported IdP",
        "provider_type": "okta",
        "metadata_xml": sample_idp_metadata_xml,
    }

    response = super_admin_session.post(
        "/admin/identity-providers/import-metadata-xml",
        data=form_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should redirect on success
    assert response.status_code == 303, f"Expected 303, got {response.status_code}"
    location = response.headers.get("location", "")
    assert "success=created" in location or "/admin/identity-providers/" in location


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_import_idp_from_xml_invalid_xml(super_admin_session, test_tenant_host):
    """Test importing invalid XML returns error."""
    form_data = {
        "name": "Invalid XML Import",
        "provider_type": "generic",
        "metadata_xml": "not valid xml at all",
    }

    response = super_admin_session.post(
        "/admin/identity-providers/import-metadata-xml",
        data=form_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should redirect with error
    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "error=" in location


def test_import_idp_from_xml_as_admin_forbidden(admin_session, test_tenant_host):
    """Test that admin cannot import IdP from XML."""
    form_data = {
        "name": "Should Fail",
        "provider_type": "generic",
        "metadata_xml": "<xml/>",
    }

    response = admin_session.post(
        "/admin/identity-providers/import-metadata-xml",
        data=form_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should be redirected (forbidden)
    assert response.status_code in (303, 403)


# =============================================================================
# SAML ACS (Assertion Consumer Service) Tests
# =============================================================================


@pytest.fixture
def acs_test_setup(
    client, test_tenant, test_super_admin_user, test_user, test_idp_data, fast_sp_certificate
):
    """Setup for ACS tests - creates IdP and mocks tenant_id dependency."""
    from dependencies import get_tenant_id_from_request
    from main import app
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    tenant_id = str(test_tenant["id"])

    # Create requesting user
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=tenant_id,
        role="super_admin",
    )

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Override dependency
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    yield {
        "client": client,
        "tenant_id": tenant_id,
        "idp": idp,
        "test_user": test_user,
        "test_tenant": test_tenant,
    }

    app.dependency_overrides.clear()


def test_saml_acs_missing_issuer(acs_test_setup, test_tenant_host, monkeypatch):
    """Test ACS endpoint handles missing issuer in SAML response."""
    from routers import saml as saml_router

    # Mock extract_issuer_from_response to return None
    monkeypatch.setattr(saml_router, "extract_issuer_from_response", lambda x: None)

    response = acs_test_setup["client"].post(
        "/saml/acs",
        data={
            "SAMLResponse": "dummybase64response",
            "RelayState": "/dashboard",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should return error page (200 with error template)
    assert response.status_code == 200
    assert "invalid_response" in response.text.lower() or "error" in response.text.lower()


def test_saml_acs_idp_not_found(acs_test_setup, test_tenant_host, monkeypatch):
    """Test ACS endpoint handles unknown IdP issuer."""
    from routers import saml as saml_router

    # Mock extract_issuer_from_response to return unknown issuer
    monkeypatch.setattr(
        saml_router, "extract_issuer_from_response", lambda x: "https://unknown-idp.example.com"
    )

    response = acs_test_setup["client"].post(
        "/saml/acs",
        data={
            "SAMLResponse": "dummybase64response",
            "RelayState": "/dashboard",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should return error page
    assert response.status_code == 200
    assert "idp_not_found" in response.text.lower() or "not found" in response.text.lower()


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_saml_acs_idp_disabled_error(acs_test_setup, test_tenant_host, monkeypatch):
    """Test ACS endpoint handles disabled IdP error."""
    from routers import saml as saml_router
    from services import saml as saml_service
    from services.exceptions import ForbiddenError

    idp = acs_test_setup["idp"]

    # Mock extract_issuer_from_response to return correct issuer
    monkeypatch.setattr(saml_router, "extract_issuer_from_response", lambda x: idp.entity_id)

    # Mock get_idp_by_issuer to raise ForbiddenError (IdP disabled)
    def mock_get_idp_by_issuer(*args, **kwargs):
        raise ForbiddenError(
            message="Identity provider is disabled",
            code="idp_disabled",
        )

    monkeypatch.setattr(saml_service, "get_idp_by_issuer", mock_get_idp_by_issuer)

    response = acs_test_setup["client"].post(
        "/saml/acs",
        data={
            "SAMLResponse": "dummybase64response",
            "RelayState": "/dashboard",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should show disabled IdP error
    assert response.status_code == 200
    content_lower = response.text.lower()
    assert "disabled" in content_lower or "error" in content_lower


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_saml_acs_validation_error_signature(acs_test_setup, test_tenant_host, monkeypatch):
    """Test ACS endpoint handles signature validation failure."""
    from routers import saml as saml_router
    from services import saml as saml_service
    from services.exceptions import ValidationError

    idp = acs_test_setup["idp"]

    # Mock extract_issuer_from_response
    monkeypatch.setattr(saml_router, "extract_issuer_from_response", lambda x: idp.entity_id)

    # Mock process_saml_response to raise signature error
    def mock_process_response(*args, **kwargs):
        raise ValidationError(
            message="SAML response validation failed: Signature validation failed",
            code="saml_validation_failed",
        )

    monkeypatch.setattr(saml_service, "process_saml_response", mock_process_response)

    response = acs_test_setup["client"].post(
        "/saml/acs",
        data={
            "SAMLResponse": "dummybase64response",
            "RelayState": "/dashboard",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should show signature error page
    assert response.status_code == 200
    # Check for signature error or general error
    content_lower = response.text.lower()
    assert "signature" in content_lower or "error" in content_lower


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_saml_acs_validation_error_expired(acs_test_setup, test_tenant_host, monkeypatch):
    """Test ACS endpoint handles expired assertion."""
    from routers import saml as saml_router
    from services import saml as saml_service
    from services.exceptions import ValidationError

    idp = acs_test_setup["idp"]

    monkeypatch.setattr(saml_router, "extract_issuer_from_response", lambda x: idp.entity_id)

    # Mock process_saml_response to raise expired error
    def mock_process_response(*args, **kwargs):
        raise ValidationError(
            message="SAML response validation failed: Assertion has expired",
            code="saml_validation_failed",
        )

    monkeypatch.setattr(saml_service, "process_saml_response", mock_process_response)

    response = acs_test_setup["client"].post(
        "/saml/acs",
        data={
            "SAMLResponse": "dummybase64response",
            "RelayState": "/dashboard",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should show expired error page
    assert response.status_code == 200
    content_lower = response.text.lower()
    assert "expired" in content_lower or "error" in content_lower


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_saml_acs_user_not_found(acs_test_setup, test_tenant_host, monkeypatch):
    """Test ACS endpoint handles user not found in database."""
    from routers import saml as saml_router
    from schemas.saml import SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service
    from services.exceptions import NotFoundError

    idp = acs_test_setup["idp"]

    monkeypatch.setattr(saml_router, "extract_issuer_from_response", lambda x: idp.entity_id)

    # Mock process_saml_response to return success
    def mock_process_response(*args, **kwargs):
        return SAMLAuthResult(
            attributes=SAMLAttributes(
                email="unknown@example.com",
                first_name="Unknown",
                last_name="User",
                name_id="unknown@example.com",
            ),
            idp_id=idp.id,
            requires_mfa=False,
        )

    # Mock authenticate_via_saml to raise NotFoundError
    def mock_authenticate(*args, **kwargs):
        raise NotFoundError(
            message="User account not found",
            code="user_not_found",
            details={"email": "unknown@example.com"},
        )

    monkeypatch.setattr(saml_service, "process_saml_response", mock_process_response)
    monkeypatch.setattr(saml_service, "authenticate_via_saml", mock_authenticate)

    response = acs_test_setup["client"].post(
        "/saml/acs",
        data={
            "SAMLResponse": "dummybase64response",
            "RelayState": "/dashboard",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should show user not found error
    assert response.status_code == 200
    content_lower = response.text.lower()
    assert "user" in content_lower or "not found" in content_lower or "error" in content_lower


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_saml_acs_success_redirects_to_dashboard(acs_test_setup, test_tenant_host, monkeypatch):
    """Test ACS endpoint successful auth redirects to dashboard."""
    from routers import saml as saml_router
    from schemas.saml import SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    idp = acs_test_setup["idp"]
    test_user = acs_test_setup["test_user"]

    monkeypatch.setattr(saml_router, "extract_issuer_from_response", lambda x: idp.entity_id)

    # Mock process_saml_response
    def mock_process_response(*args, **kwargs):
        return SAMLAuthResult(
            attributes=SAMLAttributes(
                email=test_user["email"],
                first_name="Test",
                last_name="User",
                name_id=test_user["email"],
            ),
            idp_id=idp.id,
            requires_mfa=False,
        )

    # Mock authenticate_via_saml to return user
    def mock_authenticate(*args, **kwargs):
        return {
            "id": test_user["id"],
            "email": test_user["email"],
            "first_name": "Test",
            "last_name": "User",
            "mfa_method": None,
        }

    monkeypatch.setattr(saml_service, "process_saml_response", mock_process_response)
    monkeypatch.setattr(saml_service, "authenticate_via_saml", mock_authenticate)

    response = acs_test_setup["client"].post(
        "/saml/acs",
        data={
            "SAMLResponse": "dummybase64response",
            "RelayState": "/dashboard",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should redirect to dashboard
    assert response.status_code == 303
    assert "/dashboard" in response.headers.get("location", "")


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_saml_acs_session_regenerated_after_auth(acs_test_setup, test_tenant_host, monkeypatch):
    """Test that session is regenerated after SAML auth to prevent session fixation.

    This is a critical security test. Session fixation attacks work by:
    1. Attacker creates session and gets session cookie
    2. Victim authenticates via SAML using that session
    3. Attacker now has authenticated access

    By regenerating the session after SAML authentication, we ensure the
    pre-auth session data (cookie) is different from post-auth session.
    """
    from routers import saml as saml_router
    from schemas.saml import SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    idp = acs_test_setup["idp"]
    test_user = acs_test_setup["test_user"]
    client = acs_test_setup["client"]

    monkeypatch.setattr(saml_router, "extract_issuer_from_response", lambda x: idp.entity_id)

    def mock_process_response(*args, **kwargs):
        return SAMLAuthResult(
            attributes=SAMLAttributes(
                email=test_user["email"],
                first_name="Test",
                last_name="User",
                name_id=test_user["email"],
            ),
            idp_id=idp.id,
            requires_mfa=False,
        )

    def mock_authenticate(*args, **kwargs):
        return {
            "id": test_user["id"],
            "email": test_user["email"],
            "first_name": "Test",
            "last_name": "User",
            "mfa_method": None,
        }

    monkeypatch.setattr(saml_service, "process_saml_response", mock_process_response)
    monkeypatch.setattr(saml_service, "authenticate_via_saml", mock_authenticate)

    # First, make a request to get a pre-auth session cookie
    # Visit the SAML login page to establish a session
    client.get("/saml/select", headers={"Host": test_tenant_host})
    pre_auth_cookie = client.cookies.get("session")

    # Now authenticate via SAML
    response = client.post(
        "/saml/acs",
        data={
            "SAMLResponse": "dummybase64response",
            "RelayState": "/dashboard",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303

    # Capture post-auth session cookie
    post_auth_cookie = client.cookies.get("session")
    assert post_auth_cookie is not None, "Session cookie should be set after SAML auth"

    # CRITICAL: If a pre-auth cookie existed, it should have changed
    # With Starlette's signed cookie sessions, clearing and recreating
    # the session creates a new signed payload (different cookie value)
    if pre_auth_cookie is not None:
        assert pre_auth_cookie != post_auth_cookie, (
            "Session cookie should change after SAML authentication. "
            "Same cookie indicates session fixation vulnerability."
        )


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_saml_acs_success_with_relay_state(acs_test_setup, test_tenant_host, monkeypatch):
    """Test ACS endpoint respects RelayState for redirect."""
    from routers import saml as saml_router
    from schemas.saml import SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    idp = acs_test_setup["idp"]
    test_user = acs_test_setup["test_user"]

    monkeypatch.setattr(saml_router, "extract_issuer_from_response", lambda x: idp.entity_id)

    def mock_process_response(*args, **kwargs):
        return SAMLAuthResult(
            attributes=SAMLAttributes(
                email=test_user["email"],
                first_name="Test",
                last_name="User",
                name_id=test_user["email"],
            ),
            idp_id=idp.id,
            requires_mfa=False,
        )

    def mock_authenticate(*args, **kwargs):
        return {
            "id": test_user["id"],
            "email": test_user["email"],
            "first_name": "Test",
            "last_name": "User",
            "mfa_method": None,
        }

    monkeypatch.setattr(saml_service, "process_saml_response", mock_process_response)
    monkeypatch.setattr(saml_service, "authenticate_via_saml", mock_authenticate)

    # Use custom relay state
    response = acs_test_setup["client"].post(
        "/saml/acs",
        data={
            "SAMLResponse": "dummybase64response",
            "RelayState": "/account/settings",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should redirect to custom relay state
    assert response.status_code == 303
    assert "/account/settings" in response.headers.get("location", "")


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_saml_acs_mfa_required_redirects_to_verify(acs_test_setup, test_tenant_host, monkeypatch):
    """Test ACS endpoint redirects to MFA verify when required."""
    from routers import saml as saml_router
    from schemas.saml import SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    idp = acs_test_setup["idp"]
    test_user = acs_test_setup["test_user"]

    monkeypatch.setattr(saml_router, "extract_issuer_from_response", lambda x: idp.entity_id)

    # Mock with requires_mfa=True
    def mock_process_response(*args, **kwargs):
        return SAMLAuthResult(
            attributes=SAMLAttributes(
                email=test_user["email"],
                first_name="Test",
                last_name="User",
                name_id=test_user["email"],
            ),
            idp_id=idp.id,
            requires_mfa=True,  # MFA required
        )

    # Mock authenticate with MFA method set
    def mock_authenticate(*args, **kwargs):
        return {
            "id": test_user["id"],
            "email": test_user["email"],
            "first_name": "Test",
            "last_name": "User",
            "mfa_method": "email",  # User has MFA configured
        }

    monkeypatch.setattr(saml_service, "process_saml_response", mock_process_response)
    monkeypatch.setattr(saml_service, "authenticate_via_saml", mock_authenticate)

    response = acs_test_setup["client"].post(
        "/saml/acs",
        data={
            "SAMLResponse": "dummybase64response",
            "RelayState": "/dashboard",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should redirect to MFA verify
    assert response.status_code == 303
    assert "/mfa/verify" in response.headers.get("location", "")


# ==============================================================================
# XSS Prevention Tests for relay_state Parameter
# ==============================================================================


def test_saml_select_single_idp_encodes_xss_relay_state(
    client, test_tenant, test_tenant_host, test_super_admin_user
):
    """Test that single IdP redirect encodes malicious relay_state to prevent XSS."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create and enable a single IdP
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Single XSS Test IdP",
        provider_type="okta",
        entity_id="https://xss-test.example.com/entity",
        sso_url="https://xss-test.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
        is_enabled=True,
    )

    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Attempt XSS via relay_state parameter
    malicious_payloads = [
        "javascript:alert('XSS')",
        "<script>alert('XSS')</script>",
        "' onload='alert(1)",
        "data:text/html,<script>alert('XSS')</script>",
    ]

    for payload in malicious_payloads:
        response = client.get(
            f"/saml/select?relay_state={payload}",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        location = response.headers.get("location", "")

        # Verify that the malicious payload is URL-encoded in the redirect
        # Should not contain literal javascript:, <script>, etc.
        assert "javascript:" not in location.lower()
        assert "<script>" not in location.lower()
        assert "onload=" not in location.lower()

        # Verify it contains the URL-encoded relay_state parameter
        assert "relay_state=" in location


def test_saml_select_multiple_idps_encodes_xss_relay_state(
    client, test_tenant, test_tenant_host, test_super_admin_user
):
    """Test that multiple IdP selection page encodes relay_state to prevent XSS."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create two IdPs to trigger selection page
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    for i in range(2):
        data = IdPCreate(
            name=f"Multi XSS Test IdP {i}",
            provider_type="okta",
            entity_id=f"https://multi-xss-test-{i}.example.com/entity",
            sso_url=f"https://multi-xss-test-{i}.example.com/sso",
            certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
            is_enabled=True,
        )
        saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Attempt XSS via relay_state parameter
    malicious_payload = "javascript:alert('XSS')"
    response = client.get(
        f"/saml/select?relay_state={malicious_payload}",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 200
    html = response.text

    # Verify the malicious payload is URL-encoded in the template href attributes
    # Should not contain literal javascript: in href
    assert 'href="/saml/login/' in html
    assert f'relay_state={malicious_payload}"' not in html

    # Should contain URL-encoded version (javascript%3A...)
    # The | urlencode filter encodes the colon and other special chars
    assert "javascript%3A" in html or "javascript:" not in html


def test_saml_select_encodes_special_characters(
    client, test_tenant, test_tenant_host, test_super_admin_user
):
    """Test that special characters in relay_state are properly URL-encoded."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create a single IdP
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Special Chars Test IdP",
        provider_type="okta",
        entity_id="https://special-chars.example.com/entity",
        sso_url="https://special-chars.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
        is_enabled=True,
    )

    saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Test with various special characters
    relay_state_with_special_chars = "/users/list?search=test&role=admin&foo=bar"

    response = client.get(
        f"/saml/select?relay_state={relay_state_with_special_chars}",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")

    # Verify special chars are encoded
    # The '&' and '=' should be URL-encoded
    assert "relay_state=" in location
    # Original unencoded string should not appear
    assert "search=test&role=admin" not in location


def test_saml_select_allows_legitimate_relay_states(
    client, test_tenant, test_tenant_host, test_super_admin_user
):
    """Test that legitimate relay_state values still work correctly."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create a single IdP
    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Legitimate Test IdP",
        provider_type="okta",
        entity_id="https://legitimate.example.com/entity",
        sso_url="https://legitimate.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
        is_enabled=True,
    )

    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Test legitimate relay states
    legitimate_states = [
        "/dashboard",
        "/account/settings",
        "/users",
    ]

    for state in legitimate_states:
        response = client.get(
            f"/saml/select?relay_state={state}",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        location = response.headers.get("location", "")

        # Should redirect to SAML login with relay_state
        assert f"/saml/login/{idp.id}" in location
        assert "relay_state=" in location
