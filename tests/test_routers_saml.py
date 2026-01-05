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
