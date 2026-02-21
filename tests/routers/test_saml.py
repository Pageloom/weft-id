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
    app_dir = Path(__file__).parent.parent.parent / "app"
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
def super_admin_session(client, test_tenant_host, test_super_admin_user, override_auth):
    """Create a client with super_admin session."""
    override_auth(test_super_admin_user, level="super_admin")
    yield client


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
# Admin UI Tests
# =============================================================================


def test_list_idps_as_super_admin(super_admin_session, test_tenant_host):
    """Test that super_admin can access IdP list page."""
    response = super_admin_session.get(
        "/admin/settings/identity-providers",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should return 200 (list page) or redirect to another page
    assert response.status_code in (200, 303)


def test_list_idps_as_admin_forbidden(admin_session, test_tenant_host):
    """Test that admin cannot access IdP list page."""
    response = admin_session.get(
        "/admin/settings/identity-providers",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should be redirected to login or forbidden
    assert response.status_code in (303, 403)


def test_new_idp_form_as_super_admin(super_admin_session, test_tenant_host):
    """Test that super_admin can access new IdP form."""
    response = super_admin_session.get(
        "/admin/settings/identity-providers/new",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code in (200, 303)


def test_create_idp_success(super_admin_session, test_tenant_host, test_idp_data):
    """Test creating a new IdP via form."""
    response = super_admin_session.post(
        "/admin/settings/identity-providers/new",
        data=test_idp_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should redirect on success
    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "success=created" in location or "/admin/settings/identity-providers" in location


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
        f"/admin/settings/identity-providers/{idp.id}/toggle",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "success=enabled" in location or "/admin/settings/identity-providers" in location


def test_delete_idp_via_admin(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    """Test deleting a disabled IdP via the admin interface."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    # Create a disabled IdP to delete (is_enabled defaults to False)
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
        is_enabled=False,
    )

    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Delete the disabled IdP
    response = super_admin_session.post(
        f"/admin/settings/identity-providers/{idp.id}/delete",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "success=deleted" in location or "/admin/settings/identity-providers" in location


def test_view_idp_detail_redirects_to_details_tab(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    """Test that the IdP detail base URL redirects to the details tab."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

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

    # Base URL should redirect to /details tab
    response = super_admin_session.get(
        f"/admin/settings/identity-providers/{idp.id}",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert f"/admin/settings/identity-providers/{idp.id}/details" in location


def test_view_idp_details_tab(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    """Test viewing the IdP details tab renders correctly."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Detail Tab Test IdP",
        provider_type="azure_ad",
        entity_id="https://detail-tab-test.example.com/entity",
        sso_url="https://detail-tab-test.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
    )

    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # View the details tab
    response = super_admin_session.get(
        f"/admin/settings/identity-providers/{idp.id}/details",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Detail Tab Test IdP" in response.text
    # Verify trust page link is displayed (ACS URL moved to public trust page)
    assert "/pub/idp/" in response.text, "Trust page link not displayed in template"


def test_update_idp_name_via_form(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    """Test updating IdP name via the edit endpoint."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

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

    # Update name via the edit endpoint
    response = super_admin_session.post(
        f"/admin/settings/identity-providers/{idp.id}/edit",
        data={"name": "Updated IdP Name"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303, f"Expected 303, got {response.status_code}"
    location = response.headers.get("location", "")
    assert "success=updated" in location, f"Expected success=updated in location, got: {location}"

    # Verify the name was updated
    updated_idp = saml_service.get_identity_provider(requesting_user, idp.id)
    assert updated_idp.name == "Updated IdP Name"


def test_update_idp_attributes_via_form(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
):
    """Test updating IdP attribute mapping via the edit-attributes endpoint."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Attr Update Test IdP",
        provider_type="okta",
        entity_id="https://attr-update-test.example.com/entity",
        sso_url="https://attr-update-test.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
    )

    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Update attributes
    response = super_admin_session.post(
        f"/admin/settings/identity-providers/{idp.id}/edit-attributes",
        data={
            "attr_email": "user.email",
            "attr_first_name": "user.firstName",
            "attr_last_name": "user.lastName",
            "attr_groups": "user.groups",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "success=attributes_updated" in location

    # Verify the mapping was updated
    updated_idp = saml_service.get_identity_provider(requesting_user, idp.id)
    assert updated_idp.attribute_mapping["email"] == "user.email"
    assert updated_idp.attribute_mapping["first_name"] == "user.firstName"


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
        "/admin/settings/identity-providers/import-metadata-xml",
        data=form_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should redirect on success
    assert response.status_code == 303, f"Expected 303, got {response.status_code}"
    location = response.headers.get("location", "")
    assert "success=created" in location or "/admin/settings/identity-providers/" in location


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_import_idp_from_xml_invalid_xml(super_admin_session, test_tenant_host):
    """Test importing invalid XML returns error."""
    form_data = {
        "name": "Invalid XML Import",
        "provider_type": "generic",
        "metadata_xml": "not valid xml at all",
    }

    response = super_admin_session.post(
        "/admin/settings/identity-providers/import-metadata-xml",
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
        "/admin/settings/identity-providers/import-metadata-xml",
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
    from routers.saml import authentication as saml_router

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
    from routers.saml import authentication as saml_router

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
    from routers.saml import authentication as saml_router
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
    from routers.saml import authentication as saml_router
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
    from routers.saml import authentication as saml_router
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
    from routers.saml import authentication as saml_router
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
    from routers.saml import authentication as saml_router
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
    from routers.saml import authentication as saml_router
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
    from routers.saml import authentication as saml_router
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
    """Test ACS endpoint redirects to MFA verify when required and sends email code."""
    from routers.saml import authentication as saml_router
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

    # Mock email OTP sending
    monkeypatch.setattr(saml_router, "create_email_otp", lambda tid, uid: "123456")
    monkeypatch.setattr(
        saml_router,
        "emails_service",
        type(
            "MockEmailsService",
            (),
            {"get_primary_email": staticmethod(lambda tid, uid: test_user["email"])},
        )(),
    )
    send_calls = []
    monkeypatch.setattr(
        saml_router, "send_mfa_code_email", lambda email, code: send_calls.append((email, code))
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

    # Should redirect to MFA verify
    assert response.status_code == 303
    assert "/mfa/verify" in response.headers.get("location", "")

    # Should have sent email MFA code
    assert len(send_calls) == 1
    assert send_calls[0] == (test_user["email"], "123456")


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_saml_acs_mfa_totp_does_not_send_email(acs_test_setup, test_tenant_host, monkeypatch):
    """Test ACS endpoint does not send email code when MFA method is TOTP."""
    from routers.saml import authentication as saml_router
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
            requires_mfa=True,
        )

    def mock_authenticate(*args, **kwargs):
        return {
            "id": test_user["id"],
            "email": test_user["email"],
            "first_name": "Test",
            "last_name": "User",
            "mfa_method": "totp",  # TOTP, not email
        }

    monkeypatch.setattr(saml_service, "process_saml_response", mock_process_response)
    monkeypatch.setattr(saml_service, "authenticate_via_saml", mock_authenticate)

    # Mock email OTP sending — these should NOT be called
    otp_calls = []
    monkeypatch.setattr(
        saml_router, "create_email_otp", lambda tid, uid: otp_calls.append((tid, uid)) or "123456"
    )
    send_calls = []
    monkeypatch.setattr(
        saml_router, "send_mfa_code_email", lambda email, code: send_calls.append((email, code))
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

    # Should still redirect to MFA verify
    assert response.status_code == 303
    assert "/mfa/verify" in response.headers.get("location", "")

    # Should NOT have sent any email
    assert len(otp_calls) == 0
    assert len(send_calls) == 0


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

    saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

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


# =============================================================================
# SAML Phase 4: Single Logout (SLO) Endpoint Tests
# =============================================================================


def test_slo_get_without_params_redirects_to_login(client, test_tenant_host):
    """Test SLO GET endpoint redirects to login when no SAMLRequest/SAMLResponse."""
    from dependencies import get_tenant_id_from_request
    from main import app

    app.dependency_overrides[get_tenant_id_from_request] = lambda: "test-tenant-id"

    response = client.get(
        "/saml/slo",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "/login" in response.headers.get("location", "")
    assert "slo=complete" in response.headers.get("location", "")


def test_slo_get_with_logout_response_redirects_to_login(client, test_tenant_host):
    """Test SLO GET with SAMLResponse (SP-initiated callback) redirects to login."""
    from dependencies import get_tenant_id_from_request
    from main import app

    app.dependency_overrides[get_tenant_id_from_request] = lambda: "test-tenant-id"

    # Provide a dummy SAMLResponse (callback from IdP after SP-initiated logout)
    response = client.get(
        "/saml/slo?SAMLResponse=dummyresponse",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "/login" in response.headers.get("location", "")
    assert "slo=complete" in response.headers.get("location", "")


def test_slo_get_with_logout_request_processes_idp_initiated(
    client, test_tenant_host, test_tenant, test_super_admin_user, monkeypatch
):
    """Test SLO GET with SAMLRequest (IdP-initiated) processes and redirects."""
    from dependencies import get_tenant_id_from_request
    from main import app
    from services import saml as saml_service

    tenant_id = str(test_tenant["id"])
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    # Mock the service to return a redirect URL
    def mock_process_idp_logout(*args, **kwargs):
        return "https://idp.example.com/slo/callback?SAMLResponse=xyz"

    monkeypatch.setattr(saml_service, "process_idp_logout_request", mock_process_idp_logout)

    response = client.get(
        "/saml/slo?SAMLRequest=dummyrequest",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "idp.example.com" in response.headers.get("location", "")


def test_slo_get_idp_initiated_failure_redirects_to_login(
    client, test_tenant_host, test_tenant, monkeypatch
):
    """Test SLO GET with IdP-initiated logout failure still redirects to login."""
    from dependencies import get_tenant_id_from_request
    from main import app
    from services import saml as saml_service

    tenant_id = str(test_tenant["id"])
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    # Mock the service to return None (failure)
    monkeypatch.setattr(saml_service, "process_idp_logout_request", lambda *args, **kwargs: None)

    response = client.get(
        "/saml/slo?SAMLRequest=invalidrequest",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "/login" in response.headers.get("location", "")


def test_slo_post_without_params_redirects_to_login(client, test_tenant_host):
    """Test SLO POST endpoint redirects to login when no SAMLRequest/SAMLResponse."""
    from dependencies import get_tenant_id_from_request
    from main import app

    app.dependency_overrides[get_tenant_id_from_request] = lambda: "test-tenant-id"

    response = client.post(
        "/saml/slo",
        data={},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "/login" in response.headers.get("location", "")


def test_slo_post_with_logout_request_processes_idp_initiated(
    client, test_tenant_host, test_tenant, monkeypatch
):
    """Test SLO POST with SAMLRequest (IdP-initiated) processes and redirects."""
    from dependencies import get_tenant_id_from_request
    from main import app
    from services import saml as saml_service

    tenant_id = str(test_tenant["id"])
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    # Mock the service to return a redirect URL
    def mock_process_idp_logout(*args, **kwargs):
        return "https://idp.example.com/slo/response"

    monkeypatch.setattr(saml_service, "process_idp_logout_request", mock_process_idp_logout)

    response = client.post(
        "/saml/slo",
        data={"SAMLRequest": "dummyrequest"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "idp.example.com" in response.headers.get("location", "")


def test_slo_post_with_logout_response_redirects_to_login(client, test_tenant_host):
    """Test SLO POST with SAMLResponse (callback) redirects to login."""
    from dependencies import get_tenant_id_from_request
    from main import app

    app.dependency_overrides[get_tenant_id_from_request] = lambda: "test-tenant-id"

    response = client.post(
        "/saml/slo",
        data={"SAMLResponse": "dummyresponse"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "/login" in response.headers.get("location", "")


def test_slo_post_idp_initiated_failure_redirects_to_login(
    client, test_tenant_host, test_tenant, monkeypatch
):
    """Test SLO POST with IdP-initiated failure still redirects to login."""
    from dependencies import get_tenant_id_from_request
    from main import app
    from services import saml as saml_service

    tenant_id = str(test_tenant["id"])
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    # Mock the service to return None (failure)
    monkeypatch.setattr(saml_service, "process_idp_logout_request", lambda *args, **kwargs: None)

    response = client.post(
        "/saml/slo",
        data={"SAMLRequest": "invalidrequest"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "/login" in response.headers.get("location", "")


# =============================================================================
# SAML Phase 4: Debug Storage Router Tests
# =============================================================================


def test_debug_list_as_super_admin_success(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user, monkeypatch
):
    """Test debug list as super admin returns page successfully."""
    from services import saml as saml_service

    # Mock the list to return empty
    monkeypatch.setattr(saml_service, "list_saml_debug_entries", lambda *args, **kwargs: [])

    response = super_admin_session.get(
        "/admin/settings/identity-providers/debug",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 200


def test_debug_list_as_admin_forbidden(admin_session, test_tenant_host):
    """Test debug list as admin is forbidden."""
    response = admin_session.get(
        "/admin/settings/identity-providers/debug",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should be redirected (forbidden via RedirectError)
    assert response.status_code in (303, 403)


def test_debug_list_unauthenticated_redirects(client, test_tenant_host):
    """Test debug list when not authenticated redirects to login."""
    from dependencies import get_tenant_id_from_request
    from main import app

    app.dependency_overrides[get_tenant_id_from_request] = lambda: "test-tenant-id"

    response = client.get(
        "/admin/settings/identity-providers/debug",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    # Should redirect to login or return 401/403
    assert response.status_code in (303, 401, 403)


def test_debug_list_shows_entries(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user, monkeypatch
):
    """Test debug list shows recent debug entries."""
    from datetime import UTC, datetime

    from services import saml as saml_service

    # Mock entries as dicts (matching real service return type)
    mock_entries = [
        {
            "id": "entry-1",
            "created_at": datetime.now(UTC),
            "error_type": "signature_error",
            "error_detail": "Signature validation failed",
            "idp_name": "Test IdP",
        },
        {
            "id": "entry-2",
            "created_at": datetime.now(UTC),
            "error_type": "expired",
            "error_detail": "Assertion has expired",
            "idp_name": "Another IdP",
        },
    ]

    monkeypatch.setattr(
        saml_service, "list_saml_debug_entries", lambda *args, **kwargs: mock_entries
    )

    response = super_admin_session.get(
        "/admin/settings/identity-providers/debug",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 200
    # Check that entry info appears in response
    assert "signature_error" in response.text or "Signature" in response.text


def test_debug_detail_as_super_admin_success(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user, monkeypatch
):
    """Test debug detail as super admin returns page successfully."""
    from datetime import UTC, datetime

    from services import saml as saml_service

    # Mock the detail entry as a dict (matching database return format)
    mock_entry = {
        "id": "entry-123",
        "tenant_id": str(test_tenant["id"]),
        "idp_id": "idp-456",
        "idp_name": "Test IdP",
        "error_type": "signature_error",
        "error_detail": "Signature validation failed: Invalid signature",
        "saml_response_b64": None,
        "saml_response_xml": "<saml:Response>...</saml:Response>",
        "request_ip": "192.168.1.1",
        "user_agent": "Mozilla/5.0",
        "created_at": datetime.now(UTC),
    }

    monkeypatch.setattr(saml_service, "get_saml_debug_entry", lambda *args, **kwargs: mock_entry)

    response = super_admin_session.get(
        "/admin/settings/identity-providers/debug/entry-123",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 200


def test_debug_detail_not_found_redirects(super_admin_session, test_tenant_host, monkeypatch):
    """Test debug detail with invalid ID redirects with error."""
    from services import saml as saml_service
    from services.exceptions import NotFoundError

    # Mock the detail to raise NotFoundError
    def mock_get_entry(*args, **kwargs):
        raise NotFoundError(message="Debug entry not found", code="debug_entry_not_found")

    monkeypatch.setattr(saml_service, "get_saml_debug_entry", mock_get_entry)

    response = super_admin_session.get(
        "/admin/settings/identity-providers/debug/nonexistent-id",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "error=" in location or "debug" in location


def test_debug_detail_as_admin_forbidden(admin_session, test_tenant_host):
    """Test debug detail as admin is forbidden."""
    response = admin_session.get(
        "/admin/settings/identity-providers/debug/some-entry-id",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should be redirected (forbidden via RedirectError)
    assert response.status_code in (303, 403)


def test_debug_detail_shows_saml_xml(
    super_admin_session, test_tenant_host, test_tenant, test_super_admin_user, monkeypatch
):
    """Test debug detail shows decoded SAML XML."""
    from datetime import UTC, datetime

    from services import saml as saml_service

    # Mock entry with XML as a dict (matching database return format)
    mock_entry = {
        "id": "entry-xml",
        "tenant_id": str(test_tenant["id"]),
        "idp_id": None,
        "idp_name": "XML Test IdP",
        "error_type": "invalid_response",
        "error_detail": "Validation failed",
        "saml_response_b64": None,
        "saml_response_xml": "<saml:Response>TEST</saml:Response>",
        "request_ip": None,
        "user_agent": None,
        "created_at": datetime.now(UTC),
    }

    monkeypatch.setattr(saml_service, "get_saml_debug_entry", lambda *args, **kwargs: mock_entry)

    response = super_admin_session.get(
        "/admin/settings/identity-providers/debug/entry-xml",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 200
    # XML content should be visible in response (might be escaped)
    assert "saml" in response.text.lower() or "Response" in response.text


# =============================================================================
# SAML Phase 4: Integration Tests - Debug Storage on Auth Failure
# =============================================================================


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_saml_acs_error_creates_debug_entry(acs_test_setup, test_tenant_host, monkeypatch):
    """Test that SAML ACS errors create debug entries for troubleshooting."""
    from routers.saml import authentication as saml_router
    from services import saml as saml_service
    from services.exceptions import ValidationError

    idp = acs_test_setup["idp"]

    # Track if debug entry was stored
    debug_entry_stored = {"called": False, "error_type": None}

    original_store = saml_service.store_saml_debug_entry

    def mock_store_debug(*args, **kwargs):
        debug_entry_stored["called"] = True
        debug_entry_stored["error_type"] = kwargs.get("error_type")
        # Call original if it exists, or just pass
        try:
            return original_store(*args, **kwargs)
        except Exception:
            pass  # Ignore DB errors in test

    monkeypatch.setattr(saml_service, "store_saml_debug_entry", mock_store_debug)
    monkeypatch.setattr(saml_router, "extract_issuer_from_response", lambda x: idp.entity_id)

    # Mock validation to fail
    def mock_process(*args, **kwargs):
        raise ValidationError(
            message="Signature validation failed",
            code="saml_validation_failed",
        )

    monkeypatch.setattr(saml_service, "process_saml_response", mock_process)

    response = acs_test_setup["client"].post(
        "/saml/acs",
        data={
            "SAMLResponse": "ZmFrZXNhbWxyZXNwb25zZQ==",  # base64 "fakesamlresponse"
            "RelayState": "/dashboard",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    # Should return error page
    assert response.status_code == 200

    # Debug entry should have been stored
    assert debug_entry_stored["called"], "Debug entry should be stored on SAML error"
    assert debug_entry_stored["error_type"] == "signature_error"
