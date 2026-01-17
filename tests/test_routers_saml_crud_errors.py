"""Tests for SAML router CRUD error handling paths.

This test file covers error paths in SAML admin endpoints:
- Create IdP validation and service errors
- Update IdP not found and service errors
- Toggle IdP not found and service errors
- Delete IdP not found and service errors
- Set default IdP not found and service errors
- Refresh metadata not found, validation, and service errors
- Import from URL validation and service errors
- Import from XML validation and service errors
- Edit IdP form not found and service errors
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from services.exceptions import NotFoundError, ServiceError, ValidationError


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


@pytest.fixture
def test_idp_data():
    """Provide test IdP data for form submissions."""
    return {
        "name": "Test IdP",
        "provider_type": "okta",
        "entity_id": "https://idp.example.com/entity",
        "sso_url": "https://idp.example.com/sso",
        "certificate_pem": """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
-----END CERTIFICATE-----""",
        "attr_email": "email",
        "attr_first_name": "firstName",
        "attr_last_name": "lastName",
    }


# =============================================================================
# Create IdP Error Tests
# =============================================================================


@patch("routers.saml.saml_service.create_identity_provider")
def test_create_idp_validation_error(
    mock_create, super_admin_session, test_tenant_host, test_idp_data
):
    """Test create IdP returns redirect with error on ValidationError."""
    mock_create.side_effect = ValidationError("Invalid certificate format")

    response = super_admin_session.post(
        "/admin/identity-providers/new",
        data=test_idp_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/new" in location
    assert "error=" in location


@patch("routers.saml.saml_service.create_identity_provider")
def test_create_idp_service_error(
    mock_create, super_admin_session, test_tenant_host, test_idp_data
):
    """Test create IdP returns redirect with error on ServiceError."""
    mock_create.side_effect = ServiceError("Database connection failed")

    response = super_admin_session.post(
        "/admin/identity-providers/new",
        data=test_idp_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/new" in location
    assert "error=" in location


# =============================================================================
# Import from URL Error Tests
# =============================================================================


@patch("routers.saml.saml_service.import_idp_from_metadata_url")
def test_import_from_url_validation_error(mock_import, super_admin_session, test_tenant_host):
    """Test import from URL returns redirect with error on ValidationError."""
    mock_import.side_effect = ValidationError("Invalid metadata URL")

    response = super_admin_session.post(
        "/admin/identity-providers/import-metadata",
        data={
            "metadata_url": "https://idp.example.com/metadata",
            "provider_type": "okta",
            "name": "Test IdP",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/new" in location
    assert "error=" in location


@patch("routers.saml.saml_service.import_idp_from_metadata_url")
def test_import_from_url_service_error(mock_import, super_admin_session, test_tenant_host):
    """Test import from URL returns redirect with error on ServiceError."""
    mock_import.side_effect = ServiceError("Failed to fetch metadata")

    response = super_admin_session.post(
        "/admin/identity-providers/import-metadata",
        data={
            "metadata_url": "https://idp.example.com/metadata",
            "provider_type": "okta",
            "name": "Test IdP",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/new" in location
    assert "error=" in location


# =============================================================================
# Import from XML Error Tests
# =============================================================================


@patch("routers.saml.saml_service.import_idp_from_metadata_xml")
def test_import_from_xml_validation_error(mock_import, super_admin_session, test_tenant_host):
    """Test import from XML returns redirect with error on ValidationError."""
    mock_import.side_effect = ValidationError("Invalid XML format")

    response = super_admin_session.post(
        "/admin/identity-providers/import-metadata-xml",
        data={
            "metadata_xml": "<invalid>xml</invalid>",
            "provider_type": "okta",
            "name": "Test IdP",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/new" in location
    assert "error=" in location


@patch("routers.saml.saml_service.import_idp_from_metadata_xml")
def test_import_from_xml_service_error(mock_import, super_admin_session, test_tenant_host):
    """Test import from XML returns redirect with error on ServiceError."""
    mock_import.side_effect = ServiceError("Failed to parse metadata")

    response = super_admin_session.post(
        "/admin/identity-providers/import-metadata-xml",
        data={
            "metadata_xml": "<EntityDescriptor>...</EntityDescriptor>",
            "provider_type": "okta",
            "name": "Test IdP",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/new" in location
    assert "error=" in location


# =============================================================================
# Edit IdP Form Error Tests
# =============================================================================


@patch("routers.saml.saml_service.get_identity_provider")
def test_edit_idp_form_not_found(mock_get, super_admin_session, test_tenant_host):
    """Test edit IdP form returns redirect on NotFoundError."""
    mock_get.side_effect = NotFoundError("IdP not found")

    response = super_admin_session.get(
        "/admin/identity-providers/non-existent-id",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers" in location
    assert "error=not_found" in location


@patch("routers.saml.saml_service.get_identity_provider")
def test_edit_idp_form_service_error(mock_get, super_admin_session, test_tenant_host):
    """Test edit IdP form returns redirect on ServiceError."""
    mock_get.side_effect = ServiceError("Database error")

    response = super_admin_session.get(
        "/admin/identity-providers/some-id",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers" in location
    assert "error=" in location


# =============================================================================
# Update IdP Error Tests
# =============================================================================


@patch("routers.saml.saml_service.update_identity_provider")
def test_update_idp_not_found(mock_update, super_admin_session, test_tenant_host, test_idp_data):
    """Test update IdP returns redirect on NotFoundError."""
    mock_update.side_effect = NotFoundError("IdP not found")

    response = super_admin_session.post(
        "/admin/identity-providers/non-existent-id",
        data=test_idp_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers" in location
    assert "error=not_found" in location


@patch("routers.saml.saml_service.update_identity_provider")
def test_update_idp_service_error(
    mock_update, super_admin_session, test_tenant_host, test_idp_data
):
    """Test update IdP returns redirect on ServiceError."""
    mock_update.side_effect = ServiceError("Update failed")

    response = super_admin_session.post(
        "/admin/identity-providers/some-id",
        data=test_idp_data,
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/some-id" in location
    assert "error=" in location


# =============================================================================
# Toggle IdP Error Tests
# =============================================================================


@patch("routers.saml.saml_service.get_identity_provider")
def test_toggle_idp_not_found(mock_get, super_admin_session, test_tenant_host):
    """Test toggle IdP returns redirect on NotFoundError."""
    mock_get.side_effect = NotFoundError("IdP not found")

    response = super_admin_session.post(
        "/admin/identity-providers/non-existent-id/toggle",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers" in location
    assert "error=not_found" in location


@patch("routers.saml.saml_service.get_identity_provider")
@patch("routers.saml.saml_service.set_idp_enabled")
def test_toggle_idp_service_error(mock_set, mock_get, super_admin_session, test_tenant_host):
    """Test toggle IdP returns redirect on ServiceError."""
    from unittest.mock import MagicMock

    mock_idp = MagicMock()
    mock_idp.is_enabled = True
    mock_get.return_value = mock_idp
    mock_set.side_effect = ServiceError("Toggle failed")

    response = super_admin_session.post(
        "/admin/identity-providers/some-id/toggle",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers" in location
    assert "error=" in location


# =============================================================================
# Set Default IdP Error Tests
# =============================================================================


@patch("routers.saml.saml_service.set_idp_default")
def test_set_default_idp_not_found(mock_set, super_admin_session, test_tenant_host):
    """Test set default IdP returns redirect on NotFoundError."""
    mock_set.side_effect = NotFoundError("IdP not found")

    response = super_admin_session.post(
        "/admin/identity-providers/non-existent-id/set-default",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers" in location
    assert "error=not_found" in location


@patch("routers.saml.saml_service.set_idp_default")
def test_set_default_idp_service_error(mock_set, super_admin_session, test_tenant_host):
    """Test set default IdP returns redirect on ServiceError."""
    mock_set.side_effect = ServiceError("Set default failed")

    response = super_admin_session.post(
        "/admin/identity-providers/some-id/set-default",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers" in location
    assert "error=" in location


# =============================================================================
# Refresh Metadata Error Tests
# =============================================================================


@patch("routers.saml.saml_service.refresh_idp_from_metadata")
def test_refresh_metadata_not_found(mock_refresh, super_admin_session, test_tenant_host):
    """Test refresh metadata returns redirect on NotFoundError."""
    mock_refresh.side_effect = NotFoundError("IdP not found")

    response = super_admin_session.post(
        "/admin/identity-providers/non-existent-id/refresh-metadata",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers" in location
    assert "error=not_found" in location


@patch("routers.saml.saml_service.refresh_idp_from_metadata")
def test_refresh_metadata_validation_error(mock_refresh, super_admin_session, test_tenant_host):
    """Test refresh metadata returns redirect on ValidationError."""
    mock_refresh.side_effect = ValidationError("No metadata URL configured")

    response = super_admin_session.post(
        "/admin/identity-providers/some-id/refresh-metadata",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/some-id" in location
    assert "error=" in location


@patch("routers.saml.saml_service.refresh_idp_from_metadata")
def test_refresh_metadata_service_error(mock_refresh, super_admin_session, test_tenant_host):
    """Test refresh metadata returns redirect on ServiceError."""
    mock_refresh.side_effect = ServiceError("Failed to fetch metadata")

    response = super_admin_session.post(
        "/admin/identity-providers/some-id/refresh-metadata",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers/some-id" in location
    assert "error=" in location


# =============================================================================
# Delete IdP Error Tests
# =============================================================================


@patch("routers.saml.saml_service.delete_identity_provider")
def test_delete_idp_not_found(mock_delete, super_admin_session, test_tenant_host):
    """Test delete IdP returns redirect on NotFoundError."""
    mock_delete.side_effect = NotFoundError("IdP not found")

    response = super_admin_session.post(
        "/admin/identity-providers/non-existent-id/delete",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers" in location
    assert "error=not_found" in location


@patch("routers.saml.saml_service.delete_identity_provider")
def test_delete_idp_service_error(mock_delete, super_admin_session, test_tenant_host):
    """Test delete IdP returns redirect on ServiceError."""
    mock_delete.side_effect = ServiceError("Cannot delete IdP with active users")

    response = super_admin_session.post(
        "/admin/identity-providers/some-id/delete",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert "/admin/identity-providers" in location
    assert "error=" in location


# =============================================================================
# Test IdP Connection Error Tests
# =============================================================================


@patch("routers.saml.saml_service.build_authn_request")
def test_test_idp_connection_not_found(mock_build, super_admin_session, test_tenant_host):
    """Test test connection returns error template on NotFoundError."""
    mock_build.side_effect = NotFoundError("IdP not found")

    response = super_admin_session.get(
        "/admin/identity-providers/non-existent-id/test",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "idp_not_found" in response.text or "not found" in response.text.lower()


@patch("routers.saml.saml_service.build_authn_request")
def test_test_idp_connection_service_error(mock_build, super_admin_session, test_tenant_host):
    """Test test connection returns error template on ServiceError."""
    mock_build.side_effect = ServiceError("SAML configuration error")

    response = super_admin_session.get(
        "/admin/identity-providers/some-id/test",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "configuration_error" in response.text or "error" in response.text.lower()


# =============================================================================
# List IdPs Service Error Test
# =============================================================================


@patch("routers.saml.saml_service.list_identity_providers")
def test_list_idps_service_error(mock_list, super_admin_session, test_tenant_host):
    """Test list IdPs returns error template on ServiceError."""
    mock_list.side_effect = ServiceError("Database connection failed")

    response = super_admin_session.get(
        "/admin/identity-providers",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "configuration_error" in response.text or "error" in response.text.lower()
