"""Tests for SAML admin provider tab routes and post actions.

Covers tab GET routes (certificates, attributes, metadata, danger)
and POST actions (reimport, trust establishment, certificate rotation)
that are not covered by test_saml_crud_errors.py.
"""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.responses import HTMLResponse
from services.exceptions import NotFoundError, ServiceError, ValidationError


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


@pytest.fixture
def mock_idp():
    """Return a MagicMock with standard IdP attributes."""
    idp = MagicMock()
    idp.id = "test-idp-id"
    idp.name = "Test IdP"
    idp.provider_type = "okta"
    idp.entity_id = "https://idp.example.com"
    idp.sso_url = "https://idp.example.com/sso"
    idp.slo_url = None
    idp.is_enabled = True
    idp.is_default = False
    idp.metadata_xml = None
    idp.metadata_url = None
    return idp


# =============================================================================
# Tab GET Routes - Happy Paths
# =============================================================================


@patch("routers.saml.admin.providers.saml_service.get_idp_sp_certificate_for_display")
@patch("routers.saml.admin.providers.saml_service.get_unbound_domains")
@patch("routers.saml.admin.providers.saml_service.list_domain_bindings")
@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
@patch("routers.saml.admin.providers.templates.TemplateResponse")
def test_idp_tab_details_renders(
    mock_template,
    mock_get,
    mock_bindings,
    mock_unbound,
    mock_cert,
    super_admin_session,
    test_tenant_host,
    mock_idp,
):
    """Test details tab renders successfully."""
    mock_get.return_value = mock_idp
    mock_bindings.return_value = MagicMock(items=[])
    mock_unbound.return_value = []
    mock_cert.return_value = None
    mock_template.return_value = HTMLResponse(content="<html>details</html>")

    response = super_admin_session.get(
        "/admin/settings/identity-providers/test-idp-id/details",
        headers={"Host": test_tenant_host},
    )
    assert response.status_code == 200


@patch("routers.saml.admin.providers.saml_service.get_idp_sp_certificate_for_display")
@patch("routers.saml.admin.providers.saml_service.list_idp_certificates")
@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
@patch("routers.saml.admin.providers.templates.TemplateResponse")
def test_idp_tab_certificates_renders(
    mock_template,
    mock_get,
    mock_certs,
    mock_sp_cert,
    super_admin_session,
    test_tenant_host,
    mock_idp,
):
    """Test certificates tab renders successfully."""
    mock_get.return_value = mock_idp
    mock_certs.return_value = []
    mock_sp_cert.return_value = None
    mock_template.return_value = HTMLResponse(content="<html>certificates</html>")

    response = super_admin_session.get(
        "/admin/settings/identity-providers/test-idp-id/certificates",
        headers={"Host": test_tenant_host},
    )
    assert response.status_code == 200


@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
@patch("routers.saml.admin.providers.templates.TemplateResponse")
def test_idp_tab_attributes_renders(
    mock_template,
    mock_get,
    super_admin_session,
    test_tenant_host,
    mock_idp,
):
    """Test attributes tab renders successfully."""
    mock_get.return_value = mock_idp
    mock_template.return_value = HTMLResponse(content="<html>attributes</html>")

    response = super_admin_session.get(
        "/admin/settings/identity-providers/test-idp-id/attributes",
        headers={"Host": test_tenant_host},
    )
    assert response.status_code == 200


@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
@patch("routers.saml.admin.providers.templates.TemplateResponse")
def test_idp_tab_metadata_renders(
    mock_template,
    mock_get,
    super_admin_session,
    test_tenant_host,
    mock_idp,
):
    """Test metadata tab renders successfully."""
    mock_get.return_value = mock_idp
    mock_template.return_value = HTMLResponse(content="<html>metadata</html>")

    response = super_admin_session.get(
        "/admin/settings/identity-providers/test-idp-id/metadata",
        headers={"Host": test_tenant_host},
    )
    assert response.status_code == 200


@patch("routers.saml.admin.providers.saml_service.list_domain_bindings")
@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
@patch("routers.saml.admin.providers.templates.TemplateResponse")
def test_idp_tab_danger_renders(
    mock_template,
    mock_get,
    mock_bindings,
    super_admin_session,
    test_tenant_host,
    mock_idp,
):
    """Test danger tab renders successfully."""
    mock_get.return_value = mock_idp
    mock_bindings.return_value = MagicMock(items=[])
    mock_template.return_value = HTMLResponse(content="<html>danger</html>")

    response = super_admin_session.get(
        "/admin/settings/identity-providers/test-idp-id/danger",
        headers={"Host": test_tenant_host},
    )
    assert response.status_code == 200


# =============================================================================
# Tab GET Routes - Access Denied
# =============================================================================


@pytest.mark.parametrize(
    "tab_path,page_key",
    [
        ("test-idp-id", "/admin/settings/identity-providers/idp"),
        ("test-idp-id/details", "/admin/settings/identity-providers/idp/details"),
        ("test-idp-id/certificates", "/admin/settings/identity-providers/idp/certificates"),
        ("test-idp-id/attributes", "/admin/settings/identity-providers/idp/attributes"),
        ("test-idp-id/metadata", "/admin/settings/identity-providers/idp/metadata"),
        ("test-idp-id/danger", "/admin/settings/identity-providers/idp/danger"),
    ],
)
@patch("routers.saml.admin.providers.has_page_access")
def test_tab_access_denied_redirects_to_dashboard(
    mock_access,
    tab_path,
    page_key,
    super_admin_session,
    test_tenant_host,
):
    """Test tab redirects to dashboard when access denied."""
    mock_access.return_value = False

    response = super_admin_session.get(
        f"/admin/settings/identity-providers/{tab_path}",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# Tab GET Routes - NotFoundError
# =============================================================================


@pytest.mark.parametrize(
    "tab",
    ["details", "certificates", "attributes", "metadata", "danger"],
)
@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
def test_tab_not_found_redirects(
    mock_get,
    tab,
    super_admin_session,
    test_tenant_host,
):
    """Test tab redirect on NotFoundError."""
    mock_get.side_effect = NotFoundError("IdP not found")

    response = super_admin_session.get(
        f"/admin/settings/identity-providers/nonexistent/{tab}",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


# =============================================================================
# Tab GET Routes - ServiceError
# =============================================================================


@pytest.mark.parametrize(
    "tab",
    ["details", "certificates", "attributes", "metadata", "danger"],
)
@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
def test_tab_service_error_redirects(
    mock_get,
    tab,
    super_admin_session,
    test_tenant_host,
):
    """Test tab redirect on ServiceError."""
    mock_get.side_effect = ServiceError("Database error")

    response = super_admin_session.get(
        f"/admin/settings/identity-providers/some-id/{tab}",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]


# =============================================================================
# Certificates Tab - SP Certificate ServiceError
# =============================================================================


@patch("routers.saml.admin.providers.saml_service.get_idp_sp_certificate_for_display")
@patch("routers.saml.admin.providers.saml_service.list_idp_certificates")
@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
@patch("routers.saml.admin.providers.templates.TemplateResponse")
def test_certificates_tab_sp_cert_error_silenced(
    mock_template,
    mock_get,
    mock_certs,
    mock_sp_cert,
    super_admin_session,
    test_tenant_host,
    mock_idp,
):
    """Test certificates tab silences ServiceError from SP certificate lookup."""
    mock_get.return_value = mock_idp
    mock_certs.return_value = []
    mock_sp_cert.side_effect = ServiceError("SP cert error")
    mock_template.return_value = HTMLResponse(content="<html>certificates</html>")

    response = super_admin_session.get(
        "/admin/settings/identity-providers/test-idp-id/certificates",
        headers={"Host": test_tenant_host},
    )
    assert response.status_code == 200


# =============================================================================
# Reimport Metadata Tests
# =============================================================================


@patch("routers.saml.admin.providers.saml_service.update_identity_provider")
@patch("routers.saml.admin.providers.saml_service.parse_idp_metadata_xml_to_schema")
@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
def test_reimport_metadata_success(
    mock_get,
    mock_parse,
    mock_update,
    super_admin_session,
    test_tenant_host,
    mock_idp,
):
    """Test reimport metadata success."""
    mock_get.return_value = mock_idp
    mock_parsed = MagicMock()
    mock_parsed.sso_url = "https://new.example.com/sso"
    mock_parsed.slo_url = None
    mock_parsed.certificate_pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    mock_parse.return_value = mock_parsed

    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/reimport-metadata",
        data={"metadata_xml": "<EntityDescriptor>...</EntityDescriptor>"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=refreshed" in response.headers["location"]


@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
def test_reimport_metadata_not_found(
    mock_get,
    super_admin_session,
    test_tenant_host,
):
    """Test reimport metadata when IdP not found."""
    mock_get.side_effect = NotFoundError("IdP not found")

    response = super_admin_session.post(
        "/admin/settings/identity-providers/nonexistent/reimport-metadata",
        data={"metadata_xml": "<xml>"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_found" in response.headers["location"]


@patch("routers.saml.admin.providers.saml_service.parse_idp_metadata_xml_to_schema")
@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
def test_reimport_metadata_validation_error(
    mock_get,
    mock_parse,
    super_admin_session,
    test_tenant_host,
    mock_idp,
):
    """Test reimport metadata with invalid XML."""
    mock_get.return_value = mock_idp
    mock_parse.side_effect = ValidationError("Invalid XML format")

    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/reimport-metadata",
        data={"metadata_xml": "<bad>xml</bad>"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/test-idp-id/metadata" in response.headers["location"]
    assert "error=" in response.headers["location"]


@patch("routers.saml.admin.providers.saml_service.parse_idp_metadata_xml_to_schema")
@patch("routers.saml.admin.providers.saml_service.get_identity_provider")
def test_reimport_metadata_service_error(
    mock_get,
    mock_parse,
    super_admin_session,
    test_tenant_host,
    mock_idp,
):
    """Test reimport metadata service error."""
    mock_get.return_value = mock_idp
    mock_parse.side_effect = ServiceError("Parse failed")

    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/reimport-metadata",
        data={"metadata_xml": "<xml>"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/test-idp-id/metadata" in response.headers["location"]
    assert "error=" in response.headers["location"]


# =============================================================================
# Trust Establishment Tests
# =============================================================================


@patch("routers.saml.admin.providers.saml_service.import_idp_from_metadata_url")
def test_establish_trust_url_success(
    mock_import,
    super_admin_session,
    test_tenant_host,
):
    """Test establish trust via URL success."""
    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/establish-trust-url",
        data={"metadata_url": "https://idp.example.com/metadata"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=trust_established" in response.headers["location"]
    mock_import.assert_called_once()


@patch("routers.saml.admin.providers.saml_service.import_idp_from_metadata_url")
def test_establish_trust_url_validation_error(
    mock_import,
    super_admin_session,
    test_tenant_host,
):
    """Test establish trust via URL with validation error."""
    mock_import.side_effect = ValidationError("Invalid URL")

    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/establish-trust-url",
        data={"metadata_url": "not-a-url"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/test-idp-id/details" in response.headers["location"]
    assert "error=" in response.headers["location"]


@patch("routers.saml.admin.providers.saml_service.import_idp_from_metadata_url")
def test_establish_trust_url_service_error(
    mock_import,
    super_admin_session,
    test_tenant_host,
):
    """Test establish trust via URL with service error."""
    mock_import.side_effect = ServiceError("Fetch failed")

    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/establish-trust-url",
        data={"metadata_url": "https://idp.example.com/metadata"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/test-idp-id/details" in response.headers["location"]
    assert "error=" in response.headers["location"]


@patch("routers.saml.admin.providers.saml_service.import_idp_from_metadata_xml")
def test_establish_trust_xml_success(
    mock_import,
    super_admin_session,
    test_tenant_host,
):
    """Test establish trust via XML paste success."""
    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/establish-trust-xml",
        data={"metadata_xml": "<EntityDescriptor>...</EntityDescriptor>"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=trust_established" in response.headers["location"]
    mock_import.assert_called_once()


@patch("routers.saml.admin.providers.saml_service.import_idp_from_metadata_xml")
def test_establish_trust_xml_validation_error(
    mock_import,
    super_admin_session,
    test_tenant_host,
):
    """Test establish trust via XML with validation error."""
    mock_import.side_effect = ValidationError("Invalid XML")

    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/establish-trust-xml",
        data={"metadata_xml": "<bad>"},
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/test-idp-id/details" in response.headers["location"]
    assert "error=" in response.headers["location"]


@patch("routers.saml.admin.providers.saml_service.establish_idp_trust")
def test_establish_trust_manual_success(
    mock_establish,
    super_admin_session,
    test_tenant_host,
):
    """Test establish trust via manual config success."""
    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/establish-trust-manual",
        data={
            "entity_id": "https://idp.example.com",
            "sso_url": "https://idp.example.com/sso",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=trust_established" in response.headers["location"]
    mock_establish.assert_called_once()


@patch("routers.saml.admin.providers.saml_service.establish_idp_trust")
def test_establish_trust_manual_validation_error(
    mock_establish,
    super_admin_session,
    test_tenant_host,
):
    """Test establish trust via manual config with validation error."""
    mock_establish.side_effect = ValidationError("Invalid certificate")

    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/establish-trust-manual",
        data={
            "entity_id": "https://idp.example.com",
            "sso_url": "https://idp.example.com/sso",
            "certificate_pem": "invalid-cert",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/test-idp-id/details" in response.headers["location"]
    assert "error=" in response.headers["location"]


@patch("routers.saml.admin.providers.saml_service.establish_idp_trust")
def test_establish_trust_manual_service_error(
    mock_establish,
    super_admin_session,
    test_tenant_host,
):
    """Test establish trust via manual config with service error."""
    mock_establish.side_effect = ServiceError("Database error")

    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/establish-trust-manual",
        data={
            "entity_id": "https://idp.example.com",
            "sso_url": "https://idp.example.com/sso",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/test-idp-id/details" in response.headers["location"]
    assert "error=" in response.headers["location"]


# =============================================================================
# Certificate Rotation Tests
# =============================================================================


@patch("routers.saml.admin.providers.saml_service.rotate_idp_sp_certificate")
def test_rotate_sp_certificate_success(
    mock_rotate,
    super_admin_session,
    test_tenant_host,
):
    """Test SP certificate rotation success."""
    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/rotate-sp-certificate",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=rotated" in response.headers["location"]
    mock_rotate.assert_called_once()


@patch("routers.saml.admin.providers.saml_service.rotate_idp_sp_certificate")
def test_rotate_sp_certificate_not_found(
    mock_rotate,
    super_admin_session,
    test_tenant_host,
):
    """Test SP certificate rotation when IdP not found."""
    mock_rotate.side_effect = NotFoundError("IdP not found")

    response = super_admin_session.post(
        "/admin/settings/identity-providers/nonexistent/rotate-sp-certificate",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/nonexistent/certificates" in response.headers["location"]
    assert "error=" in response.headers["location"]


@patch("routers.saml.admin.providers.saml_service.rotate_idp_sp_certificate")
def test_rotate_sp_certificate_service_error(
    mock_rotate,
    super_admin_session,
    test_tenant_host,
):
    """Test SP certificate rotation service error."""
    mock_rotate.side_effect = ServiceError("Rotation failed")

    response = super_admin_session.post(
        "/admin/settings/identity-providers/test-idp-id/rotate-sp-certificate",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/test-idp-id/certificates" in response.headers["location"]
    assert "error=" in response.headers["location"]


# =============================================================================
# Import from Metadata Success Tests
# =============================================================================


@patch("routers.saml.admin.providers.saml_service.import_idp_from_metadata_url")
def test_import_from_metadata_url_success(
    mock_import,
    super_admin_session,
    test_tenant_host,
):
    """Test import from metadata URL success."""
    response = super_admin_session.post(
        "/admin/settings/identity-providers/import-metadata",
        data={
            "metadata_url": "https://idp.example.com/metadata",
            "provider_type": "okta",
            "name": "New IdP",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=created" in response.headers["location"]


@patch("routers.saml.admin.providers.saml_service.import_idp_from_metadata_xml")
def test_import_from_metadata_xml_success(
    mock_import,
    super_admin_session,
    test_tenant_host,
):
    """Test import from metadata XML success."""
    response = super_admin_session.post(
        "/admin/settings/identity-providers/import-metadata-xml",
        data={
            "metadata_xml": "<EntityDescriptor>...</EntityDescriptor>",
            "provider_type": "okta",
            "name": "New IdP",
        },
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=created" in response.headers["location"]
