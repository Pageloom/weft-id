"""Tests for the SAML IdP admin UI routes."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.responses import HTMLResponse
from schemas.service_providers import (
    SPConfig,
    SPGroupAssignmentList,
    SPListItem,
    SPListResponse,
    SPMetadataChangePreview,
    SPMetadataFieldChange,
    SPSigningCertificate,
    SPSigningCertificateRotationResult,
)

ROUTER_MODULE = "routers.saml_idp.admin"
METADATA_MODULE = "routers.saml_idp.metadata"

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sp_user():
    """Mock super admin user dict for dependency overrides."""
    tenant_id = str(uuid4())
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "role": "super_admin",
        "email": "admin@test.com",
        "first_name": "Test",
        "last_name": "Admin",
        "tz": "UTC",
        "locale": "en_US",
    }


@pytest.fixture
def sp_admin_session(client, sp_user, override_auth):
    """Client with super_admin session for SP routes."""
    override_auth(sp_user, level="super_admin")
    return client


@pytest.fixture
def sp_host(sp_user):
    """Host header matching the user's tenant."""
    import settings

    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_tenant_lookup(sp_user):
    """Mock tenant lookup so test host resolves to our test tenant."""
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": sp_user["tenant_id"],
            "subdomain": "test",
        }
        yield


@pytest.fixture
def sample_sp_list():
    """Sample SP list response."""
    return SPListResponse(
        items=[
            SPListItem(
                id=str(uuid4()),
                name="Test App",
                entity_id="https://app.example.com",
                created_at=datetime.now(UTC),
            ),
        ],
        total=1,
    )


@pytest.fixture
def sample_sp_config():
    """Sample SP config response."""
    return SPConfig(
        id=str(uuid4()),
        name="New App",
        entity_id="https://new.example.com",
        acs_url="https://new.example.com/acs",
        nameid_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


@pytest.fixture
def mock_sp_common(sample_sp_config):
    """Patch get_service_provider and count_sp_group_assignments for tab routes."""
    with (
        patch(
            "services.service_providers.get_service_provider",
            return_value=sample_sp_config,
        ),
        patch(
            "services.service_providers.count_sp_group_assignments",
            return_value=0,
        ),
    ):
        yield


# =============================================================================
# SP List Page
# =============================================================================


class TestSPListPage:
    """Tests for the SP list page."""

    def test_list_page_renders(self, sp_admin_session, sp_host, sample_sp_list, mocker):
        """SP list page renders for super admin."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>sp list</html>")

        with patch(
            "services.service_providers.list_service_providers",
            return_value=sample_sp_list,
        ):
            response = sp_admin_session.get(
                "/admin/settings/service-providers",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_list.html"
        ctx_kwargs = mock_ctx.call_args[1]
        assert "service_providers" in ctx_kwargs

    def test_list_page_empty(self, sp_admin_session, sp_host, mocker):
        """SP list page shows empty state when no SPs exist."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>empty</html>")

        empty = SPListResponse(items=[], total=0)

        with patch(
            "services.service_providers.list_service_providers",
            return_value=empty,
        ):
            response = sp_admin_session.get(
                "/admin/settings/service-providers",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["service_providers"] == []

    def test_list_page_shows_success_created(
        self, sp_admin_session, sp_host, sample_sp_list, mocker
    ):
        """SP list page passes success param to template context."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>success</html>")

        with patch(
            "services.service_providers.list_service_providers",
            return_value=sample_sp_list,
        ):
            response = sp_admin_session.get(
                "/admin/settings/service-providers?success=created",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["success"] == "created"


# =============================================================================
# SP New Page
# =============================================================================


class TestSPNewPage:
    """Tests for the SP registration form."""

    def test_new_page_renders(self, sp_admin_session, sp_host, mocker):
        """SP registration form renders."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>new sp</html>")

        response = sp_admin_session.get(
            "/admin/settings/service-providers/new",
            headers={"Host": sp_host},
        )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_new.html"


# =============================================================================
# SP Create (Manual)
# =============================================================================


class TestSPCreateManual:
    """Tests for manual SP creation."""

    def test_create_success(self, sp_admin_session, sp_host, sample_sp_config):
        """Successful manual creation redirects with success."""
        with patch(
            "services.service_providers.create_service_provider",
            return_value=sample_sp_config,
        ):
            response = sp_admin_session.post(
                "/admin/settings/service-providers/create",
                data={
                    "name": "New App",
                    "entity_id": "https://new.example.com",
                    "acs_url": "https://new.example.com/acs",
                },
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "success=created" in response.headers["location"]

    def test_create_missing_name(self, sp_admin_session, sp_host):
        """Missing name redirects with error."""
        response = sp_admin_session.post(
            "/admin/settings/service-providers/create",
            data={"name": "", "entity_id": "x", "acs_url": "x"},
            headers={"Host": sp_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]

    def test_create_missing_entity_id(self, sp_admin_session, sp_host):
        """Missing entity_id redirects with error."""
        response = sp_admin_session.post(
            "/admin/settings/service-providers/create",
            data={"name": "App", "entity_id": "", "acs_url": "x"},
            headers={"Host": sp_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]

    def test_create_missing_acs_url(self, sp_admin_session, sp_host):
        """Missing acs_url redirects with error."""
        response = sp_admin_session.post(
            "/admin/settings/service-providers/create",
            data={"name": "App", "entity_id": "x", "acs_url": ""},
            headers={"Host": sp_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]


# =============================================================================
# SP Import from XML
# =============================================================================


class TestSPImportXML:
    """Tests for SP import from metadata XML."""

    def test_import_xml_success(self, sp_admin_session, sp_host, sample_sp_config):
        """Successful XML import redirects with success."""
        with patch(
            "services.service_providers.import_sp_from_metadata_xml",
            return_value=sample_sp_config,
        ):
            response = sp_admin_session.post(
                "/admin/settings/service-providers/import-metadata-xml",
                data={"name": "XML App", "metadata_xml": "<xml>test</xml>"},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "success=created" in response.headers["location"]

    def test_import_xml_missing_name(self, sp_admin_session, sp_host):
        """Missing name redirects with error."""
        response = sp_admin_session.post(
            "/admin/settings/service-providers/import-metadata-xml",
            data={"name": "", "metadata_xml": "<xml/>"},
            headers={"Host": sp_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]


# =============================================================================
# SP Import from URL
# =============================================================================


class TestSPImportURL:
    """Tests for SP import from metadata URL."""

    def test_import_url_success(self, sp_admin_session, sp_host, sample_sp_config):
        """Successful URL import redirects with success."""
        with patch(
            "services.service_providers.import_sp_from_metadata_url",
            return_value=sample_sp_config,
        ):
            response = sp_admin_session.post(
                "/admin/settings/service-providers/import-metadata-url",
                data={"name": "URL App", "metadata_url": "https://example.com/metadata"},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "success=created" in response.headers["location"]


# =============================================================================
# SP Delete
# =============================================================================


class TestSPDelete:
    """Tests for SP deletion."""

    def test_delete_success(self, sp_admin_session, sp_host):
        """Successful deletion redirects with success."""
        sp_id = str(uuid4())

        with patch(
            "services.service_providers.delete_service_provider",
            return_value=None,
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/delete",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "success=deleted" in response.headers["location"]

    def test_delete_not_found(self, sp_admin_session, sp_host):
        """Deleting non-existent SP shows error."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.delete_service_provider",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/delete",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]

    def test_delete_enabled_sp_rejected(self, sp_admin_session, sp_host):
        """Deleting an enabled SP is rejected with an error."""
        from services.exceptions import ValidationError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.delete_service_provider",
            side_effect=ValidationError(
                message="Service provider must be disabled before it can be deleted"
            ),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/delete",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]


# =============================================================================
# IdP Metadata Endpoint
# =============================================================================

SAMPLE_IDP_METADATA_XML = '<?xml version="1.0"?><md:EntityDescriptor />'


class TestIdPMetadata:
    """Tests for the public IdP metadata endpoints."""

    def test_metadata_returns_xml(self, sp_admin_session, sp_host):
        """GET /saml/idp/metadata returns XML with correct content type."""
        with patch(
            "services.service_providers.get_tenant_idp_metadata_xml",
            return_value=SAMPLE_IDP_METADATA_XML,
        ):
            response = sp_admin_session.get(
                "/saml/idp/metadata",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        assert "application/xml" in response.headers["content-type"]
        assert "EntityDescriptor" in response.text

    def test_metadata_returns_404_when_no_cert(self, sp_admin_session, sp_host):
        """GET /saml/idp/metadata returns 404 when no cert configured."""
        from services.exceptions import NotFoundError

        with patch(
            "services.service_providers.get_tenant_idp_metadata_xml",
            side_effect=NotFoundError(message="IdP certificate not configured"),
        ):
            response = sp_admin_session.get(
                "/saml/idp/metadata",
                headers={"Host": sp_host},
            )

        assert response.status_code == 404
        assert "not configured" in response.text

    def test_metadata_download_sets_content_disposition(self, sp_admin_session, sp_host):
        """GET /saml/idp/metadata/download sets Content-Disposition header."""
        with patch(
            "services.service_providers.get_tenant_idp_metadata_xml",
            return_value=SAMPLE_IDP_METADATA_XML,
        ):
            response = sp_admin_session.get(
                "/saml/idp/metadata/download",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        assert 'attachment; filename="idp-metadata.xml"' in response.headers["content-disposition"]

    def test_metadata_download_returns_404_when_no_cert(self, sp_admin_session, sp_host):
        """GET /saml/idp/metadata/download returns 404 when no cert configured."""
        from services.exceptions import NotFoundError

        with patch(
            "services.service_providers.get_tenant_idp_metadata_xml",
            side_effect=NotFoundError(message="IdP certificate not configured"),
        ):
            response = sp_admin_session.get(
                "/saml/idp/metadata/download",
                headers={"Host": sp_host},
            )

        assert response.status_code == 404


# =============================================================================
# SP List Page with Metadata URL
# =============================================================================


class TestSPListMetadataURL:
    """Tests that metadata URL is no longer passed in SP list context."""

    def test_sp_list_does_not_include_metadata_url(
        self, sp_admin_session, sp_host, sample_sp_list, mocker
    ):
        """SP list page no longer passes idp_metadata_url to template context."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>sp list</html>")

        with patch(
            "services.service_providers.list_service_providers",
            return_value=sample_sp_list,
        ):
            response = sp_admin_session.get(
                "/admin/settings/service-providers",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        ctx_kwargs = mock_ctx.call_args[1]
        assert "idp_metadata_url" not in ctx_kwargs


# =============================================================================
# Per-SP Metadata Endpoint
# =============================================================================

SAMPLE_SP_METADATA_XML = '<?xml version="1.0"?><md:EntityDescriptor />'


class TestPerSPMetadata:
    """Tests for per-SP IdP metadata endpoints."""

    def test_per_sp_metadata_returns_xml(self, sp_admin_session, sp_host):
        """GET /saml/idp/metadata/{sp_id} returns XML with correct content type."""
        sp_id = str(uuid4())

        with patch(
            "services.service_providers.get_sp_idp_metadata_xml",
            return_value=SAMPLE_SP_METADATA_XML,
        ):
            response = sp_admin_session.get(
                f"/saml/idp/metadata/{sp_id}",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        assert "application/xml" in response.headers["content-type"]

    def test_per_sp_metadata_returns_404_when_not_found(self, sp_admin_session, sp_host):
        """GET /saml/idp/metadata/{sp_id} returns 404 when SP not found."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.get_sp_idp_metadata_xml",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_admin_session.get(
                f"/saml/idp/metadata/{sp_id}",
                headers={"Host": sp_host},
            )

        assert response.status_code == 404

    def test_per_sp_metadata_download(self, sp_admin_session, sp_host):
        """GET /saml/idp/metadata/{sp_id}/download sets Content-Disposition."""
        sp_id = str(uuid4())

        with patch(
            "services.service_providers.get_sp_idp_metadata_xml",
            return_value=SAMPLE_SP_METADATA_XML,
        ):
            response = sp_admin_session.get(
                f"/saml/idp/metadata/{sp_id}/download",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        assert "attachment" in response.headers["content-disposition"]


# =============================================================================
# SP Detail Redirect
# =============================================================================


class TestSPDetailRedirect:
    """Tests for the SP detail redirect to /details tab."""

    def test_detail_redirects_to_details_tab(self, sp_admin_session, sp_host, sample_sp_config):
        """GET /{sp_id} redirects to /{sp_id}/details."""
        response = sp_admin_session.get(
            f"/admin/settings/service-providers/{sample_sp_config.id}",
            headers={"Host": sp_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert f"/{sample_sp_config.id}/details" in response.headers["location"]


# =============================================================================
# SP Tab: Details
# =============================================================================


class TestSPTabDetails:
    """Tests for the Details tab."""

    def test_details_tab_renders(
        self, sp_admin_session, sp_host, sample_sp_config, mock_sp_common, mocker
    ):
        """Details tab renders with correct template and context."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>details tab</html>")

        response = sp_admin_session.get(
            f"/admin/settings/service-providers/{sample_sp_config.id}/details",
            headers={"Host": sp_host},
        )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_tab_details.html"
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["active_tab"] == "details"
        assert "sp" in ctx_kwargs
        assert "sp_metadata_url" in ctx_kwargs
        assert "group_count" in ctx_kwargs

    def test_details_tab_sp_not_found(self, sp_admin_session, sp_host):
        """Details tab redirects to list when SP not found."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with (
            patch(
                "services.service_providers.get_service_provider",
                side_effect=NotFoundError(message="Service provider not found"),
            ),
        ):
            response = sp_admin_session.get(
                f"/admin/settings/service-providers/{sp_id}/details",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]


# =============================================================================
# SP Tab: Attributes
# =============================================================================


class TestSPTabAttributes:
    """Tests for the Attributes tab."""

    def test_attributes_tab_renders(
        self, sp_admin_session, sp_host, sample_sp_config, mock_sp_common, mocker
    ):
        """Attributes tab renders with correct template and context."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>attributes tab</html>")

        response = sp_admin_session.get(
            f"/admin/settings/service-providers/{sample_sp_config.id}/attributes",
            headers={"Host": sp_host},
        )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_tab_attributes.html"
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["active_tab"] == "attributes"
        assert "saml_attributes" in ctx_kwargs


# =============================================================================
# SP Tab: Groups
# =============================================================================


class TestSPTabGroups:
    """Tests for the Groups tab."""

    def test_groups_tab_renders(
        self, sp_admin_session, sp_host, sample_sp_config, mock_sp_common, mocker
    ):
        """Groups tab renders with correct template and context."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>groups tab</html>")

        empty_assignments = SPGroupAssignmentList(items=[], total=0)

        with (
            patch(
                "services.service_providers.list_sp_group_assignments",
                return_value=empty_assignments,
            ),
            patch(
                "services.service_providers.list_available_groups_for_sp",
                return_value=[],
            ),
        ):
            response = sp_admin_session.get(
                f"/admin/settings/service-providers/{sample_sp_config.id}/groups",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_tab_groups.html"
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["active_tab"] == "groups"
        assert "assigned_groups" in ctx_kwargs
        assert "available_groups" in ctx_kwargs

    def test_groups_tab_with_assigned_groups(
        self, sp_admin_session, sp_host, sample_sp_config, mock_sp_common, mocker
    ):
        """Groups tab passes assigned and available groups to context."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>groups tab</html>")

        from schemas.service_providers import SPGroupAssignment

        assigned = SPGroupAssignmentList(
            items=[
                SPGroupAssignment(
                    id=str(uuid4()),
                    sp_id=sample_sp_config.id,
                    group_id=str(uuid4()),
                    group_name="Engineering",
                    group_description="Engineering team",
                    group_type="weftid",
                    assigned_by=str(uuid4()),
                    assigned_at=datetime.now(UTC),
                ),
            ],
            total=1,
        )
        available = [
            {"id": str(uuid4()), "name": "Marketing", "type": "weftid"},
        ]

        with (
            patch(
                "services.service_providers.list_sp_group_assignments",
                return_value=assigned,
            ),
            patch(
                "services.service_providers.list_available_groups_for_sp",
                return_value=available,
            ),
        ):
            response = sp_admin_session.get(
                f"/admin/settings/service-providers/{sample_sp_config.id}/groups",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        ctx_kwargs = mock_ctx.call_args[1]
        assert len(ctx_kwargs["assigned_groups"]) == 1
        assert len(ctx_kwargs["available_groups"]) == 1

    def test_groups_tab_service_error_still_renders(
        self, sp_admin_session, sp_host, sample_sp_config, mock_sp_common, mocker
    ):
        """Groups tab still renders when group fetching fails."""
        from services.exceptions import ServiceError

        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>groups tab</html>")

        with patch(
            "services.service_providers.list_sp_group_assignments",
            side_effect=ServiceError(message="Database error"),
        ):
            response = sp_admin_session.get(
                f"/admin/settings/service-providers/{sample_sp_config.id}/groups",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["assigned_groups"] == []
        assert ctx_kwargs["available_groups"] == []


# =============================================================================
# SP Tab: Certificates
# =============================================================================


class TestSPTabCertificates:
    """Tests for the Certificates tab."""

    def test_certificates_tab_renders(
        self, sp_admin_session, sp_host, sample_sp_config, mock_sp_common, mocker
    ):
        """Certificates tab renders with correct template and context."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>certificates tab</html>")

        signing_cert = SPSigningCertificate(
            id=str(uuid4()),
            sp_id=sample_sp_config.id,
            certificate_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
            expires_at=datetime(2036, 1, 1, tzinfo=UTC),
            created_at=datetime.now(UTC),
        )

        with patch(
            "services.service_providers.get_sp_signing_certificate",
            return_value=signing_cert,
        ):
            response = sp_admin_session.get(
                f"/admin/settings/service-providers/{sample_sp_config.id}/certificates",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_tab_certificates.html"
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["active_tab"] == "certificates"
        assert "signing_cert" in ctx_kwargs

    def test_certificates_tab_without_cert(
        self, sp_admin_session, sp_host, sample_sp_config, mock_sp_common, mocker
    ):
        """Certificates tab renders even when no signing cert exists."""
        from services.exceptions import NotFoundError

        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>certificates tab</html>")

        with patch(
            "services.service_providers.get_sp_signing_certificate",
            side_effect=NotFoundError(message="not found"),
        ):
            response = sp_admin_session.get(
                f"/admin/settings/service-providers/{sample_sp_config.id}/certificates",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["signing_cert"] is None


# =============================================================================
# SP Tab: Metadata
# =============================================================================


class TestSPTabMetadata:
    """Tests for the Metadata tab."""

    def test_metadata_tab_renders(
        self, sp_admin_session, sp_host, sample_sp_config, mock_sp_common, mocker
    ):
        """Metadata tab renders with correct template and context."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>metadata tab</html>")

        response = sp_admin_session.get(
            f"/admin/settings/service-providers/{sample_sp_config.id}/metadata",
            headers={"Host": sp_host},
        )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_tab_metadata.html"
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["active_tab"] == "metadata"


# =============================================================================
# SP Tab: Danger
# =============================================================================


class TestSPTabDanger:
    """Tests for the Danger tab."""

    def test_danger_tab_renders(
        self, sp_admin_session, sp_host, sample_sp_config, mock_sp_common, mocker
    ):
        """Danger tab renders with correct template and context."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>danger tab</html>")

        response = sp_admin_session.get(
            f"/admin/settings/service-providers/{sample_sp_config.id}/danger",
            headers={"Host": sp_host},
        )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_tab_danger.html"
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["active_tab"] == "danger"
        assert "assigned_group_count" in ctx_kwargs


# =============================================================================
# SP Certificate Rotation
# =============================================================================


class TestSPRotateCertificate:
    """Tests for SP certificate rotation via admin UI."""

    def test_rotate_success(self, sp_admin_session, sp_host):
        """Successful rotation redirects to certificates tab with success."""
        sp_id = str(uuid4())
        rotation_result = SPSigningCertificateRotationResult(
            new_certificate_pem="-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----",
            new_expires_at=datetime(2036, 1, 1, tzinfo=UTC),
            grace_period_ends_at=datetime.now(UTC),
        )

        with patch(
            "services.service_providers.rotate_sp_signing_certificate",
            return_value=rotation_result,
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/rotate-certificate",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/certificates" in response.headers["location"]
        assert "success=certificate_rotated" in response.headers["location"]

    def test_rotate_failure(self, sp_admin_session, sp_host):
        """Failed rotation redirects to certificates tab with error."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.rotate_sp_signing_certificate",
            side_effect=NotFoundError(message="No signing certificate exists"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/rotate-certificate",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/certificates" in response.headers["location"]
        assert "error=" in response.headers["location"]


# =============================================================================
# SP Add Group
# =============================================================================


class TestSPAddGroup:
    """Tests for assigning a group to a service provider."""

    def test_add_group_success(self, sp_admin_session, sp_host):
        """Successful group assignment redirects to groups tab with success."""
        sp_id = str(uuid4())
        group_id = str(uuid4())

        with patch("services.service_providers.assign_sp_to_group"):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/add",
                data={"group_id": group_id},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/groups" in response.headers["location"]
        assert "success=group_assigned" in response.headers["location"]

    def test_add_group_service_error(self, sp_admin_session, sp_host):
        """ServiceError during group assignment redirects to groups tab with error."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())
        group_id = str(uuid4())

        with patch(
            "services.service_providers.assign_sp_to_group",
            side_effect=NotFoundError(message="Group not found"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/add",
                data={"group_id": group_id},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/groups" in response.headers["location"]
        assert "error=" in response.headers["location"]

    def test_add_group_validation_error(self, sp_admin_session, sp_host):
        """ValidationError during group assignment redirects to groups tab with error."""
        from services.exceptions import ValidationError

        sp_id = str(uuid4())
        group_id = str(uuid4())

        with patch(
            "services.service_providers.assign_sp_to_group",
            side_effect=ValidationError(message="Group already assigned"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/add",
                data={"group_id": group_id},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]

    def test_add_group_missing_group_id(self, sp_admin_session, sp_host):
        """Missing group_id redirects with 'Please select a group' error."""
        sp_id = str(uuid4())

        response = sp_admin_session.post(
            f"/admin/settings/service-providers/{sp_id}/groups/add",
            data={"group_id": ""},
            headers={"Host": sp_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert (
            "error=Please+select+a+group" in response.headers["location"]
            or "error=Please%20select%20a%20group" in response.headers["location"]
        )
        assert f"/{sp_id}/groups" in response.headers["location"]

    def test_add_group_no_group_id_field(self, sp_admin_session, sp_host):
        """No group_id form field at all redirects with 'Please select a group' error."""
        sp_id = str(uuid4())

        response = sp_admin_session.post(
            f"/admin/settings/service-providers/{sp_id}/groups/add",
            data={},
            headers={"Host": sp_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]
        assert f"/{sp_id}/groups" in response.headers["location"]

    def test_add_group_whitespace_group_id(self, sp_admin_session, sp_host):
        """Whitespace-only group_id redirects with 'Please select a group' error."""
        sp_id = str(uuid4())

        response = sp_admin_session.post(
            f"/admin/settings/service-providers/{sp_id}/groups/add",
            data={"group_id": "   "},
            headers={"Host": sp_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]


# =============================================================================
# SP Bulk Add Groups
# =============================================================================


class TestSPBulkAddGroups:
    """Tests for bulk-assigning groups to a service provider."""

    def test_bulk_add_groups_success(self, sp_admin_session, sp_host):
        """Successful bulk group assignment redirects to groups tab with success."""
        from urllib.parse import urlencode

        sp_id = str(uuid4())
        group_ids = [str(uuid4()), str(uuid4()), str(uuid4())]

        body = urlencode([("group_ids", gid) for gid in group_ids])

        with patch("services.service_providers.bulk_assign_sp_to_groups"):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/bulk",
                content=body,
                headers={
                    "Host": sp_host,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/groups" in response.headers["location"]
        assert "success=groups_assigned" in response.headers["location"]

    def test_bulk_add_groups_single_group(self, sp_admin_session, sp_host):
        """Bulk assignment with a single group still works."""
        sp_id = str(uuid4())
        group_id = str(uuid4())

        with patch("services.service_providers.bulk_assign_sp_to_groups"):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/bulk",
                data={"group_ids": group_id},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "success=groups_assigned" in response.headers["location"]

    def test_bulk_add_groups_service_error(self, sp_admin_session, sp_host):
        """ServiceError during bulk assignment redirects to groups tab with error."""
        from urllib.parse import urlencode

        from services.exceptions import ValidationError

        sp_id = str(uuid4())
        group_ids = [str(uuid4())]
        body = urlencode([("group_ids", gid) for gid in group_ids])

        with patch(
            "services.service_providers.bulk_assign_sp_to_groups",
            side_effect=ValidationError(message="Some groups already assigned"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/bulk",
                content=body,
                headers={
                    "Host": sp_host,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/groups" in response.headers["location"]
        assert "error=" in response.headers["location"]

    def test_bulk_add_groups_not_found(self, sp_admin_session, sp_host):
        """NotFoundError during bulk assignment redirects to groups tab with error."""
        from urllib.parse import urlencode

        from services.exceptions import NotFoundError

        sp_id = str(uuid4())
        group_ids = [str(uuid4())]
        body = urlencode([("group_ids", gid) for gid in group_ids])

        with patch(
            "services.service_providers.bulk_assign_sp_to_groups",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/bulk",
                content=body,
                headers={
                    "Host": sp_host,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]

    def test_bulk_add_groups_empty_list(self, sp_admin_session, sp_host):
        """Empty group_ids list redirects with 'Please select groups' error."""
        sp_id = str(uuid4())

        response = sp_admin_session.post(
            f"/admin/settings/service-providers/{sp_id}/groups/bulk",
            data={},
            headers={"Host": sp_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]
        assert f"/{sp_id}/groups" in response.headers["location"]


# =============================================================================
# SP Remove Group
# =============================================================================


class TestSPRemoveGroup:
    """Tests for removing a group assignment from a service provider."""

    def test_remove_group_success(self, sp_admin_session, sp_host):
        """Successful group removal redirects to groups tab with success."""
        sp_id = str(uuid4())
        group_id = str(uuid4())

        with patch("services.service_providers.remove_sp_group_assignment"):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/{group_id}/remove",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/groups" in response.headers["location"]
        assert "success=group_removed" in response.headers["location"]

    def test_remove_group_not_found(self, sp_admin_session, sp_host):
        """Removing non-existent group assignment redirects to groups tab with error."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())
        group_id = str(uuid4())

        with patch(
            "services.service_providers.remove_sp_group_assignment",
            side_effect=NotFoundError(message="Group assignment not found"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/{group_id}/remove",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/groups" in response.headers["location"]
        assert "error=" in response.headers["location"]

    def test_remove_group_forbidden(self, sp_admin_session, sp_host):
        """ForbiddenError during group removal redirects with error."""
        from services.exceptions import ForbiddenError

        sp_id = str(uuid4())
        group_id = str(uuid4())

        with patch(
            "services.service_providers.remove_sp_group_assignment",
            side_effect=ForbiddenError(message="Insufficient permissions"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/{group_id}/remove",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]

    def test_remove_group_validation_error(self, sp_admin_session, sp_host):
        """ValidationError during group removal redirects with error."""
        from services.exceptions import ValidationError

        sp_id = str(uuid4())
        group_id = str(uuid4())

        with patch(
            "services.service_providers.remove_sp_group_assignment",
            side_effect=ValidationError(message="Cannot remove last group"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/groups/{group_id}/remove",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]


# =============================================================================
# SP Edit (Name/Description/URLs)
# =============================================================================


class TestSPEdit:
    """Tests for SP edit (update) via admin UI."""

    def test_edit_success(self, sp_admin_session, sp_host, sample_sp_config):
        """All fields submitted, redirects to details tab with success=updated."""
        sp_id = str(uuid4())

        with patch(
            "services.service_providers.update_service_provider",
            return_value=sample_sp_config,
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/edit",
                data={
                    "name": "Updated App",
                    "description": "New description",
                    "acs_url": "https://updated.example.com/acs",
                },
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/details" in response.headers["location"]
        assert "success=updated" in response.headers["location"]

    def test_edit_partial_fields(self, sp_admin_session, sp_host, sample_sp_config):
        """Only name submitted (description & acs_url empty), still succeeds."""
        sp_id = str(uuid4())

        with patch(
            "services.service_providers.update_service_provider",
            return_value=sample_sp_config,
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/edit",
                data={"name": "Just Name", "description": "", "acs_url": ""},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/details" in response.headers["location"]
        assert "success=updated" in response.headers["location"]

    def test_edit_no_changes(self, sp_admin_session, sp_host, sample_sp_config):
        """All text fields empty returns error about no changes."""
        sp_id = str(uuid4())

        response = sp_admin_session.post(
            f"/admin/settings/service-providers/{sp_id}/edit",
            data={"name": "", "description": "", "acs_url": ""},
            headers={"Host": sp_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert f"/{sp_id}/details" in response.headers["location"]
        assert "error=" in response.headers["location"]

    def test_edit_not_found(self, sp_admin_session, sp_host):
        """SP doesn't exist, redirects with error."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.update_service_provider",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/edit",
                data={"name": "Updated"},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]

    def test_edit_service_error(self, sp_admin_session, sp_host):
        """Service raises ValidationError, redirects with error."""
        from services.exceptions import ValidationError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.update_service_provider",
            side_effect=ValidationError(message="Invalid ACS URL"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/edit",
                data={"acs_url": "not-a-url"},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]


# =============================================================================
# SP Edit Attributes
# =============================================================================


class TestSPEditAttributes:
    """Tests for SP attribute edit via admin UI."""

    def test_edit_attributes_include_group_claims_on(
        self, sp_admin_session, sp_host, sample_sp_config
    ):
        """Submitting include_group_claims checkbox passes True to service."""
        sp_id = str(uuid4())

        with patch(
            "services.service_providers.update_service_provider",
            return_value=sample_sp_config,
        ) as mock_update:
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/edit-attributes",
                data={
                    "include_group_claims": "true",
                },
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/attributes" in response.headers["location"]
        assert "success=attributes_updated" in response.headers["location"]
        call_args = mock_update.call_args
        sp_update = call_args[0][2]
        assert sp_update.include_group_claims is True

    def test_edit_attributes_include_group_claims_off(
        self, sp_admin_session, sp_host, sample_sp_config
    ):
        """Omitting include_group_claims checkbox passes False to service."""
        sp_id = str(uuid4())

        with patch(
            "services.service_providers.update_service_provider",
            return_value=sample_sp_config,
        ) as mock_update:
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/edit-attributes",
                data={},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/attributes" in response.headers["location"]
        assert "success=attributes_updated" in response.headers["location"]
        call_args = mock_update.call_args
        sp_update = call_args[0][2]
        assert sp_update.include_group_claims is False

    def test_edit_attributes_service_error(self, sp_admin_session, sp_host):
        """Service error redirects to attributes tab with error."""
        from services.exceptions import ValidationError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.update_service_provider",
            side_effect=ValidationError(message="Invalid"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/edit-attributes",
                data={"include_group_claims": "true"},
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/attributes" in response.headers["location"]
        assert "error=" in response.headers["location"]


# =============================================================================
# SP Enable
# =============================================================================


class TestSPEnable:
    """Tests for enabling a service provider via admin UI."""

    def test_enable_success(self, sp_admin_session, sp_host, sample_sp_config):
        """Redirects to danger tab with success=enabled."""
        sp_id = str(uuid4())

        with patch(
            "services.service_providers.enable_service_provider",
            return_value=sample_sp_config,
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/enable",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/danger" in response.headers["location"]
        assert "success=enabled" in response.headers["location"]

    def test_enable_already_enabled(self, sp_admin_session, sp_host):
        """Already enabled SP redirects to danger tab with error."""
        from services.exceptions import ValidationError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.enable_service_provider",
            side_effect=ValidationError(message="Service provider is already enabled"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/enable",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/danger" in response.headers["location"]
        assert "error=" in response.headers["location"]

    def test_enable_not_found(self, sp_admin_session, sp_host):
        """Non-existent SP redirects with error."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.enable_service_provider",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/enable",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]


# =============================================================================
# SP Disable
# =============================================================================


class TestSPDisable:
    """Tests for disabling a service provider via admin UI."""

    def test_disable_success(self, sp_admin_session, sp_host, sample_sp_config):
        """Redirects to danger tab with success=disabled."""
        sp_id = str(uuid4())

        with patch(
            "services.service_providers.disable_service_provider",
            return_value=sample_sp_config,
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/disable",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/danger" in response.headers["location"]
        assert "success=disabled" in response.headers["location"]

    def test_disable_already_disabled(self, sp_admin_session, sp_host):
        """Already disabled SP redirects to danger tab with error."""
        from services.exceptions import ValidationError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.disable_service_provider",
            side_effect=ValidationError(message="Service provider is already disabled"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/disable",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/danger" in response.headers["location"]
        assert "error=" in response.headers["location"]

    def test_disable_not_found(self, sp_admin_session, sp_host):
        """Non-existent SP redirects with error."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.disable_service_provider",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/disable",
                headers={"Host": sp_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "error=" in response.headers["location"]


# =============================================================================
# Metadata Refresh Preview
# =============================================================================


class TestSPRefreshMetadataPreview:
    """Tests for POST /{sp_id}/refresh-metadata-preview."""

    def test_preview_renders_template(self, sp_admin_session, sp_host, mocker):
        """Preview route renders the preview template."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>preview</html>")

        sp_id = str(uuid4())
        preview = SPMetadataChangePreview(
            sp_id=sp_id,
            sp_name="Test App",
            source="url",
            changes=[
                SPMetadataFieldChange(
                    field="ACS URL",
                    old_value="https://old.example.com/acs",
                    new_value="https://new.example.com/acs",
                )
            ],
            has_changes=True,
        )

        with patch(
            "services.service_providers.preview_sp_metadata_refresh",
            return_value=preview,
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/refresh-metadata-preview",
                headers={"Host": sp_host},
                data={"csrf_token": "test"},
            )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_metadata_preview.html"

    def test_preview_error_redirects_to_metadata_tab(self, sp_admin_session, sp_host):
        """Preview error redirects to metadata tab with error."""
        from services.exceptions import ValidationError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.preview_sp_metadata_refresh",
            side_effect=ValidationError(message="No metadata URL configured"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/refresh-metadata-preview",
                headers={"Host": sp_host},
                data={"csrf_token": "test"},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/metadata" in response.headers["location"]
        assert "error=" in response.headers["location"]


# =============================================================================
# Metadata Refresh Apply
# =============================================================================


class TestSPRefreshMetadataApply:
    """Tests for POST /{sp_id}/refresh-metadata-apply."""

    def test_apply_redirects_to_metadata_tab_with_success(
        self, sp_admin_session, sp_host, sample_sp_config
    ):
        """Apply redirects to metadata tab with success message."""
        with patch(
            "services.service_providers.apply_sp_metadata_refresh",
            return_value=sample_sp_config,
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sample_sp_config.id}/refresh-metadata-apply",
                headers={"Host": sp_host},
                data={"csrf_token": "test"},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sample_sp_config.id}/metadata" in response.headers["location"]
        assert "success=metadata_refreshed" in response.headers["location"]

    def test_apply_error_redirects_to_metadata_tab(self, sp_admin_session, sp_host):
        """Apply error redirects to metadata tab with error."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.apply_sp_metadata_refresh",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/refresh-metadata-apply",
                headers={"Host": sp_host},
                data={"csrf_token": "test"},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/metadata" in response.headers["location"]
        assert "error=" in response.headers["location"]


# =============================================================================
# Metadata Reimport Preview
# =============================================================================


class TestSPReimportMetadataPreview:
    """Tests for POST /{sp_id}/reimport-metadata-preview."""

    def test_preview_renders_template(self, sp_admin_session, sp_host, mocker):
        """Preview route renders the preview template."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>preview</html>")

        sp_id = str(uuid4())
        preview = SPMetadataChangePreview(
            sp_id=sp_id,
            sp_name="Test App",
            source="xml",
            changes=[],
            has_changes=False,
        )

        with patch(
            "services.service_providers.preview_sp_metadata_reimport",
            return_value=preview,
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/reimport-metadata-preview",
                headers={"Host": sp_host},
                data={"csrf_token": "test", "metadata_xml": "<xml>test</xml>"},
            )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_metadata_preview.html"

    def test_preview_empty_xml_redirects_to_metadata_tab(self, sp_admin_session, sp_host):
        """Empty XML redirects to metadata tab with error."""
        sp_id = str(uuid4())

        response = sp_admin_session.post(
            f"/admin/settings/service-providers/{sp_id}/reimport-metadata-preview",
            headers={"Host": sp_host},
            data={"csrf_token": "test", "metadata_xml": ""},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert f"/{sp_id}/metadata" in response.headers["location"]
        assert "error=" in response.headers["location"]


# =============================================================================
# Metadata Reimport Apply
# =============================================================================


class TestSPReimportMetadataApply:
    """Tests for POST /{sp_id}/reimport-metadata-apply."""

    def test_apply_redirects_to_metadata_tab_with_success(
        self, sp_admin_session, sp_host, sample_sp_config
    ):
        """Apply redirects to metadata tab with success message."""
        with patch(
            "services.service_providers.apply_sp_metadata_reimport",
            return_value=sample_sp_config,
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sample_sp_config.id}/reimport-metadata-apply",
                headers={"Host": sp_host},
                data={"csrf_token": "test", "metadata_xml": "<xml>test</xml>"},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sample_sp_config.id}/metadata" in response.headers["location"]
        assert "success=metadata_reimported" in response.headers["location"]

    def test_apply_empty_xml_redirects_to_metadata_tab(self, sp_admin_session, sp_host):
        """Empty XML redirects to metadata tab with error."""
        sp_id = str(uuid4())

        response = sp_admin_session.post(
            f"/admin/settings/service-providers/{sp_id}/reimport-metadata-apply",
            headers={"Host": sp_host},
            data={"csrf_token": "test", "metadata_xml": ""},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert f"/{sp_id}/metadata" in response.headers["location"]
        assert "error=" in response.headers["location"]

    def test_apply_error_redirects_to_metadata_tab(self, sp_admin_session, sp_host):
        """Apply error redirects to metadata tab with error."""
        from services.exceptions import ValidationError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.apply_sp_metadata_reimport",
            side_effect=ValidationError(message="Invalid XML"),
        ):
            response = sp_admin_session.post(
                f"/admin/settings/service-providers/{sp_id}/reimport-metadata-apply",
                headers={"Host": sp_host},
                data={"csrf_token": "test", "metadata_xml": "bad xml"},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert f"/{sp_id}/metadata" in response.headers["location"]
        assert "error=" in response.headers["location"]
