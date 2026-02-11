"""Tests for the SAML IdP admin UI routes."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.responses import HTMLResponse
from schemas.service_providers import (
    SPConfig,
    SPListItem,
    SPListResponse,
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
    """Tests for the metadata URL display on the SP list page."""

    def test_sp_list_includes_metadata_url(self, sp_admin_session, sp_host, sample_sp_list, mocker):
        """SP list page passes idp_metadata_url to template context."""
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
        assert "idp_metadata_url" in ctx_kwargs
        assert ctx_kwargs["idp_metadata_url"].endswith("/saml/idp/metadata")

    def test_sp_list_hides_metadata_url_when_empty(self, sp_admin_session, sp_host, mocker):
        """SP list page does not pass idp_metadata_url when no SPs exist."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>sp list</html>")

        empty_list = SPListResponse(items=[], total=0)
        with patch(
            "services.service_providers.list_service_providers",
            return_value=empty_list,
        ):
            response = sp_admin_session.get(
                "/admin/settings/service-providers",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["idp_metadata_url"] is None


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
# SP Detail Page
# =============================================================================


class TestSPDetailPage:
    """Tests for the SP detail page."""

    def test_detail_page_renders(self, sp_admin_session, sp_host, sample_sp_config, mocker):
        """SP detail page renders for super admin."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>sp detail</html>")

        signing_cert = SPSigningCertificate(
            id=str(uuid4()),
            sp_id=sample_sp_config.id,
            certificate_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
            expires_at=datetime(2036, 1, 1, tzinfo=UTC),
            created_at=datetime.now(UTC),
        )

        with (
            patch(
                "services.service_providers.get_service_provider",
                return_value=sample_sp_config,
            ),
            patch(
                "services.service_providers.get_sp_signing_certificate",
                return_value=signing_cert,
            ),
        ):
            response = sp_admin_session.get(
                f"/admin/settings/service-providers/{sample_sp_config.id}",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        mock_tmpl.assert_called_once()
        template_name = mock_tmpl.call_args[0][0]
        assert template_name == "saml_idp_sp_detail.html"
        ctx_kwargs = mock_ctx.call_args[1]
        assert "sp" in ctx_kwargs
        assert "signing_cert" in ctx_kwargs
        assert "sp_metadata_url" in ctx_kwargs

    def test_detail_page_without_cert(self, sp_admin_session, sp_host, sample_sp_config, mocker):
        """SP detail page renders even when no signing cert exists."""
        mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
        mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
        mock_ctx.return_value = {"request": MagicMock()}
        mock_tmpl.return_value = HTMLResponse(content="<html>sp detail</html>")

        from services.exceptions import NotFoundError

        with (
            patch(
                "services.service_providers.get_service_provider",
                return_value=sample_sp_config,
            ),
            patch(
                "services.service_providers.get_sp_signing_certificate",
                side_effect=NotFoundError(message="not found"),
            ),
        ):
            response = sp_admin_session.get(
                f"/admin/settings/service-providers/{sample_sp_config.id}",
                headers={"Host": sp_host},
            )

        assert response.status_code == 200
        ctx_kwargs = mock_ctx.call_args[1]
        assert ctx_kwargs["signing_cert"] is None


# =============================================================================
# SP Certificate Rotation
# =============================================================================


class TestSPRotateCertificate:
    """Tests for SP certificate rotation via admin UI."""

    def test_rotate_success(self, sp_admin_session, sp_host):
        """Successful rotation redirects with success."""
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
        assert "success=certificate_rotated" in response.headers["location"]

    def test_rotate_failure(self, sp_admin_session, sp_host):
        """Failed rotation redirects with error."""
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
        assert "error=" in response.headers["location"]
