"""Tests for the Service Providers REST API endpoints."""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from schemas.service_providers import SPConfig, SPListItem, SPListResponse

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def api_user():
    """Mock super admin user dict for API auth overrides."""
    tenant_id = str(uuid4())
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "role": "super_admin",
        "email": "admin@test.com",
        "first_name": "Test",
        "last_name": "Admin",
    }


@pytest.fixture
def api_admin_user():
    """Mock admin user (not super_admin) for forbidden tests."""
    tenant_id = str(uuid4())
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "role": "admin",
        "email": "admin@test.com",
    }


@pytest.fixture
def api_host(api_user):
    """Host header for API requests."""
    import settings

    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_api_tenant(api_user):
    """Mock tenant lookup for API requests."""
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": api_user["tenant_id"],
            "subdomain": "test",
        }
        yield


@pytest.fixture
def sp_api_client(client, api_user, override_api_auth):
    """Authenticated API client with super_admin."""
    override_api_auth(api_user, level="super_admin")
    return client


@pytest.fixture
def sample_sp_list():
    """Sample SP list response."""
    return SPListResponse(
        items=[
            SPListItem(
                id=str(uuid4()),
                name="API App",
                entity_id="https://api.example.com",
                created_at=datetime.now(UTC),
            ),
        ],
        total=1,
    )


@pytest.fixture
def sample_sp():
    """Sample SP config."""
    return SPConfig(
        id=str(uuid4()),
        name="API App",
        entity_id="https://api.example.com",
        acs_url="https://api.example.com/acs",
        nameid_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


# =============================================================================
# List Endpoints
# =============================================================================


class TestListAPI:
    """Tests for GET /api/v1/service-providers."""

    def test_list_success(self, sp_api_client, api_host, sample_sp_list):
        """Super admin can list SPs via API."""
        with patch(
            "services.service_providers.list_service_providers",
            return_value=sample_sp_list,
        ):
            response = sp_api_client.get(
                "/api/v1/service-providers/",
                headers={"Host": api_host},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["name"] == "API App"

    def test_list_unauthenticated(self, client, api_host):
        """Unauthenticated requests return 401."""
        response = client.get(
            "/api/v1/service-providers/",
            headers={"Host": api_host},
        )

        assert response.status_code == 401


# =============================================================================
# Create Endpoints
# =============================================================================


class TestCreateAPI:
    """Tests for POST /api/v1/service-providers."""

    def test_create_success(self, sp_api_client, api_host, sample_sp):
        """Super admin can create SP via API."""
        with patch(
            "services.service_providers.create_service_provider",
            return_value=sample_sp,
        ):
            response = sp_api_client.post(
                "/api/v1/service-providers/",
                headers={"Host": api_host},
                json={
                    "name": "API App",
                    "entity_id": "https://api.example.com",
                    "acs_url": "https://api.example.com/acs",
                },
            )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "API App"
        assert data["entity_id"] == "https://api.example.com"

    def test_create_validation_error(self, sp_api_client, api_host):
        """Invalid request body returns 422."""
        response = sp_api_client.post(
            "/api/v1/service-providers/",
            headers={"Host": api_host},
            json={"name": ""},  # Missing required fields
        )

        assert response.status_code == 422

    def test_create_conflict(self, sp_api_client, api_host):
        """Duplicate entity_id returns 409."""
        from services.exceptions import ConflictError

        with patch(
            "services.service_providers.create_service_provider",
            side_effect=ConflictError(message="Entity ID already exists"),
        ):
            response = sp_api_client.post(
                "/api/v1/service-providers/",
                headers={"Host": api_host},
                json={
                    "name": "Dup App",
                    "entity_id": "https://dup.example.com",
                    "acs_url": "https://dup.example.com/acs",
                },
            )

        assert response.status_code == 409


# =============================================================================
# Import XML Endpoint
# =============================================================================


class TestImportXMLAPI:
    """Tests for POST /api/v1/service-providers/import-xml."""

    def test_import_xml_success(self, sp_api_client, api_host, sample_sp):
        """Super admin can import SP from XML via API."""
        with patch(
            "services.service_providers.import_sp_from_metadata_xml",
            return_value=sample_sp,
        ):
            response = sp_api_client.post(
                "/api/v1/service-providers/import-xml",
                headers={"Host": api_host},
                json={
                    "name": "XML App",
                    "metadata_xml": "<xml>valid</xml>",
                },
            )

        assert response.status_code == 201
        assert response.json()["name"] == "API App"

    def test_import_xml_parse_error(self, sp_api_client, api_host):
        """Invalid XML returns 400."""
        from services.exceptions import ValidationError

        with patch(
            "services.service_providers.import_sp_from_metadata_xml",
            side_effect=ValidationError(message="Failed to parse XML"),
        ):
            response = sp_api_client.post(
                "/api/v1/service-providers/import-xml",
                headers={"Host": api_host},
                json={
                    "name": "Bad XML",
                    "metadata_xml": "not xml",
                },
            )

        assert response.status_code == 400


# =============================================================================
# Import URL Endpoint
# =============================================================================


class TestImportURLAPI:
    """Tests for POST /api/v1/service-providers/import-url."""

    def test_import_url_success(self, sp_api_client, api_host, sample_sp):
        """Super admin can import SP from URL via API."""
        with patch(
            "services.service_providers.import_sp_from_metadata_url",
            return_value=sample_sp,
        ):
            response = sp_api_client.post(
                "/api/v1/service-providers/import-url",
                headers={"Host": api_host},
                json={
                    "name": "URL App",
                    "metadata_url": "https://example.com/metadata",
                },
            )

        assert response.status_code == 201

    def test_import_url_fetch_error(self, sp_api_client, api_host):
        """Fetch failure returns 400."""
        from services.exceptions import ValidationError

        with patch(
            "services.service_providers.import_sp_from_metadata_url",
            side_effect=ValidationError(message="Connection refused"),
        ):
            response = sp_api_client.post(
                "/api/v1/service-providers/import-url",
                headers={"Host": api_host},
                json={
                    "name": "Bad URL",
                    "metadata_url": "https://unreachable.example.com",
                },
            )

        assert response.status_code == 400


# =============================================================================
# Get Endpoint
# =============================================================================


class TestGetAPI:
    """Tests for GET /api/v1/service-providers/{sp_id}."""

    def test_get_success(self, sp_api_client, api_host, sample_sp):
        """Super admin can get SP details."""
        with patch(
            "services.service_providers.get_service_provider",
            return_value=sample_sp,
        ):
            response = sp_api_client.get(
                f"/api/v1/service-providers/{sample_sp.id}",
                headers={"Host": api_host},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == sample_sp.id
        assert data["acs_url"] == "https://api.example.com/acs"

    def test_get_not_found(self, sp_api_client, api_host):
        """Non-existent SP returns 404."""
        from services.exceptions import NotFoundError

        with patch(
            "services.service_providers.get_service_provider",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_api_client.get(
                f"/api/v1/service-providers/{uuid4()}",
                headers={"Host": api_host},
            )

        assert response.status_code == 404


# =============================================================================
# Delete Endpoint
# =============================================================================


class TestDeleteAPI:
    """Tests for DELETE /api/v1/service-providers/{sp_id}."""

    def test_delete_success(self, sp_api_client, api_host):
        """Super admin can delete SP."""
        sp_id = str(uuid4())

        with patch(
            "services.service_providers.delete_service_provider",
            return_value=None,
        ):
            response = sp_api_client.delete(
                f"/api/v1/service-providers/{sp_id}",
                headers={"Host": api_host},
            )

        assert response.status_code == 204

    def test_delete_not_found(self, sp_api_client, api_host):
        """Deleting non-existent SP returns 404."""
        from services.exceptions import NotFoundError

        with patch(
            "services.service_providers.delete_service_provider",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_api_client.delete(
                f"/api/v1/service-providers/{uuid4()}",
                headers={"Host": api_host},
            )

        assert response.status_code == 404
