"""Tests for the Service Providers REST API endpoints."""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from schemas.service_providers import (
    SPConfig,
    SPListItem,
    SPListResponse,
    SPMetadataURLInfo,
    SPSigningCertificate,
    SPSigningCertificateRotationResult,
)

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

    def test_get_returns_new_fields(self, sp_api_client, api_host, sample_sp):
        """GET returns sp_requested_attributes and attribute_mapping fields."""
        sp_with_mapping = sample_sp.model_copy(
            update={
                "sp_requested_attributes": [
                    {
                        "name": "urn:oid:0.9.2342.19200300.100.1.3",
                        "friendly_name": "mail",
                        "is_required": True,
                    }
                ],
                "attribute_mapping": {"email": "urn:oid:0.9.2342.19200300.100.1.3"},
            }
        )

        with patch(
            "services.service_providers.get_service_provider",
            return_value=sp_with_mapping,
        ):
            response = sp_api_client.get(
                f"/api/v1/service-providers/{sample_sp.id}",
                headers={"Host": api_host},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["sp_requested_attributes"] is not None
        assert len(data["sp_requested_attributes"]) == 1
        assert data["attribute_mapping"] == {"email": "urn:oid:0.9.2342.19200300.100.1.3"}

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


# =============================================================================
# IdP Metadata Info Endpoint
# =============================================================================


class TestIdPMetadataInfoAPI:
    """Tests for GET /api/v1/service-providers/idp-metadata-url."""

    def test_returns_metadata_info(self, sp_api_client, api_host):
        """Super admin gets IdP metadata info."""
        response = sp_api_client.get(
            "/api/v1/service-providers/idp-metadata-url",
            headers={"Host": api_host},
        )

        assert response.status_code == 200
        data = response.json()
        assert "metadata_url" in data
        assert "entity_id" in data
        assert "sso_url" in data
        assert data["metadata_url"].endswith("/saml/idp/metadata")
        assert data["entity_id"].endswith("/saml/idp/metadata")
        assert data["sso_url"].endswith("/saml/idp/sso")

    def test_unauthenticated_returns_401(self, client, api_host):
        """Unauthenticated requests return 401."""
        response = client.get(
            "/api/v1/service-providers/idp-metadata-url",
            headers={"Host": api_host},
        )

        assert response.status_code == 401

    def test_non_super_admin_rejected(self, client, api_admin_user, api_host, override_api_auth):
        """Non-super_admin role is rejected (no super_admin override applied)."""
        override_api_auth(api_admin_user, level="admin")

        response = client.get(
            "/api/v1/service-providers/idp-metadata-url",
            headers={"Host": api_host},
        )

        # Returns 401 because require_super_admin_api dependency is not overridden
        assert response.status_code == 401


# =============================================================================
# Per-SP Signing Certificate Endpoints
# =============================================================================


class TestGetSigningCertificateAPI:
    """Tests for GET /api/v1/service-providers/{sp_id}/signing-certificate."""

    def test_get_signing_cert_success(self, sp_api_client, api_host):
        """Super admin can get signing certificate info."""
        sp_id = str(uuid4())
        signing_cert = SPSigningCertificate(
            id=str(uuid4()),
            sp_id=sp_id,
            certificate_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
            expires_at=datetime(2036, 1, 1, tzinfo=UTC),
            created_at=datetime.now(UTC),
        )

        with patch(
            "services.service_providers.get_sp_signing_certificate",
            return_value=signing_cert,
        ):
            response = sp_api_client.get(
                f"/api/v1/service-providers/{sp_id}/signing-certificate",
                headers={"Host": api_host},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["sp_id"] == sp_id
        assert "certificate_pem" in data

    def test_get_signing_cert_not_found(self, sp_api_client, api_host):
        """Returns 404 when no signing cert exists."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.get_sp_signing_certificate",
            side_effect=NotFoundError(message="Signing certificate not found"),
        ):
            response = sp_api_client.get(
                f"/api/v1/service-providers/{sp_id}/signing-certificate",
                headers={"Host": api_host},
            )

        assert response.status_code == 404

    def test_unauthenticated_returns_401(self, client, api_host):
        """Unauthenticated requests return 401."""
        response = client.get(
            f"/api/v1/service-providers/{uuid4()}/signing-certificate",
            headers={"Host": api_host},
        )

        assert response.status_code == 401


class TestRotateSigningCertificateAPI:
    """Tests for POST /api/v1/service-providers/{sp_id}/signing-certificate/rotate."""

    def test_rotate_success(self, sp_api_client, api_host):
        """Super admin can rotate a signing certificate."""
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
            response = sp_api_client.post(
                f"/api/v1/service-providers/{sp_id}/signing-certificate/rotate",
                headers={"Host": api_host},
            )

        assert response.status_code == 200
        data = response.json()
        assert "new_certificate_pem" in data
        assert "grace_period_ends_at" in data

    def test_rotate_not_found(self, sp_api_client, api_host):
        """Returns 404 when no cert exists to rotate."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.rotate_sp_signing_certificate",
            side_effect=NotFoundError(message="No signing certificate exists"),
        ):
            response = sp_api_client.post(
                f"/api/v1/service-providers/{sp_id}/signing-certificate/rotate",
                headers={"Host": api_host},
            )

        assert response.status_code == 404

    def test_unauthenticated_returns_401(self, client, api_host):
        """Unauthenticated requests return 401."""
        response = client.post(
            f"/api/v1/service-providers/{uuid4()}/signing-certificate/rotate",
            headers={"Host": api_host},
        )

        assert response.status_code == 401


class TestGetSPMetadataURLAPI:
    """Tests for GET /api/v1/service-providers/{sp_id}/metadata-url."""

    def test_get_metadata_url_success(self, sp_api_client, api_host):
        """Super admin can get per-SP metadata URL info."""
        sp_id = str(uuid4())
        metadata_info = SPMetadataURLInfo(
            metadata_url=f"https://test.example.com/saml/idp/metadata/{sp_id}",
            entity_id=f"https://test.example.com/saml/idp/metadata/{sp_id}",
            sso_url="https://test.example.com/saml/idp/sso",
            sp_id=sp_id,
            sp_name="Test App",
        )

        with patch(
            "services.service_providers.get_sp_metadata_url_info",
            return_value=metadata_info,
        ):
            response = sp_api_client.get(
                f"/api/v1/service-providers/{sp_id}/metadata-url",
                headers={"Host": api_host},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["sp_id"] == sp_id
        assert sp_id in data["metadata_url"]

    def test_get_metadata_url_sp_not_found(self, sp_api_client, api_host):
        """Returns 404 when SP not found."""
        from services.exceptions import NotFoundError

        sp_id = str(uuid4())

        with patch(
            "services.service_providers.get_sp_metadata_url_info",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_api_client.get(
                f"/api/v1/service-providers/{sp_id}/metadata-url",
                headers={"Host": api_host},
            )

        assert response.status_code == 404

    def test_unauthenticated_returns_401(self, client, api_host):
        """Unauthenticated requests return 401."""
        response = client.get(
            f"/api/v1/service-providers/{uuid4()}/metadata-url",
            headers={"Host": api_host},
        )

        assert response.status_code == 401


# =============================================================================
# Update (PATCH) Endpoint
# =============================================================================


class TestUpdateAPI:
    """Tests for PATCH /api/v1/service-providers/{sp_id}."""

    def test_patch_success(self, sp_api_client, api_host, sample_sp):
        """Super admin can update SP via API."""
        updated_sp = sample_sp.model_copy(update={"name": "Updated App"})

        with patch(
            "services.service_providers.update_service_provider",
            return_value=updated_sp,
        ):
            response = sp_api_client.patch(
                f"/api/v1/service-providers/{sample_sp.id}",
                headers={"Host": api_host},
                json={"name": "Updated App"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated App"

    def test_patch_not_found(self, sp_api_client, api_host):
        """Non-existent SP returns 404."""
        from services.exceptions import NotFoundError

        with patch(
            "services.service_providers.update_service_provider",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_api_client.patch(
                f"/api/v1/service-providers/{uuid4()}",
                headers={"Host": api_host},
                json={"name": "Updated"},
            )

        assert response.status_code == 404

    def test_patch_validation_error(self, sp_api_client, api_host):
        """No fields provided returns 400."""
        from services.exceptions import ValidationError

        with patch(
            "services.service_providers.update_service_provider",
            side_effect=ValidationError(message="At least one field must be provided"),
        ):
            response = sp_api_client.patch(
                f"/api/v1/service-providers/{uuid4()}",
                headers={"Host": api_host},
                json={},
            )

        assert response.status_code == 400

    def test_patch_attribute_mapping(self, sp_api_client, api_host, sample_sp):
        """Can update attribute_mapping via PATCH."""
        new_mapping = {
            "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        }
        updated_sp = sample_sp.model_copy(update={"attribute_mapping": new_mapping})

        with patch(
            "services.service_providers.update_service_provider",
            return_value=updated_sp,
        ):
            response = sp_api_client.patch(
                f"/api/v1/service-providers/{sample_sp.id}",
                headers={"Host": api_host},
                json={"attribute_mapping": new_mapping},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["attribute_mapping"] == new_mapping

    def test_patch_unauthenticated(self, client, api_host):
        """Unauthenticated requests return 401."""
        response = client.patch(
            f"/api/v1/service-providers/{uuid4()}",
            headers={"Host": api_host},
            json={"name": "Updated"},
        )

        assert response.status_code == 401


# =============================================================================
# Enable Endpoint
# =============================================================================


class TestEnableAPI:
    """Tests for POST /api/v1/service-providers/{sp_id}/enable."""

    def test_enable_success(self, sp_api_client, api_host, sample_sp):
        """Super admin can enable SP via API."""
        enabled_sp = sample_sp.model_copy(update={"enabled": True})

        with patch(
            "services.service_providers.enable_service_provider",
            return_value=enabled_sp,
        ):
            response = sp_api_client.post(
                f"/api/v1/service-providers/{sample_sp.id}/enable",
                headers={"Host": api_host},
            )

        assert response.status_code == 200
        assert response.json()["enabled"] is True

    def test_enable_already_enabled(self, sp_api_client, api_host):
        """Already enabled SP returns 400."""
        from services.exceptions import ValidationError

        with patch(
            "services.service_providers.enable_service_provider",
            side_effect=ValidationError(message="Service provider is already enabled"),
        ):
            response = sp_api_client.post(
                f"/api/v1/service-providers/{uuid4()}/enable",
                headers={"Host": api_host},
            )

        assert response.status_code == 400

    def test_enable_not_found(self, sp_api_client, api_host):
        """Non-existent SP returns 404."""
        from services.exceptions import NotFoundError

        with patch(
            "services.service_providers.enable_service_provider",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_api_client.post(
                f"/api/v1/service-providers/{uuid4()}/enable",
                headers={"Host": api_host},
            )

        assert response.status_code == 404


# =============================================================================
# Disable Endpoint
# =============================================================================


class TestDisableAPI:
    """Tests for POST /api/v1/service-providers/{sp_id}/disable."""

    def test_disable_success(self, sp_api_client, api_host, sample_sp):
        """Super admin can disable SP via API."""
        disabled_sp = sample_sp.model_copy(update={"enabled": False})

        with patch(
            "services.service_providers.disable_service_provider",
            return_value=disabled_sp,
        ):
            response = sp_api_client.post(
                f"/api/v1/service-providers/{sample_sp.id}/disable",
                headers={"Host": api_host},
            )

        assert response.status_code == 200
        assert response.json()["enabled"] is False

    def test_disable_already_disabled(self, sp_api_client, api_host):
        """Already disabled SP returns 400."""
        from services.exceptions import ValidationError

        with patch(
            "services.service_providers.disable_service_provider",
            side_effect=ValidationError(message="Service provider is already disabled"),
        ):
            response = sp_api_client.post(
                f"/api/v1/service-providers/{uuid4()}/disable",
                headers={"Host": api_host},
            )

        assert response.status_code == 400

    def test_disable_not_found(self, sp_api_client, api_host):
        """Non-existent SP returns 404."""
        from services.exceptions import NotFoundError

        with patch(
            "services.service_providers.disable_service_provider",
            side_effect=NotFoundError(message="Service provider not found"),
        ):
            response = sp_api_client.post(
                f"/api/v1/service-providers/{uuid4()}/disable",
                headers={"Host": api_host},
            )

        assert response.status_code == 404
