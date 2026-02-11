"""Tests for the service_providers service layer."""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from services.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationError

SAMPLE_CERT_PEM = (
    "-----BEGIN CERTIFICATE-----\nMIICsDCCAZigAwIBAgIJALwzrJEIQ9UHMA0=\n-----END CERTIFICATE-----"
)

# =============================================================================
# Helpers
# =============================================================================


def _make_sp_row(
    tenant_id: str | None = None,
    sp_id: str | None = None,
    name: str = "Test App",
    entity_id: str = "https://app.example.com/saml/metadata",
    acs_url: str = "https://app.example.com/saml/acs",
) -> dict:
    """Create a mock SP database row."""
    return {
        "id": sp_id or str(uuid4()),
        "tenant_id": tenant_id or str(uuid4()),
        "name": name,
        "entity_id": entity_id,
        "acs_url": acs_url,
        "certificate_pem": None,
        "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "metadata_xml": None,
        "created_by": str(uuid4()),
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }


# =============================================================================
# list_service_providers
# =============================================================================


class TestListServiceProviders:
    """Tests for list_service_providers."""

    def test_success_as_super_admin(self, make_requesting_user):
        """Super admin can list SPs."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        row = _make_sp_row(tenant_id=tenant_id)

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.track_activity"),
        ):
            mock_db.service_providers.list_service_providers.return_value = [row]

            result = sp_service.list_service_providers(requesting_user)

            assert result.total == 1
            assert len(result.items) == 1
            assert result.items[0].name == "Test App"

    def test_empty_list(self, make_requesting_user):
        """Returns empty list when no SPs exist."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="super_admin")

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.track_activity"),
        ):
            mock_db.service_providers.list_service_providers.return_value = []

            result = sp_service.list_service_providers(requesting_user)

            assert result.total == 0
            assert result.items == []

    def test_forbidden_for_admin(self, make_requesting_user):
        """Admin role cannot list SPs."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="admin")

        with pytest.raises(ForbiddenError):
            sp_service.list_service_providers(requesting_user)

    def test_forbidden_for_user(self, make_requesting_user):
        """Regular user cannot list SPs."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="user")

        with pytest.raises(ForbiddenError):
            sp_service.list_service_providers(requesting_user)


# =============================================================================
# get_service_provider
# =============================================================================


class TestGetServiceProvider:
    """Tests for get_service_provider."""

    def test_success(self, make_requesting_user):
        """Super admin can get an SP by ID."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id)

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.track_activity"),
        ):
            mock_db.service_providers.get_service_provider.return_value = row

            result = sp_service.get_service_provider(requesting_user, sp_id)

            assert result.id == sp_id
            assert result.name == "Test App"

    def test_not_found(self, make_requesting_user):
        """Raises NotFoundError for non-existent SP."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="super_admin")

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.track_activity"),
        ):
            mock_db.service_providers.get_service_provider.return_value = None

            with pytest.raises(NotFoundError, match="Service provider not found"):
                sp_service.get_service_provider(requesting_user, str(uuid4()))


# =============================================================================
# create_service_provider
# =============================================================================


class TestCreateServiceProvider:
    """Tests for create_service_provider."""

    def test_success(self, make_requesting_user):
        """Super admin can create an SP."""
        from schemas.service_providers import SPCreate
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        data = SPCreate(
            name="New App",
            entity_id="https://new.example.com",
            acs_url="https://new.example.com/acs",
        )
        row = _make_sp_row(
            tenant_id=tenant_id,
            sp_id=sp_id,
            name="New App",
            entity_id="https://new.example.com",
            acs_url="https://new.example.com/acs",
        )

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.log_event"),
        ):
            mock_db.service_providers.get_service_provider_by_entity_id.return_value = None
            mock_db.service_providers.create_service_provider.return_value = row

            result = sp_service.create_service_provider(requesting_user, data)

            assert result.id == sp_id
            assert result.name == "New App"
            mock_db.service_providers.create_service_provider.assert_called_once()

    def test_duplicate_entity_id(self, make_requesting_user):
        """Raises ConflictError for duplicate entity ID."""
        from schemas.service_providers import SPCreate
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        data = SPCreate(
            name="Duplicate",
            entity_id="https://existing.example.com",
            acs_url="https://existing.example.com/acs",
        )

        with patch("services.service_providers.database") as mock_db:
            mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
                "id": str(uuid4())
            }

            with pytest.raises(ConflictError, match="already exists"):
                sp_service.create_service_provider(requesting_user, data)

    def test_creation_failure(self, make_requesting_user):
        """Raises ValidationError if database returns None."""
        from schemas.service_providers import SPCreate
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="super_admin")
        data = SPCreate(
            name="Fail",
            entity_id="https://fail.example.com",
            acs_url="https://fail.example.com/acs",
        )

        with patch("services.service_providers.database") as mock_db:
            mock_db.service_providers.get_service_provider_by_entity_id.return_value = None
            mock_db.service_providers.create_service_provider.return_value = None

            with pytest.raises(ValidationError, match="Failed to create"):
                sp_service.create_service_provider(requesting_user, data)

    def test_logs_event(self, make_requesting_user):
        """Creating an SP logs a service_provider_created event."""
        from schemas.service_providers import SPCreate
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        data = SPCreate(
            name="Logged App",
            entity_id="https://logged.example.com",
            acs_url="https://logged.example.com/acs",
        )
        row = _make_sp_row(tenant_id=tenant_id, name="Logged App")

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.log_event") as mock_log,
        ):
            mock_db.service_providers.get_service_provider_by_entity_id.return_value = None
            mock_db.service_providers.create_service_provider.return_value = row

            sp_service.create_service_provider(requesting_user, data)

            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args[1]
            assert call_kwargs["event_type"] == "service_provider_created"
            assert call_kwargs["metadata"]["method"] == "manual"


# =============================================================================
# import_sp_from_metadata_xml
# =============================================================================


class TestImportSPFromMetadataXML:
    """Tests for import_sp_from_metadata_xml."""

    def test_success(self, make_requesting_user):
        """Import SP from valid metadata XML."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        parsed = {
            "entity_id": "https://parsed.example.com",
            "acs_url": "https://parsed.example.com/acs",
            "certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        }
        row = _make_sp_row(
            tenant_id=tenant_id,
            entity_id="https://parsed.example.com",
            acs_url="https://parsed.example.com/acs",
        )

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.log_event"),
            patch("utils.saml_idp.parse_sp_metadata_xml", return_value=parsed),
        ):
            mock_db.service_providers.get_service_provider_by_entity_id.return_value = None
            mock_db.service_providers.create_service_provider.return_value = row

            result = sp_service.import_sp_from_metadata_xml(
                requesting_user, name="Parsed App", metadata_xml="<xml/>"
            )

            assert result.entity_id == "https://parsed.example.com"

    def test_invalid_xml(self, make_requesting_user):
        """Raises ValidationError for unparseable XML."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="super_admin")

        with patch(
            "utils.saml_idp.parse_sp_metadata_xml",
            side_effect=ValueError("Invalid XML"),
        ):
            with pytest.raises(ValidationError, match="Invalid XML"):
                sp_service.import_sp_from_metadata_xml(
                    requesting_user, name="Bad", metadata_xml="not xml"
                )

    def test_logs_event_with_metadata_xml_method(self, make_requesting_user):
        """Import from XML logs with method=metadata_xml."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        parsed = {
            "entity_id": "https://xml.example.com",
            "acs_url": "https://xml.example.com/acs",
            "certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        }
        row = _make_sp_row(tenant_id=tenant_id)

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.log_event") as mock_log,
            patch("utils.saml_idp.parse_sp_metadata_xml", return_value=parsed),
        ):
            mock_db.service_providers.get_service_provider_by_entity_id.return_value = None
            mock_db.service_providers.create_service_provider.return_value = row

            sp_service.import_sp_from_metadata_xml(
                requesting_user, name="XML App", metadata_xml="<xml/>"
            )

            call_kwargs = mock_log.call_args[1]
            assert call_kwargs["metadata"]["method"] == "metadata_xml"


# =============================================================================
# import_sp_from_metadata_url
# =============================================================================


class TestImportSPFromMetadataURL:
    """Tests for import_sp_from_metadata_url."""

    def test_success(self, make_requesting_user):
        """Import SP from metadata URL."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        parsed = {
            "entity_id": "https://url.example.com",
            "acs_url": "https://url.example.com/acs",
            "certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        }
        row = _make_sp_row(tenant_id=tenant_id)

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.log_event"),
            patch("utils.saml_idp.fetch_sp_metadata", return_value="<xml/>"),
            patch("utils.saml_idp.parse_sp_metadata_xml", return_value=parsed),
        ):
            mock_db.service_providers.get_service_provider_by_entity_id.return_value = None
            mock_db.service_providers.create_service_provider.return_value = row

            result = sp_service.import_sp_from_metadata_url(
                requesting_user,
                name="URL App",
                metadata_url="https://url.example.com/metadata",
            )

            assert result.name == "Test App"

    def test_fetch_failure(self, make_requesting_user):
        """Raises ValidationError if metadata fetch fails."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="super_admin")

        with patch(
            "utils.saml_idp.fetch_sp_metadata",
            side_effect=ValueError("Connection refused"),
        ):
            with pytest.raises(ValidationError, match="Connection refused"):
                sp_service.import_sp_from_metadata_url(
                    requesting_user,
                    name="Bad URL",
                    metadata_url="https://unreachable.example.com",
                )

    def test_logs_event_with_metadata_url_method(self, make_requesting_user):
        """Import from URL logs with method=metadata_url."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        parsed = {
            "entity_id": "https://logged-url.example.com",
            "acs_url": "https://logged-url.example.com/acs",
            "certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        }
        row = _make_sp_row(tenant_id=tenant_id)

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.log_event") as mock_log,
            patch("utils.saml_idp.fetch_sp_metadata", return_value="<xml/>"),
            patch("utils.saml_idp.parse_sp_metadata_xml", return_value=parsed),
        ):
            mock_db.service_providers.get_service_provider_by_entity_id.return_value = None
            mock_db.service_providers.create_service_provider.return_value = row

            sp_service.import_sp_from_metadata_url(
                requesting_user,
                name="URL App",
                metadata_url="https://logged-url.example.com/metadata",
            )

            call_kwargs = mock_log.call_args[1]
            assert call_kwargs["metadata"]["method"] == "metadata_url"
            assert (
                call_kwargs["metadata"]["metadata_url"] == "https://logged-url.example.com/metadata"
            )


# =============================================================================
# delete_service_provider
# =============================================================================


class TestDeleteServiceProvider:
    """Tests for delete_service_provider."""

    def test_success(self, make_requesting_user):
        """Super admin can delete an SP."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id)

        with (
            patch("services.service_providers.database") as mock_db,
            patch("services.service_providers.log_event") as mock_log,
        ):
            mock_db.service_providers.get_service_provider.return_value = row
            mock_db.service_providers.delete_service_provider.return_value = 1

            sp_service.delete_service_provider(requesting_user, sp_id)

            mock_db.service_providers.delete_service_provider.assert_called_once_with(
                tenant_id, sp_id
            )
            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args[1]
            assert call_kwargs["event_type"] == "service_provider_deleted"

    def test_not_found(self, make_requesting_user):
        """Raises NotFoundError for non-existent SP."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="super_admin")

        with patch("services.service_providers.database") as mock_db:
            mock_db.service_providers.get_service_provider.return_value = None

            with pytest.raises(NotFoundError, match="Service provider not found"):
                sp_service.delete_service_provider(requesting_user, str(uuid4()))

    def test_forbidden_for_admin(self, make_requesting_user):
        """Admin role cannot delete SPs."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="admin")

        with pytest.raises(ForbiddenError):
            sp_service.delete_service_provider(requesting_user, str(uuid4()))


# =============================================================================
# get_tenant_idp_metadata_xml
# =============================================================================


class TestGetTenantIdPMetadataXML:
    """Tests for get_tenant_idp_metadata_xml."""

    def test_returns_xml_when_cert_exists(self):
        """Returns XML string when tenant has a certificate."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())

        with patch("services.service_providers.database") as mock_db:
            mock_db.saml.get_sp_certificate.return_value = {
                "certificate_pem": SAMPLE_CERT_PEM,
            }

            result = sp_service.get_tenant_idp_metadata_xml(tenant_id, "https://idp.example.com")

            assert "IDPSSODescriptor" in result
            assert "<?xml" in result
            mock_db.saml.get_sp_certificate.assert_called_once_with(tenant_id)

    def test_raises_not_found_when_no_cert(self):
        """Raises NotFoundError when no certificate is configured."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())

        with patch("services.service_providers.database") as mock_db:
            mock_db.saml.get_sp_certificate.return_value = None

            with pytest.raises(NotFoundError, match="IdP certificate not configured"):
                sp_service.get_tenant_idp_metadata_xml(tenant_id, "https://idp.example.com")

    def test_entity_id_from_base_url(self):
        """Entity ID is constructed from base_url + /saml/idp/metadata."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())

        with patch("services.service_providers.database") as mock_db:
            mock_db.saml.get_sp_certificate.return_value = {
                "certificate_pem": SAMPLE_CERT_PEM,
            }

            result = sp_service.get_tenant_idp_metadata_xml(tenant_id, "https://acme.example.com")

            assert 'entityID="https://acme.example.com/saml/idp/metadata"' in result

    def test_sso_url_from_base_url(self):
        """SSO URL is constructed from base_url + /saml/idp/sso."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())

        with patch("services.service_providers.database") as mock_db:
            mock_db.saml.get_sp_certificate.return_value = {
                "certificate_pem": SAMPLE_CERT_PEM,
            }

            result = sp_service.get_tenant_idp_metadata_xml(tenant_id, "https://acme.example.com")

            assert 'Location="https://acme.example.com/saml/idp/sso"' in result
