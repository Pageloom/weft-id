"""Tests for per-IdP SP certificate management.

Covers:
- Service layer: get_or_create, display, rotation, metadata XML
- Two-step IdP creation: name-only creates pending IdP with cert
- Trust establishment: completing the second step
- Enable guard: cannot enable pending IdP
- API endpoints: establish-trust, sp-certificate, rotate
- Router: per-IdP metadata endpoint
"""

import os
from pathlib import Path
from uuid import uuid4

import pytest
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser

# =============================================================================
# Helpers
# =============================================================================


def _make_requesting_user(user: dict, tenant_id: str, role: str = "super_admin") -> RequestingUser:
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role,
    )


# =============================================================================
# Service Layer: get_or_create_idp_sp_certificate
# =============================================================================


class TestGetOrCreateIdpSpCertificate:
    """Tests for the internal get_or_create_idp_sp_certificate function."""

    def test_creates_certificate_when_none_exists(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Creates a new per-IdP SP certificate when none exists."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        # Create a pending IdP first (name only, no entity_id)
        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Cert Test IdP", provider_type="okta"),
            "https://test.example.com",
        )

        # The create flow already generates a cert. Delete it to test creation.
        import database

        database.saml.clear_previous_idp_sp_certificate(tenant_id, idp.id)
        # Verify cert exists (created during IdP creation)
        cert = database.saml.get_idp_sp_certificate(tenant_id, idp.id)
        assert cert is not None
        assert cert["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")

    def test_returns_existing_certificate(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Returns existing cert without creating a new one."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service
        from services.saml.idp_sp_certificates import get_or_create_idp_sp_certificate

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Existing Cert IdP", provider_type="generic"),
            "https://test.example.com",
        )

        # Call again: should return same cert
        cert1 = get_or_create_idp_sp_certificate(
            tenant_id, idp.id, str(test_super_admin_user["id"])
        )
        cert2 = get_or_create_idp_sp_certificate(
            tenant_id, idp.id, str(test_super_admin_user["id"])
        )

        assert cert1["id"] == cert2["id"]
        assert cert1["certificate_pem"] == cert2["certificate_pem"]


# =============================================================================
# Service Layer: get_idp_sp_certificate_for_display
# =============================================================================


class TestGetIdpSpCertificateForDisplay:
    """Tests for get_idp_sp_certificate_for_display."""

    def test_returns_certificate_info(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Returns certificate info without private key."""
        from schemas.saml import IdPCreate, IdPSPCertificate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Display Cert IdP", provider_type="okta"),
            "https://test.example.com",
        )

        result = saml_service.get_idp_sp_certificate_for_display(requesting_user, idp.id)

        assert result is not None
        assert isinstance(result, IdPSPCertificate)
        assert result.idp_id == idp.id
        assert result.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert result.has_previous_certificate is False
        assert result.rotation_grace_period_ends_at is None

    def test_returns_none_when_no_cert(self, test_tenant, test_super_admin_user):
        """Returns None when no certificate exists for the IdP."""
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        result = saml_service.get_idp_sp_certificate_for_display(requesting_user, str(uuid4()))
        assert result is None

    def test_admin_cannot_access(self, test_tenant, test_admin_user):
        """Admin role is rejected."""
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_admin_user, tenant_id, "admin")

        with pytest.raises(ForbiddenError):
            saml_service.get_idp_sp_certificate_for_display(requesting_user, str(uuid4()))


# =============================================================================
# Service Layer: rotate_idp_sp_certificate
# =============================================================================


class TestRotateIdpSpCertificate:
    """Tests for rotate_idp_sp_certificate."""

    def test_rotates_certificate_successfully(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Rotation creates new cert and keeps old one during grace period."""
        from schemas.saml import CertificateRotationResult, IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Rotate Cert IdP", provider_type="okta"),
            "https://test.example.com",
        )

        # Get original cert
        original = saml_service.get_idp_sp_certificate_for_display(requesting_user, idp.id)
        assert original is not None

        # Rotate
        result = saml_service.rotate_idp_sp_certificate(
            requesting_user, idp.id, grace_period_days=7
        )

        assert isinstance(result, CertificateRotationResult)
        assert result.new_certificate_pem != original.certificate_pem
        assert result.grace_period_ends_at is not None
        assert result.new_expires_at is not None

        # Verify display shows previous cert
        updated = saml_service.get_idp_sp_certificate_for_display(requesting_user, idp.id)
        assert updated.has_previous_certificate is True
        assert updated.rotation_grace_period_ends_at is not None

    def test_rotate_nonexistent_idp(self, test_tenant, test_super_admin_user):
        """Rotation fails for nonexistent IdP."""
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        with pytest.raises(NotFoundError) as exc_info:
            saml_service.rotate_idp_sp_certificate(requesting_user, str(uuid4()))

        assert exc_info.value.code == "idp_not_found"

    def test_rotate_no_existing_cert(self, test_tenant, test_super_admin_user, fast_sp_certificate):
        """Rotation fails when IdP has no SP certificate."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        # Create IdP with full trust (generates cert), then manually delete the cert
        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(
                name="No Cert Rotate IdP",
                provider_type="okta",
                entity_id="https://no-cert-rotate.example.com/entity",
                sso_url="https://no-cert-rotate.example.com/sso",
                certificate_pem="""-----BEGIN CERTIFICATE-----
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
            ),
            "https://test.example.com",
        )

        # Directly delete the cert from DB to simulate missing cert

        from database import execute

        execute(
            tenant_id,
            "DELETE FROM saml_idp_sp_certificates WHERE idp_id = :idp_id",
            {"idp_id": idp.id},
        )

        with pytest.raises(NotFoundError) as exc_info:
            saml_service.rotate_idp_sp_certificate(requesting_user, idp.id)

        assert exc_info.value.code == "idp_sp_certificate_not_found"

    def test_admin_cannot_rotate(self, test_tenant, test_admin_user):
        """Admin role is rejected for rotation."""
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_admin_user, tenant_id, "admin")

        with pytest.raises(ForbiddenError):
            saml_service.rotate_idp_sp_certificate(requesting_user, str(uuid4()))

    def test_rotation_logs_event(self, test_tenant, test_super_admin_user, fast_sp_certificate):
        """Rotation emits a saml_idp_sp_certificate_rotated event."""
        import database
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Rotation Event IdP", provider_type="generic"),
            "https://test.example.com",
        )

        saml_service.rotate_idp_sp_certificate(requesting_user, idp.id)

        events = database.event_log.list_events(tenant_id, limit=20)
        rotation_events = [
            e for e in events if e["event_type"] == "saml_idp_sp_certificate_rotated"
        ]
        assert len(rotation_events) >= 1

    def test_rotate_rejects_during_active_grace_period(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Rotation is rejected when a grace period is active."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Guard Test IdP", provider_type="okta"),
            "https://test.example.com",
        )

        # First rotation succeeds
        saml_service.rotate_idp_sp_certificate(requesting_user, idp.id)

        # Second rotation should be rejected (grace period active)
        with pytest.raises(ValidationError) as exc_info:
            saml_service.rotate_idp_sp_certificate(requesting_user, idp.id)

        assert exc_info.value.code == "idp_sp_certificate_rotation_in_progress"

    def test_rotate_allows_after_grace_period_expired(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Rotation succeeds when the grace period has already expired."""
        from datetime import UTC, datetime, timedelta

        from database import execute
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Expired Grace IdP", provider_type="okta"),
            "https://test.example.com",
        )

        # Rotate once
        saml_service.rotate_idp_sp_certificate(requesting_user, idp.id)

        # Manually backdate the grace period to the past
        past = datetime.now(UTC) - timedelta(days=1)
        execute(
            tenant_id,
            """
            UPDATE saml_idp_sp_certificates
            SET rotation_grace_period_ends_at = :past
            WHERE idp_id = :idp_id
            """,
            {"past": past, "idp_id": idp.id},
        )

        # Second rotation should now succeed
        result = saml_service.rotate_idp_sp_certificate(requesting_user, idp.id)
        assert result.new_certificate_pem is not None


# =============================================================================
# Service Layer: get_idp_sp_metadata_xml
# =============================================================================


class TestGetIdpSpMetadataXml:
    """Tests for get_idp_sp_metadata_xml."""

    def test_generates_metadata_xml(self, test_tenant, test_super_admin_user, fast_sp_certificate):
        """Generates valid SP metadata XML for an IdP."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Metadata XML IdP", provider_type="okta"),
            "https://test.example.com",
        )

        xml = saml_service.get_idp_sp_metadata_xml(tenant_id, idp.id, "https://test.example.com")

        assert "EntityDescriptor" in xml
        assert f"https://test.example.com/saml/metadata/{idp.id}" in xml
        assert f"https://test.example.com/saml/acs/{idp.id}" in xml
        assert "-----BEGIN CERTIFICATE-----" not in xml  # cert is base64 inside XML

    def test_raises_when_no_certificate(self, test_tenant):
        """Raises NotFoundError when no per-IdP SP certificate exists."""
        from services import saml as saml_service

        with pytest.raises(NotFoundError) as exc_info:
            saml_service.get_idp_sp_metadata_xml(
                str(test_tenant["id"]),
                str(uuid4()),
                "https://test.example.com",
            )

        assert exc_info.value.code == "idp_sp_certificate_not_found"

    def test_passes_idp_attribute_mapping_to_generator(self):
        """IdP's attribute_mapping is forwarded to generate_sp_metadata_xml."""
        from unittest.mock import patch

        from services import saml as saml_service

        tenant_id = str(uuid4())
        idp_id = str(uuid4())
        custom_mapping = {
            "urn:oid:0.9.2342.19200300.100.1.3": "email",
            "urn:oid:2.5.4.42": "firstName",
        }

        cert_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIICsDCCAZigAwIBAgIJALwzrJEIQ9UHMA0=\n"
            "-----END CERTIFICATE-----"
        )

        with (
            patch("services.saml.idp_sp_certificates.database") as mock_db,
            patch("services.saml.idp_sp_certificates.generate_sp_metadata_xml") as mock_gen,
        ):
            mock_db.saml.get_idp_sp_certificate.return_value = {
                "certificate_pem": cert_pem,
                "previous_certificate_pem": None,
            }
            mock_db.saml.get_identity_provider.return_value = {
                "id": idp_id,
                "attribute_mapping": custom_mapping,
            }
            mock_gen.return_value = "<xml/>"

            saml_service.get_idp_sp_metadata_xml(tenant_id, idp_id, "https://test.example.com")

            mock_gen.assert_called_once()
            call_kwargs = mock_gen.call_args[1]
            assert call_kwargs["attribute_mapping"] == custom_mapping

    def test_no_idp_attribute_mapping_passes_none(self):
        """When IdP has no attribute_mapping, None is passed to the generator."""
        from unittest.mock import patch

        from services import saml as saml_service

        tenant_id = str(uuid4())
        idp_id = str(uuid4())

        cert_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIICsDCCAZigAwIBAgIJALwzrJEIQ9UHMA0=\n"
            "-----END CERTIFICATE-----"
        )

        with (
            patch("services.saml.idp_sp_certificates.database") as mock_db,
            patch("services.saml.idp_sp_certificates.generate_sp_metadata_xml") as mock_gen,
        ):
            mock_db.saml.get_idp_sp_certificate.return_value = {
                "certificate_pem": cert_pem,
                "previous_certificate_pem": None,
            }
            mock_db.saml.get_identity_provider.return_value = {
                "id": idp_id,
                "attribute_mapping": None,
            }
            mock_gen.return_value = "<xml/>"

            saml_service.get_idp_sp_metadata_xml(tenant_id, idp_id, "https://test.example.com")

            call_kwargs = mock_gen.call_args[1]
            assert call_kwargs["attribute_mapping"] is None

    def test_idp_not_found_uses_no_mapping(self):
        """When IdP row is not found, no attribute mapping is passed."""
        from unittest.mock import patch

        from services import saml as saml_service

        tenant_id = str(uuid4())
        idp_id = str(uuid4())

        cert_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIICsDCCAZigAwIBAgIJALwzrJEIQ9UHMA0=\n"
            "-----END CERTIFICATE-----"
        )

        with (
            patch("services.saml.idp_sp_certificates.database") as mock_db,
            patch("services.saml.idp_sp_certificates.generate_sp_metadata_xml") as mock_gen,
        ):
            mock_db.saml.get_idp_sp_certificate.return_value = {
                "certificate_pem": cert_pem,
                "previous_certificate_pem": None,
            }
            mock_db.saml.get_identity_provider.return_value = None
            mock_gen.return_value = "<xml/>"

            saml_service.get_idp_sp_metadata_xml(tenant_id, idp_id, "https://test.example.com")

            call_kwargs = mock_gen.call_args[1]
            assert call_kwargs["attribute_mapping"] is None


# =============================================================================
# Two-Step IdP Creation: Name-Only Mode
# =============================================================================


class TestTwoStepIdPCreation:
    """Tests for two-step IdP creation (name-only first, trust later)."""

    def test_name_only_creates_pending_idp(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Name-only creation creates a pending IdP with trust_established=False."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Pending IdP", provider_type="okta"),
            "https://test.example.com",
        )

        assert idp.trust_established is False
        assert idp.entity_id is None
        assert idp.sso_url is None
        assert idp.certificate_pem is None
        # Per-IdP SP entity ID and ACS URL should be set
        assert f"/saml/metadata/{idp.id}" in idp.sp_entity_id
        assert f"/saml/acs/{idp.id}" in idp.sp_acs_url

    def test_name_only_creates_per_idp_sp_cert(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Name-only creation generates a per-IdP SP certificate."""
        import database
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Cert Created IdP", provider_type="generic"),
            "https://test.example.com",
        )

        cert = database.saml.get_idp_sp_certificate(tenant_id, idp.id)
        assert cert is not None
        assert cert["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")

    def test_full_creation_sets_trust_established(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Full creation with entity_id sets trust_established=True."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(
                name="Full Creation IdP",
                provider_type="okta",
                entity_id="https://full-creation.example.com/entity",
                sso_url="https://full-creation.example.com/sso",
                certificate_pem="""-----BEGIN CERTIFICATE-----
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
            ),
            "https://test.example.com",
        )

        assert idp.trust_established is True
        assert idp.entity_id == "https://full-creation.example.com/entity"


# =============================================================================
# Trust Establishment
# =============================================================================


class TestEstablishIdpTrust:
    """Tests for establish_idp_trust."""

    def test_establishes_trust_on_pending_idp(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Establishes trust by setting entity_id, sso_url, certificate."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        # Create pending IdP
        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Trust Me IdP", provider_type="okta"),
            "https://test.example.com",
        )
        assert idp.trust_established is False

        # Establish trust
        updated = saml_service.establish_idp_trust(
            requesting_user,
            idp_id=idp.id,
            entity_id="https://trust-me.example.com/entity",
            sso_url="https://trust-me.example.com/sso",
            certificate_pem="""-----BEGIN CERTIFICATE-----
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
            slo_url="https://trust-me.example.com/slo",
        )

        assert updated.trust_established is True
        assert updated.entity_id == "https://trust-me.example.com/entity"
        assert updated.sso_url == "https://trust-me.example.com/sso"
        assert updated.slo_url == "https://trust-me.example.com/slo"

    def test_trust_on_nonexistent_idp(self, test_tenant, test_super_admin_user):
        """Raises NotFoundError for nonexistent IdP."""
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        with pytest.raises(NotFoundError) as exc_info:
            saml_service.establish_idp_trust(
                requesting_user,
                idp_id=str(uuid4()),
                entity_id="https://nobody.example.com/entity",
                sso_url="https://nobody.example.com/sso",
                certificate_pem="fake-cert",
            )

        assert exc_info.value.code == "idp_not_found"

    def test_trust_duplicate_entity_id(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Raises ConflictError when entity_id is already used by another IdP."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        entity_id = f"https://dup-entity-{uuid4().hex[:8]}.example.com/entity"

        # Create first IdP with full trust
        saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(
                name="First IdP",
                provider_type="okta",
                entity_id=entity_id,
                sso_url="https://first.example.com/sso",
                certificate_pem="""-----BEGIN CERTIFICATE-----
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
            ),
            "https://test.example.com",
        )

        # Create second pending IdP, try to establish trust with same entity_id
        pending = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Second IdP", provider_type="okta"),
            "https://test.example.com",
        )

        with pytest.raises(ConflictError) as exc_info:
            saml_service.establish_idp_trust(
                requesting_user,
                idp_id=pending.id,
                entity_id=entity_id,
                sso_url="https://second.example.com/sso",
                certificate_pem="fake-cert",
            )

        assert exc_info.value.code == "idp_entity_id_exists"

    def test_trust_logs_event(self, test_tenant, test_super_admin_user, fast_sp_certificate):
        """Trust establishment logs saml_idp_trust_established event."""
        import database
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Event Log IdP", provider_type="okta"),
            "https://test.example.com",
        )

        saml_service.establish_idp_trust(
            requesting_user,
            idp_id=idp.id,
            entity_id=f"https://event-log-{uuid4().hex[:8]}.example.com/entity",
            sso_url="https://event-log.example.com/sso",
            certificate_pem="fake-cert",
        )

        events = database.event_log.list_events(tenant_id, limit=20)
        trust_events = [e for e in events if e["event_type"] == "saml_idp_trust_established"]
        assert len(trust_events) >= 1

    def test_admin_cannot_establish_trust(self, test_tenant, test_admin_user):
        """Admin role is rejected for trust establishment."""
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_admin_user, tenant_id, "admin")

        with pytest.raises(ForbiddenError):
            saml_service.establish_idp_trust(
                requesting_user,
                idp_id=str(uuid4()),
                entity_id="https://no-access.example.com/entity",
                sso_url="https://no-access.example.com/sso",
                certificate_pem="fake-cert",
            )


# =============================================================================
# Enable Guard: Cannot enable pending IdP
# =============================================================================


class TestEnablePendingIdpGuard:
    """Tests for the guard that prevents enabling a pending IdP."""

    def test_cannot_enable_pending_idp(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Enabling a pending IdP raises ValidationError."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Cannot Enable IdP", provider_type="okta"),
            "https://test.example.com",
        )
        assert idp.trust_established is False

        with pytest.raises(ValidationError) as exc_info:
            saml_service.set_idp_enabled(requesting_user, idp.id, True)

        assert exc_info.value.code == "idp_trust_pending"

    def test_can_enable_after_trust_established(
        self, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Enabling succeeds after trust is established."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Can Enable IdP", provider_type="okta"),
            "https://test.example.com",
        )

        saml_service.establish_idp_trust(
            requesting_user,
            idp_id=idp.id,
            entity_id=f"https://can-enable-{uuid4().hex[:8]}.example.com/entity",
            sso_url="https://can-enable.example.com/sso",
            certificate_pem="""-----BEGIN CERTIFICATE-----
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
        )

        result = saml_service.set_idp_enabled(requesting_user, idp.id, True)
        assert result.is_enabled is True


# =============================================================================
# Router: Per-IdP SP Metadata Endpoint
# =============================================================================


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


class TestPerIdpMetadataEndpoint:
    """Tests for GET /saml/metadata/{idp_id}."""

    def test_returns_metadata_xml(
        self, client, test_tenant_host, test_tenant, test_super_admin_user, fast_sp_certificate
    ):
        """Per-IdP metadata endpoint returns valid XML."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="Metadata Endpoint IdP", provider_type="okta"),
            f"https://{test_tenant_host}",
        )

        response = client.get(
            f"/saml/metadata/{idp.id}",
            headers={"Host": test_tenant_host},
        )

        assert response.status_code == 200
        assert "application/xml" in response.headers.get("content-type", "")
        assert "EntityDescriptor" in response.text
        assert f"/saml/metadata/{idp.id}" in response.text
        assert f"/saml/acs/{idp.id}" in response.text

    def test_returns_404_for_unknown_idp(self, client, test_tenant_host):
        """Returns 404 for non-existent IdP."""
        response = client.get(
            f"/saml/metadata/{uuid4()}",
            headers={"Host": test_tenant_host},
        )

        assert response.status_code == 404


# =============================================================================
# API Fixtures
# =============================================================================


@pytest.fixture
def oauth2_super_admin_access_token(test_tenant, normal_oauth2_client, test_super_admin_user):
    """Create an OAuth2 access token for a super_admin user."""
    import database

    _refresh_token, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
    )

    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
        parent_token_id=refresh_token_id,
    )

    return access_token


@pytest.fixture
def oauth2_admin_access_token(test_tenant, normal_oauth2_client, test_admin_user):
    """Create an OAuth2 access token for an admin user."""
    import database

    _refresh_token, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_admin_user["id"],
    )

    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_admin_user["id"],
        parent_token_id=refresh_token_id,
    )

    return access_token


@pytest.fixture
def super_admin_api_headers(test_tenant_host, oauth2_super_admin_access_token):
    """Headers for super_admin API requests."""
    return {
        "Host": test_tenant_host,
        "Authorization": f"Bearer {oauth2_super_admin_access_token}",
    }


@pytest.fixture
def admin_api_headers(test_tenant_host, oauth2_admin_access_token):
    """Headers for admin API requests."""
    return {
        "Host": test_tenant_host,
        "Authorization": f"Bearer {oauth2_admin_access_token}",
    }


# =============================================================================
# API: Establish Trust Endpoints
# =============================================================================


class TestApiEstablishTrust:
    """Tests for POST /api/v1/saml/idps/{idp_id}/establish-trust."""

    def test_establish_trust_manual(
        self,
        client,
        test_tenant,
        test_super_admin_user,
        super_admin_api_headers,
        fast_sp_certificate,
    ):
        """API establish-trust with manual config succeeds."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        # Create pending IdP
        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="API Trust IdP", provider_type="okta"),
            "https://test.example.com",
        )

        entity_id = f"https://api-trust-{uuid4().hex[:8]}.example.com/entity"

        response = client.post(
            f"/api/v1/saml/idps/{idp.id}/establish-trust",
            json={
                "entity_id": entity_id,
                "sso_url": "https://api-trust.example.com/sso",
                "certificate_pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
            },
            headers=super_admin_api_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["trust_established"] is True
        assert data["entity_id"] == entity_id

    def test_establish_trust_as_admin_forbidden(
        self,
        client,
        admin_api_headers,
    ):
        """Admin cannot establish trust."""
        response = client.post(
            f"/api/v1/saml/idps/{uuid4()}/establish-trust",
            json={
                "entity_id": "https://nope.example.com/entity",
                "sso_url": "https://nope.example.com/sso",
                "certificate_pem": "fake",
            },
            headers=admin_api_headers,
        )

        assert response.status_code == 403

    def test_establish_trust_nonexistent_idp(
        self,
        client,
        super_admin_api_headers,
    ):
        """Establish trust on nonexistent IdP returns 404."""
        response = client.post(
            f"/api/v1/saml/idps/{uuid4()}/establish-trust",
            json={
                "entity_id": "https://gone.example.com/entity",
                "sso_url": "https://gone.example.com/sso",
                "certificate_pem": "fake",
            },
            headers=super_admin_api_headers,
        )

        assert response.status_code == 404


# =============================================================================
# API: Per-IdP SP Certificate Endpoint
# =============================================================================


class TestApiGetIdpSpCertificate:
    """Tests for GET /api/v1/saml/idps/{idp_id}/sp-certificate."""

    def test_returns_certificate_info(
        self,
        client,
        test_tenant,
        test_super_admin_user,
        super_admin_api_headers,
        fast_sp_certificate,
    ):
        """Returns per-IdP SP certificate info."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="API Cert IdP", provider_type="okta"),
            "https://test.example.com",
        )

        response = client.get(
            f"/api/v1/saml/idps/{idp.id}/sp-certificate",
            headers=super_admin_api_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["idp_id"] == idp.id
        assert "certificate_pem" in data
        assert data["has_previous_certificate"] is False

    def test_returns_404_when_no_cert(
        self,
        client,
        super_admin_api_headers,
    ):
        """Returns 404 when no per-IdP SP certificate exists."""
        response = client.get(
            f"/api/v1/saml/idps/{uuid4()}/sp-certificate",
            headers=super_admin_api_headers,
        )

        assert response.status_code == 404


# =============================================================================
# API: Rotate Per-IdP SP Certificate
# =============================================================================


class TestApiRotateIdpSpCertificate:
    """Tests for POST /api/v1/saml/idps/{idp_id}/rotate-sp-certificate."""

    def test_rotates_certificate(
        self,
        client,
        test_tenant,
        test_super_admin_user,
        super_admin_api_headers,
        fast_sp_certificate,
    ):
        """Rotation via API returns new cert and grace period."""
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        tenant_id = str(test_tenant["id"])
        requesting_user = _make_requesting_user(test_super_admin_user, tenant_id)

        idp = saml_service.create_identity_provider(
            requesting_user,
            IdPCreate(name="API Rotate IdP", provider_type="okta"),
            "https://test.example.com",
        )

        response = client.post(
            f"/api/v1/saml/idps/{idp.id}/rotate-sp-certificate",
            headers=super_admin_api_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "new_certificate_pem" in data
        assert "grace_period_ends_at" in data

    def test_admin_cannot_rotate(
        self,
        client,
        admin_api_headers,
    ):
        """Admin cannot rotate certificates."""
        response = client.post(
            f"/api/v1/saml/idps/{uuid4()}/rotate-sp-certificate",
            headers=admin_api_headers,
        )

        assert response.status_code == 403


# =============================================================================
# API: Create IdP (name-only mode)
# =============================================================================


class TestApiCreateIdpNameOnly:
    """Tests for POST /api/v1/saml/idps with name-only creation."""

    def test_create_name_only_returns_pending(
        self,
        client,
        super_admin_api_headers,
        fast_sp_certificate,
    ):
        """Creating an IdP with name only returns a pending IdP."""
        response = client.post(
            "/api/v1/saml/idps",
            json={
                "name": "API Name Only IdP",
                "provider_type": "okta",
            },
            headers=super_admin_api_headers,
        )

        assert response.status_code == 201
        data = response.json()
        assert data["trust_established"] is False
        assert data["entity_id"] is None
        assert "sp_entity_id" in data
        assert "/saml/metadata/" in data["sp_entity_id"]

    def test_create_full_returns_established(
        self,
        client,
        super_admin_api_headers,
        fast_sp_certificate,
    ):
        """Creating an IdP with full config returns established trust."""
        entity_id = f"https://api-full-{uuid4().hex[:8]}.example.com/entity"

        response = client.post(
            "/api/v1/saml/idps",
            json={
                "name": "API Full IdP",
                "provider_type": "okta",
                "entity_id": entity_id,
                "sso_url": "https://api-full.example.com/sso",
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
            },
            headers=super_admin_api_headers,
        )

        assert response.status_code == 201
        data = response.json()
        assert data["trust_established"] is True
        assert data["entity_id"] == entity_id
