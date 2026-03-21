"""Tests for IdP certificate management and SAML auth error paths.

Covers:
- get_certificate_fingerprint utility
- build_saml_settings with multi-cert
- parse_idp_metadata_xml certificate extraction
- Service layer: list, validation fallback, sync, backfill
- SAML auth multi-cert integration
- SAML auth/test error handling paths
"""

import datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from app.utils.saml import (
    build_saml_settings,
    generate_sp_certificate,
    get_certificate_fingerprint,
    parse_idp_metadata_xml,
)

# Try to import python3-saml
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # noqa: F401

    HAS_SAML_LIBRARY = True
except ImportError:
    HAS_SAML_LIBRARY = False


# =============================================================================
# Utility: get_certificate_fingerprint
# =============================================================================


def test_get_certificate_fingerprint_returns_colon_separated_hex():
    """Fingerprint should be colon-separated uppercase hex."""
    cert_pem, _ = generate_sp_certificate("test-tenant")
    fp = get_certificate_fingerprint(cert_pem)

    parts = fp.split(":")
    assert len(parts) == 32  # SHA-256 = 32 bytes
    for part in parts:
        assert len(part) == 2
        int(part, 16)  # Should parse as hex


def test_get_certificate_fingerprint_deterministic():
    """Same certificate should always produce the same fingerprint."""
    cert_pem, _ = generate_sp_certificate("test-tenant")
    fp1 = get_certificate_fingerprint(cert_pem)
    fp2 = get_certificate_fingerprint(cert_pem)
    assert fp1 == fp2


def test_get_certificate_fingerprint_different_certs():
    """Different certificates should produce different fingerprints."""
    cert1, _ = generate_sp_certificate("tenant-1")
    cert2, _ = generate_sp_certificate("tenant-2")
    fp1 = get_certificate_fingerprint(cert1)
    fp2 = get_certificate_fingerprint(cert2)
    assert fp1 != fp2


def test_get_certificate_fingerprint_invalid_pem():
    """Invalid PEM should raise an exception."""
    with pytest.raises(Exception):
        get_certificate_fingerprint("not-a-certificate")


# =============================================================================
# Utility: build_saml_settings with multi-cert
# =============================================================================


def test_build_saml_settings_single_cert_no_multi():
    """With a single cert, x509certMulti should not be set."""
    cert_pem, key_pem = generate_sp_certificate("test-tenant")

    settings = build_saml_settings(
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        sp_certificate_pem=cert_pem,
        sp_private_key_pem=key_pem,
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_certificate_pem=cert_pem,
        idp_certificate_pems=[cert_pem],
    )

    assert "x509certMulti" not in settings["idp"]


def test_build_saml_settings_multi_cert():
    """With multiple certs, x509certMulti should be set."""
    cert1, key1 = generate_sp_certificate("tenant-1")
    cert2, _ = generate_sp_certificate("tenant-2")

    settings = build_saml_settings(
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        sp_certificate_pem=cert1,
        sp_private_key_pem=key1,
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_certificate_pem=cert1,
        idp_certificate_pems=[cert1, cert2],
    )

    assert "x509certMulti" in settings["idp"]
    assert len(settings["idp"]["x509certMulti"]["signing"]) == 2


def test_build_saml_settings_no_pems_param():
    """Without idp_certificate_pems, x509certMulti should not be set."""
    cert_pem, key_pem = generate_sp_certificate("test-tenant")

    settings = build_saml_settings(
        sp_entity_id="https://sp.example.com",
        sp_acs_url="https://sp.example.com/acs",
        sp_certificate_pem=cert_pem,
        sp_private_key_pem=key_pem,
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_certificate_pem=cert_pem,
    )

    assert "x509certMulti" not in settings["idp"]


# =============================================================================
# Utility: parse_idp_metadata_xml with certificates list
# =============================================================================


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_parse_idp_metadata_returns_certificates_list():
    """parse_idp_metadata_xml should return a certificates list."""
    xml = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.com/entity">
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
        Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""

    result = parse_idp_metadata_xml(xml)

    assert "certificates" in result
    assert isinstance(result["certificates"], list)
    assert len(result["certificates"]) >= 1
    # Each cert should be PEM formatted
    for cert in result["certificates"]:
        assert "-----BEGIN CERTIFICATE-----" in cert


# =============================================================================
# Service Layer Tests (Mocked)
# =============================================================================


@pytest.fixture
def mock_requesting_user():
    """A super_admin requesting user for service tests."""
    return {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "role": "super_admin",
        "email": "admin@example.com",
    }


@pytest.fixture
def sample_cert_pem():
    """Generate a real certificate PEM for testing."""
    cert_pem, _ = generate_sp_certificate("test-tenant")
    return cert_pem


class TestListIdPCertificates:
    """Tests for list_idp_certificates service function."""

    @patch("services.saml.idp_certificates.database")
    @patch("services.saml.idp_certificates.track_activity")
    def test_list_returns_certs(self, mock_track, mock_db, mock_requesting_user, sample_cert_pem):
        from services.saml.idp_certificates import list_idp_certificates

        idp_id = str(uuid4())
        cert_id = str(uuid4())
        fp = get_certificate_fingerprint(sample_cert_pem)

        mock_db.saml.get_identity_provider.return_value = {"id": idp_id}
        mock_db.saml.list_idp_certificates.return_value = [
            {
                "id": cert_id,
                "idp_id": idp_id,
                "tenant_id": mock_requesting_user["tenant_id"],
                "certificate_pem": sample_cert_pem,
                "fingerprint": fp,
                "expires_at": datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC),
                "created_at": datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
            }
        ]

        result = list_idp_certificates(mock_requesting_user, idp_id)

        assert len(result) == 1
        assert result[0].id == cert_id
        assert result[0].fingerprint == fp
        mock_track.assert_called_once()

    @patch("services.saml.idp_certificates.database")
    @patch("services.saml.idp_certificates.track_activity")
    def test_list_idp_not_found(self, mock_track, mock_db, mock_requesting_user):
        from services.exceptions import NotFoundError
        from services.saml.idp_certificates import list_idp_certificates

        mock_db.saml.get_identity_provider.return_value = None

        with pytest.raises(NotFoundError):
            list_idp_certificates(mock_requesting_user, str(uuid4()))

    @patch("services.saml.idp_certificates.database")
    @patch("services.saml.idp_certificates.track_activity")
    def test_list_requires_super_admin(self, mock_track, mock_db):
        from services.exceptions import ForbiddenError
        from services.saml.idp_certificates import list_idp_certificates

        user = {
            "id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "role": "user",
            "email": "user@example.com",
        }

        with pytest.raises(ForbiddenError):
            list_idp_certificates(user, str(uuid4()))


class TestGetCertificatesForValidation:
    """Tests for get_certificates_for_validation."""

    @patch("services.saml.idp_certificates.database")
    def test_returns_pem_strings(self, mock_db, sample_cert_pem):
        from services.saml.idp_certificates import get_certificates_for_validation

        tenant_id = str(uuid4())
        idp_id = str(uuid4())
        fp = get_certificate_fingerprint(sample_cert_pem)

        mock_db.saml.list_idp_certificates.return_value = [
            {
                "id": str(uuid4()),
                "idp_id": idp_id,
                "certificate_pem": sample_cert_pem,
                "fingerprint": fp,
                "expires_at": None,
                "created_at": datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
                "tenant_id": tenant_id,
            }
        ]

        result = get_certificates_for_validation(tenant_id, idp_id)
        assert len(result) == 1
        assert result[0] == sample_cert_pem

    @patch("services.saml.idp_certificates.database")
    def test_returns_empty_when_no_certs(self, mock_db):
        from services.saml.idp_certificates import get_certificates_for_validation

        mock_db.saml.list_idp_certificates.return_value = []

        result = get_certificates_for_validation(str(uuid4()), str(uuid4()))
        assert result == []


class TestBackfillFingerprint:
    """Tests for _backfill_fingerprint internal function."""

    @patch("services.saml.idp_certificates.database")
    def test_backfill_when_fingerprint_empty(self, mock_db, sample_cert_pem):
        """When fingerprint is empty string, backfill from certificate PEM."""
        from services.saml.idp_certificates import _backfill_fingerprint

        cert_id = str(uuid4())
        tenant_id = str(uuid4())
        row = {
            "id": cert_id,
            "certificate_pem": sample_cert_pem,
            "fingerprint": "",
            "expires_at": None,
        }

        updated_row = {**row, "fingerprint": "AA:BB:CC"}
        mock_db.saml.update_idp_certificate_fingerprint.return_value = updated_row

        result = _backfill_fingerprint(tenant_id, row)

        assert result == updated_row
        mock_db.saml.update_idp_certificate_fingerprint.assert_called_once()
        call_args = mock_db.saml.update_idp_certificate_fingerprint.call_args
        assert call_args[0][0] == tenant_id
        assert call_args[0][1] == cert_id

    @patch("services.saml.idp_certificates.database")
    def test_backfill_returns_original_when_update_returns_none(self, mock_db, sample_cert_pem):
        """When database update returns None, return original row."""
        from services.saml.idp_certificates import _backfill_fingerprint

        tenant_id = str(uuid4())
        row = {
            "id": str(uuid4()),
            "certificate_pem": sample_cert_pem,
            "fingerprint": "",
            "expires_at": None,
        }

        mock_db.saml.update_idp_certificate_fingerprint.return_value = None

        result = _backfill_fingerprint(tenant_id, row)
        assert result is row

    @patch("services.saml.idp_certificates.database")
    @patch("services.saml.idp_certificates.get_certificate_fingerprint")
    def test_backfill_handles_exception_gracefully(self, mock_fp, mock_db):
        """When fingerprint calculation fails, return original row."""
        from services.saml.idp_certificates import _backfill_fingerprint

        mock_fp.side_effect = Exception("Invalid certificate")

        row = {
            "id": str(uuid4()),
            "certificate_pem": "bad-cert",
            "fingerprint": "",
            "expires_at": None,
        }

        result = _backfill_fingerprint(str(uuid4()), row)
        assert result is row
        mock_db.saml.update_idp_certificate_fingerprint.assert_not_called()

    def test_backfill_skips_when_fingerprint_present(self, sample_cert_pem):
        """When fingerprint is already present, return row unchanged."""
        from services.saml.idp_certificates import _backfill_fingerprint

        row = {
            "id": str(uuid4()),
            "certificate_pem": sample_cert_pem,
            "fingerprint": "AA:BB:CC:DD",
            "expires_at": None,
        }

        result = _backfill_fingerprint(str(uuid4()), row)
        assert result is row


class TestSyncCertificatesFromMetadata:
    """Tests for sync_certificates_from_metadata."""

    @patch("services.saml.idp_certificates.database")
    def test_adds_new_cert(self, mock_db, sample_cert_pem):
        from services.saml.idp_certificates import sync_certificates_from_metadata

        tenant_id = str(uuid4())
        idp_id = str(uuid4())

        mock_db.saml.list_idp_certificates.return_value = []

        sync_certificates_from_metadata(tenant_id, idp_id, [sample_cert_pem])

        mock_db.saml.create_idp_certificate.assert_called_once()

    @patch("services.saml.idp_certificates.database")
    def test_skips_existing_cert(self, mock_db, sample_cert_pem):
        from services.saml.idp_certificates import sync_certificates_from_metadata

        tenant_id = str(uuid4())
        idp_id = str(uuid4())
        fp = get_certificate_fingerprint(sample_cert_pem)

        mock_db.saml.list_idp_certificates.return_value = [
            {
                "id": str(uuid4()),
                "idp_id": idp_id,
                "certificate_pem": sample_cert_pem,
                "fingerprint": fp,
                "expires_at": None,
                "created_at": datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
                "tenant_id": tenant_id,
            }
        ]

        sync_certificates_from_metadata(tenant_id, idp_id, [sample_cert_pem])

        mock_db.saml.create_idp_certificate.assert_not_called()

    @patch("services.saml.idp_certificates.database")
    def test_removes_stale_metadata_cert(self, mock_db, sample_cert_pem):
        from services.saml.idp_certificates import sync_certificates_from_metadata

        tenant_id = str(uuid4())
        idp_id = str(uuid4())
        stale_cert_id = str(uuid4())
        stale_fp = "AA:BB:CC:DD"  # Not matching any incoming cert

        # New cert to add
        new_cert_pem, _ = generate_sp_certificate("new-tenant")

        mock_db.saml.list_idp_certificates.return_value = [
            {
                "id": stale_cert_id,
                "idp_id": idp_id,
                "certificate_pem": "stale-pem",
                "fingerprint": stale_fp,
                "expires_at": None,
                "created_at": datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
                "tenant_id": tenant_id,
            }
        ]

        sync_certificates_from_metadata(tenant_id, idp_id, [new_cert_pem])

        mock_db.saml.delete_idp_certificate.assert_called_once_with(tenant_id, stale_cert_id)

    @patch("services.saml.idp_certificates.database")
    def test_no_op_with_empty_certs(self, mock_db):
        from services.saml.idp_certificates import sync_certificates_from_metadata

        sync_certificates_from_metadata(str(uuid4()), str(uuid4()), [])
        mock_db.saml.list_idp_certificates.assert_not_called()

    @patch("services.saml.idp_certificates.database")
    @patch("services.saml.idp_certificates.get_certificate_expiry")
    def test_sync_handles_cert_expiry_exception(self, mock_expiry, mock_db, sample_cert_pem):
        """When get_certificate_expiry raises, cert is still added with expires_at=None."""
        from services.saml.idp_certificates import sync_certificates_from_metadata

        tenant_id = str(uuid4())
        idp_id = str(uuid4())

        mock_db.saml.list_idp_certificates.return_value = []
        mock_expiry.side_effect = Exception("Cannot parse expiry")

        sync_certificates_from_metadata(tenant_id, idp_id, [sample_cert_pem])

        mock_db.saml.create_idp_certificate.assert_called_once()
        call_kwargs = mock_db.saml.create_idp_certificate.call_args[1]
        assert call_kwargs["expires_at"] is None

    @patch("services.saml.idp_certificates.database")
    @patch("services.saml.idp_certificates.get_certificate_fingerprint")
    def test_sync_handles_fingerprint_exception(self, mock_fp, mock_db):
        """When fingerprint calculation fails for a cert, it is skipped."""
        from services.saml.idp_certificates import sync_certificates_from_metadata

        tenant_id = str(uuid4())
        idp_id = str(uuid4())

        mock_db.saml.list_idp_certificates.return_value = []
        mock_fp.side_effect = Exception("Bad cert")

        sync_certificates_from_metadata(tenant_id, idp_id, ["invalid-pem"])

        mock_db.saml.create_idp_certificate.assert_not_called()


# =============================================================================
# SAML Auth: get_idp_for_saml_login / get_idp_by_issuer error paths
# =============================================================================


class TestGetIdPForSamlLoginEdgeCases:
    """Tests for untested error paths in get_idp_for_saml_login."""

    @patch("services.saml.auth.database")
    def test_trust_not_established_raises_forbidden(self, mock_db):
        """When trust_established is False, raises ForbiddenError."""
        from services.exceptions import ForbiddenError
        from services.saml.auth import get_idp_for_saml_login

        mock_db.saml.get_identity_provider.return_value = {
            "id": str(uuid4()),
            "name": "Test IdP",
            "is_enabled": True,
            "trust_established": False,
            "entity_id": "https://idp.example.com",
            "sso_url": "https://idp.example.com/sso",
            "slo_url": None,
            "certificate_pem": "cert",
            "sp_entity_id": "https://sp.example.com",
            "require_platform_mfa": False,
            "jit_provisioning": False,
        }

        with pytest.raises(ForbiddenError, match="trust not yet established"):
            get_idp_for_saml_login(str(uuid4()), str(uuid4()))


class TestGetIdPByIssuerEdgeCases:
    """Tests for untested error paths in get_idp_by_issuer."""

    @patch("services.saml.auth.database")
    def test_disabled_idp_raises_forbidden(self, mock_db):
        """When IdP is disabled, get_idp_by_issuer raises ForbiddenError."""
        from services.exceptions import ForbiddenError
        from services.saml.auth import get_idp_by_issuer

        mock_db.saml.get_identity_provider_by_entity_id.return_value = {
            "id": str(uuid4()),
            "name": "Test IdP",
            "is_enabled": False,
            "trust_established": True,
            "entity_id": "https://idp.example.com",
            "sso_url": "https://idp.example.com/sso",
            "slo_url": None,
            "certificate_pem": "cert",
            "sp_entity_id": "https://sp.example.com",
            "require_platform_mfa": False,
            "jit_provisioning": False,
        }

        with pytest.raises(ForbiddenError, match="not enabled"):
            get_idp_by_issuer(str(uuid4()), "https://idp.example.com")


# =============================================================================
# SAML Response Processing: Error Paths
# =============================================================================


class TestProcessSamlResponseErrors:
    """Tests for error paths in process_saml_response."""

    @patch("services.saml.auth._prepare_saml_auth")
    def test_not_authenticated_raises_validation_error(self, mock_prepare):
        """When auth.is_authenticated() returns False, raises ValidationError."""
        from services.exceptions import ValidationError
        from services.saml.auth import process_saml_response

        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth.is_authenticated.return_value = False

        mock_idp = MagicMock()
        mock_prepare.return_value = (mock_auth, mock_idp)

        with pytest.raises(ValidationError, match="authentication failed") as exc_info:
            process_saml_response("tenant-id", "idp-id", "dummy-response")

        assert exc_info.value.code == "saml_auth_failed"


class TestProcessSamlTestResponseErrors:
    """Tests for error paths in process_saml_test_response."""

    @patch("services.saml.auth._prepare_saml_auth")
    def test_invalid_response_error_type(self, mock_prepare):
        """When error reason doesn't match signature/expired, returns invalid_response."""
        from services.saml.auth import process_saml_test_response

        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = ["some_error"]
        mock_auth.get_last_error_reason.return_value = "Unknown XML parsing failure"

        mock_idp = MagicMock()
        mock_prepare.return_value = (mock_auth, mock_idp)

        result = process_saml_test_response("tenant-id", "idp-id", "dummy-response")

        assert result.success is False
        assert result.error_type == "invalid_response"
        assert "Unknown XML parsing failure" in result.error_detail

    @patch("services.saml.auth._prepare_saml_auth")
    def test_not_authenticated_returns_auth_failed(self, mock_prepare):
        """When auth passes validation but is_authenticated() is False."""
        from services.saml.auth import process_saml_test_response

        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth.is_authenticated.return_value = False

        mock_idp = MagicMock()
        mock_prepare.return_value = (mock_auth, mock_idp)

        result = process_saml_test_response("tenant-id", "idp-id", "dummy-response")

        assert result.success is False
        assert result.error_type == "auth_failed"

    @patch("services.saml.auth._prepare_saml_auth")
    def test_forbidden_error_returns_idp_disabled(self, mock_prepare):
        """When _prepare_saml_auth raises ForbiddenError, returns idp_disabled."""
        from services.exceptions import ForbiddenError
        from services.saml.auth import process_saml_test_response

        mock_prepare.side_effect = ForbiddenError(
            message="Identity provider is not enabled", code="idp_disabled"
        )

        result = process_saml_test_response("tenant-id", "idp-id", "dummy-response")

        assert result.success is False
        assert result.error_type == "idp_disabled"

    @patch("services.saml.auth._prepare_saml_auth")
    def test_unexpected_exception_returns_unexpected_error(self, mock_prepare):
        """When _prepare_saml_auth raises an unexpected exception."""
        from services.saml.auth import process_saml_test_response

        mock_prepare.side_effect = RuntimeError("Something went very wrong")

        result = process_saml_test_response("tenant-id", "idp-id", "dummy-response")

        assert result.success is False
        assert result.error_type == "unexpected_error"
        assert "Something went very wrong" in result.error_detail


# =============================================================================
# Router Tests
# =============================================================================


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    import os
    from pathlib import Path

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


# =============================================================================
# SAML Auth Multi-Cert Integration Tests
# =============================================================================


class TestPrepareAuthMultiCert:
    """Test that _prepare_saml_auth loads certificates."""

    @patch("services.saml.auth.get_certificates_for_validation")
    @patch("services.saml.auth.build_saml_settings")
    @patch("services.saml.auth.decrypt_private_key")
    @patch("services.saml.auth.database")
    @patch("services.saml.auth.get_idp_for_saml_login")
    def test_multi_cert_passed_to_build_settings(
        self, mock_get_idp, mock_db, mock_decrypt, mock_build, mock_get_certs
    ):
        """When multiple certs exist, they should be passed to build_saml_settings."""

        idp = MagicMock()
        idp.sp_entity_id = "https://sp.example.com/saml/metadata"
        idp.entity_id = "https://idp.example.com"
        idp.sso_url = "https://idp.example.com/sso"
        idp.certificate_pem = "cert1"
        idp.slo_url = None

        mock_get_idp.return_value = idp
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "sp-cert",
            "private_key_pem_enc": "encrypted-key",
        }
        mock_decrypt.return_value = "decrypted-key"
        mock_get_certs.return_value = ["cert1", "cert2"]
        mock_build.return_value = {"sp": {}, "idp": {}}

        # We can't easily test _prepare_saml_auth because it also creates
        # OneLogin_Saml2_Auth. Instead verify the call to build_saml_settings.
        from services.saml.auth import _prepare_saml_auth

        with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth"):
            _prepare_saml_auth("tenant-id", "idp-id")

        # Verify multi-cert was passed
        call_kwargs = mock_build.call_args.kwargs
        assert call_kwargs["idp_certificate_pems"] == ["cert1", "cert2"]
        assert call_kwargs["idp_certificate_pem"] == "cert1"

    @patch("services.saml.auth.get_certificates_for_validation")
    @patch("services.saml.auth.build_saml_settings")
    @patch("services.saml.auth.decrypt_private_key")
    @patch("services.saml.auth.database")
    @patch("services.saml.auth.get_idp_for_saml_login")
    def test_fallback_to_idp_cert_when_no_certs(
        self, mock_get_idp, mock_db, mock_decrypt, mock_build, mock_get_certs
    ):
        """When no certs in DB, should fall back to IdP config cert."""

        idp = MagicMock()
        idp.sp_entity_id = "https://sp.example.com/saml/metadata"
        idp.entity_id = "https://idp.example.com"
        idp.sso_url = "https://idp.example.com/sso"
        idp.certificate_pem = "fallback-cert"
        idp.slo_url = None

        mock_get_idp.return_value = idp
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "sp-cert",
            "private_key_pem_enc": "encrypted-key",
        }
        mock_decrypt.return_value = "decrypted-key"
        mock_get_certs.return_value = []  # No certs in DB
        mock_build.return_value = {"sp": {}, "idp": {}}

        from services.saml.auth import _prepare_saml_auth

        with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth"):
            _prepare_saml_auth("tenant-id", "idp-id")

        call_kwargs = mock_build.call_args.kwargs
        assert call_kwargs["idp_certificate_pem"] == "fallback-cert"
        assert call_kwargs["idp_certificate_pems"] == ["fallback-cert"]

    @patch("services.saml.auth.get_certificates_for_validation")
    @patch("services.saml.auth.decrypt_private_key")
    @patch("services.saml.auth.database")
    @patch("services.saml.auth.get_idp_for_saml_login")
    def test_raises_when_idp_config_incomplete(
        self, mock_get_idp, mock_db, mock_decrypt, mock_get_certs
    ):
        """When IdP has no entity_id or sso_url, raises ValidationError."""
        from services.exceptions import ValidationError

        idp = MagicMock()
        idp.sp_entity_id = "https://sp.example.com/saml/metadata"
        idp.entity_id = None  # Missing
        idp.sso_url = None  # Missing
        idp.certificate_pem = "cert1"
        idp.slo_url = None

        mock_get_idp.return_value = idp
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "sp-cert",
            "private_key_pem_enc": "encrypted-key",
        }
        mock_decrypt.return_value = "decrypted-key"

        from services.saml.auth import _prepare_saml_auth

        with pytest.raises(ValidationError, match="entity ID and SSO URL"):
            _prepare_saml_auth("tenant-id", "idp-id")

    @patch("services.saml.auth.get_certificates_for_validation")
    @patch("services.saml.auth.decrypt_private_key")
    @patch("services.saml.auth.database")
    @patch("services.saml.auth.get_idp_for_saml_login")
    def test_raises_when_no_certificates(
        self, mock_get_idp, mock_db, mock_decrypt, mock_get_certs
    ):
        """When IdP has no certificates at all, raises ValidationError."""
        from services.exceptions import ValidationError

        idp = MagicMock()
        idp.sp_entity_id = "https://sp.example.com/saml/metadata"
        idp.entity_id = "https://idp.example.com"
        idp.sso_url = "https://idp.example.com/sso"
        idp.certificate_pem = None  # No fallback cert
        idp.slo_url = None

        mock_get_idp.return_value = idp
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "sp-cert",
            "private_key_pem_enc": "encrypted-key",
        }
        mock_decrypt.return_value = "decrypted-key"
        mock_get_certs.return_value = []  # No certs in DB

        from services.saml.auth import _prepare_saml_auth

        with pytest.raises(ValidationError, match="no certificates"):
            _prepare_saml_auth("tenant-id", "idp-id")
