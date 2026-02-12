"""Tests for SSO-related service layer functions in service_providers."""

from unittest.mock import patch

import pytest
from services.exceptions import NotFoundError, ValidationError
from services.service_providers import (
    build_sso_response,
    get_sp_by_entity_id,
    get_user_consent_info,
)

# ============================================================================
# get_sp_by_entity_id
# ============================================================================


class TestGetSpByEntityId:
    @patch("services.service_providers.database")
    def test_returns_sp_when_found(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }

        result = get_sp_by_entity_id("tenant-1", "https://sp.example.com")

        assert result is not None
        assert result.entity_id == "https://sp.example.com"
        assert result.name == "Test SP"
        mock_db.service_providers.get_service_provider_by_entity_id.assert_called_once_with(
            "tenant-1", "https://sp.example.com"
        )

    @patch("services.service_providers.database")
    def test_returns_none_when_not_found(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = None

        result = get_sp_by_entity_id("tenant-1", "https://unknown.com")

        assert result is None


# ============================================================================
# build_sso_response
# ============================================================================


class TestBuildSsoResponse:
    def _setup_mocks(self, mock_db, *, use_per_sp_cert=False):
        """Set up standard mocks for a successful SSO response."""
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        if use_per_sp_cert:
            mock_db.sp_signing_certificates.get_signing_certificate.return_value = {
                "certificate_pem": "-----BEGIN CERTIFICATE-----\nper-sp\n-----END CERTIFICATE-----",
                "private_key_pem_enc": "encrypted-sp-key",
            }
        else:
            mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
            mock_db.saml.get_sp_certificate.return_value = {
                "certificate_pem": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                "private_key_pem_enc": "encrypted-key",
            }
        mock_db.users.get_user_by_id.return_value = {
            "id": "user-1",
            "first_name": "Alice",
            "last_name": "Smith",
        }
        mock_db.user_emails.get_primary_email.return_value = {
            "email": "alice@example.com",
        }

    @patch("services.service_providers.log_event")
    @patch("services.service_providers.database")
    def test_returns_response_and_acs_url(self, mock_db, mock_log_event):
        self._setup_mocks(mock_db)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value="base64-response",
            ),
        ):
            result_b64, acs_url = build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id="_req123",
                base_url="https://idp.example.com",
            )

        assert result_b64 == "base64-response"
        assert acs_url == "https://sp.example.com/acs"

    @patch("services.service_providers.log_event")
    @patch("services.service_providers.database")
    def test_logs_sso_assertion_issued_event(self, mock_db, mock_log_event):
        self._setup_mocks(mock_db)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value="base64-response",
            ),
        ):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        mock_log_event.assert_called_once()
        call_kwargs = mock_log_event.call_args[1]
        assert call_kwargs["event_type"] == "sso_assertion_issued"
        assert call_kwargs["artifact_type"] == "service_provider"
        assert call_kwargs["artifact_id"] == "sp-1"
        assert call_kwargs["metadata"]["sp_entity_id"] == "https://sp.example.com"

    @patch("services.service_providers.database")
    def test_raises_not_found_when_sp_missing(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = None

        with pytest.raises(NotFoundError, match="Service provider not found"):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://unknown.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

    @patch("services.service_providers.database")
    def test_raises_not_found_when_cert_missing(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = None

        with pytest.raises(NotFoundError, match="certificate not configured"):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

    @patch("services.service_providers.database")
    def test_raises_not_found_when_user_missing(self, mock_db):
        self._setup_mocks(mock_db)
        mock_db.users.get_user_by_id.return_value = None

        with patch("utils.saml.decrypt_private_key", return_value="decrypted-key"):
            with pytest.raises(NotFoundError, match="User not found"):
                build_sso_response(
                    tenant_id="tenant-1",
                    user_id="user-missing",
                    sp_entity_id="https://sp.example.com",
                    authn_request_id=None,
                    base_url="https://idp.example.com",
                )

    @patch("services.service_providers.database")
    def test_raises_validation_error_when_no_email(self, mock_db):
        self._setup_mocks(mock_db)
        mock_db.user_emails.get_primary_email.return_value = None

        with patch("utils.saml.decrypt_private_key", return_value="decrypted-key"):
            with pytest.raises(ValidationError, match="no primary email"):
                build_sso_response(
                    tenant_id="tenant-1",
                    user_id="user-1",
                    sp_entity_id="https://sp.example.com",
                    authn_request_id=None,
                    base_url="https://idp.example.com",
                )

    @patch("services.service_providers.log_event")
    @patch("services.service_providers.database")
    def test_uses_per_sp_cert_when_available(self, mock_db, mock_log_event):
        """build_sso_response uses per-SP signing cert when available."""
        self._setup_mocks(mock_db, use_per_sp_cert=True)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value="base64-response",
            ),
        ):
            result_b64, acs_url = build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        assert result_b64 == "base64-response"
        # Per-SP cert was used, so tenant cert should not have been fetched
        mock_db.saml.get_sp_certificate.assert_not_called()

    @patch("services.service_providers.log_event")
    @patch("services.service_providers.database")
    def test_falls_back_to_tenant_cert(self, mock_db, mock_log_event):
        """build_sso_response falls back to tenant cert when no per-SP cert."""
        self._setup_mocks(mock_db, use_per_sp_cert=False)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value="base64-response",
            ),
        ):
            result_b64, acs_url = build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        assert result_b64 == "base64-response"
        # Tenant cert was used as fallback
        mock_db.saml.get_sp_certificate.assert_called_once()

    @patch("services.service_providers.database")
    def test_fails_when_neither_cert_exists(self, mock_db):
        """build_sso_response fails when neither per-SP nor tenant cert exists."""
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = None

        with pytest.raises(NotFoundError, match="certificate not configured"):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )


# ============================================================================
# get_user_consent_info
# ============================================================================


class TestGetUserConsentInfo:
    @patch("services.service_providers.database")
    def test_returns_user_info(self, mock_db):
        mock_db.users.get_user_by_id.return_value = {
            "id": "user-1",
            "first_name": "Alice",
            "last_name": "Smith",
        }
        mock_db.user_emails.get_primary_email.return_value = {
            "email": "alice@example.com",
        }

        result = get_user_consent_info("tenant-1", "user-1")

        assert result == {
            "email": "alice@example.com",
            "first_name": "Alice",
            "last_name": "Smith",
        }
        mock_db.users.get_user_by_id.assert_called_once_with("tenant-1", "user-1")
        mock_db.user_emails.get_primary_email.assert_called_once_with("tenant-1", "user-1")

    @patch("services.service_providers.database")
    def test_returns_none_when_user_not_found(self, mock_db):
        mock_db.users.get_user_by_id.return_value = None

        result = get_user_consent_info("tenant-1", "user-missing")

        assert result is None
        mock_db.user_emails.get_primary_email.assert_not_called()

    @patch("services.service_providers.database")
    def test_returns_none_when_no_primary_email(self, mock_db):
        mock_db.users.get_user_by_id.return_value = {
            "id": "user-1",
            "first_name": "Alice",
            "last_name": "Smith",
        }
        mock_db.user_emails.get_primary_email.return_value = None

        result = get_user_consent_info("tenant-1", "user-1")

        assert result is None

    @patch("services.service_providers.database")
    def test_handles_missing_name_fields(self, mock_db):
        mock_db.users.get_user_by_id.return_value = {"id": "user-1"}
        mock_db.user_emails.get_primary_email.return_value = {
            "email": "user@example.com",
        }

        result = get_user_consent_info("tenant-1", "user-1")

        assert result == {
            "email": "user@example.com",
            "first_name": "",
            "last_name": "",
        }
