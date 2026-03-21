"""Tests for SSO-related service layer functions in service_providers."""

from unittest.mock import patch

import pytest
from constants.nameid_formats import NAMEID_FORMAT_EMAIL, NAMEID_FORMAT_PERSISTENT
from services.exceptions import NotFoundError, ValidationError
from services.service_providers import (
    build_sso_response,
    get_service_provider_by_id,
    get_sp_by_entity_id,
    get_user_consent_info,
)

_RESOLVE_EMAIL = ("alice@example.com", NAMEID_FORMAT_EMAIL)

# ============================================================================
# get_service_provider_by_id
# ============================================================================


class TestGetServiceProviderById:
    @patch("services.service_providers.sso.database")
    def test_returns_row_when_found(self, mock_db):
        row = {"id": "sp-1", "name": "Test SP", "entity_id": "https://sp.example.com"}
        mock_db.service_providers.get_service_provider.return_value = row

        result = get_service_provider_by_id("tenant-1", "sp-1")

        assert result == row
        mock_db.service_providers.get_service_provider.assert_called_once_with("tenant-1", "sp-1")

    @patch("services.service_providers.sso.database")
    def test_returns_none_when_not_found(self, mock_db):
        mock_db.service_providers.get_service_provider.return_value = None

        result = get_service_provider_by_id("tenant-1", "nonexistent")

        assert result is None


# ============================================================================
# get_sp_by_entity_id
# ============================================================================


class TestGetSpByEntityId:
    @patch("services.service_providers.sso.database")
    def test_returns_sp_when_found(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "trust_established": True,
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

    @patch("services.service_providers.sso.database")
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
            "trust_established": True,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        mock_db.security.get_group_assertion_scope.return_value = "access_relevant"
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

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_returns_response_and_acs_url(self, mock_db, mock_log_event):
        self._setup_mocks(mock_db)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ),
        ):
            result_b64, acs_url, session_idx = build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id="_req123",
                base_url="https://idp.example.com",
            )

        assert result_b64 == "base64-response"
        assert acs_url == "https://sp.example.com/acs"

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_logs_sso_assertion_issued_event(self, mock_db, mock_log_event):
        self._setup_mocks(mock_db)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
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

    @patch("services.service_providers.sso.database")
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

    @patch("services.service_providers.sso.database")
    def test_raises_not_found_when_cert_missing(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "trust_established": True,
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

    @patch("services.service_providers.sso.database")
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

    @patch("services.service_providers.sso.database")
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

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_uses_per_sp_cert_when_available(self, mock_db, mock_log_event):
        """build_sso_response uses per-SP signing cert when available."""
        self._setup_mocks(mock_db, use_per_sp_cert=True)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ),
        ):
            result_b64, acs_url, session_idx = build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        assert result_b64 == "base64-response"
        # Per-SP cert was used, so tenant cert should not have been fetched
        mock_db.saml.get_sp_certificate.assert_not_called()

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_falls_back_to_tenant_cert(self, mock_db, mock_log_event):
        """build_sso_response falls back to tenant cert when no per-SP cert."""
        self._setup_mocks(mock_db, use_per_sp_cert=False)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ),
        ):
            result_b64, acs_url, session_idx = build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        assert result_b64 == "base64-response"
        # Tenant cert was used as fallback
        mock_db.saml.get_sp_certificate.assert_called_once()

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_includes_group_claims_when_enabled(self, mock_db, mock_log_event):
        """build_sso_response includes groups in user_attributes when flag is on."""
        self._setup_mocks(mock_db)
        # Enable group claims on the SP row
        mock_db.service_providers.get_service_provider_by_entity_id.return_value[
            "include_group_claims"
        ] = True
        mock_db.groups.get_access_relevant_group_names.return_value = [
            "Engineering",
            "All Staff",
        ]

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ) as mock_build,
        ):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        # Check that groups were passed to the assertion builder
        call_kwargs = mock_build.call_args[1]
        assert call_kwargs["user_attributes"]["groups"] == ["Engineering", "All Staff"]

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_excludes_group_claims_when_disabled(self, mock_db, mock_log_event):
        """build_sso_response does not include groups when flag is off."""
        self._setup_mocks(mock_db)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ) as mock_build,
        ):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        call_kwargs = mock_build.call_args[1]
        assert "groups" not in call_kwargs["user_attributes"]

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_excludes_empty_group_list(self, mock_db, mock_log_event):
        """build_sso_response omits groups key when user has no groups."""
        self._setup_mocks(mock_db)
        mock_db.service_providers.get_service_provider_by_entity_id.return_value[
            "include_group_claims"
        ] = True
        mock_db.groups.get_access_relevant_group_names.return_value = []

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ) as mock_build,
        ):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        call_kwargs = mock_build.call_args[1]
        assert "groups" not in call_kwargs["user_attributes"]

    @patch("services.service_providers.sso.database")
    def test_fails_when_neither_cert_exists(self, mock_db):
        """build_sso_response fails when neither per-SP nor tenant cert exists."""
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "trust_established": True,
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
    @patch("services.service_providers.sso.database")
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

    @patch("services.service_providers.sso.database")
    def test_returns_none_when_user_not_found(self, mock_db):
        mock_db.users.get_user_by_id.return_value = None

        result = get_user_consent_info("tenant-1", "user-missing")

        assert result is None
        mock_db.user_emails.get_primary_email.assert_not_called()

    @patch("services.service_providers.sso.database")
    def test_returns_none_when_no_primary_email(self, mock_db):
        mock_db.users.get_user_by_id.return_value = {
            "id": "user-1",
            "first_name": "Alice",
            "last_name": "Smith",
        }
        mock_db.user_emails.get_primary_email.return_value = None

        result = get_user_consent_info("tenant-1", "user-1")

        assert result is None

    @patch("services.service_providers.sso.database")
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


# ============================================================================
# build_sso_response: resolve_name_id integration
# ============================================================================


class TestBuildSsoResponseNameId:
    """Tests that build_sso_response calls resolve_name_id and uses its output."""

    def _setup_mocks(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "trust_established": True,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
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

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_resolve_name_id_called_and_output_used(self, mock_db, mock_log_event):
        """resolve_name_id is called during SSO and its values flow to the assertion."""
        self._setup_mocks(mock_db)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=("persistent-opaque-id", NAMEID_FORMAT_PERSISTENT),
            ) as mock_resolve,
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ) as mock_build,
        ):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        mock_resolve.assert_called_once_with(
            tenant_id="tenant-1",
            user_id="user-1",
            sp_id="sp-1",
            nameid_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            user_email="alice@example.com",
        )

        call_kwargs = mock_build.call_args[1]
        assert call_kwargs["name_id"] == "persistent-opaque-id"
        assert call_kwargs["name_id_format"] == NAMEID_FORMAT_PERSISTENT


# ============================================================================
# build_sso_response: attribute_mapping passthrough
# ============================================================================


class TestBuildSsoResponseAttributeMapping:
    """Tests that build_sso_response passes attribute_mapping to assertion builder."""

    def _setup_mocks(self, mock_db, attribute_mapping=None):
        """Set up standard mocks with optional attribute_mapping on SP row."""
        sp_row = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "trust_established": True,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        if attribute_mapping is not None:
            sp_row["attribute_mapping"] = attribute_mapping
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = sp_row
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

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_passes_attribute_mapping_to_builder(self, mock_db, mock_log_event):
        """build_sso_response passes attribute_mapping kwarg to build_saml_response."""
        custom_mapping = {
            "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        }
        self._setup_mocks(mock_db, attribute_mapping=custom_mapping)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ) as mock_build,
        ):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        call_kwargs = mock_build.call_args[1]
        assert call_kwargs["attribute_mapping"] == custom_mapping

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_passes_none_when_no_mapping(self, mock_db, mock_log_event):
        """build_sso_response passes None when SP has no attribute_mapping."""
        self._setup_mocks(mock_db)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ) as mock_build,
        ):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        call_kwargs = mock_build.call_args[1]
        assert call_kwargs["attribute_mapping"] is None


# ============================================================================
# build_sso_response: assertion encryption
# ============================================================================


class TestBuildSsoResponseEncryption:
    """Tests that build_sso_response encrypts when SP provides encryption cert."""

    _ENC_CERT = "-----BEGIN CERTIFICATE-----\nenc-cert\n-----END CERTIFICATE-----"

    def _setup_mocks(self, mock_db, *, encryption_certificate_pem=None):
        """Set up standard mocks with optional encryption cert on the SP row."""
        sp_row = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "trust_established": True,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "encryption_certificate_pem": encryption_certificate_pem,
        }
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = sp_row
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

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_encrypts_when_cert_present(self, mock_db, mock_log_event):
        """Encrypts assertion when SP provides an encryption certificate."""
        self._setup_mocks(mock_db, encryption_certificate_pem=self._ENC_CERT)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ) as mock_build,
        ):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        assert mock_build.call_args[1]["encryption_certificate_pem"] == self._ENC_CERT
        assert mock_log_event.call_args[1]["metadata"]["assertion_encrypted"] is True

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_plain_when_no_cert(self, mock_db, mock_log_event):
        """Sends plain assertion when SP has no encryption certificate."""
        self._setup_mocks(mock_db, encryption_certificate_pem=None)

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "services.service_providers.nameid.resolve_name_id",
                return_value=_RESOLVE_EMAIL,
            ),
            patch(
                "utils.saml_assertion.build_saml_response",
                return_value=("base64-response", "_session123"),
            ) as mock_build,
        ):
            build_sso_response(
                tenant_id="tenant-1",
                user_id="user-1",
                sp_entity_id="https://sp.example.com",
                authn_request_id=None,
                base_url="https://idp.example.com",
            )

        assert mock_build.call_args[1]["encryption_certificate_pem"] is None
        assert mock_log_event.call_args[1]["metadata"]["assertion_encrypted"] is False


# ============================================================================
# get_groups_for_assertion: scope resolution
# ============================================================================


class TestGetGroupsForAssertion:
    """Tests for get_groups_for_assertion scope resolution logic."""

    @patch("services.service_providers.sso.database")
    def test_returns_empty_when_group_claims_disabled(self, mock_db):
        """include_group_claims=false takes precedence; returns empty list."""
        from services.service_providers.sso import get_groups_for_assertion

        sp_row = {"include_group_claims": False}
        result = get_groups_for_assertion("t1", "u1", "sp1", sp_row)

        assert result == []
        mock_db.groups.get_effective_group_names.assert_not_called()
        mock_db.groups.get_trunk_group_names.assert_not_called()
        mock_db.groups.get_access_relevant_group_names.assert_not_called()

    @patch("services.service_providers.sso.database")
    def test_returns_empty_when_group_claims_missing(self, mock_db):
        """SP row without include_group_claims key returns empty list."""
        from services.service_providers.sso import get_groups_for_assertion

        sp_row = {}
        result = get_groups_for_assertion("t1", "u1", "sp1", sp_row)

        assert result == []

    @patch("services.service_providers.sso.database")
    def test_scope_all_calls_effective_group_names(self, mock_db):
        """scope=all delegates to get_effective_group_names."""
        from services.service_providers.sso import get_groups_for_assertion

        mock_db.groups.get_effective_group_names.return_value = ["Eng", "All"]
        sp_row = {
            "include_group_claims": True,
            "group_assertion_scope": "all",
        }

        result = get_groups_for_assertion("t1", "u1", "sp1", sp_row)

        assert result == ["Eng", "All"]
        mock_db.groups.get_effective_group_names.assert_called_once_with("t1", "u1")

    @patch("services.service_providers.sso.database")
    def test_scope_trunk_calls_trunk_group_names(self, mock_db):
        """scope=trunk delegates to get_trunk_group_names."""
        from services.service_providers.sso import get_groups_for_assertion

        mock_db.groups.get_trunk_group_names.return_value = ["Org"]
        sp_row = {
            "include_group_claims": True,
            "group_assertion_scope": "trunk",
        }

        result = get_groups_for_assertion("t1", "u1", "sp1", sp_row)

        assert result == ["Org"]
        mock_db.groups.get_trunk_group_names.assert_called_once_with("t1", "u1")

    @patch("services.service_providers.sso.database")
    def test_scope_access_relevant_calls_access_relevant(self, mock_db):
        """scope=access_relevant delegates to get_access_relevant_group_names."""
        from services.service_providers.sso import get_groups_for_assertion

        mock_db.groups.get_access_relevant_group_names.return_value = ["Team"]
        sp_row = {
            "include_group_claims": True,
            "group_assertion_scope": "access_relevant",
        }

        result = get_groups_for_assertion("t1", "u1", "sp1", sp_row)

        assert result == ["Team"]
        mock_db.groups.get_access_relevant_group_names.assert_called_once_with("t1", "u1", "sp1")

    @patch("services.service_providers.sso.database")
    def test_access_relevant_falls_back_to_trunk_for_available_to_all(self, mock_db):
        """access_relevant with available_to_all=true falls back to trunk groups."""
        from services.service_providers.sso import get_groups_for_assertion

        mock_db.groups.get_trunk_group_names.return_value = ["Root"]
        sp_row = {
            "include_group_claims": True,
            "group_assertion_scope": "access_relevant",
            "available_to_all": True,
        }

        result = get_groups_for_assertion("t1", "u1", "sp1", sp_row)

        assert result == ["Root"]
        mock_db.groups.get_trunk_group_names.assert_called_once_with("t1", "u1")
        mock_db.groups.get_access_relevant_group_names.assert_not_called()

    @patch("services.service_providers.sso.database")
    def test_sp_override_takes_precedence_over_tenant_default(self, mock_db):
        """SP-level group_assertion_scope overrides tenant default."""
        from services.service_providers.sso import get_groups_for_assertion

        mock_db.groups.get_effective_group_names.return_value = ["All Groups"]
        sp_row = {
            "include_group_claims": True,
            "group_assertion_scope": "all",  # SP override
        }

        result = get_groups_for_assertion("t1", "u1", "sp1", sp_row)

        assert result == ["All Groups"]
        # Tenant default should NOT be consulted because SP has an override
        mock_db.security.get_group_assertion_scope.assert_not_called()

    @patch("services.service_providers.sso.database")
    def test_tenant_default_used_when_sp_has_no_override(self, mock_db):
        """When SP group_assertion_scope is None, falls back to tenant default."""
        from services.service_providers.sso import get_groups_for_assertion

        mock_db.security.get_group_assertion_scope.return_value = "trunk"
        mock_db.groups.get_trunk_group_names.return_value = ["Trunk Group"]
        sp_row = {
            "include_group_claims": True,
            "group_assertion_scope": None,  # No SP override
        }

        result = get_groups_for_assertion("t1", "u1", "sp1", sp_row)

        assert result == ["Trunk Group"]
        mock_db.security.get_group_assertion_scope.assert_called_once_with("t1")
        mock_db.groups.get_trunk_group_names.assert_called_once_with("t1", "u1")

    @patch("services.service_providers.sso.database")
    def test_tenant_default_used_when_sp_key_missing(self, mock_db):
        """When SP row has no group_assertion_scope key, falls back to tenant."""
        from services.service_providers.sso import get_groups_for_assertion

        mock_db.security.get_group_assertion_scope.return_value = "all"
        mock_db.groups.get_effective_group_names.return_value = ["Effective"]
        sp_row = {
            "include_group_claims": True,
            # No group_assertion_scope key at all
        }

        result = get_groups_for_assertion("t1", "u1", "sp1", sp_row)

        assert result == ["Effective"]
        mock_db.security.get_group_assertion_scope.assert_called_once_with("t1")

    @patch("services.service_providers.sso.database")
    def test_default_scope_is_access_relevant(self, mock_db):
        """When neither SP nor tenant has a scope set, default is access_relevant."""
        from services.service_providers.sso import get_groups_for_assertion

        mock_db.security.get_group_assertion_scope.return_value = "access_relevant"
        mock_db.groups.get_access_relevant_group_names.return_value = ["AR Group"]
        sp_row = {
            "include_group_claims": True,
            "group_assertion_scope": None,
        }

        result = get_groups_for_assertion("t1", "u1", "sp1", sp_row)

        assert result == ["AR Group"]
        mock_db.groups.get_access_relevant_group_names.assert_called_once_with("t1", "u1", "sp1")


# ============================================================================
# get_groups_for_consent
# ============================================================================


class TestGetGroupsForConsent:
    """Tests for get_groups_for_consent (consent screen group disclosure)."""

    @patch("services.service_providers.sso.database")
    def test_returns_groups_for_existing_sp(self, mock_db):
        """Returns group list for a valid SP."""
        from services.service_providers.sso import get_groups_for_consent

        mock_db.service_providers.get_service_provider.return_value = {
            "id": "sp-1",
            "include_group_claims": True,
            "group_assertion_scope": "all",
        }
        mock_db.groups.get_effective_group_names.return_value = ["Eng", "Sales"]

        result = get_groups_for_consent("t1", "u1", "sp-1")

        assert result == ["Eng", "Sales"]

    @patch("services.service_providers.sso.database")
    def test_returns_empty_when_sp_not_found(self, mock_db):
        """Returns empty list when SP does not exist."""
        from services.service_providers.sso import get_groups_for_consent

        mock_db.service_providers.get_service_provider.return_value = None

        result = get_groups_for_consent("t1", "u1", "sp-missing")

        assert result == []

    @patch("services.service_providers.sso.database")
    def test_returns_empty_when_group_claims_disabled(self, mock_db):
        """Returns empty list when SP has group claims disabled."""
        from services.service_providers.sso import get_groups_for_consent

        mock_db.service_providers.get_service_provider.return_value = {
            "id": "sp-1",
            "include_group_claims": False,
        }

        result = get_groups_for_consent("t1", "u1", "sp-1")

        assert result == []
