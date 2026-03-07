"""Tests for SLO service layer (SP-initiated and IdP-initiated propagation)."""

from unittest.mock import MagicMock, patch

import pytest
from services.exceptions import NotFoundError, ValidationError
from services.service_providers.slo import process_sp_logout_request, propagate_logout_to_sps


class TestProcessSpLogoutRequest:
    def _make_parsed_request(self, **overrides):
        base = {
            "id": "_req_slo_123",
            "issuer": "https://sp.example.com",
            "name_id": "user@example.com",
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "session_index": "_session_abc",
        }
        base.update(overrides)
        return base

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.database")
    def test_returns_response_and_slo_url(self, mock_db, mock_log):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "enabled": True,
            "slo_url": "https://sp.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "cert-pem",
            "private_key_pem_enc": "encrypted-key",
        }

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_response",
                return_value="base64-logout-response",
            ),
        ):
            response_b64, slo_url = process_sp_logout_request(
                tenant_id="tenant-1",
                parsed_request=self._make_parsed_request(),
                base_url="https://idp.example.com",
            )

        assert response_b64 == "base64-logout-response"
        assert slo_url == "https://sp.example.com/slo"

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.database")
    def test_logs_slo_sp_initiated_event(self, mock_db, mock_log):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "enabled": True,
            "slo_url": "https://sp.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "cert-pem",
            "private_key_pem_enc": "encrypted-key",
        }

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_response",
                return_value="base64-logout-response",
            ),
        ):
            process_sp_logout_request(
                tenant_id="tenant-1",
                parsed_request=self._make_parsed_request(),
                base_url="https://idp.example.com",
            )

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "slo_sp_initiated"
        assert call_kwargs["artifact_type"] == "service_provider"
        assert call_kwargs["artifact_id"] == "sp-1"
        assert call_kwargs["metadata"]["sp_entity_id"] == "https://sp.example.com"

    @patch("services.service_providers.slo.database")
    def test_raises_validation_error_when_no_issuer(self, mock_db):
        parsed = self._make_parsed_request(issuer=None)

        with pytest.raises(ValidationError, match="missing Issuer"):
            process_sp_logout_request(
                tenant_id="tenant-1",
                parsed_request=parsed,
                base_url="https://idp.example.com",
            )

    @patch("services.service_providers.slo.database")
    def test_raises_not_found_when_sp_missing(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = None

        with pytest.raises(NotFoundError, match="not found"):
            process_sp_logout_request(
                tenant_id="tenant-1",
                parsed_request=self._make_parsed_request(),
                base_url="https://idp.example.com",
            )

    @patch("services.service_providers.slo.database")
    def test_raises_validation_error_when_sp_disabled(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Disabled SP",
            "entity_id": "https://sp.example.com",
            "enabled": False,
            "slo_url": "https://sp.example.com/slo",
        }

        with pytest.raises(ValidationError, match="disabled"):
            process_sp_logout_request(
                tenant_id="tenant-1",
                parsed_request=self._make_parsed_request(),
                base_url="https://idp.example.com",
            )

    @patch("services.service_providers.slo.database")
    def test_raises_not_found_when_no_slo_url(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "enabled": True,
            "slo_url": None,
        }

        with pytest.raises(NotFoundError, match="no SLO URL"):
            process_sp_logout_request(
                tenant_id="tenant-1",
                parsed_request=self._make_parsed_request(),
                base_url="https://idp.example.com",
            )

    @patch("services.service_providers.slo.database")
    def test_raises_not_found_when_no_certificate(self, mock_db):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "enabled": True,
            "slo_url": "https://sp.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = None

        with pytest.raises(NotFoundError, match="certificate not configured"):
            process_sp_logout_request(
                tenant_id="tenant-1",
                parsed_request=self._make_parsed_request(),
                base_url="https://idp.example.com",
            )

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.database")
    def test_uses_per_sp_cert_when_available(self, mock_db, mock_log):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-1",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "enabled": True,
            "slo_url": "https://sp.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = {
            "certificate_pem": "per-sp-cert",
            "private_key_pem_enc": "encrypted-sp-key",
        }

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_response",
                return_value="base64-logout-response",
            ),
        ):
            process_sp_logout_request(
                tenant_id="tenant-1",
                parsed_request=self._make_parsed_request(),
                base_url="https://idp.example.com",
            )

        # Tenant cert should not have been fetched
        mock_db.saml.get_sp_certificate.assert_not_called()

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.database")
    def test_builds_entity_id_from_sp_id(self, mock_db, mock_log):
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = {
            "id": "sp-42",
            "name": "Test SP",
            "entity_id": "https://sp.example.com",
            "enabled": True,
            "slo_url": "https://sp.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "cert-pem",
            "private_key_pem_enc": "encrypted-key",
        }

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_response",
                return_value="base64-logout-response",
            ) as mock_build,
        ):
            process_sp_logout_request(
                tenant_id="tenant-1",
                parsed_request=self._make_parsed_request(),
                base_url="https://idp.example.com",
            )

        # Verify the entity ID passed to build_idp_logout_response
        call_kwargs = mock_build.call_args[1]
        assert call_kwargs["issuer_entity_id"] == "urn:weftid:tenant-1:idp:sp-42"


# ============================================================================
# propagate_logout_to_sps
# ============================================================================


class TestPropagateLogoutToSps:
    def _make_active_sps(self, count=1):
        return [
            {
                "sp_id": f"sp-{i}",
                "sp_entity_id": f"https://sp{i}.example.com",
                "name_id": "user@example.com",
                "session_index": f"_session_{i}",
            }
            for i in range(count)
        ]

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_returns_zero_for_empty_list(self, mock_db, mock_httpx, mock_log):
        result = propagate_logout_to_sps(
            tenant_id="tenant-1",
            user_id="user-1",
            active_sps=[],
            base_url="https://idp.example.com",
        )
        assert result == 0
        mock_log.assert_not_called()

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_propagates_to_sp_with_slo_url(self, mock_db, mock_httpx, mock_log):
        mock_db.service_providers.get_service_provider.return_value = {
            "id": "sp-0",
            "name": "Test SP",
            "slo_url": "https://sp0.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "cert-pem",
            "private_key_pem_enc": "encrypted-key",
        }

        mock_response = MagicMock()
        mock_response.is_success = True
        mock_httpx.post.return_value = mock_response

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_request",
                return_value="base64-logout-request",
            ),
        ):
            result = propagate_logout_to_sps(
                tenant_id="tenant-1",
                user_id="user-1",
                active_sps=self._make_active_sps(1),
                base_url="https://idp.example.com",
            )

        assert result == 1
        mock_httpx.post.assert_called_once_with(
            "https://sp0.example.com/slo",
            data={"SAMLRequest": "base64-logout-request"},
            timeout=5.0,
        )

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_skips_sp_without_slo_url(self, mock_db, mock_httpx, mock_log):
        mock_db.service_providers.get_service_provider.return_value = {
            "id": "sp-0",
            "name": "No SLO SP",
            "slo_url": None,
        }

        result = propagate_logout_to_sps(
            tenant_id="tenant-1",
            user_id="user-1",
            active_sps=self._make_active_sps(1),
            base_url="https://idp.example.com",
        )

        assert result == 0
        mock_httpx.post.assert_not_called()

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_skips_sp_not_found(self, mock_db, mock_httpx, mock_log):
        mock_db.service_providers.get_service_provider.return_value = None

        result = propagate_logout_to_sps(
            tenant_id="tenant-1",
            user_id="user-1",
            active_sps=self._make_active_sps(1),
            base_url="https://idp.example.com",
        )

        assert result == 0
        mock_httpx.post.assert_not_called()

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_handles_http_error_gracefully(self, mock_db, mock_httpx, mock_log):
        mock_db.service_providers.get_service_provider.return_value = {
            "id": "sp-0",
            "name": "Test SP",
            "slo_url": "https://sp0.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "cert-pem",
            "private_key_pem_enc": "encrypted-key",
        }

        mock_response = MagicMock()
        mock_response.is_success = False
        mock_response.status_code = 500
        mock_httpx.post.return_value = mock_response

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_request",
                return_value="base64-logout-request",
            ),
        ):
            result = propagate_logout_to_sps(
                tenant_id="tenant-1",
                user_id="user-1",
                active_sps=self._make_active_sps(1),
                base_url="https://idp.example.com",
            )

        assert result == 0

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_handles_connection_error_gracefully(self, mock_db, mock_httpx, mock_log):
        mock_db.service_providers.get_service_provider.return_value = {
            "id": "sp-0",
            "name": "Test SP",
            "slo_url": "https://sp0.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "cert-pem",
            "private_key_pem_enc": "encrypted-key",
        }

        mock_httpx.post.side_effect = Exception("Connection refused")

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_request",
                return_value="base64-logout-request",
            ),
        ):
            result = propagate_logout_to_sps(
                tenant_id="tenant-1",
                user_id="user-1",
                active_sps=self._make_active_sps(1),
                base_url="https://idp.example.com",
            )

        # Should not raise, just return 0
        assert result == 0

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_logs_propagation_event(self, mock_db, mock_httpx, mock_log):
        mock_db.service_providers.get_service_provider.return_value = {
            "id": "sp-0",
            "name": "Test SP",
            "slo_url": "https://sp0.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "cert-pem",
            "private_key_pem_enc": "encrypted-key",
        }

        mock_response = MagicMock()
        mock_response.is_success = True
        mock_httpx.post.return_value = mock_response

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_request",
                return_value="base64-logout-request",
            ),
        ):
            propagate_logout_to_sps(
                tenant_id="tenant-1",
                user_id="user-1",
                active_sps=self._make_active_sps(1),
                base_url="https://idp.example.com",
            )

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "slo_idp_propagated"
        assert call_kwargs["artifact_type"] == "user"
        assert call_kwargs["metadata"]["sp_count"] == 1
        assert call_kwargs["metadata"]["notified_count"] == 1

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_skips_sp_without_certificate(self, mock_db, mock_httpx, mock_log):
        mock_db.service_providers.get_service_provider.return_value = {
            "id": "sp-0",
            "name": "Test SP",
            "slo_url": "https://sp0.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = None

        result = propagate_logout_to_sps(
            tenant_id="tenant-1",
            user_id="user-1",
            active_sps=self._make_active_sps(1),
            base_url="https://idp.example.com",
        )

        assert result == 0
        mock_httpx.post.assert_not_called()

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_propagate_multiple_sps_all_succeed(self, mock_db, mock_httpx, mock_log):
        mock_db.service_providers.get_service_provider.side_effect = [
            {"id": f"sp-{i}", "name": f"SP {i}", "slo_url": f"https://sp{i}.example.com/slo"}
            for i in range(3)
        ]
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "cert-pem",
            "private_key_pem_enc": "encrypted-key",
        }

        mock_response = MagicMock()
        mock_response.is_success = True
        mock_httpx.post.return_value = mock_response

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_request",
                return_value="base64-logout-request",
            ),
        ):
            result = propagate_logout_to_sps(
                tenant_id="tenant-1",
                user_id="user-1",
                active_sps=self._make_active_sps(3),
                base_url="https://idp.example.com",
            )

        assert result == 3
        assert mock_httpx.post.call_count == 3
        # Verify event metadata
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["metadata"]["sp_count"] == 3
        assert call_kwargs["metadata"]["notified_count"] == 3

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_propagate_multiple_sps_partial_failure(self, mock_db, mock_httpx, mock_log):
        """3 SPs: first not found, second no SLO URL, third succeeds."""
        mock_db.service_providers.get_service_provider.side_effect = [
            None,  # SP 0 not found
            {"id": "sp-1", "name": "No SLO SP", "slo_url": None},  # SP 1 no SLO URL
            {"id": "sp-2", "name": "Good SP", "slo_url": "https://sp2.example.com/slo"},
        ]
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = None
        mock_db.saml.get_sp_certificate.return_value = {
            "certificate_pem": "cert-pem",
            "private_key_pem_enc": "encrypted-key",
        }

        mock_response = MagicMock()
        mock_response.is_success = True
        mock_httpx.post.return_value = mock_response

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_request",
                return_value="base64-logout-request",
            ),
        ):
            result = propagate_logout_to_sps(
                tenant_id="tenant-1",
                user_id="user-1",
                active_sps=self._make_active_sps(3),
                base_url="https://idp.example.com",
            )

        assert result == 1
        assert mock_httpx.post.call_count == 1
        # Verify event counts reflect partial success
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["metadata"]["sp_count"] == 3
        assert call_kwargs["metadata"]["notified_count"] == 1

    @patch("services.service_providers.slo.log_event")
    @patch("services.service_providers.slo.httpx")
    @patch("services.service_providers.slo.database")
    def test_propagate_uses_per_sp_certificate(self, mock_db, mock_httpx, mock_log):
        """Per-SP cert is used when available; tenant cert lookup is skipped."""
        mock_db.service_providers.get_service_provider.return_value = {
            "id": "sp-0",
            "name": "Test SP",
            "slo_url": "https://sp0.example.com/slo",
        }
        mock_db.sp_signing_certificates.get_signing_certificate.return_value = {
            "certificate_pem": "per-sp-cert",
            "private_key_pem_enc": "encrypted-sp-key",
        }

        mock_response = MagicMock()
        mock_response.is_success = True
        mock_httpx.post.return_value = mock_response

        with (
            patch("utils.saml.decrypt_private_key", return_value="decrypted-key"),
            patch(
                "utils.saml_slo.build_idp_logout_request",
                return_value="base64-logout-request",
            ),
        ):
            result = propagate_logout_to_sps(
                tenant_id="tenant-1",
                user_id="user-1",
                active_sps=self._make_active_sps(1),
                base_url="https://idp.example.com",
            )

        assert result == 1
        # Tenant cert should not have been fetched
        mock_db.saml.get_sp_certificate.assert_not_called()
