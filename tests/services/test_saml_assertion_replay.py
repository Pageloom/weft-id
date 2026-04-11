"""Tests for SAML assertion replay prevention.

Tests the _check_assertion_replay function and its integration with
process_saml_response.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # noqa: F401

    HAS_SAML_LIBRARY = True
except ImportError:
    HAS_SAML_LIBRARY = False


@pytest.fixture()
def test_idp_data():
    """Provide test IdP data for integration tests."""
    return {
        "name": "Test Okta IdP",
        "provider_type": "okta",
        "entity_id": "https://idp.example.com/entity",
        "sso_url": "https://idp.example.com/sso",
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
    }


# =============================================================================
# _check_assertion_replay unit tests
# =============================================================================


class TestCheckAssertionReplay:
    """Tests for the _check_assertion_replay helper."""

    def test_first_assertion_accepted(self):
        """First use of an assertion ID should succeed (cache.add returns True)."""
        from services.saml.auth import _check_assertion_replay

        mock_auth = MagicMock()
        mock_auth.get_last_assertion_id.return_value = "assertion-123"
        mock_auth.get_last_assertion_not_on_or_after.return_value = None

        with patch("services.saml.auth.cache") as mock_cache:
            mock_cache.add.return_value = True
            # Should not raise
            _check_assertion_replay(mock_auth, "tenant-1")

            mock_cache.add.assert_called_once()
            key = mock_cache.add.call_args[0][0]
            assert "tenant-1" in key
            assert "assertion-123" in key

    def test_replayed_assertion_rejected(self):
        """Second use of the same assertion ID should raise ValidationError."""
        from services.exceptions import ValidationError
        from services.saml.auth import _check_assertion_replay

        mock_auth = MagicMock()
        mock_auth.get_last_assertion_id.return_value = "assertion-123"
        mock_auth.get_last_assertion_not_on_or_after.return_value = None

        with patch("services.saml.auth.cache") as mock_cache:
            mock_cache.add.return_value = False  # Key already exists
            mock_cache.get.return_value = b"1"  # Confirms it's in cache

            with pytest.raises(ValidationError) as exc_info:
                _check_assertion_replay(mock_auth, "tenant-1")

            assert exc_info.value.code == "saml_assertion_replay"

    def test_memcached_unavailable_fails_open(self):
        """When Memcached is down, allow the request through."""
        from services.saml.auth import _check_assertion_replay

        mock_auth = MagicMock()
        mock_auth.get_last_assertion_id.return_value = "assertion-123"
        mock_auth.get_last_assertion_not_on_or_after.return_value = None

        with patch("services.saml.auth.cache") as mock_cache:
            mock_cache.add.return_value = False  # Memcached unavailable
            mock_cache.get.return_value = None  # Also unavailable

            # Should not raise (fail-open)
            _check_assertion_replay(mock_auth, "tenant-1")

    def test_no_assertion_id_skips_check(self):
        """When assertion has no ID, skip the replay check entirely."""
        from services.saml.auth import _check_assertion_replay

        mock_auth = MagicMock()
        mock_auth.get_last_assertion_id.return_value = None

        with patch("services.saml.auth.cache") as mock_cache:
            _check_assertion_replay(mock_auth, "tenant-1")
            mock_cache.add.assert_not_called()

    def test_empty_assertion_id_skips_check(self):
        """When assertion ID is empty string, skip the replay check."""
        from services.saml.auth import _check_assertion_replay

        mock_auth = MagicMock()
        mock_auth.get_last_assertion_id.return_value = ""

        with patch("services.saml.auth.cache") as mock_cache:
            _check_assertion_replay(mock_auth, "tenant-1")
            mock_cache.add.assert_not_called()

    def test_ttl_from_not_on_or_after(self):
        """TTL should be derived from the assertion's NotOnOrAfter timestamp."""
        from services.saml.auth import _check_assertion_replay

        mock_auth = MagicMock()
        mock_auth.get_last_assertion_id.return_value = "assertion-123"
        # NotOnOrAfter is 120 seconds from now
        mock_auth.get_last_assertion_not_on_or_after.return_value = (
            datetime.now(UTC).timestamp() + 120
        )

        with patch("services.saml.auth.cache") as mock_cache:
            mock_cache.add.return_value = True
            _check_assertion_replay(mock_auth, "tenant-1")

            ttl = mock_cache.add.call_args[1]["ttl"]
            # Should be approximately 120 seconds (allow small drift)
            assert 115 <= ttl <= 125

    def test_ttl_capped_at_max(self):
        """TTL should not exceed _MAX_REPLAY_TTL even if NotOnOrAfter is far out."""
        from services.saml.auth import _MAX_REPLAY_TTL, _check_assertion_replay

        mock_auth = MagicMock()
        mock_auth.get_last_assertion_id.return_value = "assertion-123"
        # NotOnOrAfter is 1 hour from now (way beyond max)
        mock_auth.get_last_assertion_not_on_or_after.return_value = (
            datetime.now(UTC).timestamp() + 3600
        )

        with patch("services.saml.auth.cache") as mock_cache:
            mock_cache.add.return_value = True
            _check_assertion_replay(mock_auth, "tenant-1")

            ttl = mock_cache.add.call_args[1]["ttl"]
            assert ttl == _MAX_REPLAY_TTL

    def test_default_ttl_when_no_not_on_or_after(self):
        """When assertion has no NotOnOrAfter, use default TTL."""
        from services.saml.auth import _DEFAULT_REPLAY_TTL, _check_assertion_replay

        mock_auth = MagicMock()
        mock_auth.get_last_assertion_id.return_value = "assertion-123"
        mock_auth.get_last_assertion_not_on_or_after.return_value = None

        with patch("services.saml.auth.cache") as mock_cache:
            mock_cache.add.return_value = True
            _check_assertion_replay(mock_auth, "tenant-1")

            ttl = mock_cache.add.call_args[1]["ttl"]
            assert ttl == _DEFAULT_REPLAY_TTL

    def test_expired_not_on_or_after_uses_minimum_ttl(self):
        """When NotOnOrAfter is in the past, TTL should be clamped to 1 second."""
        from services.saml.auth import _check_assertion_replay

        mock_auth = MagicMock()
        mock_auth.get_last_assertion_id.return_value = "assertion-123"
        # NotOnOrAfter already passed
        mock_auth.get_last_assertion_not_on_or_after.return_value = (
            datetime.now(UTC).timestamp() - 10
        )

        with patch("services.saml.auth.cache") as mock_cache:
            mock_cache.add.return_value = True
            _check_assertion_replay(mock_auth, "tenant-1")

            ttl = mock_cache.add.call_args[1]["ttl"]
            assert ttl == 1

    def test_tenant_isolation_in_cache_key(self):
        """Different tenants should use different cache keys for the same assertion ID."""
        from services.saml.auth import _check_assertion_replay

        mock_auth = MagicMock()
        mock_auth.get_last_assertion_id.return_value = "assertion-same"
        mock_auth.get_last_assertion_not_on_or_after.return_value = None

        keys_used = []

        with patch("services.saml.auth.cache") as mock_cache:
            mock_cache.add.return_value = True

            _check_assertion_replay(mock_auth, "tenant-a")
            keys_used.append(mock_cache.add.call_args[0][0])

            _check_assertion_replay(mock_auth, "tenant-b")
            keys_used.append(mock_cache.add.call_args[0][0])

        assert keys_used[0] != keys_used[1]
        assert "tenant-a" in keys_used[0]
        assert "tenant-b" in keys_used[1]


# =============================================================================
# Integration: replay check through process_saml_response
# =============================================================================


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_response_rejects_replayed_assertion(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """process_saml_response should reject a replayed assertion ID."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.exceptions import ValidationError
    from services.types import RequestingUser

    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=test_tenant["id"],
        role="super_admin",
    )

    saml_service.get_or_create_sp_certificate(requesting_user)

    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    mock_auth = MagicMock()
    mock_auth.get_errors.return_value = []
    mock_auth.is_authenticated.return_value = True
    mock_auth.get_last_assertion_id.return_value = f"replay-test-{uuid4()}"
    mock_auth.get_last_assertion_not_on_or_after.return_value = None
    mock_auth.get_attributes.return_value = {
        "email": ["user@example.com"],
        "firstName": ["John"],
        "lastName": ["Doe"],
    }
    mock_auth.get_nameid.return_value = "user@example.com"
    mock_auth.get_nameid_format.return_value = (
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    mock_auth.get_session_index.return_value = "session123"

    monkeypatch.setattr(
        "onelogin.saml2.auth.OneLogin_Saml2_Auth",
        lambda req, settings: mock_auth,
    )

    # Simulate replay: cache.add returns False (already seen), cache.get confirms
    with patch("services.saml.auth.cache") as mock_cache:
        mock_cache.add.return_value = False
        mock_cache.get.return_value = b"1"

        with pytest.raises(ValidationError) as exc_info:
            saml_service.process_saml_response(
                tenant_id=test_tenant["id"],
                idp_id=created.id,
                saml_response="dummybase64response",
            )

        assert exc_info.value.code == "saml_assertion_replay"


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_response_allows_first_assertion(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """process_saml_response should accept a never-seen assertion ID."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=test_tenant["id"],
        role="super_admin",
    )

    saml_service.get_or_create_sp_certificate(requesting_user)

    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    mock_auth = MagicMock()
    mock_auth.get_errors.return_value = []
    mock_auth.is_authenticated.return_value = True
    mock_auth.get_last_assertion_id.return_value = f"first-use-{uuid4()}"
    mock_auth.get_last_assertion_not_on_or_after.return_value = None
    mock_auth.get_attributes.return_value = {
        "email": ["user@example.com"],
        "firstName": ["John"],
        "lastName": ["Doe"],
    }
    mock_auth.get_nameid.return_value = "user@example.com"
    mock_auth.get_nameid_format.return_value = (
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    mock_auth.get_session_index.return_value = "session123"

    monkeypatch.setattr(
        "onelogin.saml2.auth.OneLogin_Saml2_Auth",
        lambda req, settings: mock_auth,
    )

    # First use: cache.add returns True
    with patch("services.saml.auth.cache") as mock_cache:
        mock_cache.add.return_value = True

        result = saml_service.process_saml_response(
            tenant_id=test_tenant["id"],
            idp_id=created.id,
            saml_response="dummybase64response",
        )

        assert result.attributes.email == "user@example.com"
