"""Unit tests for password lifecycle hardening features.

Tests for:
- HIBP monitoring data computation
- HIBP suffix matching
- Policy compliance enforcement
"""

import hashlib
import hmac as hmac_mod
from unittest.mock import patch
from uuid import uuid4

from utils.password_strength import (
    check_hibp_suffix_against_hmac,
    compute_hibp_monitoring_data,
)


class TestHibpMonitoringData:
    """Tests for compute_hibp_monitoring_data()."""

    def test_returns_prefix_and_hmac(self):
        key = b"test-hmac-key-32-bytes-long-here!"
        prefix, check_hmac = compute_hibp_monitoring_data("test_password", key)

        # Prefix should be 5 chars (first 5 hex of SHA-1)
        assert len(prefix) == 5
        assert all(c in "0123456789ABCDEF" for c in prefix)

        # HMAC should be a 64-char hex string (SHA-256)
        assert len(check_hmac) == 64
        assert all(c in "0123456789abcdef" for c in check_hmac)

    def test_prefix_matches_sha1(self):
        key = b"test-hmac-key-32-bytes-long-here!"
        password = "my_secret_password"
        prefix, _ = compute_hibp_monitoring_data(password, key)

        # Verify prefix matches actual SHA-1
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324
        assert prefix == sha1[:5]

    def test_hmac_is_deterministic(self):
        key = b"test-hmac-key-32-bytes-long-here!"
        _, hmac1 = compute_hibp_monitoring_data("same_password", key)
        _, hmac2 = compute_hibp_monitoring_data("same_password", key)
        assert hmac1 == hmac2

    def test_different_passwords_different_output(self):
        key = b"test-hmac-key-32-bytes-long-here!"
        prefix1, hmac1 = compute_hibp_monitoring_data("password_one", key)
        prefix2, hmac2 = compute_hibp_monitoring_data("password_two", key)
        # Extremely unlikely to have same prefix AND hmac
        assert (prefix1, hmac1) != (prefix2, hmac2)

    def test_different_keys_different_hmac(self):
        key1 = b"key-one-32-bytes-long-xxxxxxxxxxx"
        key2 = b"key-two-32-bytes-long-xxxxxxxxxxx"
        _, hmac1 = compute_hibp_monitoring_data("same_password", key1)
        _, hmac2 = compute_hibp_monitoring_data("same_password", key2)
        assert hmac1 != hmac2


class TestHibpSuffixMatching:
    """Tests for check_hibp_suffix_against_hmac()."""

    def test_match_found(self):
        key = b"test-hmac-key-32-bytes-long-here!"
        password = "breached_password"

        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324
        prefix = sha1[:5]
        suffix = sha1[5:]

        stored_hmac = hmac_mod.new(key, sha1.encode(), hashlib.sha256).hexdigest()

        # Simulate HIBP response with the matching suffix
        suffixes = [
            "0000000000000000000000000000000000A",
            suffix,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ]
        assert check_hibp_suffix_against_hmac(prefix, stored_hmac, key, suffixes) is True

    def test_no_match(self):
        key = b"test-hmac-key-32-bytes-long-here!"
        password = "safe_password"

        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324
        prefix = sha1[:5]
        stored_hmac = hmac_mod.new(key, sha1.encode(), hashlib.sha256).hexdigest()

        # HIBP returns suffixes that don't include ours
        suffixes = ["0000000000000000000000000000000000A", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"]
        assert check_hibp_suffix_against_hmac(prefix, stored_hmac, key, suffixes) is False

    def test_empty_suffixes(self):
        key = b"test-hmac-key-32-bytes-long-here!"
        assert check_hibp_suffix_against_hmac("ABCDE", "somehex", key, []) is False

    def test_wrong_key_no_match(self):
        key1 = b"key-one-32-bytes-long-xxxxxxxxxxx"
        key2 = b"key-two-32-bytes-long-xxxxxxxxxxx"
        password = "test_password"

        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324
        prefix = sha1[:5]
        suffix = sha1[5:]

        # HMAC computed with key1
        stored_hmac = hmac_mod.new(key1, sha1.encode(), hashlib.sha256).hexdigest()

        # Checking with key2 should not match
        assert check_hibp_suffix_against_hmac(prefix, stored_hmac, key2, [suffix]) is False


class TestPolicyComplianceEnforcement:
    """Tests for _enforce_password_policy_compliance()."""

    def test_flags_users_with_weaker_policy(self):
        from services.settings.security import _enforce_password_policy_compliance

        tenant_id = str(uuid4())
        actor_id = str(uuid4())
        user1_id = str(uuid4())
        user2_id = str(uuid4())

        with (
            patch("services.settings.security.database") as mock_db,
            patch("services.settings.security.log_event") as mock_log,
        ):
            mock_db.users.get_users_with_weak_policy.return_value = [
                {"id": user1_id},
                {"id": user2_id},
            ]
            mock_db.users.bulk_set_password_reset_required.return_value = 2

            result = _enforce_password_policy_compliance(
                tenant_id, actor_id, new_min_length=16, new_min_score=4
            )

            assert result == 2
            mock_db.users.get_users_with_weak_policy.assert_called_once_with(tenant_id, 16, 4)
            mock_db.users.bulk_set_password_reset_required.assert_called_once_with(
                tenant_id, [str(user1_id), str(user2_id)]
            )

            # OAuth2 tokens revoked for each user
            assert mock_db.oauth2.revoke_all_user_tokens.call_count == 2

            # Event logged
            compliance_events = [
                c
                for c in mock_log.call_args_list
                if c.kwargs.get("event_type") == "password_policy_compliance_enforced"
            ]
            assert len(compliance_events) == 1
            assert compliance_events[0].kwargs["metadata"]["affected_users"] == 2

    def test_no_users_affected(self):
        from services.settings.security import _enforce_password_policy_compliance

        tenant_id = str(uuid4())
        actor_id = str(uuid4())

        with (
            patch("services.settings.security.database") as mock_db,
            patch("services.settings.security.log_event") as mock_log,
        ):
            mock_db.users.get_users_with_weak_policy.return_value = []

            result = _enforce_password_policy_compliance(
                tenant_id, actor_id, new_min_length=14, new_min_score=3
            )

            assert result == 0
            mock_db.users.bulk_set_password_reset_required.assert_not_called()
            mock_db.oauth2.revoke_all_user_tokens.assert_not_called()
            mock_log.assert_not_called()
