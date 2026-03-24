"""Unit tests for the HIBP breach checking background job."""

import hashlib
import hmac as hmac_mod
from unittest.mock import MagicMock, patch
from uuid import uuid4


class TestFetchHibpSuffixes:
    """Tests for _fetch_hibp_suffixes()."""

    def test_parses_response(self):
        from jobs.check_hibp_breaches import _fetch_hibp_suffixes

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = (
            "0018A45C4D1DEF81644B54AB7F969B88D65:3\n"
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n"
            "011053FD0102E94D6AE2F8B83D76FAF94F6:1\n"
        )

        with patch("jobs.check_hibp_breaches.httpx") as mock_httpx:
            mock_httpx.get.return_value = mock_response
            mock_httpx.HTTPError = Exception
            mock_httpx.TimeoutException = Exception

            suffixes = _fetch_hibp_suffixes("ABCDE")

            assert len(suffixes) == 3
            assert "0018A45C4D1DEF81644B54AB7F969B88D65" in suffixes

    def test_returns_empty_on_error(self):
        from jobs.check_hibp_breaches import _fetch_hibp_suffixes

        with patch("jobs.check_hibp_breaches.httpx") as mock_httpx:
            mock_httpx.get.side_effect = Exception("Network error")
            mock_httpx.HTTPError = Exception
            mock_httpx.TimeoutException = TimeoutError

            suffixes = _fetch_hibp_suffixes("ABCDE")
            assert suffixes == []


class TestProcessTenant:
    """Tests for _process_tenant()."""

    def test_detects_breach_and_flags_user(self):
        from jobs.check_hibp_breaches import _process_tenant

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        hmac_key = b"test-key-32-bytes-long-xxxxxxxxxx"

        # Create realistic HIBP data
        password = "breached_password_123"
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324
        prefix = sha1[:5]
        suffix = sha1[5:]
        stored_hmac = hmac_mod.new(hmac_key, sha1.encode(), hashlib.sha256).hexdigest()

        with (
            patch("jobs.check_hibp_breaches.database") as mock_db,
            patch("jobs.check_hibp_breaches.log_event") as mock_log,
            patch("jobs.check_hibp_breaches._fetch_hibp_suffixes") as mock_fetch,
            patch("jobs.check_hibp_breaches._notify_admins") as mock_notify,
        ):
            mock_db.users.get_users_with_hibp_prefix.return_value = [
                {"id": user_id, "hibp_prefix": prefix, "hibp_check_hmac": stored_hmac},
            ]
            mock_fetch.return_value = [suffix, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0"]
            mock_db.oauth2.revoke_all_user_tokens.return_value = 1

            result = _process_tenant(tenant_id, hmac_key, {})

            assert result["count"] == 1
            assert str(user_id) in result["user_ids"]

            # User flagged for reset
            mock_db.users.set_password_reset_required.assert_called_once_with(
                tenant_id, str(user_id), True
            )
            # HIBP data cleared
            mock_db.users.clear_hibp_data.assert_called_once_with(tenant_id, str(user_id))
            # OAuth2 tokens revoked
            mock_db.oauth2.revoke_all_user_tokens.assert_called_once_with(tenant_id, str(user_id))
            # Events logged
            event_types = [c.kwargs["event_type"] for c in mock_log.call_args_list]
            assert "oauth2_user_tokens_revoked" in event_types
            assert "password_breach_detected" in event_types
            # Admin notified
            mock_notify.assert_called_once_with(tenant_id, 1)

    def test_no_breach_no_action(self):
        from jobs.check_hibp_breaches import _process_tenant

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        hmac_key = b"test-key-32-bytes-long-xxxxxxxxxx"

        with (
            patch("jobs.check_hibp_breaches.database") as mock_db,
            patch("jobs.check_hibp_breaches.log_event") as mock_log,
            patch("jobs.check_hibp_breaches._fetch_hibp_suffixes") as mock_fetch,
            patch("jobs.check_hibp_breaches._notify_admins") as mock_notify,
        ):
            mock_db.users.get_users_with_hibp_prefix.return_value = [
                {"id": user_id, "hibp_prefix": "ABCDE", "hibp_check_hmac": "not_matching"},
            ]
            mock_fetch.return_value = ["0000000000000000000000000000000000A"]

            result = _process_tenant(tenant_id, hmac_key, {})

            assert result["count"] == 0
            mock_db.users.set_password_reset_required.assert_not_called()
            mock_log.assert_not_called()
            mock_notify.assert_not_called()

    def test_no_users_with_hibp_data(self):
        from jobs.check_hibp_breaches import _process_tenant

        tenant_id = str(uuid4())
        hmac_key = b"test-key-32-bytes-long-xxxxxxxxxx"

        with patch("jobs.check_hibp_breaches.database") as mock_db:
            mock_db.users.get_users_with_hibp_prefix.return_value = []

            result = _process_tenant(tenant_id, hmac_key, {})
            assert result["count"] == 0
            assert result["user_ids"] == []

    def test_prefix_cache_avoids_duplicate_api_calls(self):
        from jobs.check_hibp_breaches import _process_tenant

        tenant_id = str(uuid4())
        hmac_key = b"test-key-32-bytes-long-xxxxxxxxxx"

        with (
            patch("jobs.check_hibp_breaches.database") as mock_db,
            patch("jobs.check_hibp_breaches._fetch_hibp_suffixes") as mock_fetch,
            patch("jobs.check_hibp_breaches.time"),
        ):
            # Two users with the same prefix
            mock_db.users.get_users_with_hibp_prefix.return_value = [
                {"id": str(uuid4()), "hibp_prefix": "ABCDE", "hibp_check_hmac": "h1"},
                {"id": str(uuid4()), "hibp_prefix": "ABCDE", "hibp_check_hmac": "h2"},
            ]
            mock_fetch.return_value = []

            prefix_cache: dict[str, list[str]] = {}
            _process_tenant(tenant_id, hmac_key, prefix_cache)

            # API called only once for the shared prefix
            mock_fetch.assert_called_once_with("ABCDE")

    def test_breach_event_metadata(self):
        """password_breach_detected event has correct metadata."""
        from jobs.check_hibp_breaches import _process_tenant

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        hmac_key = b"test-key-32-bytes-long-xxxxxxxxxx"

        password = "breached_pw"
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324
        prefix = sha1[:5]
        suffix = sha1[5:]
        stored_hmac = hmac_mod.new(hmac_key, sha1.encode(), hashlib.sha256).hexdigest()

        with (
            patch("jobs.check_hibp_breaches.database") as mock_db,
            patch("jobs.check_hibp_breaches.log_event") as mock_log,
            patch("jobs.check_hibp_breaches._fetch_hibp_suffixes", return_value=[suffix]),
            patch("jobs.check_hibp_breaches._notify_admins"),
        ):
            mock_db.users.get_users_with_hibp_prefix.return_value = [
                {"id": user_id, "hibp_prefix": prefix, "hibp_check_hmac": stored_hmac},
            ]
            mock_db.oauth2.revoke_all_user_tokens.return_value = 0

            _process_tenant(tenant_id, hmac_key, {})

            # Find the breach event
            breach_events = [
                c
                for c in mock_log.call_args_list
                if c.kwargs.get("event_type") == "password_breach_detected"
            ]
            assert len(breach_events) == 1
            assert breach_events[0].kwargs["artifact_id"] == str(user_id)


class TestCheckHibpBreaches:
    """Tests for the top-level check_hibp_breaches() function."""

    def test_iterates_all_tenants(self):
        from jobs.check_hibp_breaches import check_hibp_breaches

        tenant1 = str(uuid4())
        tenant2 = str(uuid4())

        with (
            patch("jobs.check_hibp_breaches.database") as mock_db,
            patch("jobs.check_hibp_breaches.derive_hmac_key", return_value=b"k" * 32),
            patch("jobs.check_hibp_breaches.session"),
            patch("jobs.check_hibp_breaches._process_tenant") as mock_process,
        ):
            mock_db.security.get_all_tenant_ids.return_value = [
                {"tenant_id": tenant1},
                {"tenant_id": tenant2},
            ]
            mock_process.return_value = {"count": 0, "user_ids": []}

            result = check_hibp_breaches()

            assert result["tenants_processed"] == 2
            assert mock_process.call_count == 2

    def test_no_tenants(self):
        from jobs.check_hibp_breaches import check_hibp_breaches

        with patch("jobs.check_hibp_breaches.database") as mock_db:
            mock_db.security.get_all_tenant_ids.return_value = []

            result = check_hibp_breaches()

            assert result["tenants_processed"] == 0
            assert result["breaches_found"] == 0

    def test_tenant_exception_logged_and_continues(self):
        """When processing one tenant fails, error is logged and other tenants still run."""
        from jobs.check_hibp_breaches import check_hibp_breaches

        tenant1 = str(uuid4())
        tenant2 = str(uuid4())

        with (
            patch("jobs.check_hibp_breaches.database") as mock_db,
            patch("jobs.check_hibp_breaches.derive_hmac_key", return_value=b"k" * 32),
            patch("jobs.check_hibp_breaches.session") as mock_session,
            patch("jobs.check_hibp_breaches._process_tenant") as mock_process,
        ):
            mock_db.security.get_all_tenant_ids.return_value = [
                {"tenant_id": tenant1},
                {"tenant_id": tenant2},
            ]
            # First tenant fails, second succeeds
            mock_session.side_effect = [
                MagicMock(__enter__=MagicMock(side_effect=RuntimeError("DB crash"))),
                MagicMock(
                    __enter__=MagicMock(return_value=None),
                    __exit__=MagicMock(return_value=False),
                ),
            ]
            mock_process.return_value = {"count": 0, "user_ids": []}

            result = check_hibp_breaches()

            assert result["tenants_processed"] == 2
            # First tenant's error is recorded in details
            assert any("error" in d for d in result["details"])

    def test_breaches_appended_to_details(self):
        """When breaches are found, tenant details include user IDs."""
        from jobs.check_hibp_breaches import check_hibp_breaches

        tenant_id = str(uuid4())
        user_id = str(uuid4())

        with (
            patch("jobs.check_hibp_breaches.database") as mock_db,
            patch("jobs.check_hibp_breaches.derive_hmac_key", return_value=b"k" * 32),
            patch("jobs.check_hibp_breaches.session"),
            patch("jobs.check_hibp_breaches._process_tenant") as mock_process,
        ):
            mock_db.security.get_all_tenant_ids.return_value = [{"tenant_id": tenant_id}]
            mock_process.return_value = {"count": 1, "user_ids": [user_id]}

            result = check_hibp_breaches()

            assert result["breaches_found"] == 1
            assert len(result["details"]) == 1
            assert result["details"][0]["tenant_id"] == tenant_id
            assert result["details"][0]["user_ids"] == [user_id]


class TestNotifyAdmins:
    """Tests for _notify_admins()."""

    def test_sends_email_to_all_admins(self):
        from jobs.check_hibp_breaches import _notify_admins

        with (
            patch("jobs.check_hibp_breaches.database") as mock_db,
            patch("jobs.check_hibp_breaches.send_hibp_breach_admin_notification") as mock_send,
        ):
            mock_db.users.get_admin_emails.return_value = ["admin1@test.com", "admin2@test.com"]

            _notify_admins("tenant-1", 3)

            assert mock_send.call_count == 2
            mock_send.assert_any_call("admin1@test.com", 3, tenant_id="tenant-1")
            mock_send.assert_any_call("admin2@test.com", 3, tenant_id="tenant-1")

    def test_email_failure_does_not_raise(self):
        """If sending one admin email fails, the others still send."""
        from jobs.check_hibp_breaches import _notify_admins

        with (
            patch("jobs.check_hibp_breaches.database") as mock_db,
            patch("jobs.check_hibp_breaches.send_hibp_breach_admin_notification") as mock_send,
        ):
            mock_db.users.get_admin_emails.return_value = ["fail@test.com", "ok@test.com"]
            mock_send.side_effect = [Exception("SMTP error"), None]

            # Should not raise
            _notify_admins("tenant-1", 1)

            assert mock_send.call_count == 2
