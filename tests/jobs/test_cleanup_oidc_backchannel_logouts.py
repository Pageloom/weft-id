"""Tests for the OIDC back-channel logout retention job.

The purge and sweep are tested against the database in
tests/database/test_oauth2_backchannel.py; this covers the job wrapper.
"""

from unittest.mock import MagicMock, patch

from jobs.cleanup_oidc_backchannel_logouts import cleanup_oidc_backchannel_logouts

MODULE = "jobs.cleanup_oidc_backchannel_logouts"


class TestCleanupOidcBackchannelLogouts:
    def test_returns_service_result(self):
        expected = {"deliveries_purged": 4, "session_records_swept": 2}
        with patch(f"{MODULE}.cleanup_backchannel_logout_state", return_value=expected) as svc:
            assert cleanup_oidc_backchannel_logouts() == expected
        svc.assert_called_once()

    def test_runs_inside_system_context(self):
        ctx = MagicMock()
        with (
            patch(f"{MODULE}.system_context", return_value=ctx),
            patch(
                f"{MODULE}.cleanup_backchannel_logout_state",
                return_value={"deliveries_purged": 0, "session_records_swept": 0},
            ),
        ):
            cleanup_oidc_backchannel_logouts()
        ctx.__enter__.assert_called_once()
