"""Tests for the OIDC logout retention job.

The purges and sweeps are tested against the database in
tests/database/test_oauth2_backchannel.py and
tests/database/test_session_revocation.py; this covers the job wrapper.
"""

from unittest.mock import MagicMock, patch

from jobs.cleanup_oidc_backchannel_logouts import cleanup_oidc_backchannel_logouts

MODULE = "jobs.cleanup_oidc_backchannel_logouts"

_SESSION_STATE = {
    "revoked_sessions_purged": 3,
    "upstream_sessions_swept": 1,
    "logout_token_jtis_purged": 5,
}


class TestCleanupOidcBackchannelLogouts:
    def test_returns_merged_service_results(self):
        backchannel = {"deliveries_purged": 4, "session_records_swept": 2}
        with (
            patch(f"{MODULE}.cleanup_backchannel_logout_state", return_value=backchannel) as bc,
            patch(f"{MODULE}.cleanup_session_state", return_value=_SESSION_STATE) as sessions,
        ):
            assert cleanup_oidc_backchannel_logouts() == {**backchannel, **_SESSION_STATE}
        bc.assert_called_once()
        sessions.assert_called_once()

    def test_runs_inside_system_context(self):
        ctx = MagicMock()
        with (
            patch(f"{MODULE}.system_context", return_value=ctx),
            patch(
                f"{MODULE}.cleanup_backchannel_logout_state",
                return_value={"deliveries_purged": 0, "session_records_swept": 0},
            ),
            patch(f"{MODULE}.cleanup_session_state", return_value=_SESSION_STATE),
        ):
            cleanup_oidc_backchannel_logouts()
        ctx.__enter__.assert_called_once()
