"""Tests for the forward-auth nonce cleanup job.

The job sweeps expired rows from `forward_auth_nonces` via the service-layer
`cleanup_expired_nonces` (which is integration-tested in
tests/services/test_forward_auth.py; the underlying database function in
tests/database/test_forward_auth_nonces.py). These tests verify the job's
orchestration: the sweep call, the no-work fast path, and the system_context
wrapper.
"""

from unittest.mock import patch

from jobs.cleanup_forward_auth_nonces import cleanup_forward_auth_nonces


class TestCleanupForwardAuthNonces:
    def test_deletes_expired_nonces(self):
        with (
            patch("jobs.cleanup_forward_auth_nonces.cleanup_expired_nonces") as mock_cleanup,
            patch("jobs.cleanup_forward_auth_nonces.system_context"),
        ):
            mock_cleanup.return_value = 3
            result = cleanup_forward_auth_nonces()

        assert result == {"deleted": 3}
        mock_cleanup.assert_called_once()

    def test_no_expired_nonces_is_fast_noop(self):
        with (
            patch("jobs.cleanup_forward_auth_nonces.cleanup_expired_nonces") as mock_cleanup,
            patch("jobs.cleanup_forward_auth_nonces.system_context"),
        ):
            mock_cleanup.return_value = 0
            result = cleanup_forward_auth_nonces()

        assert result == {"deleted": 0}

    def test_runs_inside_system_context(self):
        """The sweep is a background action; system_context must be entered."""
        with (
            patch("jobs.cleanup_forward_auth_nonces.cleanup_expired_nonces") as mock_cleanup,
            patch("jobs.cleanup_forward_auth_nonces.system_context") as mock_ctx,
        ):
            mock_cleanup.return_value = 0
            cleanup_forward_auth_nonces()

        mock_ctx.assert_called_once()
