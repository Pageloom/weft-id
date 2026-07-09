"""Tests for the retired OIDC signing-key cleanup job.

The job walks the cross-tenant list of expired-grace signing keys (via the
SECURITY DEFINER accessor) and clears each one through the service layer.
The database accessor and the service function are unit-tested elsewhere
(tests/database/test_oidc_signing_keys.py, tests/services/oidc/test_keys.py);
these tests verify the job's orchestration: counting, per-tenant error
isolation, and the no-work fast path.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

from jobs.cleanup_oidc_signing_keys import cleanup_oidc_signing_keys


def _make_row(tenant_id: str | None = None, previous_kid: str = "kid-old") -> dict:
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id or str(uuid4()),
        "previous_kid": previous_kid,
        "rotation_grace_period_ends_at": datetime.now(UTC) - timedelta(hours=1),
    }


class TestCleanupOidcSigningKeys:
    def test_no_rows_is_fast_noop(self):
        with (
            patch("jobs.cleanup_oidc_signing_keys.list_signing_keys_needing_cleanup") as mock_list,
            patch("jobs.cleanup_oidc_signing_keys.cleanup_previous_signing_key") as mock_cleanup,
        ):
            mock_list.return_value = []
            result = cleanup_oidc_signing_keys()

        assert result == {"cleaned_up": 0, "errors": []}
        mock_cleanup.assert_not_called()

    def test_cleans_each_expired_tenant(self):
        rows = [_make_row(), _make_row()]
        with (
            patch("jobs.cleanup_oidc_signing_keys.list_signing_keys_needing_cleanup") as mock_list,
            patch("jobs.cleanup_oidc_signing_keys.cleanup_previous_signing_key") as mock_cleanup,
        ):
            mock_list.return_value = rows
            mock_cleanup.return_value = True
            result = cleanup_oidc_signing_keys()

        assert result["cleaned_up"] == 2
        assert result["errors"] == []
        called_tenants = [call.args[0] for call in mock_cleanup.call_args_list]
        assert called_tenants == [str(r["tenant_id"]) for r in rows]

    def test_already_cleared_row_not_counted(self):
        """A row swept by a concurrent manual cleanup returns False and is skipped."""
        with (
            patch("jobs.cleanup_oidc_signing_keys.list_signing_keys_needing_cleanup") as mock_list,
            patch("jobs.cleanup_oidc_signing_keys.cleanup_previous_signing_key") as mock_cleanup,
        ):
            mock_list.return_value = [_make_row()]
            mock_cleanup.return_value = False
            result = cleanup_oidc_signing_keys()

        assert result["cleaned_up"] == 0
        assert result["errors"] == []

    def test_error_on_one_tenant_does_not_stop_the_sweep(self):
        rows = [_make_row(previous_kid="kid-a"), _make_row(previous_kid="kid-b")]
        with (
            patch("jobs.cleanup_oidc_signing_keys.list_signing_keys_needing_cleanup") as mock_list,
            patch("jobs.cleanup_oidc_signing_keys.cleanup_previous_signing_key") as mock_cleanup,
        ):
            mock_list.return_value = rows
            mock_cleanup.side_effect = [RuntimeError("db down"), True]
            result = cleanup_oidc_signing_keys()

        assert result["cleaned_up"] == 1
        assert len(result["errors"]) == 1
        assert result["errors"][0]["tenant_id"] == str(rows[0]["tenant_id"])
        assert result["errors"][0]["previous_kid"] == "kid-a"
        assert result["errors"][0]["error"] == "db down"

    def test_runs_inside_system_context(self):
        """log_event inside the service call must not require request context."""
        with (
            patch("jobs.cleanup_oidc_signing_keys.list_signing_keys_needing_cleanup") as mock_list,
            patch("jobs.cleanup_oidc_signing_keys.cleanup_previous_signing_key") as mock_cleanup,
            patch("jobs.cleanup_oidc_signing_keys.system_context") as mock_ctx,
        ):
            mock_list.return_value = [_make_row()]
            mock_cleanup.return_value = True
            cleanup_oidc_signing_keys()

        mock_ctx.assert_called_once()
