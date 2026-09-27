"""Tests for the OIDC back-channel logout delivery job.

The delivery itself is tested in tests/services/oidc/test_backchannel.py.
These tests cover the job's orchestration: tenant iteration, totals,
per-tenant error isolation, and the system_context wrapper.
"""

from unittest.mock import MagicMock, patch

from jobs.deliver_oidc_backchannel_logouts import deliver_oidc_backchannel_logouts

MODULE = "jobs.deliver_oidc_backchannel_logouts"


def _counts(delivered=0, retried=0, failed=0, skipped=0):
    return {"delivered": delivered, "retried": retried, "failed": failed, "skipped": skipped}


class TestDeliverOidcBackchannelLogouts:
    def test_no_tenants_is_a_quiet_noop(self):
        with (
            patch(f"{MODULE}.list_tenants_with_due_backchannel_logouts", return_value=[]),
            patch(f"{MODULE}.deliver_due_backchannel_logouts") as deliver,
            patch(f"{MODULE}.logger") as logger,
        ):
            result = deliver_oidc_backchannel_logouts()

        assert result == {**_counts(), "errors": []}
        deliver.assert_not_called()
        logger.info.assert_not_called()

    def test_totals_across_tenants(self):
        with (
            patch(f"{MODULE}.list_tenants_with_due_backchannel_logouts", return_value=["t1", "t2"]),
            patch(
                f"{MODULE}.deliver_due_backchannel_logouts",
                side_effect=[_counts(delivered=2), _counts(delivered=1, retried=1, skipped=1)],
            ) as deliver,
        ):
            result = deliver_oidc_backchannel_logouts()

        assert result == {**_counts(delivered=3, retried=1, skipped=1), "errors": []}
        assert [c.args[0] for c in deliver.call_args_list] == ["t1", "t2"]

    def test_one_tenant_failing_does_not_stop_the_others(self):
        with (
            patch(
                f"{MODULE}.list_tenants_with_due_backchannel_logouts", return_value=["bad", "ok"]
            ),
            patch(
                f"{MODULE}.deliver_due_backchannel_logouts",
                side_effect=[RuntimeError("boom"), _counts(delivered=1)],
            ),
        ):
            result = deliver_oidc_backchannel_logouts()

        assert result["delivered"] == 1
        assert result["errors"] == ["bad"]

    def test_runs_inside_system_context(self):
        ctx = MagicMock()
        with (
            patch(f"{MODULE}.system_context", return_value=ctx),
            patch(f"{MODULE}.list_tenants_with_due_backchannel_logouts", return_value=[]),
        ):
            deliver_oidc_backchannel_logouts()
        ctx.__enter__.assert_called_once()
