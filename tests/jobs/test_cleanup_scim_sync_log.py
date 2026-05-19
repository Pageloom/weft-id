"""Tests for the `cleanup_scim_sync_log` periodic job."""

from __future__ import annotations

from unittest.mock import patch

from jobs.cleanup_scim_sync_log import cleanup_scim_sync_log


def test_returns_empty_summary_when_no_scim_enabled_sps() -> None:
    with patch("jobs.cleanup_scim_sync_log.database") as db:
        db.service_providers.list_scim_enabled_sps_all_tenants.return_value = []
        result = cleanup_scim_sync_log()

    assert result["sps_processed"] == 0
    assert result["sps_skipped"] == 0
    assert result["rows_deleted"] == 0


def test_processes_each_retention_value_with_correct_interval() -> None:
    sps = [
        {"id": "sp-3", "tenant_id": "t-1", "scim_log_retention": "3"},
        {"id": "sp-6", "tenant_id": "t-1", "scim_log_retention": "6"},
        {"id": "sp-12", "tenant_id": "t-2", "scim_log_retention": "12"},
        {"id": "sp-24", "tenant_id": "t-2", "scim_log_retention": "24"},
    ]
    with (
        patch("jobs.cleanup_scim_sync_log.database") as db,
        patch("jobs.cleanup_scim_sync_log.session"),
    ):
        db.service_providers.list_scim_enabled_sps_all_tenants.return_value = sps
        db.scim_sync_log.delete_older_than.return_value = 7
        result = cleanup_scim_sync_log()

    assert result["sps_processed"] == 4
    assert result["sps_skipped"] == 0
    assert result["rows_deleted"] == 28
    call_args = db.scim_sync_log.delete_older_than.call_args_list
    intervals = sorted(c.args[2] for c in call_args)
    assert intervals == ["12 months", "24 months", "3 months", "6 months"]


def test_forever_retention_skips_sp() -> None:
    sps = [{"id": "sp-x", "tenant_id": "t-1", "scim_log_retention": "forever"}]
    with (
        patch("jobs.cleanup_scim_sync_log.database") as db,
        patch("jobs.cleanup_scim_sync_log.session"),
    ):
        db.service_providers.list_scim_enabled_sps_all_tenants.return_value = sps
        result = cleanup_scim_sync_log()

    assert result["sps_processed"] == 0
    assert result["sps_skipped"] == 1
    db.scim_sync_log.delete_older_than.assert_not_called()
    assert result["details"][0]["skipped"] == "forever"


def test_invalid_retention_skips_sp_and_does_not_raise() -> None:
    sps = [{"id": "sp-x", "tenant_id": "t-1", "scim_log_retention": "weird"}]
    with (
        patch("jobs.cleanup_scim_sync_log.database") as db,
        patch("jobs.cleanup_scim_sync_log.session"),
    ):
        db.service_providers.list_scim_enabled_sps_all_tenants.return_value = sps
        result = cleanup_scim_sync_log()

    assert result["sps_skipped"] == 1
    assert result["details"][0]["skipped"] == "invalid_retention"
    db.scim_sync_log.delete_older_than.assert_not_called()


def test_tenant_failure_does_not_block_other_tenants() -> None:
    sps = [
        {"id": "sp-a", "tenant_id": "bad", "scim_log_retention": "3"},
        {"id": "sp-b", "tenant_id": "good", "scim_log_retention": "3"},
    ]
    session_calls = {"n": 0}

    def fake_session(tenant_id):  # noqa: ANN001
        session_calls["n"] += 1
        if tenant_id == "bad":
            raise RuntimeError("session blew up for bad tenant")

        class _Cx:
            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

        return _Cx()

    with (
        patch("jobs.cleanup_scim_sync_log.database") as db,
        patch("jobs.cleanup_scim_sync_log.session", side_effect=fake_session),
    ):
        db.service_providers.list_scim_enabled_sps_all_tenants.return_value = sps
        db.scim_sync_log.delete_older_than.return_value = 2
        result = cleanup_scim_sync_log()

    # bad tenant errored, good tenant continued
    assert any("error" in d for d in result["details"])
    assert result["rows_deleted"] == 2


def test_per_sp_delete_failure_does_not_block_other_sps_in_same_tenant() -> None:
    """A failure deep in the SQL on one SP must not skip the rest of its tenant."""
    sps = [
        {"id": "sp-a", "tenant_id": "t1", "scim_log_retention": "3"},
        {"id": "sp-b", "tenant_id": "t1", "scim_log_retention": "3"},
    ]
    call_log: list[str] = []

    def fake_delete(_tenant, sp_id, _interval):  # noqa: ANN001
        call_log.append(sp_id)
        if sp_id == "sp-a":
            raise RuntimeError("bad lock")
        return 4

    class _Cx:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    with (
        patch("jobs.cleanup_scim_sync_log.database") as db,
        patch("jobs.cleanup_scim_sync_log.session", return_value=_Cx()),
    ):
        db.service_providers.list_scim_enabled_sps_all_tenants.return_value = sps
        db.scim_sync_log.delete_older_than.side_effect = fake_delete
        result = cleanup_scim_sync_log()

    # Both SPs attempted; sp-a failed (skipped), sp-b succeeded.
    assert call_log == ["sp-a", "sp-b"]
    assert result["sps_processed"] == 1
    assert result["sps_skipped"] == 1
    assert result["rows_deleted"] == 4
    assert any(d.get("sp_id") == "sp-a" and "error" in d for d in result["details"])
