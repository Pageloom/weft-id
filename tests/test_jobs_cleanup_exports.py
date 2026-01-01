"""Comprehensive tests for Export Cleanup job handler.

This test file covers all functions in jobs/cleanup_exports.py.
Tests include:
- Cleanup success cases
- Error handling and resilience
- File not found handling
- Database cleanup
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

# =============================================================================
# Cleanup Expired Exports Tests
# =============================================================================


def test_cleanup_expired_exports_no_expired_files():
    """Test cleanup when there are no expired exports."""
    from jobs.cleanup_exports import cleanup_expired_exports

    with patch(
        "jobs.cleanup_exports.database.export_files.get_expired_exports"
    ) as mock_get_expired:
        mock_get_expired.return_value = []

        result = cleanup_expired_exports()

        assert result["deleted"] == 0
        assert result["failed"] == 0


def test_cleanup_expired_exports_success(test_tenant, test_admin_user):
    """Test successful cleanup of expired export."""
    import database
    from jobs.cleanup_exports import cleanup_expired_exports

    # Create background task and export file
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    # Create export file that's already expired
    expires_at = datetime.now(UTC) - timedelta(hours=1)
    export_file = database.export_files.create_export_file(
        tenant_id=test_tenant["id"],
        filename="expired-export.json.gz",
        storage_type="local",
        storage_path="exports/test/expired-export.json.gz",
        expires_at=expires_at,
        created_by=test_admin_user["id"],
        bg_task_id=bg_task["id"],
        file_size=1024,
    )

    with patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.exists.return_value = True
        mock_backend.delete.return_value = True
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # Verify cleanup succeeded
        assert result["deleted"] == 1
        assert result["failed"] == 0

        # Verify backend methods were called
        mock_backend.exists.assert_called_once_with("exports/test/expired-export.json.gz")
        mock_backend.delete.assert_called_once_with("exports/test/expired-export.json.gz")

        # Verify database record was deleted
        deleted_file = database.export_files.get_export_file(test_tenant["id"], export_file["id"])
        assert deleted_file is None


def test_cleanup_expired_exports_file_not_found(test_tenant, test_admin_user):
    """Test cleanup when file doesn't exist in storage."""
    import database
    from jobs.cleanup_exports import cleanup_expired_exports

    # Create background task and export file
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    expires_at = datetime.now(UTC) - timedelta(hours=1)
    export_file = database.export_files.create_export_file(
        tenant_id=test_tenant["id"],
        filename="missing-file.json.gz",
        storage_type="local",
        storage_path="exports/test/missing-file.json.gz",
        expires_at=expires_at,
        created_by=test_admin_user["id"],
        bg_task_id=bg_task["id"],
        file_size=1024,
    )

    with patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.exists.return_value = False  # File doesn't exist
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # Should still delete database record
        assert result["deleted"] == 1
        assert result["failed"] == 0

        # Verify exists was checked but delete was not called
        mock_backend.exists.assert_called_once()
        mock_backend.delete.assert_not_called()

        # Verify database record was deleted
        deleted_file = database.export_files.get_export_file(test_tenant["id"], export_file["id"])
        assert deleted_file is None


def test_cleanup_expired_exports_delete_failure(test_tenant, test_admin_user):
    """Test cleanup when storage delete fails."""
    import database
    from jobs.cleanup_exports import cleanup_expired_exports

    # Create background task and export file
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    expires_at = datetime.now(UTC) - timedelta(hours=1)
    export_file = database.export_files.create_export_file(
        tenant_id=test_tenant["id"],
        filename="failed-delete.json.gz",
        storage_type="local",
        storage_path="exports/test/failed-delete.json.gz",
        expires_at=expires_at,
        created_by=test_admin_user["id"],
        bg_task_id=bg_task["id"],
        file_size=1024,
    )

    with patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.exists.return_value = True
        mock_backend.delete.return_value = False  # Delete failed
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # Should still delete database record even if file deletion failed
        assert result["deleted"] == 1
        assert result["failed"] == 0

        # Verify database record was deleted
        deleted_file = database.export_files.get_export_file(test_tenant["id"], export_file["id"])
        assert deleted_file is None


def test_cleanup_expired_exports_exception_handling(test_tenant, test_admin_user):
    """Test cleanup continues on exception."""
    import database
    from jobs.cleanup_exports import cleanup_expired_exports

    # Create background task and export file
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    expires_at = datetime.now(UTC) - timedelta(hours=1)
    database.export_files.create_export_file(
        tenant_id=test_tenant["id"],
        filename="exception-test.json.gz",
        storage_type="local",
        storage_path="exports/test/exception-test.json.gz",
        expires_at=expires_at,
        created_by=test_admin_user["id"],
        bg_task_id=bg_task["id"],
        file_size=1024,
    )

    with patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.exists.side_effect = Exception("Storage error")
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # Should report failure but not crash
        assert result["deleted"] == 0
        assert result["failed"] == 1


def test_cleanup_expired_exports_multiple_files(test_tenant, test_admin_user):
    """Test cleanup with multiple expired files."""
    import database
    from jobs.cleanup_exports import cleanup_expired_exports

    # Create background task
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    # Create 3 expired export files
    expires_at = datetime.now(UTC) - timedelta(hours=1)
    for i in range(3):
        database.export_files.create_export_file(
            tenant_id=test_tenant["id"],
            filename=f"multi-export-{i}.json.gz",
            storage_type="local",
            storage_path=f"exports/test/multi-export-{i}.json.gz",
            expires_at=expires_at,
            created_by=test_admin_user["id"],
            bg_task_id=bg_task["id"],
            file_size=1024,
        )

    with patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.exists.return_value = True
        mock_backend.delete.return_value = True
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # All 3 should be deleted
        assert result["deleted"] == 3
        assert result["failed"] == 0


def test_cleanup_expired_exports_mixed_success_and_failure(test_tenant, test_admin_user):
    """Test cleanup with some successes and some failures."""
    import database
    from jobs.cleanup_exports import cleanup_expired_exports

    # Create background task
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    # Create 3 expired export files
    expires_at = datetime.now(UTC) - timedelta(hours=1)
    for i in range(3):
        database.export_files.create_export_file(
            tenant_id=test_tenant["id"],
            filename=f"mixed-export-{i}.json.gz",
            storage_type="local",
            storage_path=f"exports/test/mixed-export-{i}.json.gz",
            expires_at=expires_at,
            created_by=test_admin_user["id"],
            bg_task_id=bg_task["id"],
            file_size=1024,
        )

    call_count = 0

    def exists_side_effect(path):
        nonlocal call_count
        call_count += 1
        # First file succeeds, second fails, third succeeds
        if call_count == 2:
            raise Exception("Storage error")
        return True

    with patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.exists.side_effect = exists_side_effect
        mock_backend.delete.return_value = True
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # Should have 2 successes and 1 failure
        assert result["deleted"] == 2
        assert result["failed"] == 1


def test_cleanup_expired_exports_return_format():
    """Test that cleanup returns correct format."""
    from jobs.cleanup_exports import cleanup_expired_exports

    with patch(
        "jobs.cleanup_exports.database.export_files.get_expired_exports"
    ) as mock_get_expired:
        mock_get_expired.return_value = []

        result = cleanup_expired_exports()

        # Verify return format
        assert isinstance(result, dict)
        assert "deleted" in result
        assert "failed" in result
        assert isinstance(result["deleted"], int)
        assert isinstance(result["failed"], int)
