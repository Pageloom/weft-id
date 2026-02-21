"""Comprehensive tests for Export Cleanup job handler.

This test file covers all functions in jobs/cleanup_exports.py.
Tests include:
- Cleanup success cases
- Error handling and resilience
- File not found handling
- Database cleanup
"""

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


def test_cleanup_expired_exports_success():
    """Test successful cleanup of expired export."""
    from uuid import uuid4

    from jobs.cleanup_exports import cleanup_expired_exports

    export_id = str(uuid4())
    storage_path = "exports/test/expired-export.json.gz"

    mock_export = {
        "id": export_id,
        "storage_path": storage_path,
    }

    with (
        patch("jobs.cleanup_exports.database") as mock_db,
        patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend,
    ):
        mock_db.export_files.get_expired_exports.return_value = [mock_export]
        mock_db.export_files.delete_export_file.return_value = None

        mock_backend = MagicMock()
        mock_backend.exists.return_value = True
        mock_backend.delete.return_value = True
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # Verify cleanup succeeded
        assert result["deleted"] == 1
        assert result["failed"] == 0

        # Verify backend methods were called
        mock_backend.exists.assert_called_once_with(storage_path)
        mock_backend.delete.assert_called_once_with(storage_path)

        # Verify database delete was called
        mock_db.export_files.delete_export_file.assert_called_once_with(export_id)


def test_cleanup_expired_exports_file_not_found():
    """Test cleanup when file doesn't exist in storage."""
    from uuid import uuid4

    from jobs.cleanup_exports import cleanup_expired_exports

    export_id = str(uuid4())
    storage_path = "exports/test/missing-file.json.gz"

    mock_export = {
        "id": export_id,
        "storage_path": storage_path,
    }

    with (
        patch("jobs.cleanup_exports.database") as mock_db,
        patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend,
    ):
        mock_db.export_files.get_expired_exports.return_value = [mock_export]
        mock_db.export_files.delete_export_file.return_value = None

        mock_backend = MagicMock()
        mock_backend.exists.return_value = False  # File doesn't exist
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # Should still delete database record
        assert result["deleted"] == 1
        assert result["failed"] == 0

        # Verify exists was checked but delete was not called
        mock_backend.exists.assert_called_once_with(storage_path)
        mock_backend.delete.assert_not_called()

        # Verify database delete was called
        mock_db.export_files.delete_export_file.assert_called_once_with(export_id)


def test_cleanup_expired_exports_delete_failure():
    """Test cleanup when storage delete fails."""
    from uuid import uuid4

    from jobs.cleanup_exports import cleanup_expired_exports

    export_id = str(uuid4())
    storage_path = "exports/test/failed-delete.json.gz"

    mock_export = {
        "id": export_id,
        "storage_path": storage_path,
    }

    with (
        patch("jobs.cleanup_exports.database") as mock_db,
        patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend,
    ):
        mock_db.export_files.get_expired_exports.return_value = [mock_export]
        mock_db.export_files.delete_export_file.return_value = None

        mock_backend = MagicMock()
        mock_backend.exists.return_value = True
        mock_backend.delete.return_value = False  # Delete failed
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # Should still delete database record even if file deletion failed
        assert result["deleted"] == 1
        assert result["failed"] == 0

        # Verify database delete was called
        mock_db.export_files.delete_export_file.assert_called_once_with(export_id)


def test_cleanup_expired_exports_exception_handling():
    """Test cleanup continues on exception."""
    from uuid import uuid4

    from jobs.cleanup_exports import cleanup_expired_exports

    export_id = str(uuid4())
    storage_path = "exports/test/exception-test.json.gz"

    mock_export = {
        "id": export_id,
        "storage_path": storage_path,
    }

    with (
        patch("jobs.cleanup_exports.database") as mock_db,
        patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend,
    ):
        mock_db.export_files.get_expired_exports.return_value = [mock_export]

        mock_backend = MagicMock()
        mock_backend.exists.side_effect = Exception("Storage error")
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # Should report failure but not crash
        assert result["deleted"] == 0
        assert result["failed"] == 1


def test_cleanup_expired_exports_multiple_files():
    """Test cleanup with multiple expired files."""
    from uuid import uuid4

    from jobs.cleanup_exports import cleanup_expired_exports

    # Create 3 mock expired export files
    mock_exports = [
        {"id": str(uuid4()), "storage_path": f"exports/test/multi-export-{i}.json.gz"}
        for i in range(3)
    ]

    with (
        patch("jobs.cleanup_exports.database") as mock_db,
        patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend,
    ):
        mock_db.export_files.get_expired_exports.return_value = mock_exports
        mock_db.export_files.delete_export_file.return_value = None

        mock_backend = MagicMock()
        mock_backend.exists.return_value = True
        mock_backend.delete.return_value = True
        mock_get_backend.return_value = mock_backend

        result = cleanup_expired_exports()

        # All 3 should be deleted
        assert result["deleted"] == 3
        assert result["failed"] == 0

        # Verify all 3 were deleted from database
        assert mock_db.export_files.delete_export_file.call_count == 3


def test_cleanup_expired_exports_mixed_success_and_failure():
    """Test cleanup with some successes and some failures."""
    from uuid import uuid4

    from jobs.cleanup_exports import cleanup_expired_exports

    # Create 3 mock expired export files
    mock_exports = [
        {"id": str(uuid4()), "storage_path": f"exports/test/mixed-export-{i}.json.gz"}
        for i in range(3)
    ]

    call_count = 0

    def exists_side_effect(path):
        nonlocal call_count
        call_count += 1
        # First file succeeds, second fails, third succeeds
        if call_count == 2:
            raise Exception("Storage error")
        return True

    with (
        patch("jobs.cleanup_exports.database") as mock_db,
        patch("jobs.cleanup_exports.storage.get_backend") as mock_get_backend,
    ):
        mock_db.export_files.get_expired_exports.return_value = mock_exports
        mock_db.export_files.delete_export_file.return_value = None

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
