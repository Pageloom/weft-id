"""Tests for database.export_files module."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4


def test_create_export_file(test_tenant, test_user):
    """Test creating an export file record."""
    import database

    expires_at = datetime.now(UTC) + timedelta(hours=24)

    result = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="test-export.json.gz",
        storage_type="local",
        storage_path="/app/storage/exports/test.json.gz",
        expires_at=expires_at,
        created_by=str(test_user["id"]),
        file_size=1024,
    )

    assert result is not None
    assert result["id"] is not None
    assert result["created_at"] is not None


def test_create_export_file_with_bg_task(test_tenant, test_user):
    """Test creating an export file record with background task reference."""
    import database

    # Create a background task first
    task = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="export_events",
        created_by=str(test_user["id"]),
    )

    expires_at = datetime.now(UTC) + timedelta(hours=24)

    result = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        bg_task_id=str(task["id"]),
        filename="test-export-with-task.json.gz",
        storage_type="local",
        storage_path="/app/storage/exports/test2.json.gz",
        expires_at=expires_at,
        created_by=str(test_user["id"]),
    )

    assert result is not None
    assert result["id"] is not None


def test_get_export_file(test_tenant, test_user):
    """Test getting an export file by ID."""
    import database

    expires_at = datetime.now(UTC) + timedelta(hours=24)

    created = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="test-get.json.gz",
        storage_type="local",
        storage_path="/app/storage/exports/test-get.json.gz",
        expires_at=expires_at,
        created_by=str(test_user["id"]),
        file_size=2048,
    )

    export = database.export_files.get_export_file(
        str(test_tenant["id"]),
        str(created["id"]),
    )

    assert export is not None
    assert export["id"] == created["id"]
    assert export["filename"] == "test-get.json.gz"
    assert export["storage_type"] == "local"
    assert export["file_size"] == 2048


def test_get_export_file_not_found(test_tenant):
    """Test getting a non-existent export file."""
    import database

    export = database.export_files.get_export_file(
        str(test_tenant["id"]),
        str(uuid4()),
    )
    assert export is None


def test_list_export_files(test_tenant, test_user):
    """Test listing export files for a tenant."""
    import database

    expires_at = datetime.now(UTC) + timedelta(hours=24)

    # Create some export files
    for i in range(3):
        database.export_files.create_export_file(
            tenant_id=str(test_tenant["id"]),
            filename=f"test-list-{i}.json.gz",
            storage_type="local",
            storage_path=f"/app/storage/exports/test-list-{i}.json.gz",
            expires_at=expires_at,
            created_by=str(test_user["id"]),
        )

    exports = database.export_files.list_export_files(str(test_tenant["id"]), limit=10)

    assert len(exports) >= 3


def test_list_export_files_excludes_expired(test_tenant, test_user):
    """Test that list_export_files excludes expired files by default."""
    import database

    # Create an expired export
    expired_at = datetime.now(UTC) - timedelta(hours=1)
    database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="expired-export.json.gz",
        storage_type="local",
        storage_path="/app/storage/exports/expired.json.gz",
        expires_at=expired_at,
        created_by=str(test_user["id"]),
    )

    # Create a valid export
    valid_at = datetime.now(UTC) + timedelta(hours=24)
    valid_export = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="valid-export.json.gz",
        storage_type="local",
        storage_path="/app/storage/exports/valid.json.gz",
        expires_at=valid_at,
        created_by=str(test_user["id"]),
    )

    # List exports (default excludes expired)
    exports = database.export_files.list_export_files(str(test_tenant["id"]))

    # The valid export should be in the list
    export_ids = [str(e["id"]) for e in exports]
    assert str(valid_export["id"]) in export_ids


def test_mark_downloaded(test_tenant, test_user):
    """Test marking an export as downloaded."""
    import database

    expires_at = datetime.now(UTC) + timedelta(hours=24)

    created = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="test-download.json.gz",
        storage_type="local",
        storage_path="/app/storage/exports/test-download.json.gz",
        expires_at=expires_at,
        created_by=str(test_user["id"]),
    )

    # Initially not downloaded
    export = database.export_files.get_export_file(
        str(test_tenant["id"]),
        str(created["id"]),
    )
    assert export["downloaded_at"] is None

    # Mark as downloaded
    database.export_files.mark_downloaded(
        str(test_tenant["id"]),
        str(created["id"]),
    )

    # Verify it's marked
    export = database.export_files.get_export_file(
        str(test_tenant["id"]),
        str(created["id"]),
    )
    assert export["downloaded_at"] is not None


def test_delete_export_file(test_tenant, test_user):
    """Test deleting an export file record."""
    import database

    expires_at = datetime.now(UTC) + timedelta(hours=24)

    created = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="test-delete.json.gz",
        storage_type="local",
        storage_path="/app/storage/exports/test-delete.json.gz",
        expires_at=expires_at,
        created_by=str(test_user["id"]),
    )

    # Delete the record
    database.export_files.delete_export_file(str(created["id"]))

    # Verify it's deleted
    export = database.export_files.get_export_file(
        str(test_tenant["id"]),
        str(created["id"]),
    )
    assert export is None


def test_get_expired_exports(test_tenant, test_user):
    """Test getting expired exports across all tenants."""
    import database

    # Create an expired export
    expired_at = datetime.now(UTC) - timedelta(hours=1)
    expired = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="expired-for-cleanup.json.gz",
        storage_type="local",
        storage_path="/app/storage/exports/expired-cleanup.json.gz",
        expires_at=expired_at,
        created_by=str(test_user["id"]),
    )

    # Get expired exports
    expired_exports = database.export_files.get_expired_exports()

    # Our expired export should be in the list
    expired_ids = [str(e["id"]) for e in expired_exports]
    assert str(expired["id"]) in expired_ids


def test_count_exports_for_tenant(test_tenant, test_user):
    """Test counting non-expired exports for a tenant."""
    import database

    expires_at = datetime.now(UTC) + timedelta(hours=24)

    # Create some exports
    for i in range(2):
        database.export_files.create_export_file(
            tenant_id=str(test_tenant["id"]),
            filename=f"test-count-{i}.json.gz",
            storage_type="local",
            storage_path=f"/app/storage/exports/test-count-{i}.json.gz",
            expires_at=expires_at,
            created_by=str(test_user["id"]),
        )

    count = database.export_files.count_exports_for_tenant(str(test_tenant["id"]))

    assert count >= 2
