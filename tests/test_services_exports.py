"""Tests for exports service layer."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest


def test_list_exports_as_admin(test_tenant, test_admin_user):
    """Test that admins can list exports."""
    import database
    from services import exports
    from services.types import RequestingUser

    # Create some export files
    expires_at = datetime.now(UTC) + timedelta(hours=24)
    for i in range(2):
        database.export_files.create_export_file(
            tenant_id=str(test_tenant["id"]),
            filename=f"test-list-{i}.json.gz",
            storage_type="local",
            storage_path=f"/app/storage/exports/test-list-{i}.json.gz",
            expires_at=expires_at,
            created_by=str(test_admin_user["id"]),
            file_size=1024,
        )

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    result = exports.list_exports(requesting_user)

    assert result.total >= 2
    assert len(result.items) >= 2


def test_list_exports_as_super_admin(test_tenant, test_super_admin_user):
    """Test that super_admins can list exports."""
    from services import exports
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "super_admin",
    }

    result = exports.list_exports(requesting_user)

    assert result.total >= 0


def test_list_exports_forbidden_for_member(test_tenant, test_user):
    """Test that members cannot list exports."""
    from services import exports
    from services.exceptions import ForbiddenError
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }

    with pytest.raises(ForbiddenError) as exc_info:
        exports.list_exports(requesting_user)

    assert exc_info.value.code == "admin_required"


def test_get_download_local_storage(test_tenant, test_admin_user):
    """Test getting download info for local storage export."""
    import database
    from services import exports
    from services.types import RequestingUser

    # Create an export file
    expires_at = datetime.now(UTC) + timedelta(hours=24)
    export = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="test-download.json.gz",
        storage_type="local",
        storage_path="exports/test-download.json.gz",
        expires_at=expires_at,
        created_by=str(test_admin_user["id"]),
        file_size=1024,
    )

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # Mock the storage backend
    with patch("services.exports.storage.get_backend") as mock_backend:
        mock_storage = MagicMock()
        mock_storage.get_file_path.return_value = "/app/storage/exports/test-download.json.gz"
        mock_backend.return_value = mock_storage

        result = exports.get_download(requesting_user, str(export["id"]))

    assert result["storage_type"] == "local"
    assert result["filename"] == "test-download.json.gz"
    assert result["path"] == "/app/storage/exports/test-download.json.gz"


def test_get_download_spaces_storage(test_tenant, test_admin_user):
    """Test getting download info for Spaces storage export."""
    import database
    from services import exports
    from services.types import RequestingUser

    # Create an export file with spaces storage
    expires_at = datetime.now(UTC) + timedelta(hours=24)
    export = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="test-spaces.json.gz",
        storage_type="spaces",
        storage_path="exports/test-spaces.json.gz",
        expires_at=expires_at,
        created_by=str(test_admin_user["id"]),
        file_size=2048,
    )

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # Mock the storage backend
    with patch("services.exports.storage.get_backend") as mock_backend:
        mock_storage = MagicMock()
        mock_storage.get_download_url.return_value = "https://spaces.example.com/signed-url"
        mock_backend.return_value = mock_storage

        result = exports.get_download(requesting_user, str(export["id"]))

    assert result["storage_type"] == "spaces"
    assert result["filename"] == "test-spaces.json.gz"
    assert result["url"] == "https://spaces.example.com/signed-url"


def test_get_download_marks_as_downloaded(test_tenant, test_admin_user):
    """Test that get_download marks the export as downloaded."""
    import database
    from services import exports
    from services.types import RequestingUser

    # Create an export file
    expires_at = datetime.now(UTC) + timedelta(hours=24)
    export = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="test-mark-downloaded.json.gz",
        storage_type="local",
        storage_path="exports/test-mark-downloaded.json.gz",
        expires_at=expires_at,
        created_by=str(test_admin_user["id"]),
    )

    # Verify not downloaded yet
    before = database.export_files.get_export_file(
        str(test_tenant["id"]), str(export["id"])
    )
    assert before["downloaded_at"] is None

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with patch("services.exports.storage.get_backend") as mock_backend:
        mock_storage = MagicMock()
        mock_storage.get_file_path.return_value = "/app/storage/exports/test.json.gz"
        mock_backend.return_value = mock_storage

        exports.get_download(requesting_user, str(export["id"]))

    # Verify now marked as downloaded
    after = database.export_files.get_export_file(
        str(test_tenant["id"]), str(export["id"])
    )
    assert after["downloaded_at"] is not None


def test_get_download_forbidden_for_member(test_tenant, test_user):
    """Test that members cannot download exports."""
    from services import exports
    from services.exceptions import ForbiddenError
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }

    with pytest.raises(ForbiddenError) as exc_info:
        exports.get_download(requesting_user, str(uuid4()))

    assert exc_info.value.code == "admin_required"


def test_get_download_not_found(test_tenant, test_admin_user):
    """Test that getting a non-existent export raises NotFoundError."""
    from services import exports
    from services.exceptions import NotFoundError
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with pytest.raises(NotFoundError) as exc_info:
        exports.get_download(requesting_user, str(uuid4()))

    assert exc_info.value.code == "export_not_found"


def test_get_download_file_missing_from_disk(test_tenant, test_admin_user):
    """Test that get_download raises NotFoundError when file is missing from disk."""
    import database
    from services import exports
    from services.exceptions import NotFoundError
    from services.types import RequestingUser

    # Create an export file
    expires_at = datetime.now(UTC) + timedelta(hours=24)
    export = database.export_files.create_export_file(
        tenant_id=str(test_tenant["id"]),
        filename="missing-file.json.gz",
        storage_type="local",
        storage_path="exports/missing-file.json.gz",
        expires_at=expires_at,
        created_by=str(test_admin_user["id"]),
    )

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # Mock the storage backend to return None (file not found)
    with patch("services.exports.storage.get_backend") as mock_backend:
        mock_storage = MagicMock()
        mock_storage.get_file_path.return_value = None
        mock_backend.return_value = mock_storage

        with pytest.raises(NotFoundError) as exc_info:
            exports.get_download(requesting_user, str(export["id"]))

    assert exc_info.value.code == "export_file_missing"
