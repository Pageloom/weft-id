"""Tests for exports service layer."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest


def test_list_exports_as_admin_success(make_requesting_user, make_export_file_dict):
    """Test that admins can list exports."""
    from services import exports

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    export1 = make_export_file_dict(tenant_id=tenant_id, filename="test-1.json.gz")
    export2 = make_export_file_dict(tenant_id=tenant_id, filename="test-2.json.gz")

    with patch("services.exports.database") as mock_db, \
         patch("services.exports.track_activity"):
        mock_db.export_files.list_export_files.return_value = [export1, export2]
        mock_db.export_files.count_exports_for_tenant.return_value = 2

        result = exports.list_exports(requesting_user)

        assert result.total == 2
        assert len(result.items) == 2
        mock_db.export_files.list_export_files.assert_called_once()

def test_list_exports_as_super_admin_success(make_requesting_user):
    """Test that super_admins can list exports."""
    from services import exports

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")

    with patch("services.exports.database") as mock_db, \
         patch("services.exports.track_activity"):
        mock_db.export_files.list_export_files.return_value = []
        mock_db.export_files.count_exports_for_tenant.return_value = 0

        result = exports.list_exports(requesting_user)

        assert result.total == 0

def test_list_exports_forbidden_for_member(make_requesting_user):
    """Test that members cannot list exports."""
    from services import exports
    from services.exceptions import ForbiddenError

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        exports.list_exports(requesting_user)

    assert exc_info.value.code == "admin_required"

def test_get_download_local_storage(make_requesting_user, make_export_file_dict):
    """Test getting download info for local storage export."""
    from services import exports

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    export = make_export_file_dict(
        tenant_id=tenant_id,
        filename="test-download.json.gz",
        storage_type="local",
        storage_path="exports/test-download.json.gz",
    )

    with patch("services.exports.database") as mock_db, \
         patch("services.exports.track_activity"), \
         patch("services.exports.storage.get_backend") as mock_backend:
        mock_db.export_files.get_export_file.return_value = export
        mock_storage = MagicMock()
        mock_storage.get_file_path.return_value = "/app/storage/exports/test-download.json.gz"
        mock_backend.return_value = mock_storage

        result = exports.get_download(requesting_user, str(export["id"]))

        assert result["storage_type"] == "local"
        assert result["filename"] == "test-download.json.gz"
        assert result["path"] == "/app/storage/exports/test-download.json.gz"
        mock_db.export_files.mark_downloaded.assert_called_once()

def test_get_download_spaces_storage(make_requesting_user, make_export_file_dict):
    """Test getting download info for Spaces storage export."""
    from services import exports

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    export = make_export_file_dict(
        tenant_id=tenant_id,
        filename="test-spaces.json.gz",
        storage_type="spaces",
        storage_path="exports/test-spaces.json.gz",
    )

    with patch("services.exports.database") as mock_db, \
         patch("services.exports.track_activity"), \
         patch("services.exports.storage.get_backend") as mock_backend:
        mock_db.export_files.get_export_file.return_value = export
        mock_storage = MagicMock()
        mock_storage.get_download_url.return_value = "https://spaces.example.com/signed-url"
        mock_backend.return_value = mock_storage

        result = exports.get_download(requesting_user, str(export["id"]))

        assert result["storage_type"] == "spaces"
        assert result["filename"] == "test-spaces.json.gz"
        assert result["url"] == "https://spaces.example.com/signed-url"

def test_get_download_marks_as_downloaded(make_requesting_user, make_export_file_dict):
    """Test that get_download marks the export as downloaded."""
    from services import exports

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    export = make_export_file_dict(
        tenant_id=tenant_id,
        filename="test-mark-downloaded.json.gz",
        storage_type="local",
        downloaded_at=None,
    )

    with patch("services.exports.database") as mock_db, \
         patch("services.exports.track_activity"), \
         patch("services.exports.storage.get_backend") as mock_backend:
        mock_db.export_files.get_export_file.return_value = export
        mock_storage = MagicMock()
        mock_storage.get_file_path.return_value = "/app/storage/exports/test.json.gz"
        mock_backend.return_value = mock_storage

        exports.get_download(requesting_user, str(export["id"]))

        # Verify mark_downloaded was called
        mock_db.export_files.mark_downloaded.assert_called_once_with(
            tenant_id, str(export["id"])
        )

def test_get_download_forbidden_for_member(make_requesting_user):
    """Test that members cannot download exports."""
    from services import exports
    from services.exceptions import ForbiddenError

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        exports.get_download(requesting_user, str(uuid4()))

    assert exc_info.value.code == "admin_required"

def test_get_download_not_found(make_requesting_user):
    """Test that getting a non-existent export raises NotFoundError."""
    from services import exports
    from services.exceptions import NotFoundError

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.exports.database") as mock_db, \
         patch("services.exports.track_activity"):
        mock_db.export_files.get_export_file.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            exports.get_download(requesting_user, str(uuid4()))

        assert exc_info.value.code == "export_not_found"

def test_get_download_file_missing_from_disk(make_requesting_user, make_export_file_dict):
    """Test that get_download raises NotFoundError when file is missing from disk."""
    from services import exports
    from services.exceptions import NotFoundError

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    export = make_export_file_dict(
        tenant_id=tenant_id,
        filename="missing-file.json.gz",
        storage_type="local",
    )

    with patch("services.exports.database") as mock_db, \
         patch("services.exports.track_activity"), \
         patch("services.exports.storage.get_backend") as mock_backend:
        mock_db.export_files.get_export_file.return_value = export
        mock_storage = MagicMock()
        mock_storage.get_file_path.return_value = None  # File not found
        mock_backend.return_value = mock_storage

        with pytest.raises(NotFoundError) as exc_info:
            exports.get_download(requesting_user, str(export["id"]))

        assert exc_info.value.code == "export_file_missing"
