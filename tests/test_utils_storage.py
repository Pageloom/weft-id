"""Comprehensive tests for Storage utility module.

This test file covers all storage backend operations for the utils/storage.py module.
Tests include:
- LocalStorageBackend (save, exists, delete, get_download_url, get_file_path)
- SpacesStorageBackend (mocked S3 operations)
- Backend selection and caching
"""

import io
from unittest.mock import MagicMock, patch

import pytest

# =============================================================================
# LocalStorageBackend Tests
# =============================================================================


def test_local_storage_init_creates_base_path(tmp_path):
    """Test that LocalStorageBackend creates the base storage directory."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path / "storage")):
        backend = LocalStorageBackend()

        assert backend.base_path.exists()
        assert backend.base_path.is_dir()


def test_local_storage_save_success(tmp_path):
    """Test saving a file with LocalStorageBackend."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        data = io.BytesIO(b"test file content")
        result = backend.save("test/file.txt", data, "text/plain")

        assert result == str(tmp_path / "test/file.txt")
        assert (tmp_path / "test/file.txt").exists()
        assert (tmp_path / "test/file.txt").read_bytes() == b"test file content"


def test_local_storage_save_creates_parent_directories(tmp_path):
    """Test that save creates parent directories automatically."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        data = io.BytesIO(b"nested file")
        backend.save("deeply/nested/path/file.txt", data, "text/plain")

        assert (tmp_path / "deeply/nested/path/file.txt").exists()


def test_local_storage_exists_returns_true(tmp_path):
    """Test exists() returns True for existing file."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        # Create a file
        data = io.BytesIO(b"test")
        backend.save("exists.txt", data, "text/plain")

        assert backend.exists("exists.txt") is True


def test_local_storage_exists_returns_false(tmp_path):
    """Test exists() returns False for non-existent file."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        assert backend.exists("nonexistent.txt") is False


def test_local_storage_delete_success(tmp_path):
    """Test deleting a file with LocalStorageBackend."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        # Create a file
        data = io.BytesIO(b"delete me")
        backend.save("deleteme.txt", data, "text/plain")

        # Delete it
        result = backend.delete("deleteme.txt")

        assert result is True
        assert not (tmp_path / "deleteme.txt").exists()


def test_local_storage_delete_nonexistent_file(tmp_path):
    """Test deleting a non-existent file returns True (missing_ok)."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        # Delete non-existent file
        result = backend.delete("nonexistent.txt")

        assert result is True


def test_local_storage_delete_cleans_empty_directories(tmp_path):
    """Test that delete cleans up empty parent directories."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        # Create a nested file
        data = io.BytesIO(b"nested")
        backend.save("dir1/dir2/file.txt", data, "text/plain")

        # Delete it
        backend.delete("dir1/dir2/file.txt")

        # Empty directories should be cleaned up
        assert not (tmp_path / "dir1/dir2").exists()
        assert not (tmp_path / "dir1").exists()


def test_local_storage_delete_preserves_non_empty_directories(tmp_path):
    """Test that delete preserves non-empty parent directories."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        # Create two files in same directory
        data1 = io.BytesIO(b"file1")
        data2 = io.BytesIO(b"file2")
        backend.save("dir/file1.txt", data1, "text/plain")
        backend.save("dir/file2.txt", data2, "text/plain")

        # Delete one file
        backend.delete("dir/file1.txt")

        # Directory should still exist (has file2.txt)
        assert (tmp_path / "dir").exists()
        assert (tmp_path / "dir/file2.txt").exists()


def test_local_storage_get_download_url(tmp_path):
    """Test get_download_url returns internal URL."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        url = backend.get_download_url("test/file.txt", "file.txt", expires_in=3600)

        assert url == "/admin/exports/file/test/file.txt"


def test_local_storage_get_file_path_exists(tmp_path):
    """Test get_file_path returns path when file exists."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        # Create a file
        data = io.BytesIO(b"test")
        backend.save("test.txt", data, "text/plain")

        path = backend.get_file_path("test.txt")

        assert path == str(tmp_path / "test.txt")


def test_local_storage_get_file_path_not_exists(tmp_path):
    """Test get_file_path returns None when file doesn't exist."""
    from utils.storage import LocalStorageBackend

    with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
        backend = LocalStorageBackend()

        path = backend.get_file_path("nonexistent.txt")

        assert path is None


# =============================================================================
# SpacesStorageBackend Tests
# =============================================================================


def test_spaces_storage_init_success():
    """Test SpacesStorageBackend initialization with boto3."""
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client

    with patch.dict("sys.modules", {"boto3": mock_boto3}):
        with patch("settings.SPACES_ENDPOINT", "https://space.example.com"):
            with patch("settings.SPACES_KEY", "test-key"):
                with patch("settings.SPACES_SECRET", "test-secret"):
                    with patch("settings.SPACES_REGION", "us-east-1"):
                        with patch("settings.SPACES_BUCKET", "test-bucket"):
                            from utils.storage import SpacesStorageBackend

                            backend = SpacesStorageBackend()

                            assert backend.client == mock_client
                            assert backend.bucket == "test-bucket"
                            mock_boto3.client.assert_called_once()


def test_spaces_storage_init_missing_boto3():
    """Test SpacesStorageBackend raises error when boto3 not installed."""
    # Simulate boto3 not being installed by making the import fail
    import sys

    # Save the current boto3 module if it exists
    old_boto3 = sys.modules.get("boto3")

    # Remove boto3 from sys.modules to simulate it not being installed
    if "boto3" in sys.modules:
        del sys.modules["boto3"]

    # Also need to clear any cached SpacesStorageBackend class
    import importlib

    import utils.storage

    importlib.reload(utils.storage)

    try:
        from utils.storage import SpacesStorageBackend

        with pytest.raises(ImportError) as exc_info:
            SpacesStorageBackend()

        assert "boto3 is required" in str(exc_info.value)
    finally:
        # Restore boto3 if it was there
        if old_boto3 is not None:
            sys.modules["boto3"] = old_boto3
        # Reload the module to restore its state
        importlib.reload(utils.storage)


def test_spaces_storage_save_success():
    """Test saving a file to Spaces."""
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client

    with patch.dict("sys.modules", {"boto3": mock_boto3}):
        with patch("settings.SPACES_ENDPOINT", "https://space.example.com"):
            with patch("settings.SPACES_KEY", "key"):
                with patch("settings.SPACES_SECRET", "secret"):
                    with patch("settings.SPACES_REGION", "us-east-1"):
                        with patch("settings.SPACES_BUCKET", "mybucket"):
                            from utils.storage import SpacesStorageBackend

                            backend = SpacesStorageBackend()

                            data = io.BytesIO(b"spaces data")
                            result = backend.save("test/file.txt", data, "text/plain")

                            assert result == "s3://mybucket/test/file.txt"
                            mock_client.upload_fileobj.assert_called_once()
                            call_args = mock_client.upload_fileobj.call_args
                            assert call_args[0][1] == "mybucket"
                            assert call_args[0][2] == "test/file.txt"
                            assert call_args[1]["ExtraArgs"]["ContentType"] == "text/plain"


def test_spaces_storage_get_download_url():
    """Test generating presigned URL from Spaces."""
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_client.generate_presigned_url.return_value = "https://signed-url.example.com"
    mock_boto3.client.return_value = mock_client

    with patch.dict("sys.modules", {"boto3": mock_boto3}):
        with patch("settings.SPACES_ENDPOINT", "https://space.example.com"):
            with patch("settings.SPACES_KEY", "key"):
                with patch("settings.SPACES_SECRET", "secret"):
                    with patch("settings.SPACES_REGION", "us-east-1"):
                        with patch("settings.SPACES_BUCKET", "mybucket"):
                            from utils.storage import SpacesStorageBackend

                            backend = SpacesStorageBackend()

                            url = backend.get_download_url(
                                "test.txt", "download.txt", expires_in=1800
                            )

                            assert url == "https://signed-url.example.com"
                            mock_client.generate_presigned_url.assert_called_once_with(
                                "get_object",
                                Params={
                                    "Bucket": "mybucket",
                                    "Key": "test.txt",
                                    "ResponseContentDisposition": (
                                        'attachment; filename="download.txt"'
                                    ),
                                },
                                ExpiresIn=1800,
                            )


def test_spaces_storage_delete_success():
    """Test deleting a file from Spaces."""
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client

    with patch.dict("sys.modules", {"boto3": mock_boto3}):
        with patch("settings.SPACES_ENDPOINT", "https://space.example.com"):
            with patch("settings.SPACES_KEY", "key"):
                with patch("settings.SPACES_SECRET", "secret"):
                    with patch("settings.SPACES_REGION", "us-east-1"):
                        with patch("settings.SPACES_BUCKET", "mybucket"):
                            from utils.storage import SpacesStorageBackend

                            backend = SpacesStorageBackend()

                            result = backend.delete("test.txt")

                            assert result is True
                            mock_client.delete_object.assert_called_once_with(
                                Bucket="mybucket", Key="test.txt"
                            )


def test_spaces_storage_delete_failure():
    """Test Spaces delete failure handling."""
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_client.delete_object.side_effect = Exception("S3 error")
    mock_boto3.client.return_value = mock_client

    with patch.dict("sys.modules", {"boto3": mock_boto3}):
        with patch("settings.SPACES_ENDPOINT", "https://space.example.com"):
            with patch("settings.SPACES_KEY", "key"):
                with patch("settings.SPACES_SECRET", "secret"):
                    with patch("settings.SPACES_REGION", "us-east-1"):
                        with patch("settings.SPACES_BUCKET", "mybucket"):
                            from utils.storage import SpacesStorageBackend

                            backend = SpacesStorageBackend()

                            result = backend.delete("test.txt")

                            assert result is False


def test_spaces_storage_exists_returns_true():
    """Test exists() returns True when object exists in Spaces."""
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_client.head_object.return_value = {"ContentLength": 123}
    mock_boto3.client.return_value = mock_client

    with patch.dict("sys.modules", {"boto3": mock_boto3}):
        with patch("settings.SPACES_ENDPOINT", "https://space.example.com"):
            with patch("settings.SPACES_KEY", "key"):
                with patch("settings.SPACES_SECRET", "secret"):
                    with patch("settings.SPACES_REGION", "us-east-1"):
                        with patch("settings.SPACES_BUCKET", "mybucket"):
                            from utils.storage import SpacesStorageBackend

                            backend = SpacesStorageBackend()

                            result = backend.exists("test.txt")

                            assert result is True
                            mock_client.head_object.assert_called_once_with(
                                Bucket="mybucket", Key="test.txt"
                            )


def test_spaces_storage_exists_returns_false():
    """Test exists() returns False when object doesn't exist in Spaces."""
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_client.head_object.side_effect = Exception("Not found")
    mock_boto3.client.return_value = mock_client

    with patch.dict("sys.modules", {"boto3": mock_boto3}):
        with patch("settings.SPACES_ENDPOINT", "https://space.example.com"):
            with patch("settings.SPACES_KEY", "key"):
                with patch("settings.SPACES_SECRET", "secret"):
                    with patch("settings.SPACES_REGION", "us-east-1"):
                        with patch("settings.SPACES_BUCKET", "mybucket"):
                            from utils.storage import SpacesStorageBackend

                            backend = SpacesStorageBackend()

                            result = backend.exists("nonexistent.txt")

                            assert result is False


def test_spaces_storage_get_file_path_returns_none():
    """Test get_file_path returns None for remote storage."""
    mock_boto3 = MagicMock()
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client

    with patch.dict("sys.modules", {"boto3": mock_boto3}):
        with patch("settings.SPACES_ENDPOINT", "https://space.example.com"):
            with patch("settings.SPACES_KEY", "key"):
                with patch("settings.SPACES_SECRET", "secret"):
                    with patch("settings.SPACES_REGION", "us-east-1"):
                        with patch("settings.SPACES_BUCKET", "mybucket"):
                            from utils.storage import SpacesStorageBackend

                            backend = SpacesStorageBackend()

                            path = backend.get_file_path("test.txt")

                            assert path is None


# =============================================================================
# Backend Selection Tests
# =============================================================================


def test_get_backend_default_local(tmp_path):
    """Test get_backend returns LocalStorageBackend by default."""
    from utils.storage import LocalStorageBackend, get_backend, reset_backend

    reset_backend()

    with patch("settings.STORAGE_BACKEND", "local"):
        with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
            backend = get_backend()

            assert isinstance(backend, LocalStorageBackend)

    reset_backend()


def test_get_backend_spaces_when_configured():
    """Test get_backend returns SpacesStorageBackend when configured."""
    from utils.storage import SpacesStorageBackend, get_backend, reset_backend

    reset_backend()

    mock_boto3 = MagicMock()
    mock_boto3.client.return_value = MagicMock()

    with patch.dict("sys.modules", {"boto3": mock_boto3}):
        with patch("settings.STORAGE_BACKEND", "spaces"):
            with patch("settings.SPACES_BUCKET", "mybucket"):
                with patch("settings.SPACES_ENDPOINT", "https://space.example.com"):
                    with patch("settings.SPACES_KEY", "key"):
                        with patch("settings.SPACES_SECRET", "secret"):
                            with patch("settings.SPACES_REGION", "us-east-1"):
                                backend = get_backend()

                                assert isinstance(backend, SpacesStorageBackend)

    reset_backend()


def test_get_backend_falls_back_to_local_without_bucket(tmp_path):
    """Test get_backend falls back to local when Spaces bucket not configured."""
    from utils.storage import LocalStorageBackend, get_backend, reset_backend

    reset_backend()

    with patch("settings.STORAGE_BACKEND", "spaces"):
        with patch("settings.SPACES_BUCKET", ""):  # No bucket configured
            with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
                backend = get_backend()

                assert isinstance(backend, LocalStorageBackend)

    reset_backend()


def test_get_backend_caches_instance(tmp_path):
    """Test that get_backend caches the backend instance."""
    from utils.storage import get_backend, reset_backend

    reset_backend()

    with patch("settings.STORAGE_BACKEND", "local"):
        with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
            backend1 = get_backend()
            backend2 = get_backend()

            assert backend1 is backend2

    reset_backend()


def test_reset_backend_clears_cache(tmp_path):
    """Test that reset_backend clears the cached instance."""
    from utils.storage import get_backend, reset_backend

    with patch("settings.STORAGE_BACKEND", "local"):
        with patch("settings.LOCAL_STORAGE_PATH", str(tmp_path)):
            backend1 = get_backend()
            reset_backend()
            backend2 = get_backend()

            assert backend1 is not backend2

    reset_backend()
