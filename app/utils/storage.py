"""File storage abstraction with DigitalOcean Spaces and local fallback."""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import BinaryIO

import settings

logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    def save(self, key: str, data: BinaryIO, content_type: str) -> str:
        """Save data and return the full storage path."""
        pass

    @abstractmethod
    def get_download_url(self, key: str, filename: str, expires_in: int = 3600) -> str:
        """Get a download URL (signed for Spaces, internal path for local)."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a file. Returns True on success."""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if file exists."""
        pass

    @abstractmethod
    def get_file_path(self, key: str) -> str | None:
        """Get local file path if available (for streaming). Returns None for remote storage."""
        pass


class LocalStorageBackend(StorageBackend):
    """Local filesystem storage backend."""

    def __init__(self) -> None:
        self.base_path = Path(settings.LOCAL_STORAGE_PATH)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def save(self, key: str, data: BinaryIO, content_type: str) -> str:
        path = self.base_path / key
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data.read())
        return str(path)

    def get_download_url(self, key: str, filename: str, expires_in: int = 3600) -> str:
        # For local storage, we return an internal URL that the router will handle
        # The router will stream the file directly
        return f"/admin/exports/file/{key}"

    def delete(self, key: str) -> bool:
        path = self.base_path / key
        try:
            path.unlink(missing_ok=True)
            # Clean up empty parent directories
            parent = path.parent
            while parent != self.base_path:
                try:
                    parent.rmdir()  # Only removes if empty
                    parent = parent.parent
                except OSError:
                    break
            return True
        except Exception as e:
            logger.warning("Failed to delete %s: %s", key, e)
            return False

    def exists(self, key: str) -> bool:
        return (self.base_path / key).exists()

    def get_file_path(self, key: str) -> str | None:
        path = self.base_path / key
        if path.exists():
            return str(path)
        return None


class SpacesStorageBackend(StorageBackend):
    """DigitalOcean Spaces (S3-compatible) storage backend."""

    def __init__(self) -> None:
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError:
            raise ImportError(
                "boto3 is required for DigitalOcean Spaces storage. "
                "Install it with: pip install boto3"
            )

        self.client = boto3.client(
            "s3",
            endpoint_url=settings.SPACES_ENDPOINT,
            aws_access_key_id=settings.SPACES_KEY,
            aws_secret_access_key=settings.SPACES_SECRET,
            region_name=settings.SPACES_REGION,
        )
        self.bucket = settings.SPACES_BUCKET

    def save(self, key: str, data: BinaryIO, content_type: str) -> str:
        self.client.upload_fileobj(
            data,
            self.bucket,
            key,
            ExtraArgs={"ContentType": content_type},
        )
        return f"s3://{self.bucket}/{key}"

    def get_download_url(self, key: str, filename: str, expires_in: int = 3600) -> str:
        url: str = self.client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self.bucket,
                "Key": key,
                "ResponseContentDisposition": f'attachment; filename="{filename}"',
            },
            ExpiresIn=expires_in,
        )
        return url

    def delete(self, key: str) -> bool:
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
            return True
        except Exception as e:
            logger.warning("Failed to delete %s from Spaces: %s", key, e)
            return False

    def exists(self, key: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    def get_file_path(self, key: str) -> str | None:
        # Remote storage doesn't have a local file path
        return None


_backend: StorageBackend | None = None


def get_backend() -> StorageBackend:
    """Get the configured storage backend (cached)."""
    global _backend
    if _backend is not None:
        return _backend

    backend_type = settings.STORAGE_BACKEND.lower()
    if backend_type == "spaces" and settings.SPACES_BUCKET:
        _backend = SpacesStorageBackend()
    else:
        _backend = LocalStorageBackend()

    return _backend


def reset_backend() -> None:
    """Reset the cached backend (useful for testing)."""
    global _backend
    _backend = None
