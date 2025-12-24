"""Export files database operations.

This module handles CRUD operations for export files.
The export_files table uses RLS for tenant isolation.
"""

from datetime import datetime

from ._core import UNSCOPED, TenantArg, execute, fetchall, fetchone


def create_export_file(
    tenant_id: str,
    filename: str,
    storage_type: str,
    storage_path: str,
    expires_at: datetime,
    created_by: str,
    bg_task_id: str | None = None,
    file_size: int | None = None,
    content_type: str = "application/gzip",
) -> dict | None:
    """Create a new export file record.

    Args:
        tenant_id: The tenant ID
        filename: Display filename for download
        storage_type: "local" or "spaces"
        storage_path: Full path (local) or S3 key (spaces)
        expires_at: When the export should be deleted
        created_by: User ID who triggered the export
        bg_task_id: Optional associated background task ID
        file_size: Optional file size in bytes
        content_type: MIME type (default: application/gzip)

    Returns:
        Dict with id and created_at, or None if insert failed
    """
    return fetchone(
        tenant_id,
        """
        INSERT INTO export_files (
            tenant_id, bg_task_id, filename, storage_type, storage_path,
            file_size, content_type, expires_at, created_by
        )
        VALUES (
            :tenant_id, :bg_task_id, :filename, :storage_type, :storage_path,
            :file_size, :content_type, :expires_at, :created_by
        )
        RETURNING id, created_at
        """,
        {
            "tenant_id": tenant_id,
            "bg_task_id": bg_task_id,
            "filename": filename,
            "storage_type": storage_type,
            "storage_path": storage_path,
            "file_size": file_size,
            "content_type": content_type,
            "expires_at": expires_at,
            "created_by": created_by,
        },
    )


def get_export_file(tenant_id: TenantArg, export_id: str) -> dict | None:
    """Get an export file by ID.

    Args:
        tenant_id: The tenant ID (for RLS)
        export_id: The export file ID

    Returns:
        Export file dict or None if not found
    """
    return fetchone(
        tenant_id,
        """
        SELECT id, tenant_id, bg_task_id, filename, storage_type, storage_path,
               file_size, content_type, expires_at, created_by, created_at, downloaded_at
        FROM export_files
        WHERE id = :export_id
        """,
        {"export_id": export_id},
    )


def list_export_files(
    tenant_id: TenantArg,
    limit: int = 50,
    include_expired: bool = False,
) -> list[dict]:
    """List export files for a tenant.

    Args:
        tenant_id: The tenant ID
        limit: Maximum number of files to return
        include_expired: Whether to include expired files

    Returns:
        List of export file dicts, newest first
    """
    if include_expired:
        return fetchall(
            tenant_id,
            """
            SELECT id, filename, storage_type, file_size, content_type,
                   expires_at, created_by, created_at, downloaded_at
            FROM export_files
            ORDER BY created_at DESC
            LIMIT :limit
            """,
            {"limit": limit},
        )
    return fetchall(
        tenant_id,
        """
        SELECT id, filename, storage_type, file_size, content_type,
               expires_at, created_by, created_at, downloaded_at
        FROM export_files
        WHERE expires_at > now()
        ORDER BY created_at DESC
        LIMIT :limit
        """,
        {"limit": limit},
    )


def mark_downloaded(tenant_id: TenantArg, export_id: str) -> None:
    """Mark an export file as downloaded.

    Args:
        tenant_id: The tenant ID
        export_id: The export file ID
    """
    execute(
        tenant_id,
        """
        UPDATE export_files
        SET downloaded_at = now()
        WHERE id = :export_id AND downloaded_at IS NULL
        """,
        {"export_id": export_id},
    )


def delete_export_file(export_id: str) -> None:
    """Delete an export file record.

    Note: This uses UNSCOPED because it's called by the cleanup worker
    which operates across all tenants.

    Args:
        export_id: The export file ID
    """
    execute(
        UNSCOPED,
        "DELETE FROM export_files WHERE id = :export_id",
        {"export_id": export_id},
    )


def get_expired_exports() -> list[dict]:
    """Get all expired export files across all tenants.

    Called by the cleanup worker to find files to delete.

    Returns:
        List of expired export file dicts with storage info
    """
    return fetchall(
        UNSCOPED,
        """
        SELECT id, tenant_id, storage_type, storage_path
        FROM export_files
        WHERE expires_at <= now()
        """,
        {},
    )


def count_exports_for_tenant(tenant_id: TenantArg) -> int:
    """Count non-expired exports for a tenant.

    Args:
        tenant_id: The tenant ID

    Returns:
        Number of active exports
    """
    result = fetchone(
        tenant_id,
        "SELECT COUNT(*) as count FROM export_files WHERE expires_at > now()",
        {},
    )
    return result["count"] if result else 0
