"""Exports service layer.

This module provides service-level functions for managing export files.
"""

import logging
from typing import Any

import database
from schemas.event_log import ExportFileItem, ExportListResponse
from services.activity import track_activity
from services.auth import require_admin
from services.exceptions import NotFoundError
from services.types import RequestingUser
from utils import storage

logger = logging.getLogger(__name__)


def list_exports(requesting_user: RequestingUser) -> ExportListResponse:
    """
    List available export files for download.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request

    Returns:
        ExportListResponse with list of available exports
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    exports = database.export_files.list_export_files(tenant_id, limit=50)
    total = database.export_files.count_exports_for_tenant(tenant_id)

    items = [
        ExportFileItem(
            id=str(e["id"]),
            filename=e["filename"],
            storage_type=e["storage_type"],
            file_size=e["file_size"],
            content_type=e["content_type"],
            expires_at=e["expires_at"],
            created_at=e["created_at"],
            downloaded_at=e.get("downloaded_at"),
        )
        for e in exports
    ]

    return ExportListResponse(items=items, total=total)


def get_download(
    requesting_user: RequestingUser,
    export_id: str,
) -> dict[str, Any]:
    """
    Get download information for an export file.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request
        export_id: The export file ID

    Returns:
        Dict with download information:
        - For Spaces: {"storage_type": "spaces", "url": "signed_url", "filename": "..."}
        - For local: {"storage_type": "local", "path": "/path/to/file", "filename": "..."}

    Raises:
        NotFoundError: If export not found or expired
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    export = database.export_files.get_export_file(tenant_id, export_id)
    if not export:
        raise NotFoundError(
            message="Export not found",
            code="export_not_found",
        )

    # Mark as downloaded (side-effect for tracking; activity already logged above)
    database.export_files.mark_downloaded(tenant_id, export_id)

    backend = storage.get_backend()

    if export["storage_type"] == "spaces":
        url = backend.get_download_url(
            export["storage_path"],
            export["filename"],
            expires_in=3600,
        )
        return {
            "storage_type": "spaces",
            "url": url,
            "filename": export["filename"],
        }
    else:
        # For local storage, return the file path for streaming
        file_path = backend.get_file_path(export["storage_path"])
        if not file_path:
            raise NotFoundError(
                message="Export file not found on disk",
                code="export_file_missing",
            )
        return {
            "storage_type": "local",
            "path": file_path,
            "filename": export["filename"],
            "content_type": export["content_type"],
        }
