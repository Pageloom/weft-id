"""Export file cleanup job handler."""

import logging
from typing import Any

import database
from utils import storage

logger = logging.getLogger(__name__)


def cleanup_expired_exports() -> dict[str, Any]:
    """
    Delete expired export files from storage and database.

    This function is called directly by the worker's cleanup timer,
    not as a queued job.

    Returns:
        Dict with deleted count and failed count
    """
    logger.info("Starting cleanup of expired exports...")

    # Get all expired exports across all tenants
    expired = database.export_files.get_expired_exports()

    if not expired:
        logger.info("No expired exports to clean up")
        return {"deleted": 0, "failed": 0}

    logger.info("Found %d expired exports to clean up", len(expired))

    deleted_count = 0
    failed_count = 0

    backend = storage.get_backend()

    for export in expired:
        export_id = str(export["id"])
        storage_path = export["storage_path"]
        bg_task_id = str(export["bg_task_id"]) if export.get("bg_task_id") else None

        try:
            # Delete from storage
            if backend.exists(storage_path):
                if backend.delete(storage_path):
                    logger.debug("Deleted file: %s", storage_path)
                else:
                    logger.warning("Failed to delete file: %s", storage_path)

            # Delete from database (even if file deletion failed)
            database.export_files.delete_export_file(export_id)

            # Redact password from the associated background task result
            if bg_task_id:
                database.bg_tasks.redact_result_password(bg_task_id)

            deleted_count += 1
            logger.debug("Deleted export record: %s", export_id)

        except Exception as e:
            logger.error("Failed to clean up export %s: %s", export_id, e)
            failed_count += 1

    logger.info(
        "Cleanup completed: %d deleted, %d failed",
        deleted_count,
        failed_count,
    )

    return {
        "deleted": deleted_count,
        "failed": failed_count,
    }
