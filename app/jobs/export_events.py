"""Event log export job handler."""

import gzip
import json
import logging
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Any
from uuid import uuid4

import database
import settings
from constants.event_types import EVENT_TYPE_DESCRIPTIONS
from jobs.registry import register_handler
from utils import storage
from utils.email import send_email

logger = logging.getLogger(__name__)


def _json_serializer(obj: Any) -> str:
    """Custom JSON serializer for datetime and UUID objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "hex"):  # UUID objects
        return str(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


@register_handler("export_events")
def handle_export_events(task: dict) -> dict[str, Any]:
    """
    Export all event logs for a tenant as a gzipped JSON file.

    Sends email notification when complete.

    Args:
        task: The task dict with id, tenant_id, job_type, payload, created_by

    Returns:
        Dict with export_file_id, event_count, filename
    """
    tenant_id = str(task["tenant_id"])
    created_by = str(task["created_by"])
    task_id = str(task["id"])

    logger.info("Starting event log export for tenant %s", tenant_id)

    # Validate tenant exists before doing any work (avoids orphaned storage files)
    tenant = database.tenants.get_tenant_by_id(tenant_id)
    if not tenant:
        raise ValueError(f"Tenant {tenant_id} does not exist")

    # Get all events (paginated to avoid memory issues)
    all_events = []
    offset = 0
    batch_size = 1000

    while True:
        events = database.event_log.list_events(
            tenant_id,
            limit=batch_size,
            offset=offset,
        )
        if not events:
            break
        all_events.extend(events)
        offset += batch_size
        logger.info("Fetched %d events so far...", len(all_events))

    logger.info("Total events to export: %d", len(all_events))

    # Convert to JSON
    export_data = {
        "events": all_events,
        "event_type_descriptions": EVENT_TYPE_DESCRIPTIONS,
        "exported_at": datetime.now(UTC).isoformat(),
        "count": len(all_events),
        "tenant_id": tenant_id,
    }
    json_data = json.dumps(export_data, default=_json_serializer, indent=2)

    # Compress
    compressed = BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb") as gz:
        gz.write(json_data.encode("utf-8"))
    compressed.seek(0)
    file_size = compressed.getbuffer().nbytes

    # Generate unique filename and storage key
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    filename = f"event-export-{timestamp}-{uuid4().hex[:8]}.json.gz"
    storage_key = f"exports/{tenant_id}/{filename}"

    # Save to storage
    backend = storage.get_backend()
    storage_path = backend.save(storage_key, compressed, "application/gzip")
    storage_type = settings.STORAGE_BACKEND.lower()
    if storage_type != "spaces" or not settings.SPACES_BUCKET:
        storage_type = "local"

    logger.info("Saved export to: %s", storage_path)

    # Calculate expiry
    expires_at = datetime.now(UTC) + timedelta(hours=settings.EXPORT_FILE_EXPIRY_HOURS)

    # Record in database
    export_file = database.export_files.create_export_file(
        tenant_id=tenant_id,
        bg_task_id=task_id,
        filename=filename,
        storage_type=storage_type,
        storage_path=storage_key,  # Store the key, not the full path
        file_size=file_size,
        expires_at=expires_at,
        created_by=created_by,
    )

    logger.info("Created export file record: %s", export_file["id"] if export_file else "None")

    # Note: Email notifications removed per requirements - users check Background Jobs page instead

    # Return structured result with output for UI display
    size_kb = file_size // 1024
    output_msg = f"Exported {len(all_events):,} events to {filename} ({size_kb:,} KB compressed)"
    return {
        "output": output_msg,
        "file_id": str(export_file["id"]) if export_file else None,
        "records_processed": len(all_events),
        "filename": filename,
        "file_size": file_size,
    }


def _send_export_notification(
    tenant_id: str,
    user_id: str,
    filename: str,
    event_count: int,
    expires_at: datetime,
) -> None:
    """Send email notification when export is ready."""
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        logger.warning("Could not find user %s for export notification", user_id)
        return

    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if not primary_email:
        logger.warning("Could not find primary email for user %s", user_id)
        return

    user_name = user.get("first_name", "User")
    to_email = primary_email["email"]

    subject = "Your Event Log Export is Ready"

    text_body = f"""
Hi {user_name},

Your event log export is ready for download.

File: {filename}
Events: {event_count:,}
Expires: {expires_at.strftime("%Y-%m-%d %H:%M UTC")}

Please download your export from the Event Log Exports page before it expires.
"""

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.5;
            color: #333;
        }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #1a1a1a; font-size: 24px; margin-bottom: 20px; }}
        .info-box {{ background: #f3f4f6; padding: 15px; border-radius: 8px; margin: 20px 0; }}
        .info-box p {{ margin: 5px 0; }}
        .footer {{ margin-top: 30px; font-size: 14px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Your Event Log Export is Ready</h1>
        <p>Hi {user_name},</p>
        <p>Your event log export has been generated and is ready for download.</p>
        <div class="info-box">
            <p><strong>File:</strong> {filename}</p>
            <p><strong>Events:</strong> {event_count:,}</p>
            <p><strong>Expires:</strong> {expires_at.strftime("%Y-%m-%d %H:%M UTC")}</p>
        </div>
        <p>Please download your export from the Event Log Exports page before it expires.</p>
        <div class="footer">
            <p>This is an automated message.</p>
        </div>
    </div>
</body>
</html>
"""

    try:
        send_email(to_email, subject, html_body, text_body)
        logger.info("Sent export notification email to %s", to_email)
    except Exception as e:
        logger.error("Failed to send export notification: %s", e)
