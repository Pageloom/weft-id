"""Comprehensive tests for Event Export job handler.

This test file covers all functions in jobs/export_events.py.
Tests include:
- JSON serialization helper (_json_serializer)
- Export job handler (handle_export_events)
- Email notification helper (_send_export_notification)
"""

import gzip
import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest


def _prepare_event_metadata(
    custom_metadata: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    """Helper to prepare combined_metadata and metadata_hash for create_event().

    Args:
        custom_metadata: Optional custom event metadata

    Returns:
        Tuple of (combined_metadata, metadata_hash)
    """
    from utils.request_metadata import compute_metadata_hash

    # Build combined metadata with required request fields (all null for tests)
    combined_metadata: dict[str, Any] = {
        "device": None,
        "remote_address": None,
        "session_id_hash": None,
        "user_agent": None,
    }

    # Merge in custom metadata if provided
    if custom_metadata:
        combined_metadata.update(custom_metadata)

    # Compute hash
    metadata_hash = compute_metadata_hash(combined_metadata)

    return combined_metadata, metadata_hash


# =============================================================================
# JSON Serializer Tests
# =============================================================================


def test_json_serializer_with_datetime():
    """Test JSON serializer handles datetime objects."""
    from jobs.export_events import _json_serializer

    dt = datetime(2025, 1, 15, 12, 30, 45, tzinfo=UTC)
    result = _json_serializer(dt)

    assert result == "2025-01-15T12:30:45+00:00"


def test_json_serializer_with_uuid():
    """Test JSON serializer handles UUID objects."""
    from jobs.export_events import _json_serializer

    test_uuid = uuid4()
    result = _json_serializer(test_uuid)

    assert result == str(test_uuid)


def test_json_serializer_with_unsupported_type():
    """Test JSON serializer raises TypeError for unsupported types."""
    from jobs.export_events import _json_serializer

    with pytest.raises(TypeError, match="not JSON serializable"):
        _json_serializer(object())


# =============================================================================
# Export Events Handler Tests
# =============================================================================


def test_handle_export_events_success(test_tenant, test_admin_user):
    """Test successful event export with data."""
    import database
    from jobs.export_events import handle_export_events

    # Create some test events
    for i in range(5):
        combined_metadata, metadata_hash = _prepare_event_metadata({"index": i})
        database.event_log.create_event(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            event_type="test_event",
            artifact_type="test",
            artifact_id=str(uuid4()),
            actor_user_id=test_admin_user["id"],
            combined_metadata=combined_metadata,
            metadata_hash=metadata_hash,
        )

    # Create background task record (needed for foreign key)
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    task = {
        "id": bg_task["id"],
        "tenant_id": test_tenant["id"],
        "created_by": test_admin_user["id"],
        "job_type": "export_events",
    }

    with patch("jobs.export_events.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.save.return_value = f"exports/{test_tenant['id']}/test-file.json.gz"
        mock_get_backend.return_value = mock_backend

        result = handle_export_events(task)

        # Verify result structure
        assert "output" in result
        assert "file_id" in result
        assert "records_processed" in result
        assert "filename" in result
        assert "file_size" in result

        # Verify counts
        assert result["records_processed"] == 5
        assert "5 events" in result["output"]

        # Verify storage was called
        assert mock_backend.save.called
        save_call_args = mock_backend.save.call_args
        storage_key = save_call_args[0][0]
        assert storage_key.startswith(f"exports/{test_tenant['id']}/event-export-")
        assert storage_key.endswith(".json.gz")

        # Verify database record was created
        export_file = database.export_files.get_export_file(test_tenant["id"], result["file_id"])
        assert export_file is not None
        assert export_file["filename"] == result["filename"]
        assert export_file["created_by"] == test_admin_user["id"]


def test_handle_export_events_with_no_events(test_tenant, test_admin_user):
    """Test export with no events creates empty export."""
    import database
    from jobs.export_events import handle_export_events

    # Create background task record (needed for foreign key)
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    task = {
        "id": bg_task["id"],
        "tenant_id": test_tenant["id"],
        "created_by": test_admin_user["id"],
        "job_type": "export_events",
    }

    with patch("jobs.export_events.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.save.return_value = f"exports/{test_tenant['id']}/test-file.json.gz"
        mock_get_backend.return_value = mock_backend

        result = handle_export_events(task)

        # Should still create export with 0 events
        assert result["records_processed"] == 0
        assert "0 events" in result["output"]
        assert result["file_id"] is not None


def test_handle_export_events_pagination(test_tenant, test_admin_user):
    """Test export pagination with large number of events."""
    import database
    from jobs.export_events import handle_export_events

    # Create 2500 events to force pagination (batch size is 1000)
    for i in range(2500):
        combined_metadata, metadata_hash = _prepare_event_metadata()
        database.event_log.create_event(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            event_type="bulk_test",
            artifact_type="test",
            artifact_id=str(uuid4()),
            actor_user_id=test_admin_user["id"],
            combined_metadata=combined_metadata,
            metadata_hash=metadata_hash,
        )

    # Create background task record (needed for foreign key)
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    task = {
        "id": bg_task["id"],
        "tenant_id": test_tenant["id"],
        "created_by": test_admin_user["id"],
        "job_type": "export_events",
    }

    with patch("jobs.export_events.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.save.return_value = f"exports/{test_tenant['id']}/test-file.json.gz"
        mock_get_backend.return_value = mock_backend

        result = handle_export_events(task)

        # Should have all events
        assert result["records_processed"] == 2500


def test_handle_export_events_json_structure(test_tenant, test_admin_user):
    """Test that exported JSON has correct structure."""
    import database
    from jobs.export_events import handle_export_events

    # Create test event
    combined_metadata, metadata_hash = _prepare_event_metadata({"key": "value"})
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        event_type="test_structure",
        artifact_type="test",
        artifact_id=str(uuid4()),
        actor_user_id=test_admin_user["id"],
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
    )

    # Create background task record (needed for foreign key)
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    task = {
        "id": bg_task["id"],
        "tenant_id": test_tenant["id"],
        "created_by": test_admin_user["id"],
        "job_type": "export_events",
    }

    captured_data = None

    def capture_save(storage_key, file_obj, content_type):
        nonlocal captured_data
        # Decompress and parse JSON
        file_obj.seek(0)
        with gzip.GzipFile(fileobj=file_obj, mode="rb") as gz:
            captured_data = json.loads(gz.read().decode("utf-8"))
        return storage_key

    with patch("jobs.export_events.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.save.side_effect = capture_save
        mock_get_backend.return_value = mock_backend

        handle_export_events(task)

        # Verify JSON structure
        assert captured_data is not None
        assert "events" in captured_data
        assert "exported_at" in captured_data
        assert "count" in captured_data
        assert "tenant_id" in captured_data
        assert captured_data["count"] == 1
        assert captured_data["tenant_id"] == str(test_tenant["id"])
        assert len(captured_data["events"]) == 1


def test_handle_export_events_compression(test_tenant, test_admin_user):
    """Test that exported file is properly gzip compressed."""
    import database
    from jobs.export_events import handle_export_events

    # Create several events
    for i in range(10):
        combined_metadata, metadata_hash = _prepare_event_metadata()
        database.event_log.create_event(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            event_type="compression_test",
            artifact_type="test",
            artifact_id=str(uuid4()),
            actor_user_id=test_admin_user["id"],
            combined_metadata=combined_metadata,
            metadata_hash=metadata_hash,
        )

    # Create background task record (needed for foreign key)
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    task = {
        "id": bg_task["id"],
        "tenant_id": test_tenant["id"],
        "created_by": test_admin_user["id"],
        "job_type": "export_events",
    }

    captured_file = None

    def capture_save(storage_key, file_obj, content_type):
        nonlocal captured_file
        captured_file = BytesIO(file_obj.read())
        return storage_key

    with patch("jobs.export_events.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.save.side_effect = capture_save
        mock_get_backend.return_value = mock_backend

        handle_export_events(task)

        # Verify file can be decompressed
        captured_file.seek(0)
        with gzip.GzipFile(fileobj=captured_file, mode="rb") as gz:
            decompressed = gz.read().decode("utf-8")
            data = json.loads(decompressed)
            assert data["count"] == 10


def test_handle_export_events_storage_type_local(test_tenant, test_admin_user):
    """Test export uses local storage type when not using Spaces."""
    import database
    from jobs.export_events import handle_export_events

    # Create background task record (needed for foreign key)
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    task = {
        "id": bg_task["id"],
        "tenant_id": test_tenant["id"],
        "created_by": test_admin_user["id"],
        "job_type": "export_events",
    }

    with patch("jobs.export_events.storage.get_backend") as mock_get_backend:
        with patch("jobs.export_events.settings.STORAGE_BACKEND", "local"):
            mock_backend = MagicMock()
            mock_backend.save.return_value = f"exports/{test_tenant['id']}/test-file.json.gz"
            mock_get_backend.return_value = mock_backend

            result = handle_export_events(task)

            # Verify storage type in database
            export_file = database.export_files.get_export_file(
                test_tenant["id"], result["file_id"]
            )
            assert export_file["storage_type"] == "local"


def test_handle_export_events_expiry_calculation(test_tenant, test_admin_user):
    """Test that export file expiry is calculated correctly."""
    import database
    from jobs.export_events import handle_export_events

    # Create background task record (needed for foreign key)
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    task = {
        "id": bg_task["id"],
        "tenant_id": test_tenant["id"],
        "created_by": test_admin_user["id"],
        "job_type": "export_events",
    }

    with patch("jobs.export_events.storage.get_backend") as mock_get_backend:
        with patch("jobs.export_events.settings.EXPORT_FILE_EXPIRY_HOURS", 48):
            mock_backend = MagicMock()
            mock_backend.save.return_value = f"exports/{test_tenant['id']}/test-file.json.gz"
            mock_get_backend.return_value = mock_backend

            before_export = datetime.now(UTC)
            result = handle_export_events(task)
            after_export = datetime.now(UTC)

            # Verify expiry is ~48 hours from now
            export_file = database.export_files.get_export_file(
                test_tenant["id"], result["file_id"]
            )
            expires_at = export_file["expires_at"]

            # Should be between before_export + 48h and after_export + 48h
            expected_min = before_export + timedelta(hours=48)
            expected_max = after_export + timedelta(hours=48)
            assert expected_min <= expires_at <= expected_max


def test_handle_export_events_filename_format(test_tenant, test_admin_user):
    """Test that filename follows expected format."""
    import database
    from jobs.export_events import handle_export_events

    # Create background task record (needed for foreign key)
    bg_task = database.bg_tasks.create_task(
        tenant_id=test_tenant["id"],
        job_type="export_events",
        created_by=test_admin_user["id"],
    )

    task = {
        "id": bg_task["id"],
        "tenant_id": test_tenant["id"],
        "created_by": test_admin_user["id"],
        "job_type": "export_events",
    }

    with patch("jobs.export_events.storage.get_backend") as mock_get_backend:
        mock_backend = MagicMock()
        mock_backend.save.return_value = f"exports/{test_tenant['id']}/test-file.json.gz"
        mock_get_backend.return_value = mock_backend

        result = handle_export_events(task)

        # Verify filename format: event-export-YYYYMMDD-HHMMSS-xxxxxxxx.json.gz
        filename = result["filename"]
        assert filename.startswith("event-export-")
        assert filename.endswith(".json.gz")
        parts = filename.replace("event-export-", "").replace(".json.gz", "").split("-")
        assert len(parts) == 3  # date, time, hash


# =============================================================================
# Export Notification Tests
# =============================================================================


def test_send_export_notification_success(test_tenant, test_admin_user):
    """Test successful export notification email."""
    import database
    from jobs.export_events import _send_export_notification

    # Ensure user has primary email
    primary_email = database.user_emails.get_primary_email(test_tenant["id"], test_admin_user["id"])
    assert primary_email is not None

    expires_at = datetime.now(UTC) + timedelta(hours=48)

    with patch("jobs.export_events.send_email") as mock_send_email:
        _send_export_notification(
            test_tenant["id"],
            test_admin_user["id"],
            "test-export.json.gz",
            100,
            expires_at,
        )

        # Verify email was sent
        assert mock_send_email.called
        call_args = mock_send_email.call_args
        to_email = call_args[0][0]
        subject = call_args[0][1]
        _html_body = call_args[0][2]  # noqa: F841
        text_body = call_args[0][3]

        assert to_email == primary_email["email"]
        assert "Event Log Export" in subject
        assert "test-export.json.gz" in text_body
        assert "100" in text_body


def test_send_export_notification_user_not_found(test_tenant):
    """Test notification handles missing user gracefully."""
    from jobs.export_events import _send_export_notification

    expires_at = datetime.now(UTC) + timedelta(hours=48)

    with patch("jobs.export_events.send_email") as mock_send_email:
        # Should not raise, should log warning
        _send_export_notification(
            test_tenant["id"],
            str(uuid4()),  # Non-existent user
            "test-export.json.gz",
            100,
            expires_at,
        )

        # Email should not be sent
        assert not mock_send_email.called


def test_send_export_notification_no_primary_email(test_tenant, test_user):
    """Test notification handles user without primary email."""
    import database
    from jobs.export_events import _send_export_notification

    # Delete all emails for test user
    emails = database.user_emails.list_user_emails(test_tenant["id"], test_user["id"])
    for email in emails:
        database.user_emails.delete_email(test_tenant["id"], email["id"])

    expires_at = datetime.now(UTC) + timedelta(hours=48)

    with patch("jobs.export_events.send_email") as mock_send_email:
        _send_export_notification(
            test_tenant["id"],
            test_user["id"],
            "test-export.json.gz",
            100,
            expires_at,
        )

        # Email should not be sent
        assert not mock_send_email.called


def test_send_export_notification_email_failure(test_tenant, test_admin_user):
    """Test notification handles email send failure."""
    from jobs.export_events import _send_export_notification

    expires_at = datetime.now(UTC) + timedelta(hours=48)

    with patch("jobs.export_events.send_email") as mock_send_email:
        mock_send_email.side_effect = Exception("SMTP error")

        # Should not raise, should log error
        _send_export_notification(
            test_tenant["id"],
            test_admin_user["id"],
            "test-export.json.gz",
            100,
            expires_at,
        )

        # Email send was attempted
        assert mock_send_email.called
