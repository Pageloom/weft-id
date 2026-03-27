"""Tests for bulk user attribute update service."""

from io import BytesIO
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from openpyxl import Workbook
from services import bulk_update
from services.exceptions import ForbiddenError, NotFoundError, ValidationError


def _make_xlsx(rows):
    """Build an XLSX file in memory from a list of row tuples."""
    wb = Workbook()
    ws = wb.active
    for row in rows:
        ws.append(row)
    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.read()


class TestCreateDownloadTask:
    """Tests for create_download_task."""

    def test_admin_creates_task(self, make_requesting_user, make_bg_task_dict):
        admin_id = str(uuid4())
        tenant_id = str(uuid4())
        ru = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")
        task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)

        with (
            patch("services.bulk_update.database") as mock_db,
            patch("services.bulk_update.track_activity"),
            patch("services.bulk_update.log_event") as mock_log,
        ):
            mock_db.bg_tasks.create_task.return_value = task

            result = bulk_update.create_download_task(ru)

            assert result["id"] == task["id"]
            mock_db.bg_tasks.create_task.assert_called_once_with(
                tenant_id=tenant_id,
                job_type="export_users_template",
                created_by=admin_id,
                payload=None,
            )
            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args[1]
            assert call_kwargs["event_type"] == "bulk_update_task_created"

    def test_member_forbidden(self, make_requesting_user):
        ru = make_requesting_user(role="member")

        with pytest.raises(ForbiddenError):
            bulk_update.create_download_task(ru)


class TestGetDownload:
    """Tests for get_download."""

    def test_completed_job_returns_local_download(
        self, make_requesting_user, make_bg_task_dict, make_export_file_dict
    ):
        admin_id = str(uuid4())
        tenant_id = str(uuid4())
        file_id = str(uuid4())
        ru = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")

        task = make_bg_task_dict(
            tenant_id=tenant_id,
            created_by=admin_id,
            status="completed",
            result={"file_id": file_id},
        )
        export = make_export_file_dict(
            tenant_id=tenant_id,
            storage_type="local",
            storage_path="exports/test/users.xlsx",
            filename="users.xlsx",
        )

        with (
            patch("services.bulk_update.database") as mock_db,
            patch("services.bulk_update.track_activity"),
            patch("services.bulk_update.storage") as mock_storage,
        ):
            mock_db.bg_tasks.get_task_for_user.return_value = task
            mock_db.export_files.get_export_file.return_value = export
            mock_backend = MagicMock()
            mock_backend.get_file_path.return_value = "/tmp/exports/users.xlsx"
            mock_storage.get_backend.return_value = mock_backend

            result = bulk_update.get_download(ru, str(task["id"]))

            assert result["storage_type"] == "local"
            assert result["filename"] == "users.xlsx"
            mock_db.export_files.mark_downloaded.assert_called_once()

    def test_pending_job_raises_validation_error(self, make_requesting_user, make_bg_task_dict):
        admin_id = str(uuid4())
        tenant_id = str(uuid4())
        ru = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")
        task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id, status="pending")

        with (
            patch("services.bulk_update.database") as mock_db,
            patch("services.bulk_update.track_activity"),
        ):
            mock_db.bg_tasks.get_task_for_user.return_value = task

            with pytest.raises(ValidationError) as exc_info:
                bulk_update.get_download(ru, str(task["id"]))
            assert exc_info.value.code == "job_pending"

    def test_not_found_job_raises(self, make_requesting_user):
        ru = make_requesting_user(role="admin")

        with (
            patch("services.bulk_update.database") as mock_db,
            patch("services.bulk_update.track_activity"),
        ):
            mock_db.bg_tasks.get_task_for_user.return_value = None

            with pytest.raises(NotFoundError):
                bulk_update.get_download(ru, str(uuid4()))

    def test_failed_job_raises_validation_error(self, make_requesting_user, make_bg_task_dict):
        admin_id = str(uuid4())
        tenant_id = str(uuid4())
        ru = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")
        task = make_bg_task_dict(
            tenant_id=tenant_id,
            created_by=admin_id,
            status="failed",
            error="Something went wrong",
        )

        with (
            patch("services.bulk_update.database") as mock_db,
            patch("services.bulk_update.track_activity"),
        ):
            mock_db.bg_tasks.get_task_for_user.return_value = task

            with pytest.raises(ValidationError) as exc_info:
                bulk_update.get_download(ru, str(task["id"]))
            assert exc_info.value.code == "job_failed"

    def test_member_forbidden(self, make_requesting_user):
        ru = make_requesting_user(role="member")

        with pytest.raises(ForbiddenError):
            bulk_update.get_download(ru, str(uuid4()))


class TestCreateUploadTask:
    """Tests for create_upload_task."""

    def test_admin_creates_task_with_valid_file(self, make_requesting_user, make_bg_task_dict):
        admin_id = str(uuid4())
        tenant_id = str(uuid4())
        ru = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")
        task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)

        xlsx = _make_xlsx(
            [
                bulk_update.EXPECTED_COLUMNS,
                [str(uuid4()), "a@test.com", "test.com", "A", "B", "new@test.com", "", ""],
            ]
        )

        with (
            patch("services.bulk_update.database") as mock_db,
            patch("services.bulk_update.track_activity"),
            patch("services.bulk_update.log_event") as mock_log,
            patch("services.bulk_update.storage") as mock_storage,
        ):
            mock_backend = MagicMock()
            mock_storage.get_backend.return_value = mock_backend
            mock_db.bg_tasks.create_task.return_value = task

            result = bulk_update.create_upload_task(ru, xlsx)

            assert result["id"] == task["id"]
            mock_backend.save.assert_called_once()
            mock_db.bg_tasks.create_task.assert_called_once()
            call_kwargs = mock_db.bg_tasks.create_task.call_args[1]
            assert call_kwargs["job_type"] == "bulk_update_users"
            assert "storage_key" in call_kwargs["payload"]

            mock_log.assert_called_once()
            assert mock_log.call_args[1]["event_type"] == "bulk_update_task_created"

    def test_wrong_columns_rejected(self, make_requesting_user):
        ru = make_requesting_user(role="admin")
        xlsx = _make_xlsx([["wrong", "columns"], ["data", "row"]])

        with (
            patch("services.bulk_update.database"),
            patch("services.bulk_update.track_activity"),
        ):
            with pytest.raises(ValidationError) as exc_info:
                bulk_update.create_upload_task(ru, xlsx)
            assert exc_info.value.code == "invalid_columns"

    def test_invalid_file_rejected(self, make_requesting_user):
        ru = make_requesting_user(role="admin")

        with (
            patch("services.bulk_update.database"),
            patch("services.bulk_update.track_activity"),
        ):
            with pytest.raises(ValidationError) as exc_info:
                bulk_update.create_upload_task(ru, b"not a valid xlsx file")
            assert exc_info.value.code == "invalid_file"

    def test_empty_file_rejected(self, make_requesting_user):
        ru = make_requesting_user(role="admin")
        xlsx = _make_xlsx([])

        with (
            patch("services.bulk_update.database"),
            patch("services.bulk_update.track_activity"),
        ):
            with pytest.raises(ValidationError) as exc_info:
                bulk_update.create_upload_task(ru, xlsx)
            assert exc_info.value.code == "empty_file"

    def test_member_forbidden(self, make_requesting_user):
        ru = make_requesting_user(role="member")

        with pytest.raises(ForbiddenError):
            bulk_update.create_upload_task(ru, b"")
