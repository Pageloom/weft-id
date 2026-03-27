"""Tests for bulk user update job handler."""

from io import BytesIO
from unittest.mock import MagicMock, patch
from uuid import uuid4

from jobs.bulk_update_users import EXPECTED_COLUMNS, handle_bulk_update_users
from openpyxl import Workbook


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


def _make_task(tenant_id, created_by, storage_key="uploads/test.xlsx"):
    return {
        "id": uuid4(),
        "tenant_id": tenant_id,
        "created_by": created_by,
        "job_type": "bulk_update_users",
        "payload": {
            "storage_key": storage_key,
            "storage_type": "local",
        },
    }


class TestHandleBulkUpdateUsers:
    """Tests for the bulk_update_users job handler."""

    def _setup_storage(self, mock_get_backend, file_data, tmp_path):
        """Write file_data to a temp file and wire up mock storage."""
        test_file = tmp_path / "upload.xlsx"
        test_file.write_bytes(file_data)
        mock_backend = MagicMock()
        mock_backend.get_file_path.return_value = str(test_file)
        mock_get_backend.return_value = mock_backend
        return mock_backend

    def test_adds_email_and_updates_name(self, tmp_path):
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        actor_id = str(uuid4())

        xlsx = _make_xlsx(
            [
                EXPECTED_COLUMNS,
                [
                    user_id,
                    "old@test.com",
                    "test.com",
                    "Alice",
                    "Smith",
                    "new@test.com",
                    "Alicia",
                    "",
                ],
            ]
        )

        task = _make_task(tenant_id, actor_id)

        with (
            patch("jobs.bulk_update_users.storage.get_backend") as mock_gb,
            patch("jobs.bulk_update_users.database") as mock_db,
            patch("jobs.bulk_update_users.log_event"),
        ):
            self._setup_storage(mock_gb, xlsx, tmp_path)
            mock_db.users.get_user_by_id.return_value = {
                "id": user_id,
                "first_name": "Alice",
                "last_name": "Smith",
            }
            mock_db.user_emails.email_exists.return_value = False
            mock_db.user_emails.add_verified_email.return_value = {"id": str(uuid4())}

            result = handle_bulk_update_users(task)

        assert result["emails_added"] == 1
        assert result["names_updated"] == 1
        assert result["rows_skipped"] == 0
        assert result["row_errors"] == []
        assert result["total_rows"] == 1

    def test_blank_rows_skipped(self, tmp_path):
        user_id = str(uuid4())
        xlsx = _make_xlsx(
            [
                EXPECTED_COLUMNS,
                [user_id, "u@test.com", "test.com", "Bob", "Jones", "", "", ""],
            ]
        )

        task = _make_task(str(uuid4()), str(uuid4()))

        with (
            patch("jobs.bulk_update_users.storage.get_backend") as mock_gb,
            patch("jobs.bulk_update_users.database"),
            patch("jobs.bulk_update_users.log_event"),
        ):
            self._setup_storage(mock_gb, xlsx, tmp_path)

            result = handle_bulk_update_users(task)

        assert result["rows_skipped"] == 1
        assert result["emails_added"] == 0

    def test_email_already_exists_error(self, tmp_path):
        user_id = str(uuid4())
        tenant_id = str(uuid4())
        xlsx = _make_xlsx(
            [
                EXPECTED_COLUMNS,
                [user_id, "old@test.com", "test.com", "A", "B", "taken@test.com", "", ""],
            ]
        )

        task = _make_task(tenant_id, str(uuid4()))

        with (
            patch("jobs.bulk_update_users.storage.get_backend") as mock_gb,
            patch("jobs.bulk_update_users.database") as mock_db,
            patch("jobs.bulk_update_users.log_event"),
        ):
            self._setup_storage(mock_gb, xlsx, tmp_path)
            mock_db.users.get_user_by_id.return_value = {
                "id": user_id,
                "first_name": "A",
                "last_name": "B",
            }
            mock_db.user_emails.email_exists.return_value = True

            result = handle_bulk_update_users(task)

        assert result["emails_added"] == 0
        assert len(result["row_errors"]) == 1
        assert "already in use" in result["row_errors"][0]["error"]

    def test_user_not_found_error(self, tmp_path):
        bad_id = str(uuid4())
        xlsx = _make_xlsx(
            [
                EXPECTED_COLUMNS,
                [bad_id, "old@test.com", "test.com", "A", "B", "new@test.com", "", ""],
            ]
        )

        task = _make_task(str(uuid4()), str(uuid4()))

        with (
            patch("jobs.bulk_update_users.storage.get_backend") as mock_gb,
            patch("jobs.bulk_update_users.database") as mock_db,
            patch("jobs.bulk_update_users.log_event"),
        ):
            self._setup_storage(mock_gb, xlsx, tmp_path)
            mock_db.users.get_user_by_id.return_value = None

            result = handle_bulk_update_users(task)

        assert len(result["row_errors"]) == 1
        assert "User not found" in result["row_errors"][0]["error"]

    def test_missing_user_id_error(self, tmp_path):
        xlsx = _make_xlsx(
            [
                EXPECTED_COLUMNS,
                ["", "old@test.com", "test.com", "A", "B", "new@test.com", "", ""],
            ]
        )

        task = _make_task(str(uuid4()), str(uuid4()))

        with (
            patch("jobs.bulk_update_users.storage.get_backend") as mock_gb,
            patch("jobs.bulk_update_users.database"),
            patch("jobs.bulk_update_users.log_event"),
        ):
            self._setup_storage(mock_gb, xlsx, tmp_path)

            result = handle_bulk_update_users(task)

        assert len(result["row_errors"]) == 1
        assert "Missing user_id" in result["row_errors"][0]["error"]

    def test_mixed_success_and_failure(self, tmp_path):
        good_id = str(uuid4())
        bad_id = str(uuid4())
        tenant_id = str(uuid4())

        xlsx = _make_xlsx(
            [
                EXPECTED_COLUMNS,
                [good_id, "good@t.com", "t.com", "Good", "User", "new@t.com", "", ""],
                [bad_id, "bad@t.com", "t.com", "Bad", "User", "fail@t.com", "", ""],
                [str(uuid4()), "skip@t.com", "t.com", "Skip", "User", "", "", ""],
            ]
        )

        task = _make_task(tenant_id, str(uuid4()))

        with (
            patch("jobs.bulk_update_users.storage.get_backend") as mock_gb,
            patch("jobs.bulk_update_users.database") as mock_db,
            patch("jobs.bulk_update_users.log_event"),
        ):
            self._setup_storage(mock_gb, xlsx, tmp_path)

            def get_user(tid, uid):
                if uid == good_id:
                    return {"id": uid, "first_name": "Good", "last_name": "User"}
                return None

            mock_db.users.get_user_by_id.side_effect = get_user
            mock_db.user_emails.email_exists.return_value = False
            mock_db.user_emails.add_verified_email.return_value = {"id": str(uuid4())}

            result = handle_bulk_update_users(task)

        assert result["emails_added"] == 1
        assert result["rows_skipped"] == 1
        assert len(result["row_errors"]) == 1
        assert result["total_rows"] == 3

    def test_name_only_update(self, tmp_path):
        user_id = str(uuid4())
        tenant_id = str(uuid4())

        xlsx = _make_xlsx(
            [
                EXPECTED_COLUMNS,
                [user_id, "u@t.com", "t.com", "Old", "Name", "", "New", "Name"],
            ]
        )

        task = _make_task(tenant_id, str(uuid4()))

        with (
            patch("jobs.bulk_update_users.storage.get_backend") as mock_gb,
            patch("jobs.bulk_update_users.database") as mock_db,
            patch("jobs.bulk_update_users.log_event"),
        ):
            self._setup_storage(mock_gb, xlsx, tmp_path)
            mock_db.users.get_user_by_id.return_value = {
                "id": user_id,
                "first_name": "Old",
                "last_name": "Name",
            }

            result = handle_bulk_update_users(task)

        assert result["names_updated"] == 1
        assert result["emails_added"] == 0
        mock_db.users.update_user_profile.assert_called_once_with(
            tenant_id=tenant_id,
            user_id=user_id,
            first_name="New",
            last_name="Name",
        )

    def test_cleans_up_uploaded_file(self, tmp_path):
        xlsx = _make_xlsx(
            [
                EXPECTED_COLUMNS,
                [str(uuid4()), "u@t.com", "t.com", "A", "B", "", "", ""],
            ]
        )

        task = _make_task(str(uuid4()), str(uuid4()), storage_key="uploads/cleanup.xlsx")

        with (
            patch("jobs.bulk_update_users.storage.get_backend") as mock_gb,
            patch("jobs.bulk_update_users.database"),
            patch("jobs.bulk_update_users.log_event"),
        ):
            mock_backend = self._setup_storage(mock_gb, xlsx, tmp_path)

            handle_bulk_update_users(task)

        mock_backend.delete.assert_called_once_with("uploads/cleanup.xlsx")

    def test_output_message_summarizes_results(self, tmp_path):
        user_id = str(uuid4())
        xlsx = _make_xlsx(
            [
                EXPECTED_COLUMNS,
                [user_id, "u@t.com", "t.com", "A", "B", "new@t.com", "C", ""],
            ]
        )

        task = _make_task(str(uuid4()), str(uuid4()))

        with (
            patch("jobs.bulk_update_users.storage.get_backend") as mock_gb,
            patch("jobs.bulk_update_users.database") as mock_db,
            patch("jobs.bulk_update_users.log_event"),
        ):
            self._setup_storage(mock_gb, xlsx, tmp_path)
            mock_db.users.get_user_by_id.return_value = {
                "id": user_id,
                "first_name": "A",
                "last_name": "B",
            }
            mock_db.user_emails.email_exists.return_value = False
            mock_db.user_emails.add_verified_email.return_value = {"id": str(uuid4())}

            result = handle_bulk_update_users(task)

        assert "1 emails added" in result["output"]
        assert "1 names updated" in result["output"]
