"""Tests for bulk update API endpoints."""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

from main import app
from services.exceptions import ForbiddenError, ValidationError
from starlette.testclient import TestClient


class TestRequestDownload:
    """Tests for POST /api/v1/users/bulk-update/request-download."""

    def test_admin_creates_download_task(self, make_user_dict, override_api_auth):
        admin = make_user_dict(role="admin")
        override_api_auth(admin)

        task_id = str(uuid4())

        with patch("routers.api.v1.bulk_update.bulk_update_service") as mock_svc:
            mock_svc.create_download_task.return_value = {
                "id": task_id,
                "created_at": datetime.now(UTC),
            }

            client = TestClient(app)
            response = client.post(
                "/api/v1/users/bulk-update/request-download",
                headers={"Host": "test.localhost"},
            )

        assert response.status_code == 201
        data = response.json()
        assert data["id"] == task_id
        assert data["job_type"] == "export_users_template"
        assert data["status"] == "pending"

    def test_member_forbidden(self, make_user_dict, override_api_auth):
        member = make_user_dict(role="member")
        override_api_auth(member)

        with patch("routers.api.v1.bulk_update.bulk_update_service") as mock_svc:
            mock_svc.create_download_task.side_effect = ForbiddenError(
                message="Forbidden", code="forbidden"
            )

            client = TestClient(app)
            response = client.post(
                "/api/v1/users/bulk-update/request-download",
                headers={"Host": "test.localhost"},
            )

        assert response.status_code == 403

    def test_unauthenticated_returns_401(self, client, test_tenant_host):
        response = client.post(
            "/api/v1/users/bulk-update/request-download",
            headers={"Host": test_tenant_host},
        )
        assert response.status_code == 401


class TestDownloadTemplate:
    """Tests for GET /api/v1/users/bulk-update/download/{job_id}."""

    def test_pending_job_returns_202(self, make_user_dict, override_api_auth):
        admin = make_user_dict(role="admin")
        override_api_auth(admin)

        job_id = str(uuid4())

        with patch("routers.api.v1.bulk_update.bulk_update_service") as mock_svc:
            mock_svc.get_download.side_effect = ValidationError(
                message="Job is still processing",
                code="job_pending",
                details={"status": "pending"},
            )

            client = TestClient(app, follow_redirects=False)
            response = client.get(
                f"/api/v1/users/bulk-update/download/{job_id}",
                headers={"Host": "test.localhost"},
            )

        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "pending"

    def test_completed_local_job_returns_file(self, make_user_dict, override_api_auth, tmp_path):
        admin = make_user_dict(role="admin")
        override_api_auth(admin)

        test_file = tmp_path / "users.xlsx"
        test_file.write_bytes(b"fake xlsx content")

        job_id = str(uuid4())

        with patch("routers.api.v1.bulk_update.bulk_update_service") as mock_svc:
            mock_svc.get_download.return_value = {
                "storage_type": "local",
                "path": str(test_file),
                "filename": "users.xlsx",
                "content_type": (
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                ),
            }

            client = TestClient(app)
            response = client.get(
                f"/api/v1/users/bulk-update/download/{job_id}",
                headers={"Host": "test.localhost"},
            )

        assert response.status_code == 200
        assert "users.xlsx" in response.headers.get("content-disposition", "")


class TestUploadSpreadsheet:
    """Tests for POST /api/v1/users/bulk-update/upload."""

    def test_valid_upload_creates_task(self, make_user_dict, override_api_auth):
        admin = make_user_dict(role="admin")
        override_api_auth(admin)

        task_id = str(uuid4())

        with patch("routers.api.v1.bulk_update.bulk_update_service") as mock_svc:
            mock_svc.create_upload_task.return_value = {
                "id": task_id,
                "created_at": datetime.now(UTC),
            }

            client = TestClient(app)
            response = client.post(
                "/api/v1/users/bulk-update/upload",
                headers={"Host": "test.localhost"},
                files={"file": ("users.xlsx", b"fake", "application/octet-stream")},
            )

        assert response.status_code == 201
        data = response.json()
        assert data["id"] == task_id
        assert data["job_type"] == "bulk_update_users"
        assert data["status"] == "pending"

    def test_invalid_file_returns_400(self, make_user_dict, override_api_auth):
        admin = make_user_dict(role="admin")
        override_api_auth(admin)

        with patch("routers.api.v1.bulk_update.bulk_update_service") as mock_svc:
            mock_svc.create_upload_task.side_effect = ValidationError(
                message="Invalid XLSX file",
                code="invalid_file",
            )

            client = TestClient(app)
            response = client.post(
                "/api/v1/users/bulk-update/upload",
                headers={"Host": "test.localhost"},
                files={"file": ("bad.xlsx", b"not valid", "application/octet-stream")},
            )

        assert response.status_code == 400

    def test_unauthenticated_returns_401(self, client, test_tenant_host):
        response = client.post(
            "/api/v1/users/bulk-update/upload",
            headers={"Host": test_tenant_host},
            files={"file": ("users.xlsx", b"fake", "application/octet-stream")},
        )
        assert response.status_code == 401
