"""Tests for routers/admin.py endpoints."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from main import app


def test_admin_index_redirects_to_events(test_admin_user):
    """Test admin index redirects to first accessible child page."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch("routers.admin.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = "/admin/events"

        client = TestClient(app)
        response = client.get("/admin/", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/admin/events"


def test_admin_index_fallback_to_dashboard(test_admin_user):
    """Test admin index falls back to dashboard when no accessible children."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch("routers.admin.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = None

        client = TestClient(app)
        response = client.get("/admin/", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"


def test_event_log_list_renders(test_admin_user):
    """Test event log list page renders successfully."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch("services.event_log.list_events") as mock_list:
        with patch("utils.template_context.get_template_context") as mock_context:
            with patch("routers.admin.templates.TemplateResponse") as mock_template:
                # Create a mock response object
                mock_result = MagicMock()
                mock_result.items = []
                mock_result.total = 0
                mock_result.page = 1
                mock_result.limit = 50
                mock_list.return_value = mock_result

                mock_context.return_value = {"request": MagicMock()}
                mock_template.return_value = HTMLResponse(content="<html>events</html>")

                client = TestClient(app)
                response = client.get("/admin/events")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_list.assert_called_once()


def test_event_log_list_with_pagination(test_admin_user):
    """Test event log list page with pagination parameters."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch("services.event_log.list_events") as mock_list:
        with patch("utils.template_context.get_template_context") as mock_context:
            with patch("routers.admin.templates.TemplateResponse") as mock_template:
                mock_result = MagicMock()
                mock_result.items = []
                mock_result.total = 100
                mock_result.page = 2
                mock_result.limit = 25
                mock_list.return_value = mock_result

                mock_context.return_value = {"request": MagicMock()}
                mock_template.return_value = HTMLResponse(content="<html>events</html>")

                client = TestClient(app)
                response = client.get("/admin/events?page=2&size=25")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Verify pagination was passed correctly
                call_args = mock_list.call_args
                assert call_args[1]["page"] == 2
                assert call_args[1]["limit"] == 25


def test_event_log_detail_renders(test_admin_user):
    """Test event log detail page renders successfully."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin
    from fastapi.responses import HTMLResponse
    from schemas.event_log import EventLogItem

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    event_id = str(uuid4())

    with patch("services.event_log.get_event") as mock_get:
        with patch("utils.template_context.get_template_context") as mock_context:
            with patch("routers.admin.templates.TemplateResponse") as mock_template:
                mock_get.return_value = EventLogItem(
                    id=event_id,
                    actor_user_id=str(uuid4()),
                    actor_name="Test User",
                    artifact_type="user",
                    artifact_id=str(uuid4()),
                    event_type="user_created",
                    metadata={"key": "value"},
                    created_at=datetime.now(UTC),
                )

                mock_context.return_value = {"request": MagicMock()}
                mock_template.return_value = HTMLResponse(content="<html>event</html>")

                client = TestClient(app)
                response = client.get(f"/admin/events/{event_id}")

                app.dependency_overrides.clear()

                assert response.status_code == 200


def test_event_log_detail_not_found_redirects(test_admin_user):
    """Test event log detail redirects on not found."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin
    from services.exceptions import NotFoundError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch("services.event_log.get_event") as mock_get:
        mock_get.side_effect = NotFoundError(message="Not found", code="event_not_found")

        client = TestClient(app)
        response = client.get(f"/admin/events/{uuid4()}", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=not_found" in response.headers["location"]


def test_trigger_export_creates_task(test_admin_user):
    """Test trigger export creates a background task and redirects to background jobs."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch("services.bg_tasks.create_export_task") as mock_create:
        mock_create.return_value = {"id": str(uuid4())}

        client = TestClient(app)
        response = client.post("/admin/events/export", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/account/background-jobs?success=export_started"
        mock_create.assert_called_once()


@pytest.mark.skip(reason="Exports routes moved to /account/background-jobs")
def test_exports_list_renders(test_admin_user):
    """Test exports list page renders successfully."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch("services.exports.list_exports") as mock_list:
        with patch("utils.template_context.get_template_context") as mock_context:
            with patch("routers.admin.templates.TemplateResponse") as mock_template:
                mock_result = MagicMock()
                mock_result.items = []
                mock_result.total = 0
                mock_list.return_value = mock_result

                mock_context.return_value = {"request": MagicMock()}
                mock_template.return_value = HTMLResponse(content="<html>exports</html>")

                client = TestClient(app)
                response = client.get("/admin/exports")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_list.assert_called_once()


@pytest.mark.skip(reason="Exports routes moved to /account/background-jobs")
def test_download_export_local_file(test_admin_user, tmp_path):
    """Test downloading a local export file."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    # Create a temporary file
    test_file = tmp_path / "test-export.json.gz"
    test_file.write_bytes(b"test content")

    with patch("services.exports.get_download") as mock_download:
        mock_download.return_value = {
            "storage_type": "local",
            "path": str(test_file),
            "filename": "test-export.json.gz",
            "content_type": "application/gzip",
        }

        client = TestClient(app)
        response = client.get(f"/admin/exports/download/{uuid4()}")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/gzip"


@pytest.mark.skip(reason="Exports routes moved to /account/background-jobs")
def test_download_export_spaces_redirect(test_admin_user):
    """Test downloading a Spaces export redirects to signed URL."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    signed_url = "https://spaces.example.com/exports/test.json.gz?signed=abc123"

    with patch("services.exports.get_download") as mock_download:
        mock_download.return_value = {
            "storage_type": "spaces",
            "url": signed_url,
            "filename": "test-export.json.gz",
        }

        client = TestClient(app)
        response = client.get(f"/admin/exports/download/{uuid4()}", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 302
        assert response.headers["location"] == signed_url


@pytest.mark.skip(reason="Exports routes moved to /account/background-jobs")
def test_download_export_not_found_redirects(test_admin_user):
    """Test download export redirects on not found."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin
    from services.exceptions import NotFoundError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    with patch("services.exports.get_download") as mock_download:
        mock_download.side_effect = NotFoundError(message="Not found", code="export_not_found")

        client = TestClient(app)
        response = client.get(f"/admin/exports/download/{uuid4()}", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=not_found" in response.headers["location"]


@pytest.mark.skip(reason="Exports routes moved to /account/background-jobs")
def test_download_export_file_missing_on_disk(test_admin_user, tmp_path):
    """Test download redirects when file is missing from disk."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    app.dependency_overrides[get_current_user] = lambda: test_admin_user

    # Point to a non-existent file
    missing_file = tmp_path / "missing-file.json.gz"

    with patch("services.exports.get_download") as mock_download:
        mock_download.return_value = {
            "storage_type": "local",
            "path": str(missing_file),
            "filename": "missing-file.json.gz",
            "content_type": "application/gzip",
        }

        client = TestClient(app)
        response = client.get(f"/admin/exports/download/{uuid4()}", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=file_missing" in response.headers["location"]


def test_admin_routes_require_admin_role(test_user):
    """Test that admin routes require admin role."""
    from dependencies import (
        get_current_user,
        get_tenant_id_from_request,
    )
    from services.exceptions import ForbiddenError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_user["tenant_id"])
    app.dependency_overrides[get_current_user] = lambda: test_user

    # Mock require_admin to raise ForbiddenError
    def mock_require_admin():

        raise ForbiddenError(message="Admin required", code="admin_required")

    from dependencies import require_admin

    app.dependency_overrides[require_admin] = mock_require_admin

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/admin/events")

    app.dependency_overrides.clear()

    # The ForbiddenError should be raised
    assert response.status_code in [403, 500]  # Depends on error handling
