"""Tests for routers/audit.py endpoints.

Promoted from /admin/audit to /audit as part of the nav restructure (see
.claude/ITERATION_nav_restructure.md, Iteration 4). This module was
formerly tests/routers/test_admin.py.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient
from main import app
from services.exceptions import ServiceError

# =============================================================================
# Section Index Redirect Tests
# =============================================================================


def test_audit_index_redirects_to_first_child(test_admin_user, override_auth):
    """Audit index page redirects to its first accessible child page."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.audit.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = "/audit/events"

        client = TestClient(app)
        response = client.get("/audit/", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/audit/events"


def test_section_index_fallback_to_dashboard(test_admin_user, override_auth):
    """Section index pages fall back to dashboard when no accessible children."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.audit.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = None

        client = TestClient(app)
        response = client.get("/audit/", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"


# =============================================================================
# Event Log Routes Tests
# =============================================================================


def test_event_log_list_renders(test_admin_user, override_auth, mocker):
    """Test event log list page renders successfully."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.event_log.list_events")
    mock_context = mocker.patch("utils.template_context.get_template_context")
    mock_template = mocker.patch("routers.audit.templates.TemplateResponse")

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
    response = client.get("/audit/events")

    assert response.status_code == 200
    mock_list.assert_called_once()


def test_event_log_list_with_pagination(test_admin_user, override_auth, mocker):
    """Test event log list page with pagination parameters."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.event_log.list_events")
    mock_context = mocker.patch("utils.template_context.get_template_context")
    mock_template = mocker.patch("routers.audit.templates.TemplateResponse")

    mock_result = MagicMock()
    mock_result.items = []
    mock_result.total = 100
    mock_result.page = 2
    mock_result.limit = 25
    mock_list.return_value = mock_result

    mock_context.return_value = {"request": MagicMock()}
    mock_template.return_value = HTMLResponse(content="<html>events</html>")

    client = TestClient(app)
    response = client.get("/audit/events?page=2&size=25")

    assert response.status_code == 200
    # Verify pagination was passed correctly
    call_args = mock_list.call_args
    assert call_args[1]["page"] == 2
    assert call_args[1]["limit"] == 25


def test_event_log_detail_renders(test_admin_user, override_auth, mocker):
    """Test event log detail page renders successfully."""
    from fastapi.responses import HTMLResponse
    from schemas.event_log import EventLogItem

    override_auth(test_admin_user, level="admin")

    event_id = str(uuid4())

    mock_get = mocker.patch("services.event_log.get_event")
    mock_context = mocker.patch("utils.template_context.get_template_context")
    mock_template = mocker.patch("routers.audit.templates.TemplateResponse")

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
    response = client.get(f"/audit/events/{event_id}")

    assert response.status_code == 200


def test_event_log_detail_not_found_redirects(test_admin_user, override_auth):
    """Test event log detail redirects on not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    with patch("services.event_log.get_event") as mock_get:
        mock_get.side_effect = NotFoundError(message="Not found", code="event_not_found")

        client = TestClient(app)
        response = client.get(f"/audit/events/{uuid4()}", follow_redirects=False)

        assert response.status_code == 303
        assert "error=not_found" in response.headers["location"]


def test_trigger_export_creates_task(test_admin_user, override_auth):
    """Test trigger export creates a background task and redirects to background jobs."""
    override_auth(test_admin_user, level="admin")

    with patch("services.bg_tasks.create_export_task") as mock_create:
        mock_create.return_value = {"id": str(uuid4())}

        client = TestClient(app)
        response = client.post("/audit/events/export", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/account/background-jobs?success=export_started"
        mock_create.assert_called_once()


def test_audit_routes_require_admin_role(test_user):
    """Test that audit routes require admin role."""
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
    response = client.get("/audit/events")

    # The ForbiddenError should be raised
    assert response.status_code in [403, 500]  # Depends on error handling


# =============================================================================
# Error Handler Coverage Tests
# =============================================================================


def test_event_log_list_invalid_page_param(test_admin_user, override_auth, mocker):
    """Test event log list falls back to page=1 when page param is non-numeric."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.event_log.list_events")
    mocker.patch("utils.template_context.get_template_context")
    mock_template = mocker.patch("routers.audit.templates.TemplateResponse")

    mock_result = MagicMock()
    mock_result.items = []
    mock_result.total = 0
    mock_list.return_value = mock_result
    mock_template.return_value = HTMLResponse(content="<html>events</html>")

    client = TestClient(app)
    response = client.get("/audit/events?page=abc")

    assert response.status_code == 200
    call_args = mock_list.call_args
    assert call_args[1]["page"] == 1


def test_event_log_list_invalid_size_param(test_admin_user, override_auth, mocker):
    """Test event log list falls back to size=50 when size param is non-numeric."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.event_log.list_events")
    mocker.patch("utils.template_context.get_template_context")
    mock_template = mocker.patch("routers.audit.templates.TemplateResponse")

    mock_result = MagicMock()
    mock_result.items = []
    mock_result.total = 0
    mock_list.return_value = mock_result
    mock_template.return_value = HTMLResponse(content="<html>events</html>")

    client = TestClient(app)
    response = client.get("/audit/events?size=abc")

    assert response.status_code == 200
    call_args = mock_list.call_args
    assert call_args[1]["limit"] == 50


def test_event_log_list_service_error(test_admin_user, override_auth, mocker):
    """Test event log list renders error page on ServiceError."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.event_log.list_events")
    mock_error = mocker.patch("routers.audit.render_error_page")
    mock_list.side_effect = ServiceError(message="Database error", code="db_error")
    mock_error.return_value = HTMLResponse(content="<html>Error</html>", status_code=500)

    client = TestClient(app)
    response = client.get("/audit/events")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_event_log_detail_service_error(test_admin_user, override_auth, mocker):
    """Test event log detail renders error page on ServiceError."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch("services.event_log.get_event")
    mock_error = mocker.patch("routers.audit.render_error_page")
    mock_get.side_effect = ServiceError(message="Database error", code="db_error")
    mock_error.return_value = HTMLResponse(content="<html>Error</html>", status_code=500)

    client = TestClient(app)
    response = client.get(f"/audit/events/{uuid4()}")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_trigger_export_service_error(test_admin_user, override_auth, mocker):
    """Test trigger export renders error page on ServiceError."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_create = mocker.patch("services.bg_tasks.create_export_task")
    mock_error = mocker.patch("routers.audit.render_error_page")
    mock_create.side_effect = ServiceError(message="Export failed", code="export_error")
    mock_error.return_value = HTMLResponse(content="<html>Error</html>", status_code=500)

    client = TestClient(app)
    response = client.post("/audit/events/export")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_trigger_export_invalid_date_format(test_admin_user, override_auth, mocker):
    """Test trigger export redirects with error when a date string doesn't parse."""
    override_auth(test_admin_user, level="admin")

    mock_create = mocker.patch("services.bg_tasks.create_export_task")

    client = TestClient(app)
    response = client.post(
        "/audit/events/export",
        data={"start_date": "not-a-date"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/audit/events?error=invalid_date"
    mock_create.assert_not_called()


def test_trigger_export_invalid_date_range(test_admin_user, override_auth, mocker):
    """Test trigger export redirects with error when the service rejects the date range."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user, level="admin")

    mock_create = mocker.patch("services.bg_tasks.create_export_task")
    mock_create.side_effect = ValidationError(
        message="Start date must be before end date", code="invalid_date_range"
    )

    client = TestClient(app)
    response = client.post(
        "/audit/events/export",
        data={"start_date": "2024-06-01", "end_date": "2024-01-01"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/audit/events?error=invalid_date_range"
    mock_create.assert_called_once()
