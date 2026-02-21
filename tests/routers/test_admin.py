"""Tests for routers/admin.py endpoints."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from main import app

# =============================================================================
# Section Index Redirect Tests (Parametrized)
# =============================================================================


@pytest.mark.parametrize(
    "section_path,expected_child",
    [
        ("/admin/", "/admin/audit/events"),
        ("/admin/audit/", "/admin/audit/events"),
        ("/admin/todo/", "/admin/todo/reactivation"),
    ],
)
def test_section_index_redirects_to_first_child(
    test_admin_user, override_auth, section_path, expected_child
):
    """Section index pages redirect to their first accessible child page."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.admin.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = expected_child

        client = TestClient(app)
        response = client.get(section_path, follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == expected_child


@pytest.mark.parametrize(
    "section_path",
    [
        "/admin/",
        "/admin/audit/",
        "/admin/todo/",
    ],
)
def test_section_index_fallback_to_dashboard(test_admin_user, override_auth, section_path):
    """Section index pages fall back to dashboard when no accessible children."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.admin.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = None

        client = TestClient(app)
        response = client.get(section_path, follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"


@pytest.mark.parametrize(
    "section_path_no_slash,expected_child",
    [
        ("/admin/audit", "/admin/audit/events"),
        ("/admin/todo", "/admin/todo/reactivation"),
    ],
)
def test_section_index_works_without_trailing_slash(
    test_admin_user, override_auth, section_path_no_slash, expected_child
):
    """Section index pages work correctly without trailing slash."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.admin.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = expected_child

        client = TestClient(app)
        response = client.get(section_path_no_slash, follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == expected_child


# =============================================================================
# Event Log Routes Tests
# =============================================================================


def test_event_log_list_renders(test_admin_user, override_auth, mocker):
    """Test event log list page renders successfully."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.event_log.list_events")
    mock_context = mocker.patch("utils.template_context.get_template_context")
    mock_template = mocker.patch("routers.admin.templates.TemplateResponse")

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
    response = client.get("/admin/audit/events")

    assert response.status_code == 200
    mock_list.assert_called_once()


def test_event_log_list_with_pagination(test_admin_user, override_auth, mocker):
    """Test event log list page with pagination parameters."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.event_log.list_events")
    mock_context = mocker.patch("utils.template_context.get_template_context")
    mock_template = mocker.patch("routers.admin.templates.TemplateResponse")

    mock_result = MagicMock()
    mock_result.items = []
    mock_result.total = 100
    mock_result.page = 2
    mock_result.limit = 25
    mock_list.return_value = mock_result

    mock_context.return_value = {"request": MagicMock()}
    mock_template.return_value = HTMLResponse(content="<html>events</html>")

    client = TestClient(app)
    response = client.get("/admin/audit/events?page=2&size=25")

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
    mock_template = mocker.patch("routers.admin.templates.TemplateResponse")

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
    response = client.get(f"/admin/audit/events/{event_id}")

    assert response.status_code == 200


def test_event_log_detail_not_found_redirects(test_admin_user, override_auth):
    """Test event log detail redirects on not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    with patch("services.event_log.get_event") as mock_get:
        mock_get.side_effect = NotFoundError(message="Not found", code="event_not_found")

        client = TestClient(app)
        response = client.get(f"/admin/audit/events/{uuid4()}", follow_redirects=False)

        assert response.status_code == 303
        assert "error=not_found" in response.headers["location"]


def test_trigger_export_creates_task(test_admin_user, override_auth):
    """Test trigger export creates a background task and redirects to background jobs."""
    override_auth(test_admin_user, level="admin")

    with patch("services.bg_tasks.create_export_task") as mock_create:
        mock_create.return_value = {"id": str(uuid4())}

        client = TestClient(app)
        response = client.post("/admin/audit/events/export", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/account/background-jobs?success=export_started"
        mock_create.assert_called_once()


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
    response = client.get("/admin/audit/events")

    # The ForbiddenError should be raised
    assert response.status_code in [403, 500]  # Depends on error handling


# =============================================================================
# Reactivation Requests Routes Tests
# =============================================================================


def test_reactivation_requests_list_admin(test_admin_user, override_auth, mocker):
    """Test admin can access reactivation requests list page."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.reactivation.list_pending_requests")
    mock_context = mocker.patch("utils.template_context.get_template_context")
    mock_template = mocker.patch("routers.admin.templates.TemplateResponse")

    mock_list.return_value = []
    mock_context.return_value = {"request": MagicMock()}
    mock_template.return_value = HTMLResponse(content="<html>requests</html>")

    client = TestClient(app)
    response = client.get("/admin/todo/reactivation")

    assert response.status_code == 200
    mock_list.assert_called_once()


def test_reactivation_requests_list_member_forbidden(test_user):
    """Test members cannot access reactivation requests."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin
    from services.exceptions import ForbiddenError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_user["tenant_id"])
    app.dependency_overrides[get_current_user] = lambda: test_user

    def mock_require_admin():
        raise ForbiddenError(message="Admin required", code="admin_required")

    app.dependency_overrides[require_admin] = mock_require_admin

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/admin/todo/reactivation")

    assert response.status_code in [403, 500]


def test_reactivation_requests_list_success_message(test_admin_user, override_auth, mocker):
    """Test success query param is passed to template."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.reactivation.list_pending_requests")
    mock_context = mocker.patch("routers.admin.get_template_context")
    mock_template = mocker.patch("routers.admin.templates.TemplateResponse")

    mock_list.return_value = []
    mock_context.return_value = {"request": MagicMock(), "success": "approved"}
    mock_template.return_value = HTMLResponse(content="<html>requests</html>")

    client = TestClient(app)
    response = client.get("/admin/todo/reactivation?success=approved")

    assert response.status_code == 200
    # Check get_template_context was called with success param
    mock_context.assert_called_once()
    _, call_kwargs = mock_context.call_args
    assert call_kwargs.get("success") == "approved"


def test_reactivation_requests_list_error_message(test_admin_user, override_auth, mocker):
    """Test error query param is passed to template."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.reactivation.list_pending_requests")
    mock_context = mocker.patch("routers.admin.get_template_context")
    mock_template = mocker.patch("routers.admin.templates.TemplateResponse")

    mock_list.return_value = []
    mock_context.return_value = {"request": MagicMock(), "error": "request_not_found"}
    mock_template.return_value = HTMLResponse(content="<html>requests</html>")

    client = TestClient(app)
    response = client.get("/admin/todo/reactivation?error=request_not_found")

    assert response.status_code == 200
    # Check get_template_context was called with error param
    mock_context.assert_called_once()
    _, call_kwargs = mock_context.call_args
    assert call_kwargs.get("error") == "request_not_found"


def test_reactivation_history_admin(test_admin_user, override_auth, mocker):
    """Test admin can access reactivation history page."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.reactivation.list_previous_requests")
    mock_context = mocker.patch("utils.template_context.get_template_context")
    mock_template = mocker.patch("routers.admin.templates.TemplateResponse")

    mock_list.return_value = []
    mock_context.return_value = {"request": MagicMock()}
    mock_template.return_value = HTMLResponse(content="<html>history</html>")

    client = TestClient(app)
    response = client.get("/admin/todo/reactivation/history")

    assert response.status_code == 200
    mock_list.assert_called_once()


def test_reactivation_history_member_forbidden(test_user):
    """Test members cannot access reactivation history."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin
    from services.exceptions import ForbiddenError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_user["tenant_id"])
    app.dependency_overrides[get_current_user] = lambda: test_user

    def mock_require_admin():
        raise ForbiddenError(message="Admin required", code="admin_required")

    app.dependency_overrides[require_admin] = mock_require_admin

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/admin/todo/reactivation/history")

    assert response.status_code in [403, 500]


def test_approve_request_success(test_admin_user, override_auth, mocker):
    """Test approving a reactivation request redirects with success."""
    from datetime import UTC, datetime

    from schemas.reactivation import ReactivationRequest

    override_auth(test_admin_user, level="admin")

    request_id = str(uuid4())

    mock_approve = mocker.patch("services.reactivation.approve_request")
    mocker.patch("routers.admin.send_account_reactivated_notification")

    mock_approve.return_value = ReactivationRequest(
        id=request_id,
        user_id=str(uuid4()),
        email="user@example.com",
        first_name="Test",
        last_name="User",
        requested_at=datetime.now(UTC),
        decision="approved",
        decided_at=datetime.now(UTC),
        decided_by_name="Admin User",
    )

    client = TestClient(app)
    response = client.post(
        f"/admin/todo/reactivation/{request_id}/approve",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=approved" in response.headers["location"]


def test_approve_request_not_found(test_admin_user, override_auth):
    """Test approving non-existent request redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    request_id = str(uuid4())

    with patch("services.reactivation.approve_request") as mock_approve:
        mock_approve.side_effect = NotFoundError(
            message="Request not found", code="request_not_found"
        )

        client = TestClient(app)
        response = client.post(
            f"/admin/todo/reactivation/{request_id}/approve",
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=request_not_found" in response.headers["location"]


def test_approve_request_already_decided(test_admin_user, override_auth):
    """Test approving already-decided request redirects with error."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user, level="admin")

    request_id = str(uuid4())

    with patch("services.reactivation.approve_request") as mock_approve:
        mock_approve.side_effect = ValidationError(
            message="Already decided", code="already_decided"
        )

        client = TestClient(app)
        response = client.post(
            f"/admin/todo/reactivation/{request_id}/approve",
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=already_decided" in response.headers["location"]


def test_approve_request_sends_email(test_admin_user, override_auth, mocker):
    """Test approving request sends notification email."""
    from datetime import UTC, datetime

    from schemas.reactivation import ReactivationRequest

    override_auth(test_admin_user, level="admin")

    request_id = str(uuid4())
    user_email = "reactivated@example.com"

    mock_approve = mocker.patch("services.reactivation.approve_request")
    mock_send_email = mocker.patch("routers.admin.send_account_reactivated_notification")

    mock_approve.return_value = ReactivationRequest(
        id=request_id,
        user_id=str(uuid4()),
        email=user_email,
        first_name="Test",
        last_name="User",
        requested_at=datetime.now(UTC),
        decision="approved",
        decided_at=datetime.now(UTC),
        decided_by_name="Admin User",
    )

    client = TestClient(app)
    client.post(
        f"/admin/todo/reactivation/{request_id}/approve",
        follow_redirects=False,
    )

    mock_send_email.assert_called_once()
    call_args = mock_send_email.call_args[0]
    assert call_args[0] == user_email


def test_deny_request_success(test_admin_user, override_auth, mocker):
    """Test denying a reactivation request redirects with success."""
    from datetime import UTC, datetime

    from schemas.reactivation import ReactivationRequest

    override_auth(test_admin_user, level="admin")

    request_id = str(uuid4())

    mock_deny = mocker.patch("services.reactivation.deny_request")
    mocker.patch("routers.admin.send_reactivation_denied_notification")

    mock_deny.return_value = ReactivationRequest(
        id=request_id,
        user_id=str(uuid4()),
        email="user@example.com",
        first_name="Test",
        last_name="User",
        requested_at=datetime.now(UTC),
        decision="denied",
        decided_at=datetime.now(UTC),
        decided_by_name="Admin User",
    )

    client = TestClient(app)
    response = client.post(
        f"/admin/todo/reactivation/{request_id}/deny",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=denied" in response.headers["location"]


def test_deny_request_not_found(test_admin_user, override_auth):
    """Test denying non-existent request redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    request_id = str(uuid4())

    with patch("services.reactivation.deny_request") as mock_deny:
        mock_deny.side_effect = NotFoundError(message="Request not found", code="request_not_found")

        client = TestClient(app)
        response = client.post(
            f"/admin/todo/reactivation/{request_id}/deny",
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=request_not_found" in response.headers["location"]


def test_deny_request_sends_email(test_admin_user, override_auth, mocker):
    """Test denying request sends notification email."""
    from datetime import UTC, datetime

    from schemas.reactivation import ReactivationRequest

    override_auth(test_admin_user, level="admin")

    request_id = str(uuid4())
    user_email = "denied@example.com"

    mock_deny = mocker.patch("services.reactivation.deny_request")
    mock_send_email = mocker.patch("routers.admin.send_reactivation_denied_notification")

    mock_deny.return_value = ReactivationRequest(
        id=request_id,
        user_id=str(uuid4()),
        email=user_email,
        first_name="Test",
        last_name="User",
        requested_at=datetime.now(UTC),
        decision="denied",
        decided_at=datetime.now(UTC),
        decided_by_name="Admin User",
    )

    client = TestClient(app)
    client.post(
        f"/admin/todo/reactivation/{request_id}/deny",
        follow_redirects=False,
    )

    mock_send_email.assert_called_once()
    call_args = mock_send_email.call_args[0]
    assert call_args[0] == user_email
