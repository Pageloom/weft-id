"""Tests for routers/directory.py: index redirects and Requests (reactivation)."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient
from main import app
from services.exceptions import ServiceError, ValidationError

# =============================================================================
# Section Index Redirect Tests
# =============================================================================


def test_directory_index_redirects_to_first_child(test_admin_user, override_auth):
    """Directory index page redirects to its first accessible child page."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.directory.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = "/users/list"

        client = TestClient(app)
        response = client.get("/directory/", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/users/list"


def test_directory_index_fallback_to_dashboard(test_admin_user, override_auth):
    """Directory index falls back to dashboard when no accessible children."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.directory.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = None

        client = TestClient(app)
        response = client.get("/directory/", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"


def test_requests_index_redirects_to_first_child(test_admin_user, override_auth):
    """Requests index page redirects to its first accessible child page."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.directory.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = "/directory/requests/reactivation"

        client = TestClient(app)
        response = client.get("/directory/requests/", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/directory/requests/reactivation"


def test_requests_index_works_without_trailing_slash(test_admin_user, override_auth):
    """Requests index page works correctly without trailing slash."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.directory.get_first_accessible_child") as mock_first_child:
        mock_first_child.return_value = "/directory/requests/reactivation"

        client = TestClient(app)
        response = client.get("/directory/requests", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/directory/requests/reactivation"


# =============================================================================
# Reactivation Requests Routes Tests
# =============================================================================


def test_reactivation_requests_list_admin(test_admin_user, override_auth, mocker):
    """Test admin can access reactivation requests list page."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.reactivation.list_pending_requests")
    mock_context = mocker.patch("utils.template_context.get_template_context")
    mock_template = mocker.patch("routers.directory.templates.TemplateResponse")

    mock_list.return_value = []
    mock_context.return_value = {"request": MagicMock()}
    mock_template.return_value = HTMLResponse(content="<html>requests</html>")

    client = TestClient(app)
    response = client.get("/directory/requests/reactivation")

    assert response.status_code == 200
    mock_list.assert_called_once()


def test_reactivation_requests_list_member_forbidden(test_user):
    """Test members cannot access reactivation requests."""
    from dependencies import (
        get_current_user,
        get_tenant_id_from_request,
        require_admin,
        require_current_user,
    )
    from services.exceptions import ForbiddenError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_user["tenant_id"])
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    def mock_require_admin():
        raise ForbiddenError(message="Admin required", code="admin_required")

    app.dependency_overrides[require_admin] = mock_require_admin

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/directory/requests/reactivation")

    assert response.status_code in [403, 500]


def test_reactivation_requests_list_success_message(test_admin_user, override_auth, mocker):
    """Test success query param is passed to template."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.reactivation.list_pending_requests")
    mock_context = mocker.patch("routers.directory.get_template_context")
    mock_template = mocker.patch("routers.directory.templates.TemplateResponse")

    mock_list.return_value = []
    mock_context.return_value = {"request": MagicMock(), "success": "approved"}
    mock_template.return_value = HTMLResponse(content="<html>requests</html>")

    client = TestClient(app)
    response = client.get("/directory/requests/reactivation?success=approved")

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
    mock_context = mocker.patch("routers.directory.get_template_context")
    mock_template = mocker.patch("routers.directory.templates.TemplateResponse")

    mock_list.return_value = []
    mock_context.return_value = {"request": MagicMock(), "error": "request_not_found"}
    mock_template.return_value = HTMLResponse(content="<html>requests</html>")

    client = TestClient(app)
    response = client.get("/directory/requests/reactivation?error=request_not_found")

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
    mock_template = mocker.patch("routers.directory.templates.TemplateResponse")

    mock_list.return_value = []
    mock_context.return_value = {"request": MagicMock()}
    mock_template.return_value = HTMLResponse(content="<html>history</html>")

    client = TestClient(app)
    response = client.get("/directory/requests/reactivation/history")

    assert response.status_code == 200
    mock_list.assert_called_once()


def test_reactivation_history_member_forbidden(test_user):
    """Test members cannot access reactivation history."""
    from dependencies import (
        get_current_user,
        get_tenant_id_from_request,
        require_admin,
        require_current_user,
    )
    from services.exceptions import ForbiddenError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_user["tenant_id"])
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    def mock_require_admin():
        raise ForbiddenError(message="Admin required", code="admin_required")

    app.dependency_overrides[require_admin] = mock_require_admin

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/directory/requests/reactivation/history")

    assert response.status_code in [403, 500]


def test_approve_request_success(test_admin_user, override_auth, mocker):
    """Test approving a reactivation request redirects with success."""
    from datetime import UTC, datetime

    from schemas.reactivation import ReactivationRequest

    override_auth(test_admin_user, level="admin")

    request_id = str(uuid4())

    mock_approve = mocker.patch("services.reactivation.approve_request")
    mocker.patch("routers.directory.send_account_reactivated_notification")

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
        f"/directory/requests/reactivation/{request_id}/approve",
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
            f"/directory/requests/reactivation/{request_id}/approve",
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
            f"/directory/requests/reactivation/{request_id}/approve",
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
    mock_send_email = mocker.patch("routers.directory.send_account_reactivated_notification")

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
        f"/directory/requests/reactivation/{request_id}/approve",
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
    mocker.patch("routers.directory.send_reactivation_denied_notification")

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
        f"/directory/requests/reactivation/{request_id}/deny",
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
            f"/directory/requests/reactivation/{request_id}/deny",
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
    mock_send_email = mocker.patch("routers.directory.send_reactivation_denied_notification")

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
        f"/directory/requests/reactivation/{request_id}/deny",
        follow_redirects=False,
    )

    mock_send_email.assert_called_once()
    call_args = mock_send_email.call_args[0]
    assert call_args[0] == user_email


# =============================================================================
# Error Handler Coverage Tests
# =============================================================================


def test_reactivation_list_service_error(test_admin_user, override_auth, mocker):
    """Test reactivation list renders error page on ServiceError."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.reactivation.list_pending_requests")
    mock_error = mocker.patch("routers.directory.render_error_page")
    mock_list.side_effect = ServiceError(message="Database error", code="db_error")
    mock_error.return_value = HTMLResponse(content="<html>Error</html>", status_code=500)

    client = TestClient(app)
    response = client.get("/directory/requests/reactivation")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_reactivation_history_service_error(test_admin_user, override_auth, mocker):
    """Test reactivation history renders error page on ServiceError."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch("services.reactivation.list_previous_requests")
    mock_error = mocker.patch("routers.directory.render_error_page")
    mock_list.side_effect = ServiceError(message="Database error", code="db_error")
    mock_error.return_value = HTMLResponse(content="<html>Error</html>", status_code=500)

    client = TestClient(app)
    response = client.get("/directory/requests/reactivation/history")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_approve_request_service_error(test_admin_user, override_auth, mocker):
    """Test approve request renders error page on ServiceError."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_approve = mocker.patch("services.reactivation.approve_request")
    mock_error = mocker.patch("routers.directory.render_error_page")
    mock_approve.side_effect = ServiceError(message="Database error", code="db_error")
    mock_error.return_value = HTMLResponse(content="<html>Error</html>", status_code=500)

    client = TestClient(app)
    response = client.post(
        f"/directory/requests/reactivation/{uuid4()}/approve",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_deny_request_service_error(test_admin_user, override_auth, mocker):
    """Test deny request renders error page on ServiceError."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_deny = mocker.patch("services.reactivation.deny_request")
    mock_error = mocker.patch("routers.directory.render_error_page")
    mock_deny.side_effect = ServiceError(message="Database error", code="db_error")
    mock_error.return_value = HTMLResponse(content="<html>Error</html>", status_code=500)

    client = TestClient(app)
    response = client.post(
        f"/directory/requests/reactivation/{uuid4()}/deny",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_deny_request_validation_error(test_admin_user, override_auth):
    """Test denying already-decided request redirects with error code."""
    override_auth(test_admin_user, level="admin")

    request_id = str(uuid4())

    with patch("services.reactivation.deny_request") as mock_deny:
        mock_deny.side_effect = ValidationError(message="Already decided", code="already_decided")

        client = TestClient(app)
        response = client.post(
            f"/directory/requests/reactivation/{request_id}/deny",
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=already_decided" in response.headers["location"]


# =============================================================================
# Exports (User Audit Export) Routes Tests
# =============================================================================


def test_exports_page_renders_for_admin(test_admin_user, override_auth, mocker):
    """Test admin can load the Directory > Exports page."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_template = mocker.patch(
        "routers.directory.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>export</html>"),
    )

    client = TestClient(app)
    response = client.get("/directory/exports")

    assert response.status_code == 200
    mock_template.assert_called_once()
    template_name = mock_template.call_args.args[1]
    assert template_name == "admin_user_export.html"


def test_exports_page_passes_success_param(test_admin_user, override_auth, mocker):
    """Test success query param is forwarded to the template context."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_context = mocker.patch("routers.directory.get_template_context")
    mocker.patch(
        "routers.directory.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>export</html>"),
    )
    mock_context.return_value = {"request": MagicMock()}

    client = TestClient(app)
    response = client.get("/directory/exports?success=export_started")

    assert response.status_code == 200
    mock_context.assert_called_once()
    _, call_kwargs = mock_context.call_args
    assert call_kwargs.get("success") == "export_started"


def test_exports_page_forbidden_for_member(test_user):
    """Test members cannot access the Directory > Exports page."""
    from dependencies import (
        get_current_user,
        get_tenant_id_from_request,
        require_admin,
        require_current_user,
    )
    from services.exceptions import ForbiddenError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_user["tenant_id"])
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    def mock_require_admin():
        raise ForbiddenError(message="Admin required", code="admin_required")

    app.dependency_overrides[require_admin] = mock_require_admin

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/directory/exports")

    assert response.status_code in [403, 500]


def test_trigger_user_export_creates_task_and_redirects(test_admin_user, override_auth, mocker):
    """Test triggering the user export creates a background task and redirects."""
    override_auth(test_admin_user, level="admin")

    mock_create = mocker.patch("services.bg_tasks.create_user_export_task")

    client = TestClient(app)
    response = client.post("/directory/exports", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/account/background-jobs?success=export_started"
    mock_create.assert_called_once()


def test_trigger_user_export_service_error(test_admin_user, override_auth, mocker):
    """Test triggering the user export renders an error page on ServiceError."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user, level="admin")

    mock_create = mocker.patch("services.bg_tasks.create_user_export_task")
    mock_error = mocker.patch("routers.directory.render_error_page")
    mock_create.side_effect = ServiceError(message="Export failed", code="export_error")
    mock_error.return_value = HTMLResponse(content="<html>Error</html>", status_code=500)

    client = TestClient(app)
    response = client.post("/directory/exports")

    assert response.status_code == 500
    mock_error.assert_called_once()
