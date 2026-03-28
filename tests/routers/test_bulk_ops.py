"""Tests for bulk operations web routes."""

from unittest.mock import patch
from uuid import uuid4

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app

# =============================================================================
# POST /users/bulk-ops/secondary-emails/prepare
# =============================================================================


def test_prepare_renders_page_with_selected_users(test_admin_user, override_auth):
    """Prepare endpoint fetches users and renders the action page."""
    override_auth(test_admin_user, level="admin")

    user1_id = str(uuid4())
    user2_id = str(uuid4())

    with (
        patch("routers.users.bulk_ops.emails_service.list_users_by_ids_with_emails") as mock_fetch,
        patch("routers.users.bulk_ops.templates.TemplateResponse") as mock_template,
    ):
        mock_fetch.return_value = (
            [
                {
                    "id": user1_id,
                    "first_name": "Alice",
                    "last_name": "Smith",
                    "email": "alice@example.com",
                },
                {
                    "id": user2_id,
                    "first_name": "Bob",
                    "last_name": "Jones",
                    "email": "bob@example.com",
                },
            ],
            {user1_id: ["alice2@example.com"]},
        )
        mock_template.return_value = HTMLResponse(content="<html>Bulk Emails</html>")

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/secondary-emails/prepare",
            data={
                "selection_mode": "ids",
                "user_ids": [user1_id, user2_id],
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    mock_fetch.assert_called_once()
    mock_template.assert_called_once()

    # Verify template context
    args = mock_template.call_args.args
    context = args[2] if len(args) > 2 else mock_template.call_args.kwargs.get("context", {})
    assert context.get("user_count") == 2


def test_prepare_redirects_when_no_users_selected(test_admin_user, override_auth):
    """Prepare endpoint redirects if no user IDs provided."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/users/bulk-ops/secondary-emails/prepare",
        data={"selection_mode": "ids"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "no_users_selected" in response.headers["location"]


def test_prepare_filter_mode_resolves_users(test_admin_user, override_auth):
    """Prepare endpoint resolves filter criteria into user IDs."""
    override_auth(test_admin_user, level="admin")

    user_id = str(uuid4())

    with (
        patch("routers.users.bulk_ops.emails_service.resolve_users_from_filter") as mock_resolve,
        patch("routers.users.bulk_ops.emails_service.list_users_by_ids_with_emails") as mock_fetch,
        patch("routers.users.bulk_ops.templates.TemplateResponse") as mock_template,
    ):
        mock_resolve.return_value = [user_id]
        mock_fetch.return_value = (
            [
                {
                    "id": user_id,
                    "first_name": "Test",
                    "last_name": "User",
                    "email": "test@example.com",
                }
            ],
            {},
        )
        mock_template.return_value = HTMLResponse(content="<html>Bulk</html>")

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/secondary-emails/prepare",
            data={
                "selection_mode": "filter",
                "filter_criteria": '{"roles": ["admin"]}',
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    mock_resolve.assert_called_once()


# =============================================================================
# POST /users/bulk-ops/secondary-emails
# =============================================================================


def test_submit_creates_background_job(test_admin_user, override_auth):
    """Submit endpoint creates a background job and redirects."""
    override_auth(test_admin_user, level="admin")

    user1_id = str(uuid4())
    user2_id = str(uuid4())

    with patch(
        "routers.users.bulk_ops.bg_tasks_service.create_bulk_add_emails_task"
    ) as mock_create:
        mock_create.return_value = {"id": str(uuid4()), "created_at": "2026-01-01"}

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/secondary-emails",
            data={
                "user_ids": [user1_id, user2_id],
                "emails": ["new1@example.com", "new2@example.com"],
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "background-jobs" in response.headers["location"]
    assert "bulk_emails_started" in response.headers["location"]

    mock_create.assert_called_once()
    call_args = mock_create.call_args
    items = call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs.get("items", [])
    assert len(items) == 2


def test_submit_skips_blank_emails(test_admin_user, override_auth):
    """Submit endpoint filters out blank email entries."""
    override_auth(test_admin_user, level="admin")

    user1_id = str(uuid4())
    user2_id = str(uuid4())

    with patch(
        "routers.users.bulk_ops.bg_tasks_service.create_bulk_add_emails_task"
    ) as mock_create:
        mock_create.return_value = {"id": str(uuid4()), "created_at": "2026-01-01"}

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/secondary-emails",
            data={
                "user_ids": [user1_id, user2_id],
                "emails": ["new1@example.com", ""],
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    call_args = mock_create.call_args
    items = call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs.get("items", [])
    assert len(items) == 1
    assert items[0]["email"] == "new1@example.com"


def test_submit_redirects_when_all_emails_blank(test_admin_user, override_auth):
    """Submit endpoint redirects if all emails are blank."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/users/bulk-ops/secondary-emails",
        data={
            "user_ids": [str(uuid4()), str(uuid4())],
            "emails": ["", "  "],
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "no_emails_provided" in response.headers["location"]
