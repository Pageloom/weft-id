"""Tests for bulk operations web routes."""

from datetime import UTC, date
from unittest.mock import patch
from uuid import uuid4

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app
from services.exceptions import ServiceError

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


# =============================================================================
# POST /users/bulk-ops/primary-emails/prepare
# =============================================================================


def test_prepare_primary_emails_renders_page(test_admin_user, override_auth):
    """Prepare endpoint renders the primary email action page."""
    override_auth(test_admin_user, level="admin")

    user1_id = str(uuid4())

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
                }
            ],
            {user1_id: ["alice2@example.com"]},
        )
        mock_template.return_value = HTMLResponse(content="<html>Bulk Primary</html>")

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/primary-emails/prepare",
            data={"selection_mode": "ids", "user_ids": [user1_id]},
        )

    assert response.status_code == 200
    mock_template.assert_called_once()
    template_name = mock_template.call_args.args[1]
    assert template_name == "users_bulk_primary_emails.html"


def test_prepare_primary_emails_redirects_no_users(test_admin_user, override_auth):
    """Prepare redirects when no users are selected."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/users/bulk-ops/primary-emails/prepare",
        data={"selection_mode": "ids"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "no_users_selected" in response.headers["location"]


# =============================================================================
# POST /users/bulk-ops/primary-emails/preview
# =============================================================================


def test_preview_creates_background_job(test_admin_user, override_auth):
    """Preview endpoint creates a dry-run background job."""
    override_auth(test_admin_user, level="admin")

    from datetime import datetime

    task_id = str(uuid4())

    with patch(
        "routers.users.bulk_ops.bg_tasks_service.create_bulk_primary_email_preview_task"
    ) as mock_create:
        mock_create.return_value = {"id": task_id, "created_at": datetime(2026, 1, 1, tzinfo=UTC)}

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/primary-emails/preview",
            data={
                "user_ids": [str(uuid4())],
                "new_emails": ["new@example.com"],
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["task_id"] == task_id
    mock_create.assert_called_once()


def test_preview_returns_error_when_no_emails_selected(test_admin_user, override_auth):
    """Preview returns 400 when all emails are blank."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/users/bulk-ops/primary-emails/preview",
        data={
            "user_ids": [str(uuid4())],
            "new_emails": [""],
        },
    )

    assert response.status_code == 400


# =============================================================================
# POST /users/bulk-ops/primary-emails/apply
# =============================================================================


def test_apply_creates_background_job(test_admin_user, override_auth):
    """Apply endpoint creates an execution background job."""
    override_auth(test_admin_user, level="admin")

    import json
    from datetime import datetime

    task_id = str(uuid4())
    preview_id = str(uuid4())

    items = [
        {
            "user_id": str(uuid4()),
            "new_primary_email": "new@example.com",
            "idp_disposition": "keep",
        },
    ]

    with patch(
        "routers.users.bulk_ops.bg_tasks_service.create_bulk_primary_email_apply_task"
    ) as mock_create:
        mock_create.return_value = {"id": task_id, "created_at": datetime(2026, 1, 1, tzinfo=UTC)}

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/primary-emails/apply",
            data={
                "items_json": json.dumps(items),
                "preview_job_id": preview_id,
            },
        )

    assert response.status_code == 200
    data = response.json()
    assert data["task_id"] == task_id
    mock_create.assert_called_once()


# =============================================================================
# _parse_filter_criteria
# =============================================================================


class TestParseFilterCriteria:
    """Tests for the _parse_filter_criteria helper."""

    def test_invalid_json(self):
        """Returns empty dict on invalid JSON."""
        from routers.users.bulk_ops import _parse_filter_criteria

        assert _parse_filter_criteria("not-json") == {}

    def test_none_input(self):
        """Returns empty dict on None input."""
        from routers.users.bulk_ops import _parse_filter_criteria

        assert _parse_filter_criteria(None) == {}

    def test_roles_with_negation(self):
        """Parses negated role filter."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria('{"roles": "!admin,member"}')
        assert result["roles"] == ["admin", "member"]
        assert result["role_negate"] is True

    def test_roles_without_negation(self):
        """Parses role filter without negation."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria('{"roles": "admin"}')
        assert result["roles"] == ["admin"]
        assert "role_negate" not in result

    def test_statuses_with_negation(self):
        """Parses negated status filter."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria('{"statuses": "!active"}')
        assert result["statuses"] == ["active"]
        assert result["status_negate"] is True

    def test_auth_methods_with_negation(self):
        """Parses negated auth method filter."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria('{"auth_methods": "!password_email,password_totp"}')
        assert result["auth_methods"] == ["password_email", "password_totp"]
        assert result["auth_method_negate"] is True

    def test_domain_with_negation(self):
        """Parses negated domain filter."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria('{"domain": "!example.com"}')
        assert result["domain"] == "example.com"
        assert result["domain_negate"] is True

    def test_domain_without_negation(self):
        """Parses domain filter without negation."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria('{"domain": "example.com"}')
        assert result["domain"] == "example.com"
        assert "domain_negate" not in result

    def test_group_id_with_negation(self):
        """Parses negated group filter."""
        from routers.users.bulk_ops import _parse_filter_criteria

        gid = str(uuid4())
        result = _parse_filter_criteria(f'{{"group_id": "!{gid}"}}')
        assert result["group_id"] == gid
        assert result["group_negate"] is True

    def test_group_children_disabled(self):
        """Parses group_children=0 flag."""
        from routers.users.bulk_ops import _parse_filter_criteria

        gid = str(uuid4())
        result = _parse_filter_criteria(f'{{"group_id": "{gid}", "group_children": "0"}}')
        assert result["group_include_children"] is False

    def test_has_secondary_email_yes(self):
        """Parses has_secondary_email=yes."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria('{"has_secondary_email": "yes"}')
        assert result["has_secondary_email"] is True

    def test_has_secondary_email_no(self):
        """Parses has_secondary_email=no."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria('{"has_secondary_email": "no"}')
        assert result["has_secondary_email"] is False

    def test_activity_date_range(self):
        """Parses activity date range."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria(
            '{"activity_start": "2026-01-01", "activity_end": "2026-03-31"}'
        )
        assert result["activity_start"] == date(2026, 1, 1)
        assert result["activity_end"] == date(2026, 3, 31)

    def test_activity_date_invalid_ignored(self):
        """Invalid activity dates are silently ignored."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria('{"activity_start": "not-a-date"}')
        assert "activity_start" not in result

    def test_invalid_roles_filtered(self):
        """Invalid role values are filtered out."""
        from routers.users.bulk_ops import _parse_filter_criteria

        result = _parse_filter_criteria('{"roles": "invalid,admin"}')
        assert result["roles"] == ["admin"]


# =============================================================================
# Error Paths: no_users_found redirect, ServiceError, invalid JSON
# =============================================================================


def test_prepare_secondary_redirects_no_users_found(test_admin_user, override_auth):
    """Prepare redirects when service returns empty user list."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.users.bulk_ops.emails_service.list_users_by_ids_with_emails") as mock_fetch:
        mock_fetch.return_value = ([], {})

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/secondary-emails/prepare",
            data={"selection_mode": "ids", "user_ids": [str(uuid4())]},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "no_users_found" in response.headers["location"]


def test_submit_secondary_service_error(test_admin_user, override_auth):
    """Submit renders error page on ServiceError."""
    override_auth(test_admin_user, level="admin")

    with patch(
        "routers.users.bulk_ops.bg_tasks_service.create_bulk_add_emails_task"
    ) as mock_create:
        mock_create.side_effect = ServiceError(message="Task failed", code="fail")

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/secondary-emails",
            data={
                "user_ids": [str(uuid4())],
                "emails": ["test@example.com"],
            },
            follow_redirects=False,
        )

    # ServiceError returns an error page (not a redirect)
    assert response.status_code == 400 or response.status_code == 500


def test_prepare_primary_redirects_no_users_found(test_admin_user, override_auth):
    """Prepare primary redirects when service returns empty user list."""
    override_auth(test_admin_user, level="admin")

    with patch("routers.users.bulk_ops.emails_service.list_users_by_ids_with_emails") as mock_fetch:
        mock_fetch.return_value = ([], {})

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/primary-emails/prepare",
            data={"selection_mode": "ids", "user_ids": [str(uuid4())]},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "no_users_found" in response.headers["location"]


def test_preview_primary_service_error(test_admin_user, override_auth):
    """Preview returns error JSON on ServiceError."""
    override_auth(test_admin_user, level="admin")

    with patch(
        "routers.users.bulk_ops.bg_tasks_service.create_bulk_primary_email_preview_task"
    ) as mock_create:
        mock_create.side_effect = ServiceError(message="Task failed", code="fail")

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/primary-emails/preview",
            data={
                "user_ids": [str(uuid4())],
                "new_emails": ["new@example.com"],
            },
        )

    assert response.status_code == 400
    assert "Task failed" in response.json()["error"]


def test_preview_primary_null_result(test_admin_user, override_auth):
    """Preview returns 500 when service returns None."""
    override_auth(test_admin_user, level="admin")

    with patch(
        "routers.users.bulk_ops.bg_tasks_service.create_bulk_primary_email_preview_task"
    ) as mock_create:
        mock_create.return_value = None

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/primary-emails/preview",
            data={
                "user_ids": [str(uuid4())],
                "new_emails": ["new@example.com"],
            },
        )

    assert response.status_code == 500
    assert "Failed" in response.json()["error"]


def test_apply_primary_invalid_json(test_admin_user, override_auth):
    """Apply returns error on invalid JSON in items_json."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/users/bulk-ops/primary-emails/apply",
        data={
            "items_json": "not-json",
            "preview_job_id": str(uuid4()),
        },
    )

    assert response.status_code == 400
    assert "Invalid" in response.json()["error"]


def test_apply_primary_empty_items(test_admin_user, override_auth):
    """Apply returns error when items list is empty."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.post(
        "/users/bulk-ops/primary-emails/apply",
        data={
            "items_json": "[]",
            "preview_job_id": str(uuid4()),
        },
    )

    assert response.status_code == 400
    assert "No items" in response.json()["error"]


def test_apply_primary_service_error(test_admin_user, override_auth):
    """Apply returns error JSON on ServiceError."""
    override_auth(test_admin_user, level="admin")

    import json

    items = [{"user_id": str(uuid4()), "new_primary_email": "x@y.com", "idp_disposition": "keep"}]

    with patch(
        "routers.users.bulk_ops.bg_tasks_service.create_bulk_primary_email_apply_task"
    ) as mock_create:
        mock_create.side_effect = ServiceError(message="Apply failed", code="fail")

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/primary-emails/apply",
            data={
                "items_json": json.dumps(items),
                "preview_job_id": str(uuid4()),
            },
        )

    assert response.status_code == 400
    assert "Apply failed" in response.json()["error"]


def test_apply_primary_null_result(test_admin_user, override_auth):
    """Apply returns 500 when service returns None."""
    override_auth(test_admin_user, level="admin")

    import json

    items = [{"user_id": str(uuid4()), "new_primary_email": "x@y.com", "idp_disposition": "keep"}]

    with patch(
        "routers.users.bulk_ops.bg_tasks_service.create_bulk_primary_email_apply_task"
    ) as mock_create:
        mock_create.return_value = None

        client = TestClient(app)
        response = client.post(
            "/users/bulk-ops/primary-emails/apply",
            data={
                "items_json": json.dumps(items),
                "preview_job_id": str(uuid4()),
            },
        )

    assert response.status_code == 500
    assert "Failed" in response.json()["error"]
