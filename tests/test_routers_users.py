"""Tests for routers/users.py endpoints."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from main import app


def override_auth(app, user):
    """Helper to override all auth dependencies."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    # Ensure IDs are strings for comparison in route handlers
    user_with_string_id = {**user, "id": str(user["id"])}

    app.dependency_overrides[get_tenant_id_from_request] = lambda: user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: user_with_string_id
    app.dependency_overrides[require_current_user] = lambda: user_with_string_id


def test_users_index_redirects_to_list(test_admin_user):
    """Test users index redirects to list for admin."""
    override_auth(app, test_admin_user)

    client = TestClient(app)
    response = client.get("/users/", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/users/list"


def test_users_index_redirects_regular_user_to_list(test_user):
    """Test users index redirects regular user to list (they can view users)."""
    override_auth(app, test_user)

    client = TestClient(app)
    response = client.get("/users/", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/users/list"


def test_users_list_page(test_admin_user):
    """Test users list page renders."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                from fastapi.responses import HTMLResponse

                mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
                mock_count.return_value = 5
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_count.assert_called_once()
                mock_list.assert_called_once()


def test_users_list_with_search(test_admin_user):
    """Test users list with search parameter."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 2
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?search=john")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # count_users now takes (tenant_id, search, roles, statuses)
                count_call_args = mock_count.call_args[0]
                assert count_call_args[0] == test_admin_user["tenant_id"]
                assert count_call_args[1] == "john"
                assert count_call_args[2] is None  # No role filter
                assert count_call_args[3] is None  # No status filter


def test_users_list_with_sorting(test_admin_user):
    """Test users list with custom sorting."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 5
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?sort=name&order=asc")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Verify sort parameters were passed
                call_args = mock_list.call_args[0]
                assert call_args[2] == "name"  # sort_field
                assert call_args[3] == "asc"  # sort_order


def test_users_list_with_pagination(test_admin_user):
    """Test users list with pagination."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 100
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?page=2&size=50")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                call_args = mock_list.call_args[0]
                assert call_args[4] == 2  # page
                assert call_args[5] == 50  # page_size


def test_users_list_invalid_sort_field(test_admin_user):
    """Test users list defaults invalid sort field."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 5
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?sort=invalid_field")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Should default to created_at
                call_args = mock_list.call_args[0]
                assert call_args[2] == "created_at"


def test_user_detail_page(test_admin_user):
    """Test user detail page renders."""
    from datetime import UTC, datetime

    from schemas.api import UserDetail

    override_auth(app, test_admin_user)

    target_user = UserDetail(
        id="user-123",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[],
        is_service_user=False,
    )

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        with patch("services.users.get_user") as mock_get:
            with patch("database.settings.list_privileged_domains") as mock_domains:
                from fastapi.responses import HTMLResponse

                mock_template.return_value = HTMLResponse(content="<html>User Detail</html>")
                mock_get.return_value = target_user
                mock_domains.return_value = []

                client = TestClient(app)
                response = client.get("/users/user-123")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_get.assert_called_once()


def test_user_detail_not_found(test_admin_user):
    """Test user detail redirects when user not found."""
    from services.exceptions import NotFoundError

    override_auth(app, test_admin_user)

    with patch("services.users.get_user") as mock_get:
        mock_get.side_effect = NotFoundError(message="User not found", code="user_not_found")

        client = TestClient(app)
        response = client.get("/users/user-123", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/list" in response.headers["location"]


def test_user_detail_regular_user_denied(test_user):
    """Test regular user cannot access user detail page."""
    override_auth(app, test_user)

    client = TestClient(app)
    response = client.get("/users/user-123", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_update_user_name_success(test_admin_user):
    """Test updating user name as admin."""
    from schemas.api import UserDetail

    override_auth(app, test_admin_user)

    # Mock the service layer update_user function
    mock_user_detail = UserDetail(
        id="user-123",
        email="test@example.com",
        first_name="New",
        last_name="Name",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at="2025-01-01T00:00:00",
        last_login=None,
        emails=[],
        is_service_user=False,
    )

    with patch("services.users.update_user") as mock_update:
        mock_update.return_value = mock_user_detail
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-name",
            data={"first_name": "New", "last_name": "Name"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123" in response.headers["location"]
        # Verify service was called with correct parameters
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        assert call_args[0][1] == "user-123"  # user_id
        assert call_args[0][2].first_name == "New"
        assert call_args[0][2].last_name == "Name"


def test_update_user_name_empty_validation(test_admin_user):
    """Test updating user name with empty values."""
    override_auth(app, test_admin_user)

    with patch("database.users.update_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-name",
            data={"first_name": "", "last_name": "Name"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=name_required" in response.headers["location"]
        mock_update.assert_not_called()


def test_update_user_role_success(test_super_admin_user):
    """Test updating user role as super_admin."""
    from schemas.api import UserDetail

    override_auth(app, test_super_admin_user)

    # Mock the service layer update_user function
    mock_user_detail = UserDetail(
        id="user-123",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        role="admin",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at="2025-01-01T00:00:00",
        last_login=None,
        emails=[],
        is_service_user=False,
    )

    with patch("services.users.update_user") as mock_update:
        mock_update.return_value = mock_user_detail
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-role",
            data={"role": "admin"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "success=role_updated" in response.headers["location"]
        # Verify service was called with correct parameters
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        assert call_args[0][1] == "user-123"  # user_id
        assert call_args[0][2].role == "admin"


def test_update_user_role_denied_for_admin(test_admin_user):
    """Test regular admin cannot update user roles."""
    override_auth(app, test_admin_user)

    with patch("database.users.update_user_role") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-role",
            data={"role": "admin"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_update.assert_not_called()


def test_update_user_role_cannot_change_own(test_super_admin_user):
    """Test super_admin cannot change their own role."""
    override_auth(app, test_super_admin_user)

    with patch("database.users.update_user_role") as mock_update:
        client = TestClient(app)
        response = client.post(
            f"/users/{str(test_super_admin_user['id'])}/update-role",
            data={"role": "member"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=cannot_change_own_role" in response.headers["location"]
        mock_update.assert_not_called()


def test_update_user_role_invalid_role(test_super_admin_user):
    """Test updating user with invalid role."""
    override_auth(app, test_super_admin_user)

    with patch("database.users.update_user_role") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-role",
            data={"role": "invalid_role"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=invalid_role" in response.headers["location"]
        mock_update.assert_not_called()


def test_add_user_email_success(test_admin_user):
    """Test adding secondary email to user."""
    from schemas.api import EmailInfo

    override_auth(app, test_admin_user)

    mock_email_info = EmailInfo(
        id="new-email-id",
        email="new@privileged.com",
        is_primary=False,
        verified_at="2025-01-01T00:00:00",
        created_at="2025-01-01T00:00:00",
    )

    with patch("services.settings.is_privileged_domain") as mock_privileged:
        with patch("services.emails.add_user_email") as mock_add:
            with patch("services.emails.get_primary_email") as mock_primary:
                with patch("routers.users.send_secondary_email_added_notification") as mock_send:
                    mock_privileged.return_value = True
                    mock_add.return_value = mock_email_info
                    mock_primary.return_value = "primary@example.com"

                    client = TestClient(app)
                    response = client.post(
                        "/users/user-123/add-email",
                        data={"email": "new@privileged.com"},
                        follow_redirects=False,
                    )

                    app.dependency_overrides.clear()

                    assert response.status_code == 303
                    assert "success=email_added" in response.headers["location"]
                    mock_add.assert_called_once()
                    mock_send.assert_called_once()


def test_add_user_email_not_privileged(test_admin_user):
    """Test adding email from non-privileged domain."""
    override_auth(app, test_admin_user)

    with patch("services.settings.is_privileged_domain") as mock_privileged:
        mock_privileged.return_value = False

        client = TestClient(app)
        response = client.post(
            "/users/user-123/add-email",
            data={"email": "new@unprivileged.com"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=domain_not_privileged" in response.headers["location"]


def test_remove_user_email_success(test_admin_user):
    """Test removing secondary email from user."""
    override_auth(app, test_admin_user)

    with patch("services.emails.get_email_address_by_id") as mock_get_addr:
        with patch("services.emails.delete_user_email") as mock_delete:
            with patch("services.emails.get_primary_email") as mock_primary:
                with patch("routers.users.send_secondary_email_removed_notification") as mock_send:
                    mock_get_addr.return_value = "secondary@example.com"
                    mock_delete.return_value = None
                    mock_primary.return_value = "primary@example.com"

                    client = TestClient(app)
                    response = client.post(
                        "/users/user-123/remove-email/email-id", follow_redirects=False
                    )

                    app.dependency_overrides.clear()

                    assert response.status_code == 303
                    assert "success=email_removed" in response.headers["location"]
                    mock_delete.assert_called_once()
                    mock_send.assert_called_once()


def test_remove_user_email_primary_blocked(test_admin_user):
    """Test cannot remove primary email."""
    from services.exceptions import ValidationError

    override_auth(app, test_admin_user)

    with patch("services.emails.get_email_address_by_id") as mock_get_addr:
        with patch("services.emails.delete_user_email") as mock_delete:
            mock_get_addr.return_value = "primary@example.com"
            mock_delete.side_effect = ValidationError(
                message="Cannot delete primary email address",
                code="cannot_delete_primary",
            )

            client = TestClient(app)
            response = client.post("/users/user-123/remove-email/email-id", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "error=cannot_remove_primary" in response.headers["location"]


def test_promote_user_email_success(test_admin_user):
    """Test promoting secondary email to primary."""
    from schemas.api import EmailInfo

    override_auth(app, test_admin_user)

    mock_email_info = EmailInfo(
        id="email-id",
        email="new@example.com",
        is_primary=True,
        verified_at="2025-01-01T00:00:00",
        created_at="2025-01-01T00:00:00",
    )

    with patch("services.emails.get_primary_email") as mock_old_primary:
        with patch("services.emails.get_email_address_by_id") as mock_get_addr:
            with patch("services.emails.set_primary_email") as mock_set:
                with patch("routers.users.send_primary_email_changed_notification") as mock_send:
                    mock_old_primary.return_value = "old@example.com"
                    mock_get_addr.return_value = "new@example.com"
                    mock_set.return_value = mock_email_info

                    client = TestClient(app)
                    response = client.post(
                        "/users/user-123/promote-email/email-id", follow_redirects=False
                    )

                    app.dependency_overrides.clear()

                    assert response.status_code == 303
                    assert "success=email_promoted" in response.headers["location"]
                    mock_set.assert_called_once()
                    mock_send.assert_called_once()


def test_promote_user_email_already_primary(test_admin_user):
    """Test cannot promote already primary email."""
    from schemas.api import EmailInfo

    override_auth(app, test_admin_user)

    mock_email_info = EmailInfo(
        id="email-id",
        email="already@primary.com",
        is_primary=True,
        verified_at="2025-01-01T00:00:00",
        created_at="2025-01-01T00:00:00",
    )

    with patch("services.emails.get_primary_email") as mock_old_primary:
        with patch("services.emails.get_email_address_by_id") as mock_get_addr:
            with patch("services.emails.set_primary_email") as mock_set:
                # Same email - already primary
                mock_old_primary.return_value = "already@primary.com"
                mock_get_addr.return_value = "already@primary.com"
                mock_set.return_value = mock_email_info

                client = TestClient(app)
                response = client.post(
                    "/users/user-123/promote-email/email-id", follow_redirects=False
                )

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "error=already_primary" in response.headers["location"]


def test_users_list_with_locale_collation(test_admin_user):
    """Test users list with locale-specific collation."""
    user_with_locale = {**test_admin_user, "locale": "sv_SE"}
    override_auth(app, user_with_locale)

    with patch("services.users.check_collation_exists") as mock_check:
        with patch("services.users.list_users_raw") as mock_list:
            with patch("services.users.count_users") as mock_count:
                with patch("routers.users.templates.TemplateResponse") as mock_template:
                    from fastapi.responses import HTMLResponse

                    mock_check.return_value = True
                    mock_list.return_value = []
                    mock_count.return_value = 0
                    mock_template.return_value = HTMLResponse(content="<html>Users</html>")

                    client = TestClient(app)
                    response = client.get("/users/list")

                    app.dependency_overrides.clear()

                    assert response.status_code == 200
                    # Check collation was passed to list_users_raw
                    mock_list.assert_called_once()
                    call_args = mock_list.call_args
                    assert call_args[0][6] == "sv-SE-x-icu"  # collation parameter


def test_users_list_with_invalid_page_param(test_admin_user):
    """Test users list with invalid page parameter."""
    override_auth(app, test_admin_user)

    with patch("services.users.list_users_raw") as mock_list:
        with patch("services.users.count_users") as mock_count:
            with patch("routers.users.templates.TemplateResponse") as mock_template:
                from fastapi.responses import HTMLResponse

                mock_list.return_value = []
                mock_count.return_value = 0
                mock_template.return_value = HTMLResponse(content="<html>Users</html>")

                client = TestClient(app)
                response = client.get("/users/list?page=invalid")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Should default to page 1


def test_users_list_with_invalid_page_size(test_admin_user):
    """Test users list with invalid page size parameter."""
    override_auth(app, test_admin_user)

    with patch("services.users.list_users_raw") as mock_list:
        with patch("services.users.count_users") as mock_count:
            with patch("routers.users.templates.TemplateResponse") as mock_template:
                from fastapi.responses import HTMLResponse

                mock_list.return_value = []
                mock_count.return_value = 0
                mock_template.return_value = HTMLResponse(content="<html>Users</html>")

                client = TestClient(app)
                response = client.get("/users/list?size=invalid")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Should default to page size 25


def test_users_list_with_nonstandard_page_size(test_admin_user):
    """Test users list with non-standard page size."""
    override_auth(app, test_admin_user)

    with patch("services.users.list_users_raw") as mock_list:
        with patch("services.users.count_users") as mock_count:
            with patch("routers.users.templates.TemplateResponse") as mock_template:
                from fastapi.responses import HTMLResponse

                mock_list.return_value = []
                mock_count.return_value = 0
                mock_template.return_value = HTMLResponse(content="<html>Users</html>")

                client = TestClient(app)
                response = client.get("/users/list?size=35")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Should normalize to 25


def test_users_list_with_invalid_sort_order(test_admin_user):
    """Test users list with invalid sort order."""
    override_auth(app, test_admin_user)

    with patch("services.users.list_users_raw") as mock_list:
        with patch("services.users.count_users") as mock_count:
            with patch("routers.users.templates.TemplateResponse") as mock_template:
                from fastapi.responses import HTMLResponse

                mock_list.return_value = []
                mock_count.return_value = 0
                mock_template.return_value = HTMLResponse(content="<html>Users</html>")

                client = TestClient(app)
                response = client.get("/users/list?order=invalid")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Should default to desc


def test_add_user_email_invalid_email(test_admin_user):
    """Test adding invalid email address."""
    override_auth(app, test_admin_user)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/add-email", data={"email": "invalid-email"}, follow_redirects=False
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_email" in response.headers["location"]


def test_add_user_email_already_exists(test_admin_user):
    """Test adding email that already exists."""
    from services.exceptions import ConflictError

    override_auth(app, test_admin_user)

    with patch("services.settings.is_privileged_domain") as mock_privileged:
        with patch("services.emails.add_user_email") as mock_add:
            mock_privileged.return_value = True
            mock_add.side_effect = ConflictError(
                message="Email address already exists",
                code="email_exists",
            )

            client = TestClient(app)
            response = client.post(
                "/users/user-123/add-email",
                data={"email": "existing@example.com"},
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "error=email_exists" in response.headers["location"]


def test_remove_user_email_not_found(test_admin_user):
    """Test removing non-existent email."""
    from services.exceptions import NotFoundError

    override_auth(app, test_admin_user)

    with patch("services.emails.get_email_address_by_id") as mock_get_addr:
        with patch("services.emails.delete_user_email") as mock_delete:
            mock_get_addr.return_value = None
            mock_delete.side_effect = NotFoundError(
                message="Email not found",
                code="email_not_found",
            )

            client = TestClient(app)
            response = client.post(
                "/users/user-123/remove-email/invalid-id", follow_redirects=False
            )

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "error=email_not_found" in response.headers["location"]


def test_remove_user_email_must_keep_one(test_admin_user):
    """Test cannot remove last email."""
    from services.exceptions import ValidationError

    override_auth(app, test_admin_user)

    with patch("services.emails.get_email_address_by_id") as mock_get_addr:
        with patch("services.emails.delete_user_email") as mock_delete:
            mock_get_addr.return_value = "last@example.com"
            mock_delete.side_effect = ValidationError(
                message="Cannot delete last email address",
                code="must_keep_one_email",
            )

            client = TestClient(app)
            response = client.post("/users/user-123/remove-email/email-id", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "error=must_keep_one_email" in response.headers["location"]


def test_promote_user_email_not_found(test_admin_user):
    """Test promoting non-existent email."""
    from services.exceptions import NotFoundError

    override_auth(app, test_admin_user)

    with patch("services.emails.get_primary_email") as mock_old_primary:
        with patch("services.emails.get_email_address_by_id") as mock_get_addr:
            with patch("services.emails.set_primary_email") as mock_set:
                mock_old_primary.return_value = None
                mock_get_addr.return_value = None
                mock_set.side_effect = NotFoundError(
                    message="Email not found",
                    code="email_not_found",
                )

                client = TestClient(app)
                response = client.post(
                    "/users/user-123/promote-email/invalid-id", follow_redirects=False
                )

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "error=email_not_found" in response.headers["location"]


# New user creation tests


def test_new_user_page_renders(test_admin_user):
    """Test new user page renders for admin."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        with patch("database.settings.list_privileged_domains") as mock_domains:
            from fastapi.responses import HTMLResponse

            mock_template.return_value = HTMLResponse(content="<html>New User</html>")
            mock_domains.return_value = []

            client = TestClient(app)
            response = client.get("/users/new")

            app.dependency_overrides.clear()

            assert response.status_code == 200
            mock_domains.assert_called_once()


def test_new_user_page_denied_for_regular_user(test_user):
    """Test regular user cannot access new user page."""
    override_auth(app, test_user)

    client = TestClient(app)
    response = client.get("/users/new", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_create_new_user_with_privileged_domain(test_admin_user):
    """Test creating new user with privileged domain email."""
    override_auth(app, test_admin_user)

    with patch("services.settings.is_privileged_domain") as mock_privileged:
        with patch("services.users.create_user") as mock_create:
            with patch("services.users.add_verified_email_with_nonce") as mock_add_email:
                with patch("services.users.get_tenant_name") as mock_tenant:
                    with patch(
                        "routers.users.send_new_user_privileged_domain_notification"
                    ) as mock_send:
                        mock_privileged.return_value = True
                        # Mock create_user to return a UserDetail-like object
                        mock_user = type("obj", (object,), {"id": "new-user-123"})()
                        mock_create.return_value = mock_user
                        mock_add_email.return_value = {"id": "email-123"}
                        mock_tenant.return_value = "Test Organization"

                        client = TestClient(app)
                        response = client.post(
                            "/users/new",
                            data={
                                "email": "newuser@privileged.com",
                                "first_name": "New",
                                "last_name": "User",
                                "role": "member",
                            },
                            follow_redirects=False,
                        )

                        app.dependency_overrides.clear()

                        assert response.status_code == 303
                        assert "/users/new-user-123" in response.headers["location"]
                        assert "success=user_created" in response.headers["location"]
                        mock_create.assert_called_once()
                        mock_add_email.assert_called_once()
                        # Verify org name was passed to email
                        assert mock_send.call_args[0][2] == "Test Organization"


def test_create_new_user_with_non_privileged_domain(test_admin_user):
    """Test creating new user with non-privileged domain email."""
    override_auth(app, test_admin_user)

    with patch("services.settings.is_privileged_domain") as mock_privileged:
        with patch("services.users.create_user") as mock_create:
            with patch("services.users.add_unverified_email_with_nonce") as mock_add_email:
                with patch("services.users.get_tenant_name") as mock_tenant:
                    with patch("routers.users.send_new_user_invitation") as mock_send:
                        mock_privileged.return_value = False
                        # Mock create_user to return a UserDetail-like object
                        mock_user = type("obj", (object,), {"id": "new-user-123"})()
                        mock_create.return_value = mock_user
                        mock_add_email.return_value = {
                            "id": "email-123",
                            "verify_nonce": "test-nonce",
                        }
                        mock_tenant.return_value = "Test Organization"

                        client = TestClient(app)
                        response = client.post(
                            "/users/new",
                            data={
                                "email": "newuser@example.com",
                                "first_name": "New",
                                "last_name": "User",
                                "role": "member",
                            },
                            follow_redirects=False,
                        )

                        app.dependency_overrides.clear()

                        assert response.status_code == 303
                        assert "/users/new-user-123" in response.headers["location"]
                        mock_create.assert_called_once()
                        mock_add_email.assert_called_once()
                        # Verify org name was passed to email
                        assert mock_send.call_args[0][2] == "Test Organization"


def test_create_new_user_invalid_email(test_admin_user):
    """Test creating user with invalid email."""
    override_auth(app, test_admin_user)

    client = TestClient(app)
    response = client.post(
        "/users/new",
        data={
            "email": "invalid-email",
            "first_name": "Test",
            "last_name": "User",
            "role": "member",
        },
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_email" in response.headers["location"]


def test_create_new_user_missing_name(test_admin_user):
    """Test creating user with missing name."""
    override_auth(app, test_admin_user)

    client = TestClient(app)
    response = client.post(
        "/users/new",
        data={
            "email": "test@example.com",
            "first_name": "",
            "last_name": "User",
            "role": "member",
        },
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=name_required" in response.headers["location"]


def test_create_new_user_invalid_role(test_admin_user):
    """Test creating user with invalid role."""
    override_auth(app, test_admin_user)

    client = TestClient(app)
    response = client.post(
        "/users/new",
        data={
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "role": "invalid_role",
        },
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_role" in response.headers["location"]


def test_create_new_user_admin_cannot_create_admin(test_admin_user):
    """Test regular admin cannot create admin users."""
    override_auth(app, test_admin_user)

    client = TestClient(app)
    response = client.post(
        "/users/new",
        data={
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "Admin",
            "role": "admin",
        },
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=insufficient_permissions" in response.headers["location"]


def test_create_new_user_super_admin_can_create_admin(test_super_admin_user):
    """Test super admin can create admin users."""
    override_auth(app, test_super_admin_user)

    with patch("services.settings.is_privileged_domain") as mock_privileged:
        with patch("services.users.create_user") as mock_create:
            with patch("services.users.add_verified_email_with_nonce"):
                with patch("services.users.get_tenant_name") as mock_tenant:
                    with patch("routers.users.send_new_user_privileged_domain_notification"):
                        mock_privileged.return_value = True
                        # Mock create_user to return a UserDetail-like object
                        mock_user = type("obj", (object,), {"id": "new-admin-123"})()
                        mock_create.return_value = mock_user
                        mock_tenant.return_value = "Test Organization"

                        client = TestClient(app)
                        response = client.post(
                            "/users/new",
                            data={
                                "email": "admin@example.com",
                                "first_name": "New",
                                "last_name": "Admin",
                                "role": "admin",
                            },
                            follow_redirects=False,
                        )

                        app.dependency_overrides.clear()

                        assert response.status_code == 303
                        assert "/users/new-admin-123" in response.headers["location"]
                        # Verify create_user was called
                        mock_create.assert_called_once()


def test_create_new_user_email_already_exists(test_admin_user):
    """Test creating user with existing email."""
    from services.exceptions import ConflictError

    override_auth(app, test_admin_user)

    with patch("services.settings.is_privileged_domain") as mock_privileged:
        with patch("services.users.create_user") as mock_create:
            mock_privileged.return_value = True
            # Mock create_user to raise ConflictError for existing email
            mock_create.side_effect = ConflictError(
                message="Email already exists",
                code="email_exists",
            )

            client = TestClient(app)
            response = client.post(
                "/users/new",
                data={
                    "email": "existing@example.com",
                    "first_name": "Test",
                    "last_name": "User",
                    "role": "member",
                },
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "error=email_exists" in response.headers["location"]


def test_create_new_user_creation_failed(test_admin_user):
    """Test handling of user creation failure."""
    from services.exceptions import ValidationError

    override_auth(app, test_admin_user)

    with patch("services.settings.is_privileged_domain") as mock_privileged:
        with patch("services.users.create_user") as mock_create:
            mock_privileged.return_value = True
            # Mock create_user to raise ValidationError
            mock_create.side_effect = ValidationError(
                message="Failed to create user",
                code="user_creation_failed",
            )

            client = TestClient(app)
            response = client.post(
                "/users/new",
                data={
                    "email": "test@example.com",
                    "first_name": "Test",
                    "last_name": "User",
                    "role": "member",
                },
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "error=creation_failed" in response.headers["location"]


def test_create_new_user_denied_for_regular_user(test_user):
    """Test regular user cannot create new users."""
    override_auth(app, test_user)

    client = TestClient(app)
    response = client.post(
        "/users/new",
        data={
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "role": "member",
        },
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# User List Filtering Tests
# =============================================================================


def test_users_list_with_single_role_filter(test_admin_user):
    """Test users list with single role filter."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 3
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?role=admin")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Verify roles parameter was passed to count_users
                count_call_args = mock_count.call_args[0]
                assert count_call_args[2] == ["admin"]  # roles parameter
                # Verify roles parameter was passed to list_users_raw
                list_call_args = mock_list.call_args[0]
                assert list_call_args[7] == ["admin"]  # roles parameter


def test_users_list_with_multiple_role_filter(test_admin_user):
    """Test users list with multiple role filter (comma-separated)."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 5
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?role=admin,super_admin")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                count_call_args = mock_count.call_args[0]
                assert set(count_call_args[2]) == {"admin", "super_admin"}


def test_users_list_with_invalid_role_filter(test_admin_user):
    """Test users list ignores invalid role values."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 0
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?role=invalid_role")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Invalid role should result in None (no filter)
                count_call_args = mock_count.call_args[0]
                assert count_call_args[2] is None


def test_users_list_with_mixed_valid_invalid_roles(test_admin_user):
    """Test users list filters only valid roles from mixed input."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 3
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?role=admin,invalid,member")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                count_call_args = mock_count.call_args[0]
                assert set(count_call_args[2]) == {"admin", "member"}


def test_users_list_with_single_status_filter(test_admin_user):
    """Test users list with single status filter."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 10
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?status=active")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                # Verify statuses parameter was passed
                count_call_args = mock_count.call_args[0]
                assert count_call_args[3] == ["active"]  # statuses parameter
                list_call_args = mock_list.call_args[0]
                assert list_call_args[8] == ["active"]  # statuses parameter


def test_users_list_with_multiple_status_filter(test_admin_user):
    """Test users list with multiple status filter."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 15
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?status=active,inactivated")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                count_call_args = mock_count.call_args[0]
                assert set(count_call_args[3]) == {"active", "inactivated"}


def test_users_list_with_invalid_status_filter(test_admin_user):
    """Test users list ignores invalid status values."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 0
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?status=invalid_status")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                count_call_args = mock_count.call_args[0]
                assert count_call_args[3] is None


def test_users_list_with_role_and_status_filter(test_admin_user):
    """Test users list with both role and status filters."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 2
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?role=member&status=active")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                count_call_args = mock_count.call_args[0]
                assert count_call_args[2] == ["member"]
                assert count_call_args[3] == ["active"]


def test_users_list_with_search_and_filters(test_admin_user):
    """Test users list with search, role, and status filters combined."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 1
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?search=john&role=admin&status=active")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                count_call_args = mock_count.call_args[0]
                assert count_call_args[0] == test_admin_user["tenant_id"]
                assert count_call_args[1] == "john"
                assert count_call_args[2] == ["admin"]
                assert count_call_args[3] == ["active"]


def test_users_list_with_status_sort(test_admin_user):
    """Test users list with status sorting."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 5
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?sort=status&order=asc")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                list_call_args = mock_list.call_args[0]
                assert list_call_args[2] == "status"  # sort_field
                assert list_call_args[3] == "asc"  # sort_order


def test_users_list_with_status_sort_desc(test_admin_user):
    """Test users list with status sorting descending."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 5
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?sort=status&order=desc")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                list_call_args = mock_list.call_args[0]
                assert list_call_args[2] == "status"
                assert list_call_args[3] == "desc"


def test_users_list_empty_role_filter(test_admin_user):
    """Test users list with empty role filter is treated as no filter."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 10
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?role=")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                count_call_args = mock_count.call_args[0]
                assert count_call_args[2] is None  # No roles filter


def test_users_list_filters_with_pagination(test_admin_user):
    """Test users list filters work with pagination."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 100
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?role=admin&status=active&page=2&size=50")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                count_call_args = mock_count.call_args[0]
                assert count_call_args[2] == ["admin"]
                assert count_call_args[3] == ["active"]
                list_call_args = mock_list.call_args[0]
                assert list_call_args[4] == 2  # page
                assert list_call_args[5] == 50  # page_size
                assert list_call_args[7] == ["admin"]  # roles
                assert list_call_args[8] == ["active"]  # statuses


def test_users_list_all_three_statuses(test_admin_user):
    """Test users list with all three status values."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 20
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?status=active,inactivated,anonymized")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                count_call_args = mock_count.call_args[0]
                assert set(count_call_args[3]) == {"active", "inactivated", "anonymized"}


def test_users_list_all_three_roles(test_admin_user):
    """Test users list with all three role values."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("services.users.count_users") as mock_count:
            with patch("services.users.list_users_raw") as mock_list:
                mock_count.return_value = 20
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?role=member,admin,super_admin")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                count_call_args = mock_count.call_args[0]
                assert set(count_call_args[2]) == {"member", "admin", "super_admin"}


def test_create_user_privileged_domain_creates_event_log(test_admin_user, test_tenant):
    """Verify event log created when creating user via HTML router with privileged domain."""
    from unittest.mock import patch
    from uuid import uuid4

    import database

    override_auth(app, test_admin_user)

    # Add a privileged domain for the tenant
    domain = "privileged.com"
    database.execute(
        test_tenant["id"],
        """INSERT INTO tenant_privileged_domains (tenant_id, domain, created_by)
        VALUES (:tenant_id, :domain, :created_by)""",
        {
            "tenant_id": test_tenant["id"],
            "domain": domain,
            "created_by": test_admin_user["id"],
        },
    )

    # Create user via HTML router
    unique_suffix = str(uuid4())[:8]
    new_email = f"newuser-{unique_suffix}@{domain}"

    # Mock email sending and cache to avoid warnings
    with patch("routers.users.send_new_user_privileged_domain_notification"):
        with patch("services.activity.cache.get", return_value=None):
            with patch("services.activity.cache.set", return_value=True):
                client = TestClient(app)
                response = client.post(
                    "/users/new",
                    data={
                        "email": new_email,
                        "first_name": "New",
                        "last_name": "User",
                        "role": "member",
                    },
                    follow_redirects=False,
                )

    app.dependency_overrides.clear()

    # Verify redirect indicates success
    assert response.status_code == 303
    assert "success=user_created" in response.headers["location"]

    # Extract user_id from redirect URL
    location = response.headers["location"]
    user_id = location.split("/users/")[1].split("?")[0]

    # Query event_logs table to verify event was created
    event = database.fetchone(
        test_tenant["id"],
        """
        SELECT event_type, artifact_type, artifact_id, actor_user_id, metadata_hash
        FROM event_logs
        WHERE artifact_type = 'user' AND artifact_id = :user_id
        ORDER BY created_at DESC
        LIMIT 1
        """,
        {"user_id": user_id},
    )

    # Verify event exists
    assert event is not None
    assert event["event_type"] == "user_created"
    assert event["artifact_type"] == "user"
    assert str(event["artifact_id"]) == user_id
    assert str(event["actor_user_id"]) == str(test_admin_user["id"])

    # Verify metadata was stored (metadata_hash should not be null)
    assert event["metadata_hash"] is not None

    # Get metadata to verify it includes role and email
    metadata = database.fetchone(
        database.UNSCOPED,
        "SELECT metadata FROM event_log_metadata WHERE metadata_hash = :hash",
        {"hash": event["metadata_hash"]},
    )
    assert metadata is not None
    assert "role" in metadata["metadata"]
    assert metadata["metadata"]["role"] == "member"
    assert "email" in metadata["metadata"]
    assert metadata["metadata"]["email"] == new_email


def test_create_user_non_privileged_domain_creates_event_log(test_admin_user, test_tenant):
    """Verify event log created when creating user via HTML router with non-privileged domain."""
    from unittest.mock import patch
    from uuid import uuid4

    import database

    override_auth(app, test_admin_user)

    # Use a non-privileged domain (no entry in privileged_domains table)
    domain = "nonprivileged.com"

    # Create user via HTML router
    unique_suffix = str(uuid4())[:8]
    new_email = f"newuser-{unique_suffix}@{domain}"

    # Mock email sending and cache to avoid warnings
    with patch("routers.users.send_new_user_invitation"):
        with patch("services.activity.cache.get", return_value=None):
            with patch("services.activity.cache.set", return_value=True):
                client = TestClient(app)
                response = client.post(
                    "/users/new",
                    data={
                        "email": new_email,
                        "first_name": "New",
                        "last_name": "User",
                        "role": "member",
                    },
                    follow_redirects=False,
                )

    app.dependency_overrides.clear()

    # Verify redirect indicates success
    assert response.status_code == 303
    assert "success=user_created" in response.headers["location"]

    # Extract user_id from redirect URL
    location = response.headers["location"]
    user_id = location.split("/users/")[1].split("?")[0]

    # Query event_logs table to verify event was created
    event = database.fetchone(
        test_tenant["id"],
        """
        SELECT event_type, artifact_type, artifact_id, actor_user_id, metadata_hash
        FROM event_logs
        WHERE artifact_type = 'user' AND artifact_id = :user_id
        ORDER BY created_at DESC
        LIMIT 1
        """,
        {"user_id": user_id},
    )

    # Verify event exists
    assert event is not None
    assert event["event_type"] == "user_created"
    assert event["artifact_type"] == "user"
    assert str(event["artifact_id"]) == user_id
    assert str(event["actor_user_id"]) == str(test_admin_user["id"])

    # Verify metadata was stored
    assert event["metadata_hash"] is not None

    # Get metadata to verify it includes role and email
    metadata = database.fetchone(
        database.UNSCOPED,
        "SELECT metadata FROM event_log_metadata WHERE metadata_hash = :hash",
        {"hash": event["metadata_hash"]},
    )
    assert metadata is not None
    assert "role" in metadata["metadata"]
    assert metadata["metadata"]["role"] == "member"
    assert "email" in metadata["metadata"]
    assert metadata["metadata"]["email"] == new_email


def test_password_set_link_format_privileged_domain(test_admin_user, test_tenant):
    """Test password set URL format for privileged domain users."""
    from uuid import UUID, uuid4

    import database

    override_auth(app, test_admin_user)

    # Add a privileged domain for the tenant
    domain = "privileged-test.com"
    database.execute(
        test_tenant["id"],
        """INSERT INTO tenant_privileged_domains (tenant_id, domain, created_by)
        VALUES (:tenant_id, :domain, :created_by)""",
        {
            "tenant_id": test_tenant["id"],
            "domain": domain,
            "created_by": test_admin_user["id"],
        },
    )

    # Patch the email sending function to capture the password_set_url
    with patch("routers.users.send_new_user_privileged_domain_notification") as mock_send:
        # Create user via HTML router
        unique_suffix = str(uuid4())[:8]
        new_email = f"pwdtest-{unique_suffix}@{domain}"

        client = TestClient(app)
        response = client.post(
            "/users/new",
            data={
                "email": new_email,
                "first_name": "Password",
                "last_name": "Test",
                "role": "member",
            },
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        # Verify redirect indicates success
        assert response.status_code == 303
        assert "success=user_created" in response.headers["location"]

        # Verify email was sent with password set link
        assert mock_send.called
        call_args = mock_send.call_args[0]
        password_set_url = call_args[3]  # 4th argument is password_set_url

        # Verify URL format: should contain /set-password?email_id={uuid}
        assert "/set-password?email_id=" in password_set_url

        # Extract email_id from URL
        email_id = password_set_url.split("email_id=")[1]

        # Verify email_id is a valid UUID
        try:
            UUID(email_id)  # Will raise ValueError if not a valid UUID
        except ValueError:
            pytest.fail(f"email_id '{email_id}' is not a valid UUID")


def test_set_password_with_invalid_email_id_returns_error(test_tenant):
    """Test /set-password route with non-existent email_id returns error redirect."""
    from uuid import uuid4

    client = TestClient(app)

    # Use a valid UUID format that doesn't exist in database
    non_existent_email_id = str(uuid4())

    # Try to access /set-password with non-existent email_id
    response = client.get(
        f"/set-password?email_id={non_existent_email_id}",
        headers={"host": f"{test_tenant['subdomain']}.pageloom.localhost"},
        follow_redirects=False,
    )

    # Should redirect to login with error
    assert response.status_code == 303
    assert "/login" in response.headers["location"]
    assert "error=invalid_link" in response.headers["location"]


# =============================================================================
# IdP Assignment Route Tests (update_user_idp_route)
# =============================================================================


def test_update_user_idp_success(test_super_admin_user):
    """Test super_admin can assign user to an IdP."""
    override_auth(app, test_super_admin_user)

    with patch("routers.users.saml_service.assign_user_idp") as mock_assign:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-idp",
            data={"saml_idp_id": "idp-456"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?success=idp_updated" in response.headers["location"]
        mock_assign.assert_called_once()
        call_args = mock_assign.call_args
        assert call_args[1]["user_id"] == "user-123"
        assert call_args[1]["saml_idp_id"] == "idp-456"


def test_update_user_idp_remove_idp(test_super_admin_user):
    """Test super_admin can remove user from IdP (set to password-only)."""
    override_auth(app, test_super_admin_user)

    with patch("routers.users.saml_service.assign_user_idp") as mock_assign:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-idp",
            data={"saml_idp_id": ""},  # Empty = password-only
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "success=idp_updated" in response.headers["location"]
        mock_assign.assert_called_once()
        # Empty string should be converted to None
        assert mock_assign.call_args[1]["saml_idp_id"] is None


def test_update_user_idp_denied_for_admin(test_admin_user):
    """Test admin cannot assign user to IdP (super_admin only)."""
    override_auth(app, test_admin_user)

    with patch("routers.users.saml_service.assign_user_idp") as mock_assign:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-idp",
            data={"saml_idp_id": "idp-456"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_assign.assert_not_called()


def test_update_user_idp_denied_for_member(test_user):
    """Test member cannot assign user to IdP."""
    override_auth(app, test_user)

    with patch("routers.users.saml_service.assign_user_idp") as mock_assign:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-idp",
            data={"saml_idp_id": "idp-456"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_assign.assert_not_called()


def test_update_user_idp_user_not_found(test_super_admin_user):
    """Test update IdP returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(app, test_super_admin_user)

    with patch("routers.users.saml_service.assign_user_idp") as mock_assign:
        mock_assign.side_effect = NotFoundError(message="User not found", code="user_not_found")

        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-idp",
            data={"saml_idp_id": "idp-456"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?error=user_not_found" in response.headers["location"]


def test_update_user_idp_idp_not_found(test_super_admin_user):
    """Test update IdP returns error when IdP not found."""
    from services.exceptions import NotFoundError

    override_auth(app, test_super_admin_user)

    with patch("routers.users.saml_service.assign_user_idp") as mock_assign:
        mock_assign.side_effect = NotFoundError(message="IdP not found", code="idp_not_found")

        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-idp",
            data={"saml_idp_id": "idp-456"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?error=idp_not_found" in response.headers["location"]


def test_update_user_idp_validation_error(test_super_admin_user):
    """Test update IdP returns error on validation failure."""
    from services.exceptions import ValidationError

    override_auth(app, test_super_admin_user)

    with patch("routers.users.saml_service.assign_user_idp") as mock_assign:
        mock_assign.side_effect = ValidationError(
            message="Cannot assign to disabled IdP", code="idp_disabled"
        )

        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-idp",
            data={"saml_idp_id": "idp-456"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?error=idp_disabled" in response.headers["location"]


def test_update_user_idp_service_error(test_super_admin_user):
    """Test update IdP renders error page on service error."""
    from services.exceptions import ServiceError

    override_auth(app, test_super_admin_user)

    with patch("routers.users.saml_service.assign_user_idp") as mock_assign:
        with patch("routers.users.render_error_page") as mock_error_page:
            from fastapi.responses import HTMLResponse

            mock_assign.side_effect = ServiceError(message="Database error")
            mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

            client = TestClient(app)
            response = client.post(
                "/users/user-123/update-idp",
                data={"saml_idp_id": "idp-456"},
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 500
            mock_error_page.assert_called_once()


# =============================================================================
# Inactivation Route Tests (inactivate_user_route)
# =============================================================================


def test_inactivate_user_success(test_admin_user):
    """Test admin can inactivate a user."""
    override_auth(app, test_admin_user)

    with patch("routers.users.users_service.inactivate_user") as mock_inactivate:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/inactivate",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?success=user_inactivated" in response.headers["location"]
        mock_inactivate.assert_called_once()


def test_inactivate_user_denied_for_member(test_user):
    """Test member cannot inactivate a user."""
    override_auth(app, test_user)

    with patch("routers.users.users_service.inactivate_user") as mock_inactivate:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/inactivate",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_inactivate.assert_not_called()


def test_inactivate_user_not_found(test_admin_user):
    """Test inactivate returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(app, test_admin_user)

    with patch("routers.users.users_service.inactivate_user") as mock_inactivate:
        mock_inactivate.side_effect = NotFoundError(message="User not found", code="user_not_found")

        client = TestClient(app)
        response = client.post(
            "/users/user-123/inactivate",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/list?error=user_not_found" in response.headers["location"]


def test_inactivate_user_validation_error(test_admin_user):
    """Test inactivate returns error on validation failure (e.g., already inactivated)."""
    from services.exceptions import ValidationError

    override_auth(app, test_admin_user)

    with patch("routers.users.users_service.inactivate_user") as mock_inactivate:
        mock_inactivate.side_effect = ValidationError(
            message="User already inactivated", code="already_inactivated"
        )

        client = TestClient(app)
        response = client.post(
            "/users/user-123/inactivate",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?error=already_inactivated" in response.headers["location"]


def test_inactivate_user_service_error(test_admin_user):
    """Test inactivate renders error page on service error."""
    from services.exceptions import ServiceError

    override_auth(app, test_admin_user)

    with patch("routers.users.users_service.inactivate_user") as mock_inactivate:
        with patch("routers.users.render_error_page") as mock_error_page:
            from fastapi.responses import HTMLResponse

            mock_inactivate.side_effect = ServiceError(message="Database error")
            mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

            client = TestClient(app)
            response = client.post(
                "/users/user-123/inactivate",
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 500
            mock_error_page.assert_called_once()


# =============================================================================
# Reactivation Route Tests (reactivate_user_route)
# =============================================================================


def test_reactivate_user_success(test_admin_user):
    """Test admin can reactivate a user."""
    override_auth(app, test_admin_user)

    with patch("routers.users.users_service.reactivate_user") as mock_reactivate:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/reactivate",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?success=user_reactivated" in response.headers["location"]
        mock_reactivate.assert_called_once()


def test_reactivate_user_denied_for_member(test_user):
    """Test member cannot reactivate a user."""
    override_auth(app, test_user)

    with patch("routers.users.users_service.reactivate_user") as mock_reactivate:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/reactivate",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_reactivate.assert_not_called()


def test_reactivate_user_not_found(test_admin_user):
    """Test reactivate returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(app, test_admin_user)

    with patch("routers.users.users_service.reactivate_user") as mock_reactivate:
        mock_reactivate.side_effect = NotFoundError(message="User not found", code="user_not_found")

        client = TestClient(app)
        response = client.post(
            "/users/user-123/reactivate",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/list?error=user_not_found" in response.headers["location"]


def test_reactivate_user_validation_error(test_admin_user):
    """Test reactivate returns error on validation failure (e.g., already active)."""
    from services.exceptions import ValidationError

    override_auth(app, test_admin_user)

    with patch("routers.users.users_service.reactivate_user") as mock_reactivate:
        mock_reactivate.side_effect = ValidationError(
            message="User is already active", code="already_active"
        )

        client = TestClient(app)
        response = client.post(
            "/users/user-123/reactivate",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?error=already_active" in response.headers["location"]


def test_reactivate_user_service_error(test_admin_user):
    """Test reactivate renders error page on service error."""
    from services.exceptions import ServiceError

    override_auth(app, test_admin_user)

    with patch("routers.users.users_service.reactivate_user") as mock_reactivate:
        with patch("routers.users.render_error_page") as mock_error_page:
            from fastapi.responses import HTMLResponse

            mock_reactivate.side_effect = ServiceError(message="Database error")
            mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

            client = TestClient(app)
            response = client.post(
                "/users/user-123/reactivate",
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 500
            mock_error_page.assert_called_once()


# =============================================================================
# Anonymization Route Tests (anonymize_user_route)
# =============================================================================


def test_anonymize_user_success(test_super_admin_user):
    """Test super_admin can anonymize a user."""
    override_auth(app, test_super_admin_user)

    with patch("routers.users.users_service.anonymize_user") as mock_anonymize:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/anonymize",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?success=user_anonymized" in response.headers["location"]
        mock_anonymize.assert_called_once()


def test_anonymize_user_denied_for_admin(test_admin_user):
    """Test admin cannot anonymize a user (super_admin only)."""
    override_auth(app, test_admin_user)

    with patch("routers.users.users_service.anonymize_user") as mock_anonymize:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/anonymize",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_anonymize.assert_not_called()


def test_anonymize_user_denied_for_member(test_user):
    """Test member cannot anonymize a user."""
    override_auth(app, test_user)

    with patch("routers.users.users_service.anonymize_user") as mock_anonymize:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/anonymize",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_anonymize.assert_not_called()


def test_anonymize_user_not_found(test_super_admin_user):
    """Test anonymize returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(app, test_super_admin_user)

    with patch("routers.users.users_service.anonymize_user") as mock_anonymize:
        mock_anonymize.side_effect = NotFoundError(message="User not found", code="user_not_found")

        client = TestClient(app)
        response = client.post(
            "/users/user-123/anonymize",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/list?error=user_not_found" in response.headers["location"]


def test_anonymize_user_validation_error(test_super_admin_user):
    """Test anonymize returns error on validation failure (e.g., cannot anonymize self)."""
    from services.exceptions import ValidationError

    override_auth(app, test_super_admin_user)

    with patch("routers.users.users_service.anonymize_user") as mock_anonymize:
        mock_anonymize.side_effect = ValidationError(
            message="Cannot anonymize your own account", code="cannot_anonymize_self"
        )

        client = TestClient(app)
        response = client.post(
            "/users/user-123/anonymize",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?error=cannot_anonymize_self" in response.headers["location"]


def test_anonymize_user_service_error(test_super_admin_user):
    """Test anonymize renders error page on service error."""
    from services.exceptions import ServiceError

    override_auth(app, test_super_admin_user)

    with patch("routers.users.users_service.anonymize_user") as mock_anonymize:
        with patch("routers.users.render_error_page") as mock_error_page:
            from fastapi.responses import HTMLResponse

            mock_anonymize.side_effect = ServiceError(message="Database error")
            mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

            client = TestClient(app)
            response = client.post(
                "/users/user-123/anonymize",
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 500
            mock_error_page.assert_called_once()


# =============================================================================
# Reset MFA Tests
# =============================================================================


def test_reset_mfa_success(test_admin_user):
    """Test admin can reset MFA for a user."""
    override_auth(app, test_admin_user)

    with patch("routers.users.mfa_service.reset_user_mfa") as mock_reset:
        with patch(
            "routers.users.emails_service.get_primary_email",
            return_value="user@example.com",
        ):
            with patch("routers.users.send_mfa_reset_notification") as mock_email:
                client = TestClient(app)
                response = client.post(
                    "/users/user-123/reset-mfa",
                    follow_redirects=False,
                )

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "/users/user-123?success=mfa_reset" in response.headers["location"]
                mock_reset.assert_called_once()
                mock_email.assert_called_once()
                # Verify email args
                call_args = mock_email.call_args
                assert call_args[0][0] == "user@example.com"


def test_reset_mfa_denied_for_member(test_user):
    """Test member cannot reset MFA for a user."""
    override_auth(app, test_user)

    with patch("routers.users.mfa_service.reset_user_mfa") as mock_reset:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/reset-mfa",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_reset.assert_not_called()


def test_reset_mfa_user_not_found(test_admin_user):
    """Test reset MFA returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(app, test_admin_user)

    with patch("routers.users.mfa_service.reset_user_mfa") as mock_reset:
        mock_reset.side_effect = NotFoundError(message="User not found", code="user_not_found")

        client = TestClient(app)
        response = client.post(
            "/users/user-123/reset-mfa",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/list?error=user_not_found" in response.headers["location"]


def test_reset_mfa_validation_error(test_admin_user):
    """Test reset MFA returns error on validation failure."""
    from services.exceptions import ValidationError

    override_auth(app, test_admin_user)

    with patch("routers.users.mfa_service.reset_user_mfa") as mock_reset:
        mock_reset.side_effect = ValidationError(message="MFA not enabled", code="mfa_not_enabled")

        client = TestClient(app)
        response = client.post(
            "/users/user-123/reset-mfa",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123?error=mfa_not_enabled" in response.headers["location"]


def test_reset_mfa_service_error(test_admin_user):
    """Test reset MFA renders error page on service error."""
    from services.exceptions import ServiceError

    override_auth(app, test_admin_user)

    with patch("routers.users.mfa_service.reset_user_mfa") as mock_reset:
        with patch("routers.users.render_error_page") as mock_error_page:
            from fastapi.responses import HTMLResponse

            mock_reset.side_effect = ServiceError(message="Database error")
            mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

            client = TestClient(app)
            response = client.post(
                "/users/user-123/reset-mfa",
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 500
            mock_error_page.assert_called_once()


def test_reset_mfa_email_includes_admin_name_and_timestamp(test_admin_user):
    """Test email notification includes admin name and formatted timestamp."""
    override_auth(app, test_admin_user)

    with patch("routers.users.mfa_service.reset_user_mfa"):
        with patch(
            "routers.users.emails_service.get_primary_email",
            return_value="user@example.com",
        ):
            with patch("routers.users.send_mfa_reset_notification") as mock_email:
                client = TestClient(app)
                client.post("/users/user-123/reset-mfa", follow_redirects=False)

                app.dependency_overrides.clear()

                mock_email.assert_called_once()
                call_args = mock_email.call_args[0]
                # arg 0: email address
                assert call_args[0] == "user@example.com"
                # arg 1: admin name (first_name + last_name from fixture)
                admin_name = call_args[1]
                assert isinstance(admin_name, str)
                assert len(admin_name) > 0
                # arg 2: timestamp string in expected format
                reset_time = call_args[2]
                assert "UTC" in reset_time


def test_reset_mfa_no_email_notification_when_no_primary_email(test_admin_user):
    """Test no email notification sent when user has no primary email."""
    override_auth(app, test_admin_user)

    with patch("routers.users.mfa_service.reset_user_mfa") as mock_reset:
        with patch("routers.users.emails_service.get_primary_email", return_value=None):
            with patch("routers.users.send_mfa_reset_notification") as mock_email:
                client = TestClient(app)
                response = client.post(
                    "/users/user-123/reset-mfa",
                    follow_redirects=False,
                )

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "/users/user-123?success=mfa_reset" in response.headers["location"]
                mock_reset.assert_called_once()
                mock_email.assert_not_called()


# =============================================================================
# Users Index Permission & Fallback Tests
# =============================================================================


def test_users_index_no_permission_redirects_to_account(test_user):
    """Test users index redirects to /account when user has no /users access."""
    override_auth(app, test_user)

    # Mock has_page_access to return False for /users
    with patch("routers.users.has_page_access", return_value=False):
        client = TestClient(app)
        response = client.get("/users/", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/account"


def test_users_index_fallback_to_account(test_user):
    """Test users index falls back to /account when no children are accessible."""
    override_auth(app, test_user)

    with patch("routers.users.has_page_access", return_value=True):
        with patch("routers.users.get_first_accessible_child", return_value=None):
            client = TestClient(app)
            response = client.get("/users/", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert response.headers["location"] == "/account"


# =============================================================================
# Update User Name Error Path Tests
# =============================================================================


def test_update_user_name_not_found(test_admin_user):
    """Test update name returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(app, test_admin_user)

    with patch("services.users.update_user") as mock_update:
        mock_update.side_effect = NotFoundError(message="User not found", code="user_not_found")

        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-name",
            data={"first_name": "New", "last_name": "Name"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/list?error=user_not_found" in response.headers["location"]


def test_update_user_name_service_error(test_admin_user):
    """Test update name renders error page on service error."""
    from services.exceptions import ServiceError

    override_auth(app, test_admin_user)

    with patch("services.users.update_user") as mock_update:
        with patch("routers.users.render_error_page") as mock_error_page:
            from fastapi.responses import HTMLResponse

            mock_update.side_effect = ServiceError(message="Database error")
            mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

            client = TestClient(app)
            response = client.post(
                "/users/user-123/update-name",
                data={"first_name": "New", "last_name": "Name"},
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 500
            mock_error_page.assert_called_once()


def test_update_user_name_denied_for_member(test_user):
    """Test member cannot update user name."""
    override_auth(app, test_user)

    with patch("services.users.update_user") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-name",
            data={"first_name": "New", "last_name": "Name"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_update.assert_not_called()


# =============================================================================
# Update User Role Error Path Tests
# =============================================================================


def test_update_user_role_not_found(test_super_admin_user):
    """Test update role returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(app, test_super_admin_user)

    with patch("services.users.update_user") as mock_update:
        mock_update.side_effect = NotFoundError(message="User not found", code="user_not_found")

        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-role",
            data={"role": "admin"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/list?error=user_not_found" in response.headers["location"]


def test_update_user_role_last_super_admin(test_super_admin_user):
    """Test update role prevents demoting last super_admin."""
    from services.exceptions import ValidationError

    override_auth(app, test_super_admin_user)

    with patch("services.users.update_user") as mock_update:
        mock_update.side_effect = ValidationError(
            message="Cannot demote last super admin", code="last_super_admin"
        )

        client = TestClient(app)
        response = client.post(
            "/users/other-user/update-role",
            data={"role": "member"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=cannot_demote_last_super_admin" in response.headers["location"]


def test_update_user_role_validation_error(test_super_admin_user):
    """Test update role renders error page on other validation errors."""
    from services.exceptions import ValidationError

    override_auth(app, test_super_admin_user)

    with patch("services.users.update_user") as mock_update:
        with patch("routers.users.render_error_page") as mock_error_page:
            from fastapi.responses import HTMLResponse

            mock_update.side_effect = ValidationError(
                message="Some other error", code="other_error"
            )
            mock_error_page.return_value = HTMLResponse(content="Error", status_code=400)

            client = TestClient(app)
            response = client.post(
                "/users/other-user/update-role",
                data={"role": "admin"},
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 400
            mock_error_page.assert_called_once()


def test_update_user_role_service_error(test_super_admin_user):
    """Test update role renders error page on service error."""
    from services.exceptions import ServiceError

    override_auth(app, test_super_admin_user)

    with patch("services.users.update_user") as mock_update:
        with patch("routers.users.render_error_page") as mock_error_page:
            from fastapi.responses import HTMLResponse

            mock_update.side_effect = ServiceError(message="Database error")
            mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

            client = TestClient(app)
            response = client.post(
                "/users/other-user/update-role",
                data={"role": "admin"},
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 500
            mock_error_page.assert_called_once()


# =============================================================================
# Add User Email Error Path Tests
# =============================================================================


def test_add_user_email_denied_for_member(test_user):
    """Test member cannot add email to other users."""
    override_auth(app, test_user)

    with patch("services.emails.add_user_email") as mock_add:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/add-email",
            data={"email": "new@example.com"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_add.assert_not_called()


def test_add_user_email_not_found(test_admin_user):
    """Test add email returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(app, test_admin_user)

    with patch("services.settings.is_privileged_domain", return_value=True):
        with patch("services.emails.add_user_email") as mock_add:
            mock_add.side_effect = NotFoundError(message="User not found", code="user_not_found")

            client = TestClient(app)
            response = client.post(
                "/users/user-123/add-email",
                data={"email": "new@privileged.com"},
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "/users/list?error=user_not_found" in response.headers["location"]


def test_add_user_email_service_error(test_admin_user):
    """Test add email renders error page on service error."""
    from services.exceptions import ServiceError

    override_auth(app, test_admin_user)

    with patch("services.settings.is_privileged_domain", return_value=True):
        with patch("services.emails.add_user_email") as mock_add:
            with patch("routers.users.render_error_page") as mock_error_page:
                from fastapi.responses import HTMLResponse

                mock_add.side_effect = ServiceError(message="Database error")
                mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

                client = TestClient(app)
                response = client.post(
                    "/users/user-123/add-email",
                    data={"email": "new@privileged.com"},
                    follow_redirects=False,
                )

                app.dependency_overrides.clear()

                assert response.status_code == 500
                mock_error_page.assert_called_once()


# =============================================================================
# Remove User Email Error Path Tests
# =============================================================================


def test_remove_user_email_denied_for_member(test_user):
    """Test member cannot remove emails from other users."""
    override_auth(app, test_user)

    with patch("services.emails.delete_user_email") as mock_delete:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/remove-email/email-456",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_delete.assert_not_called()


def test_remove_user_email_service_error(test_admin_user):
    """Test remove email renders error page on service error."""
    from services.exceptions import ServiceError

    override_auth(app, test_admin_user)

    with patch("services.emails.get_email_address_by_id", return_value="old@example.com"):
        with patch("services.emails.delete_user_email") as mock_delete:
            with patch("routers.users.render_error_page") as mock_error_page:
                from fastapi.responses import HTMLResponse

                mock_delete.side_effect = ServiceError(message="Database error")
                mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

                client = TestClient(app)
                response = client.post(
                    "/users/user-123/remove-email/email-456",
                    follow_redirects=False,
                )

                app.dependency_overrides.clear()

                assert response.status_code == 500
                mock_error_page.assert_called_once()


# =============================================================================
# Promote User Email Error Path Tests
# =============================================================================


def test_promote_user_email_denied_for_member(test_user):
    """Test member cannot promote emails for other users."""
    override_auth(app, test_user)

    with patch("services.emails.set_primary_email") as mock_promote:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/promote-email/email-456",
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        mock_promote.assert_not_called()


def test_promote_user_email_not_verified(test_admin_user):
    """Test promote email returns error when email not verified."""
    from services.exceptions import ValidationError

    override_auth(app, test_admin_user)

    with patch("services.emails.get_primary_email", return_value="old@example.com"):
        with patch("services.emails.get_email_address_by_id", return_value="new@example.com"):
            with patch("services.emails.set_primary_email") as mock_promote:
                mock_promote.side_effect = ValidationError(
                    message="Email not verified", code="email_not_verified"
                )

                client = TestClient(app)
                response = client.post(
                    "/users/user-123/promote-email/email-456",
                    follow_redirects=False,
                )

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "error=email_not_verified" in response.headers["location"]


def test_promote_user_email_validation_error(test_admin_user):
    """Test promote email renders error page on other validation errors."""
    from services.exceptions import ValidationError

    override_auth(app, test_admin_user)

    with patch("services.emails.get_primary_email", return_value="old@example.com"):
        with patch("services.emails.get_email_address_by_id", return_value="new@example.com"):
            with patch("services.emails.set_primary_email") as mock_promote:
                with patch("routers.users.render_error_page") as mock_error_page:
                    from fastapi.responses import HTMLResponse

                    mock_promote.side_effect = ValidationError(
                        message="Other error", code="other_error"
                    )
                    mock_error_page.return_value = HTMLResponse(content="Error", status_code=400)

                    client = TestClient(app)
                    response = client.post(
                        "/users/user-123/promote-email/email-456",
                        follow_redirects=False,
                    )

                    app.dependency_overrides.clear()

                    assert response.status_code == 400
                    mock_error_page.assert_called_once()


def test_promote_user_email_service_error(test_admin_user):
    """Test promote email renders error page on service error."""
    from services.exceptions import ServiceError

    override_auth(app, test_admin_user)

    with patch("services.emails.get_primary_email", return_value="old@example.com"):
        with patch("services.emails.get_email_address_by_id", return_value="new@example.com"):
            with patch("services.emails.set_primary_email") as mock_promote:
                with patch("routers.users.render_error_page") as mock_error_page:
                    from fastapi.responses import HTMLResponse

                    mock_promote.side_effect = ServiceError(message="Database error")
                    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

                    client = TestClient(app)
                    response = client.post(
                        "/users/user-123/promote-email/email-456",
                        follow_redirects=False,
                    )

                    app.dependency_overrides.clear()

                    assert response.status_code == 500
                    mock_error_page.assert_called_once()
