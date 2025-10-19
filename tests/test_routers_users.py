"""Tests for routers/users.py endpoints."""

from unittest.mock import patch

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
        with patch("database.users.count_users") as mock_count:
            with patch("database.users.list_users") as mock_list:
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

        with patch("database.users.count_users") as mock_count:
            with patch("database.users.list_users") as mock_list:
                mock_count.return_value = 2
                mock_list.return_value = []

                client = TestClient(app)
                response = client.get("/users/list?search=john")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_count.assert_called_once_with(test_admin_user["tenant_id"], "john")


def test_users_list_with_sorting(test_admin_user):
    """Test users list with custom sorting."""
    override_auth(app, test_admin_user)

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Users List</html>")

        with patch("database.users.count_users") as mock_count:
            with patch("database.users.list_users") as mock_list:
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

        with patch("database.users.count_users") as mock_count:
            with patch("database.users.list_users") as mock_list:
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

        with patch("database.users.count_users") as mock_count:
            with patch("database.users.list_users") as mock_list:
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
    override_auth(app, test_admin_user)

    target_user = {
        "id": "user-123",
        "first_name": "Test",
        "last_name": "User",
        "role": "member",
    }

    with patch("routers.users.templates.TemplateResponse") as mock_template:
        with patch("database.users.get_user_by_id") as mock_get:
            with patch("database.user_emails.list_user_emails") as mock_emails:
                with patch("database.settings.list_privileged_domains") as mock_domains:
                    from fastapi.responses import HTMLResponse

                    mock_template.return_value = HTMLResponse(content="<html>User Detail</html>")
                    mock_get.return_value = target_user
                    mock_emails.return_value = []
                    mock_domains.return_value = []

                    client = TestClient(app)
                    response = client.get("/users/user-123")

                    app.dependency_overrides.clear()

                    assert response.status_code == 200
                    mock_get.assert_called_once_with(test_admin_user["tenant_id"], "user-123")


def test_user_detail_not_found(test_admin_user):
    """Test user detail redirects when user not found."""
    override_auth(app, test_admin_user)

    with patch("database.users.get_user_by_id") as mock_get:
        mock_get.return_value = None

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
    override_auth(app, test_admin_user)

    with patch("database.users.update_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-name",
            data={"first_name": "New", "last_name": "Name"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/users/user-123" in response.headers["location"]
        mock_update.assert_called_once_with(test_admin_user["tenant_id"], "user-123", "New", "Name")


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
    override_auth(app, test_super_admin_user)

    with patch("database.users.update_user_role") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/users/user-123/update-role",
            data={"role": "admin"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "success=role_updated" in response.headers["location"]
        mock_update.assert_called_once_with(test_super_admin_user["tenant_id"], "user-123", "admin")


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
    override_auth(app, test_admin_user)

    with patch("database.user_emails.email_exists") as mock_exists:
        with patch("database.settings.privileged_domain_exists") as mock_privileged:
            with patch("database.user_emails.add_verified_email") as mock_add:
                with patch("database.user_emails.get_primary_email") as mock_primary:
                    with patch(
                        "routers.users.send_secondary_email_added_notification"
                    ) as mock_send:
                        mock_exists.return_value = False
                        mock_privileged.return_value = True
                        mock_primary.return_value = {"email": "primary@example.com"}

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

    with patch("database.user_emails.email_exists") as mock_exists:
        with patch("database.settings.privileged_domain_exists") as mock_privileged:
            mock_exists.return_value = False
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

    with patch("database.user_emails.get_email_by_id") as mock_get:
        with patch("database.user_emails.count_user_emails") as mock_count:
            with patch("database.user_emails.list_user_emails") as mock_list:
                with patch("database.user_emails.delete_email") as mock_delete:
                    with patch("database.user_emails.get_primary_email") as mock_primary:
                        with patch(
                            "routers.users.send_secondary_email_removed_notification"
                        ) as mock_send:
                            mock_get.return_value = {"id": "email-id", "is_primary": False}
                            mock_count.return_value = 2
                            mock_list.return_value = [
                                {"id": "email-id", "email": "secondary@example.com"}
                            ]
                            mock_primary.return_value = {"email": "primary@example.com"}

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
    override_auth(app, test_admin_user)

    with patch("database.user_emails.get_email_by_id") as mock_get:
        with patch("database.user_emails.delete_email") as mock_delete:
            mock_get.return_value = {"id": "email-id", "is_primary": True}

            client = TestClient(app)
            response = client.post("/users/user-123/remove-email/email-id", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "error=cannot_remove_primary" in response.headers["location"]
            mock_delete.assert_not_called()


def test_promote_user_email_success(test_admin_user):
    """Test promoting secondary email to primary."""
    override_auth(app, test_admin_user)

    with patch("database.user_emails.get_email_by_id") as mock_get:
        with patch("database.user_emails.get_primary_email") as mock_old_primary:
            with patch("database.user_emails.list_user_emails") as mock_list:
                with patch("database.user_emails.unset_primary_emails") as mock_unset:
                    with patch("database.user_emails.set_primary_email") as mock_set:
                        with patch(
                            "routers.users.send_primary_email_changed_notification"
                        ) as mock_send:
                            mock_get.return_value = {"id": "email-id", "is_primary": False}
                            mock_old_primary.return_value = {"email": "old@example.com"}
                            mock_list.return_value = [
                                {"id": "email-id", "email": "new@example.com"}
                            ]

                            client = TestClient(app)
                            response = client.post(
                                "/users/user-123/promote-email/email-id", follow_redirects=False
                            )

                            app.dependency_overrides.clear()

                            assert response.status_code == 303
                            assert "success=email_promoted" in response.headers["location"]
                            mock_unset.assert_called_once()
                            mock_set.assert_called_once()
                            mock_send.assert_called_once()


def test_promote_user_email_already_primary(test_admin_user):
    """Test cannot promote already primary email."""
    override_auth(app, test_admin_user)

    with patch("database.user_emails.get_email_by_id") as mock_get:
        with patch("database.user_emails.set_primary_email") as mock_set:
            mock_get.return_value = {"id": "email-id", "is_primary": True}

            client = TestClient(app)
            response = client.post("/users/user-123/promote-email/email-id", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "error=already_primary" in response.headers["location"]
            mock_set.assert_not_called()


def test_users_list_with_locale_collation(test_admin_user):
    """Test users list with locale-specific collation."""
    user_with_locale = {**test_admin_user, "locale": "sv_SE"}
    override_auth(app, user_with_locale)

    with patch("database.users.check_collation_exists") as mock_check:
        with patch("database.users.list_users") as mock_list:
            with patch("database.users.count_users") as mock_count:
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
                    # Check collation was passed to list_users
                    mock_list.assert_called_once()
                    call_args = mock_list.call_args
                    assert call_args[0][6] == "sv-SE-x-icu"  # collation parameter


def test_users_list_with_invalid_page_param(test_admin_user):
    """Test users list with invalid page parameter."""
    override_auth(app, test_admin_user)

    with patch("database.users.list_users") as mock_list:
        with patch("database.users.count_users") as mock_count:
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

    with patch("database.users.list_users") as mock_list:
        with patch("database.users.count_users") as mock_count:
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

    with patch("database.users.list_users") as mock_list:
        with patch("database.users.count_users") as mock_count:
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

    with patch("database.users.list_users") as mock_list:
        with patch("database.users.count_users") as mock_count:
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
    override_auth(app, test_admin_user)

    with patch("database.user_emails.email_exists") as mock_exists:
        mock_exists.return_value = True

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
    override_auth(app, test_admin_user)

    with patch("database.user_emails.get_email_by_id") as mock_get:
        mock_get.return_value = None

        client = TestClient(app)
        response = client.post("/users/user-123/remove-email/invalid-id", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=email_not_found" in response.headers["location"]


def test_remove_user_email_must_keep_one(test_admin_user):
    """Test cannot remove last email."""
    override_auth(app, test_admin_user)

    with patch("database.user_emails.get_email_by_id") as mock_get:
        with patch("database.user_emails.count_user_emails") as mock_count:
            mock_get.return_value = {"id": "email-id", "is_primary": False}
            mock_count.return_value = 1

            client = TestClient(app)
            response = client.post("/users/user-123/remove-email/email-id", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "error=must_keep_one_email" in response.headers["location"]


def test_promote_user_email_not_found(test_admin_user):
    """Test promoting non-existent email."""
    override_auth(app, test_admin_user)

    with patch("database.user_emails.get_email_by_id") as mock_get:
        mock_get.return_value = None

        client = TestClient(app)
        response = client.post("/users/user-123/promote-email/invalid-id", follow_redirects=False)

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

    with patch("database.user_emails.email_exists") as mock_exists:
        with patch("database.settings.privileged_domain_exists") as mock_privileged:
            with patch("database.users.create_user") as mock_create:
                with patch("database.user_emails.add_verified_email") as mock_add_email:
                    with patch("database.user_emails.set_primary_email") as mock_set_primary:
                        with patch("database.tenants.get_tenant_by_id") as mock_tenant:
                            with patch(
                                "routers.users.send_new_user_privileged_domain_notification"
                            ) as mock_send:
                                mock_exists.return_value = False
                                mock_privileged.return_value = True
                                mock_create.return_value = {"user_id": "new-user-123"}
                                mock_add_email.return_value = {"id": "email-123"}
                                mock_tenant.return_value = {
                                    "id": "tenant-123",
                                    "name": "Test Organization",
                                }

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
                                mock_set_primary.assert_called_once()
                                # Verify org name was passed to email
                                assert mock_send.call_args[0][2] == "Test Organization"


def test_create_new_user_with_non_privileged_domain(test_admin_user):
    """Test creating new user with non-privileged domain email."""
    override_auth(app, test_admin_user)

    with patch("database.user_emails.email_exists") as mock_exists:
        with patch("database.settings.privileged_domain_exists") as mock_privileged:
            with patch("database.users.create_user") as mock_create:
                with patch("database.user_emails.add_email") as mock_add_email:
                    with patch("database.user_emails.set_primary_email") as mock_set_primary:
                        with patch("database.tenants.get_tenant_by_id") as mock_tenant:
                            with patch("routers.users.send_new_user_invitation") as mock_send:
                                mock_exists.return_value = False
                                mock_privileged.return_value = False
                                mock_create.return_value = {"user_id": "new-user-123"}
                                mock_add_email.return_value = {
                                    "id": "email-123",
                                    "verify_nonce": "test-nonce",
                                }
                                mock_tenant.return_value = {
                                    "id": "tenant-123",
                                    "name": "Test Organization",
                                }

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
                                mock_set_primary.assert_called_once()
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

    with patch("database.user_emails.email_exists") as mock_exists:
        with patch("database.settings.privileged_domain_exists") as mock_privileged:
            with patch("database.users.create_user") as mock_create:
                with patch("database.user_emails.add_verified_email") as mock_add_email:
                    with patch("database.user_emails.set_primary_email"):
                        with patch("database.tenants.get_tenant_by_id") as mock_tenant:
                            with patch("routers.users.send_new_user_privileged_domain_notification"):
                                mock_exists.return_value = False
                                mock_privileged.return_value = True
                                mock_create.return_value = {"user_id": "new-admin-123"}
                                mock_add_email.return_value = {"id": "email-123"}
                                mock_tenant.return_value = {
                                    "id": "tenant-123",
                                    "name": "Test Organization",
                                }

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
                                # Verify role was passed correctly
                                call_args = mock_create.call_args[0]
                                assert call_args[4] == "admin@example.com"
                                assert call_args[5] == "admin"


def test_create_new_user_email_already_exists(test_admin_user):
    """Test creating user with existing email."""
    override_auth(app, test_admin_user)

    with patch("database.user_emails.email_exists") as mock_exists:
        mock_exists.return_value = True

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
    override_auth(app, test_admin_user)

    with patch("database.user_emails.email_exists") as mock_exists:
        with patch("database.settings.privileged_domain_exists") as mock_privileged:
            with patch("database.users.create_user") as mock_create:
                mock_exists.return_value = False
                mock_privileged.return_value = True
                mock_create.return_value = None  # Simulate failure

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
