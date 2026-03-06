"""Tests for routers/users/ package endpoints."""

import pytest
from fastapi.testclient import TestClient
from main import app

# Module path constants for cleaner patch targets
# Router sub-modules (split from routers.users)
USERS_LISTING = "routers.users.listing"
USERS_CREATION = "routers.users.creation"
USERS_DETAIL = "routers.users.detail"
USERS_EMAILS = "routers.users.emails"
USERS_LIFECYCLE = "routers.users.lifecycle"
USERS_GROUPS = "routers.users.groups"

# Service and database modules
SERVICES_USERS = "services.users"
SERVICES_EMAILS = "services.emails"
SERVICES_SETTINGS = "services.settings"
SERVICES_ACTIVITY = "services.activity"
SERVICES_SP = "services.service_providers"
DATABASE_SETTINGS = "database.settings"
DATABASE_USERS = "database.users"


def test_users_index_redirects_to_list(test_admin_user, override_auth):
    """Test users index redirects to list for admin."""
    override_auth(test_admin_user)

    client = TestClient(app)
    response = client.get("/users/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/users/list"


def test_users_index_redirects_regular_user_to_list(test_user, override_auth):
    """Test users index redirects regular user to list (they can view users)."""
    override_auth(test_user)

    client = TestClient(app)
    response = client.get("/users/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/users/list"


def test_users_list_page(test_admin_user, mocker, override_auth):
    """Test users list page renders."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 5
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list")

    assert response.status_code == 200
    mock_count.assert_called_once()
    mock_list.assert_called_once()


def test_users_list_with_search(test_admin_user, mocker, override_auth):
    """Test users list with search parameter."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 2
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?search=john")

    assert response.status_code == 200
    # count_users now takes (tenant_id, search, roles, statuses)
    count_call_args = mock_count.call_args[0]
    assert count_call_args[0] == str(test_admin_user["tenant_id"])
    assert count_call_args[1] == "john"
    assert count_call_args[2] is None  # No role filter
    assert count_call_args[3] is None  # No status filter


def test_users_list_with_sorting(test_admin_user, mocker, override_auth):
    """Test users list with custom sorting."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 5
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?sort=name&order=asc")

    assert response.status_code == 200
    # Verify sort parameters were passed
    call_args = mock_list.call_args[0]
    assert call_args[2] == "name"  # sort_field
    assert call_args[3] == "asc"  # sort_order


def test_users_list_with_pagination(test_admin_user, mocker, override_auth):
    """Test users list with pagination."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 100
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?page=2&size=50")

    assert response.status_code == 200
    call_args = mock_list.call_args[0]
    assert call_args[4] == 2  # page
    assert call_args[5] == 50  # page_size


def test_users_list_invalid_sort_field(test_admin_user, mocker, override_auth):
    """Test users list defaults invalid sort field."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 5
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?sort=invalid_field")

    assert response.status_code == 200
    # Should default to created_at
    call_args = mock_list.call_args[0]
    assert call_args[2] == "created_at"


def test_user_detail_redirects_to_profile(test_admin_user, override_auth):
    """Test bare user detail URL redirects to profile tab."""
    override_auth(test_admin_user)

    client = TestClient(app)
    response = client.get("/users/user-123", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/users/user-123/profile"


def test_user_detail_page(test_admin_user, mocker, override_auth):
    """Test user detail profile tab renders."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse
    from schemas.api import UserDetail

    override_auth(test_admin_user)

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

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mock_domains = mocker.patch(f"{DATABASE_SETTINGS}.list_privileged_domains")
    mocker.patch(f"{USERS_DETAIL}.groups_service")
    mocker.patch(f"{USERS_DETAIL}.sp_service")

    mock_template.return_value = HTMLResponse(content="<html>User Detail</html>")
    mock_get.return_value = target_user
    mock_domains.return_value = []

    client = TestClient(app)
    response = client.get("/users/user-123/profile")

    assert response.status_code == 200
    mock_get.assert_called_once()


def test_user_detail_not_found(test_admin_user, mocker, override_auth):
    """Test user detail redirects when user not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mock_get.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.get("/users/user-123/profile", follow_redirects=False)

    assert response.status_code == 303
    assert "/users/list" in response.headers["location"]


def test_user_detail_regular_user_denied(test_user, override_auth):
    """Test regular user cannot access user detail page."""
    override_auth(test_user)

    client = TestClient(app)
    response = client.get("/users/user-123/profile", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_update_user_name_success(test_admin_user, mocker, override_auth):
    """Test updating user name as admin."""
    from schemas.api import UserDetail

    override_auth(test_admin_user)

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

    mock_update = mocker.patch(f"{SERVICES_USERS}.update_user")
    mock_update.return_value = mock_user_detail

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-name",
        data={"first_name": "New", "last_name": "Name"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123" in response.headers["location"]
    # Verify service was called with correct parameters
    mock_update.assert_called_once()
    call_args = mock_update.call_args
    _, user_id, profile_update = call_args[0]
    assert user_id == "user-123"
    assert profile_update.first_name == "New"
    assert profile_update.last_name == "Name"


def test_update_user_name_empty_validation(test_admin_user, mocker, override_auth):
    """Test updating user name with empty values."""
    override_auth(test_admin_user)

    mock_update = mocker.patch(f"{DATABASE_USERS}.update_user_profile")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-name",
        data={"first_name": "", "last_name": "Name"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=name_required" in response.headers["location"]
    mock_update.assert_not_called()


def test_update_user_role_success(test_super_admin_user, mocker, override_auth):
    """Test updating user role as super_admin."""
    from schemas.api import UserDetail

    override_auth(test_super_admin_user)

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

    mock_update = mocker.patch(f"{SERVICES_USERS}.update_user")
    mock_update.return_value = mock_user_detail

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-role",
        data={"role": "admin"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=role_updated" in response.headers["location"]
    # Verify service was called with correct parameters
    mock_update.assert_called_once()
    call_args = mock_update.call_args
    _, user_id, role_update = call_args[0]
    assert user_id == "user-123"
    assert role_update.role == "admin"


def test_update_user_role_denied_for_admin(test_admin_user, mocker, override_auth):
    """Test regular admin cannot update user roles."""
    override_auth(test_admin_user)

    mock_update = mocker.patch(f"{DATABASE_USERS}.update_user_role")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-role",
        data={"role": "admin"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_update.assert_not_called()


def test_update_user_role_cannot_change_own(test_super_admin_user, mocker, override_auth):
    """Test super_admin cannot change their own role."""
    override_auth(test_super_admin_user)

    mock_update = mocker.patch(f"{DATABASE_USERS}.update_user_role")

    client = TestClient(app)
    response = client.post(
        f"/users/{str(test_super_admin_user['id'])}/update-role",
        data={"role": "member"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=cannot_change_own_role" in response.headers["location"]
    mock_update.assert_not_called()


def test_update_user_role_invalid_role(test_super_admin_user, mocker, override_auth):
    """Test updating user with invalid role."""
    override_auth(test_super_admin_user)

    mock_update = mocker.patch(f"{DATABASE_USERS}.update_user_role")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-role",
        data={"role": "invalid_role"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=invalid_role" in response.headers["location"]
    mock_update.assert_not_called()


def test_add_user_email_success(test_admin_user, mocker, override_auth):
    """Test adding secondary email to user."""
    from schemas.api import EmailInfo

    override_auth(test_admin_user)

    mock_email_info = EmailInfo(
        id="new-email-id",
        email="new@privileged.com",
        is_primary=False,
        verified_at="2025-01-01T00:00:00",
        created_at="2025-01-01T00:00:00",
    )

    mock_privileged = mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain")
    mock_add = mocker.patch(f"{SERVICES_EMAILS}.add_user_email")
    mock_primary = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_send = mocker.patch(f"{USERS_EMAILS}.send_secondary_email_added_notification")

    mock_privileged.return_value = True
    mock_add.return_value = mock_email_info
    mock_primary.return_value = "primary@example.com"

    client = TestClient(app)
    response = client.post(
        "/users/user-123/add-email",
        data={"email": "new@privileged.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=email_added" in response.headers["location"]
    mock_add.assert_called_once()
    mock_send.assert_called_once()


def test_add_user_email_not_privileged(test_admin_user, mocker, override_auth):
    """Test adding email from non-privileged domain."""
    override_auth(test_admin_user)

    mock_privileged = mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain")
    mock_privileged.return_value = False

    client = TestClient(app)
    response = client.post(
        "/users/user-123/add-email",
        data={"email": "new@unprivileged.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=domain_not_privileged" in response.headers["location"]


def test_remove_user_email_success(test_admin_user, mocker, override_auth):
    """Test removing secondary email from user."""
    override_auth(test_admin_user)

    mock_get_addr = mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id")
    mock_delete = mocker.patch(f"{SERVICES_EMAILS}.delete_user_email")
    mock_primary = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_send = mocker.patch(f"{USERS_EMAILS}.send_secondary_email_removed_notification")

    mock_get_addr.return_value = "secondary@example.com"
    mock_delete.return_value = None
    mock_primary.return_value = "primary@example.com"

    client = TestClient(app)
    response = client.post("/users/user-123/remove-email/email-id", follow_redirects=False)

    assert response.status_code == 303
    assert "success=email_removed" in response.headers["location"]
    mock_delete.assert_called_once()
    mock_send.assert_called_once()


def test_remove_user_email_primary_blocked(test_admin_user, mocker, override_auth):
    """Test cannot remove primary email."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user)

    mock_get_addr = mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id")
    mock_delete = mocker.patch(f"{SERVICES_EMAILS}.delete_user_email")

    mock_get_addr.return_value = "primary@example.com"
    mock_delete.side_effect = ValidationError(
        message="Cannot delete primary email address",
        code="cannot_delete_primary",
    )

    client = TestClient(app)
    response = client.post("/users/user-123/remove-email/email-id", follow_redirects=False)

    assert response.status_code == 303
    assert "error=cannot_remove_primary" in response.headers["location"]


def test_promote_user_email_success(test_admin_user, mocker, override_auth):
    """Test promoting secondary email to primary."""
    from schemas.api import EmailInfo

    override_auth(test_admin_user)

    mock_email_info = EmailInfo(
        id="email-id",
        email="new@example.com",
        is_primary=True,
        verified_at="2025-01-01T00:00:00",
        created_at="2025-01-01T00:00:00",
    )

    mock_old_primary = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_get_addr = mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id")
    mock_set = mocker.patch(f"{SERVICES_EMAILS}.set_primary_email")
    mock_send = mocker.patch(f"{USERS_EMAILS}.send_primary_email_changed_notification")

    mock_old_primary.return_value = "old@example.com"
    mock_get_addr.return_value = "new@example.com"
    mock_set.return_value = mock_email_info

    client = TestClient(app)
    response = client.post("/users/user-123/promote-email/email-id", follow_redirects=False)

    assert response.status_code == 303
    assert "success=email_promoted" in response.headers["location"]
    mock_set.assert_called_once()
    mock_send.assert_called_once()


def test_promote_user_email_already_primary(test_admin_user, mocker, override_auth):
    """Test cannot promote already primary email."""
    from schemas.api import EmailInfo

    override_auth(test_admin_user)

    mock_email_info = EmailInfo(
        id="email-id",
        email="already@primary.com",
        is_primary=True,
        verified_at="2025-01-01T00:00:00",
        created_at="2025-01-01T00:00:00",
    )

    mock_old_primary = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_get_addr = mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id")
    mock_set = mocker.patch(f"{SERVICES_EMAILS}.set_primary_email")

    # Same email - already primary
    mock_old_primary.return_value = "already@primary.com"
    mock_get_addr.return_value = "already@primary.com"
    mock_set.return_value = mock_email_info

    client = TestClient(app)
    response = client.post("/users/user-123/promote-email/email-id", follow_redirects=False)

    assert response.status_code == 303
    assert "error=already_primary" in response.headers["location"]


def test_users_list_with_locale_collation(test_admin_user, mocker, override_auth):
    """Test users list with locale-specific collation."""
    from fastapi.responses import HTMLResponse

    user_with_locale = {**test_admin_user, "locale": "sv_SE"}
    override_auth(user_with_locale)

    mock_check = mocker.patch(f"{SERVICES_USERS}.check_collation_exists")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")

    mock_check.return_value = True
    mock_list.return_value = []
    mock_count.return_value = 0
    mock_template.return_value = HTMLResponse(content="<html>Users</html>")

    client = TestClient(app)
    response = client.get("/users/list")

    assert response.status_code == 200
    # Check collation was passed to list_users_raw (7th positional arg)
    mock_list.assert_called_once()
    call_args = mock_list.call_args
    collation = call_args[0][6]
    assert collation == "sv-SE-x-icu"


def test_users_list_with_invalid_page_param(test_admin_user, mocker, override_auth):
    """Test users list with invalid page parameter."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")

    mock_list.return_value = []
    mock_count.return_value = 0
    mock_template.return_value = HTMLResponse(content="<html>Users</html>")

    client = TestClient(app)
    response = client.get("/users/list?page=invalid")

    assert response.status_code == 200
    # Should default to page 1


def test_users_list_with_invalid_page_size(test_admin_user, mocker, override_auth):
    """Test users list with invalid page size parameter."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")

    mock_list.return_value = []
    mock_count.return_value = 0
    mock_template.return_value = HTMLResponse(content="<html>Users</html>")

    client = TestClient(app)
    response = client.get("/users/list?size=invalid")

    assert response.status_code == 200
    # Should default to page size 25


def test_users_list_with_nonstandard_page_size(test_admin_user, mocker, override_auth):
    """Test users list with non-standard page size."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")

    mock_list.return_value = []
    mock_count.return_value = 0
    mock_template.return_value = HTMLResponse(content="<html>Users</html>")

    client = TestClient(app)
    response = client.get("/users/list?size=35")

    assert response.status_code == 200
    # Should normalize to 25


def test_users_list_with_invalid_sort_order(test_admin_user, mocker, override_auth):
    """Test users list with invalid sort order."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")

    mock_list.return_value = []
    mock_count.return_value = 0
    mock_template.return_value = HTMLResponse(content="<html>Users</html>")

    client = TestClient(app)
    response = client.get("/users/list?order=invalid")

    assert response.status_code == 200
    # Should default to desc


def test_add_user_email_invalid_email(test_admin_user, override_auth):
    """Test adding invalid email address."""
    override_auth(test_admin_user)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/add-email", data={"email": "invalid-email"}, follow_redirects=False
    )

    assert response.status_code == 303
    assert "error=invalid_email" in response.headers["location"]


def test_add_user_email_already_exists(test_admin_user, mocker, override_auth):
    """Test adding email that already exists."""
    from services.exceptions import ConflictError

    override_auth(test_admin_user)

    mock_privileged = mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain")
    mock_add = mocker.patch(f"{SERVICES_EMAILS}.add_user_email")

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

    assert response.status_code == 303
    assert "error=email_exists" in response.headers["location"]


def test_remove_user_email_not_found(test_admin_user, mocker, override_auth):
    """Test removing non-existent email."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mock_get_addr = mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id")
    mock_delete = mocker.patch(f"{SERVICES_EMAILS}.delete_user_email")

    mock_get_addr.return_value = None
    mock_delete.side_effect = NotFoundError(
        message="Email not found",
        code="email_not_found",
    )

    client = TestClient(app)
    response = client.post("/users/user-123/remove-email/invalid-id", follow_redirects=False)

    assert response.status_code == 303
    assert "error=email_not_found" in response.headers["location"]


def test_remove_user_email_must_keep_one(test_admin_user, mocker, override_auth):
    """Test cannot remove last email."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user)

    mock_get_addr = mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id")
    mock_delete = mocker.patch(f"{SERVICES_EMAILS}.delete_user_email")

    mock_get_addr.return_value = "last@example.com"
    mock_delete.side_effect = ValidationError(
        message="Cannot delete last email address",
        code="must_keep_one_email",
    )

    client = TestClient(app)
    response = client.post("/users/user-123/remove-email/email-id", follow_redirects=False)

    assert response.status_code == 303
    assert "error=must_keep_one_email" in response.headers["location"]


def test_promote_user_email_not_found(test_admin_user, mocker, override_auth):
    """Test promoting non-existent email."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mock_old_primary = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_get_addr = mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id")
    mock_set = mocker.patch(f"{SERVICES_EMAILS}.set_primary_email")

    mock_old_primary.return_value = None
    mock_get_addr.return_value = None
    mock_set.side_effect = NotFoundError(
        message="Email not found",
        code="email_not_found",
    )

    client = TestClient(app)
    response = client.post("/users/user-123/promote-email/invalid-id", follow_redirects=False)

    assert response.status_code == 303
    assert "error=email_not_found" in response.headers["location"]


# New user creation tests


def test_new_user_page_renders(test_admin_user, mocker, override_auth):
    """Test new user page renders for admin."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_CREATION}.templates.TemplateResponse")
    mock_domains = mocker.patch(f"{DATABASE_SETTINGS}.list_privileged_domains")

    mock_template.return_value = HTMLResponse(content="<html>New User</html>")
    mock_domains.return_value = []

    client = TestClient(app)
    response = client.get("/users/new")

    assert response.status_code == 200
    mock_domains.assert_called_once()


def test_new_user_page_denied_for_regular_user(test_user, override_auth):
    """Test regular user cannot access new user page."""
    override_auth(test_user)

    client = TestClient(app)
    response = client.get("/users/new", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_create_new_user_with_privileged_domain(test_admin_user, mocker, override_auth):
    """Test creating new user with privileged domain email."""
    override_auth(test_admin_user)

    mock_privileged = mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain")
    mock_create = mocker.patch(f"{SERVICES_USERS}.create_user")
    mock_add_email = mocker.patch(f"{SERVICES_USERS}.add_verified_email_with_nonce")
    mock_tenant = mocker.patch(f"{SERVICES_USERS}.get_tenant_name")
    mock_send = mocker.patch(f"{USERS_CREATION}.send_new_user_privileged_domain_notification")

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

    assert response.status_code == 303
    assert "/users/new-user-123" in response.headers["location"]
    assert "success=user_created" in response.headers["location"]
    mock_create.assert_called_once()
    mock_add_email.assert_called_once()
    # Verify org name was passed to email (3rd positional arg)
    _, _, org_name, *_ = mock_send.call_args[0]
    assert org_name == "Test Organization"


def test_create_new_user_with_non_privileged_domain(test_admin_user, mocker, override_auth):
    """Test creating new user with non-privileged domain email."""
    override_auth(test_admin_user)

    mock_privileged = mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain")
    mock_create = mocker.patch(f"{SERVICES_USERS}.create_user")
    mock_add_email = mocker.patch(f"{SERVICES_USERS}.add_unverified_email_with_nonce")
    mock_tenant = mocker.patch(f"{SERVICES_USERS}.get_tenant_name")
    mock_send = mocker.patch(f"{USERS_CREATION}.send_new_user_invitation")

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

    assert response.status_code == 303
    assert "/users/new-user-123" in response.headers["location"]
    mock_create.assert_called_once()
    mock_add_email.assert_called_once()
    # Verify org name was passed to email (3rd positional arg)
    _, _, org_name, *_ = mock_send.call_args[0]
    assert org_name == "Test Organization"


def test_create_new_user_invalid_email(test_admin_user, override_auth):
    """Test creating user with invalid email."""
    override_auth(test_admin_user)

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

    assert response.status_code == 303
    assert "error=invalid_email" in response.headers["location"]


def test_create_new_user_missing_name(test_admin_user, override_auth):
    """Test creating user with missing name."""
    override_auth(test_admin_user)

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

    assert response.status_code == 303
    assert "error=name_required" in response.headers["location"]


def test_create_new_user_invalid_role(test_admin_user, override_auth):
    """Test creating user with invalid role."""
    override_auth(test_admin_user)

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

    assert response.status_code == 303
    assert "error=invalid_role" in response.headers["location"]


def test_create_new_user_admin_cannot_create_admin(test_admin_user, override_auth):
    """Test regular admin cannot create admin users."""
    override_auth(test_admin_user)

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

    assert response.status_code == 303
    assert "error=insufficient_permissions" in response.headers["location"]


def test_create_new_user_super_admin_can_create_admin(test_super_admin_user, mocker, override_auth):
    """Test super admin can create admin users."""
    override_auth(test_super_admin_user)

    mock_privileged = mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain")
    mock_create = mocker.patch(f"{SERVICES_USERS}.create_user")
    mocker.patch(f"{SERVICES_USERS}.add_verified_email_with_nonce")
    mock_tenant = mocker.patch(f"{SERVICES_USERS}.get_tenant_name")
    mocker.patch(f"{USERS_CREATION}.send_new_user_privileged_domain_notification")

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

    assert response.status_code == 303
    assert "/users/new-admin-123" in response.headers["location"]
    # Verify create_user was called
    mock_create.assert_called_once()


def test_create_new_user_email_already_exists(test_admin_user, mocker, override_auth):
    """Test creating user with existing email."""
    from services.exceptions import ConflictError

    override_auth(test_admin_user)

    mock_privileged = mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain")
    mock_create = mocker.patch(f"{SERVICES_USERS}.create_user")

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

    assert response.status_code == 303
    assert "error=email_exists" in response.headers["location"]


def test_create_new_user_creation_failed(test_admin_user, mocker, override_auth):
    """Test handling of user creation failure."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user)

    mock_privileged = mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain")
    mock_create = mocker.patch(f"{SERVICES_USERS}.create_user")

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

    assert response.status_code == 303
    assert "error=creation_failed" in response.headers["location"]


def test_create_new_user_denied_for_regular_user(test_user, override_auth):
    """Test regular user cannot create new users."""
    override_auth(test_user)

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

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# User List Filtering Tests
# =============================================================================


def test_users_list_with_single_role_filter(test_admin_user, mocker, override_auth):
    """Test users list with single role filter."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 3
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?role=admin")

    assert response.status_code == 200
    # Verify roles parameter was passed to count_users
    count_call_args = mock_count.call_args[0]
    assert count_call_args[2] == ["admin"]  # roles parameter
    # Verify roles parameter was passed to list_users_raw
    list_call_args = mock_list.call_args[0]
    assert list_call_args[7] == ["admin"]  # roles parameter


def test_users_list_with_multiple_role_filter(test_admin_user, mocker, override_auth):
    """Test users list with multiple role filter (comma-separated)."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 5
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?role=admin,super_admin")

    assert response.status_code == 200
    count_call_args = mock_count.call_args[0]
    assert set(count_call_args[2]) == {"admin", "super_admin"}


def test_users_list_with_invalid_role_filter(test_admin_user, mocker, override_auth):
    """Test users list ignores invalid role values."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 0
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?role=invalid_role")

    assert response.status_code == 200
    # Invalid role should result in None (no filter)
    count_call_args = mock_count.call_args[0]
    assert count_call_args[2] is None


def test_users_list_with_mixed_valid_invalid_roles(test_admin_user, mocker, override_auth):
    """Test users list filters only valid roles from mixed input."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 3
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?role=admin,invalid,member")

    assert response.status_code == 200
    count_call_args = mock_count.call_args[0]
    assert set(count_call_args[2]) == {"admin", "member"}


def test_users_list_with_single_status_filter(test_admin_user, mocker, override_auth):
    """Test users list with single status filter."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 10
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?status=active")

    assert response.status_code == 200
    # Verify statuses parameter was passed
    count_call_args = mock_count.call_args[0]
    assert count_call_args[3] == ["active"]  # statuses parameter
    list_call_args = mock_list.call_args[0]
    assert list_call_args[8] == ["active"]  # statuses parameter


def test_users_list_with_multiple_status_filter(test_admin_user, mocker, override_auth):
    """Test users list with multiple status filter."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 15
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?status=active,inactivated")

    assert response.status_code == 200
    count_call_args = mock_count.call_args[0]
    assert set(count_call_args[3]) == {"active", "inactivated"}


def test_users_list_with_invalid_status_filter(test_admin_user, mocker, override_auth):
    """Test users list ignores invalid status values."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 0
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?status=invalid_status")

    assert response.status_code == 200
    count_call_args = mock_count.call_args[0]
    assert count_call_args[3] is None


def test_users_list_with_role_and_status_filter(test_admin_user, mocker, override_auth):
    """Test users list with both role and status filters."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 2
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?role=member&status=active")

    assert response.status_code == 200
    count_call_args = mock_count.call_args[0]
    assert count_call_args[2] == ["member"]
    assert count_call_args[3] == ["active"]


def test_users_list_with_search_and_filters(test_admin_user, mocker, override_auth):
    """Test users list with search, role, and status filters combined."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 1
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?search=john&role=admin&status=active")

    assert response.status_code == 200
    count_call_args = mock_count.call_args[0]
    assert count_call_args[0] == str(test_admin_user["tenant_id"])
    assert count_call_args[1] == "john"
    assert count_call_args[2] == ["admin"]
    assert count_call_args[3] == ["active"]


def test_users_list_with_status_sort(test_admin_user, mocker, override_auth):
    """Test users list with status sorting."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 5
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?sort=status&order=asc")

    assert response.status_code == 200
    list_call_args = mock_list.call_args[0]
    assert list_call_args[2] == "status"  # sort_field
    assert list_call_args[3] == "asc"  # sort_order


def test_users_list_with_status_sort_desc(test_admin_user, mocker, override_auth):
    """Test users list with status sorting descending."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 5
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?sort=status&order=desc")

    assert response.status_code == 200
    list_call_args = mock_list.call_args[0]
    assert list_call_args[2] == "status"
    assert list_call_args[3] == "desc"


def test_users_list_empty_role_filter(test_admin_user, mocker, override_auth):
    """Test users list with empty role filter is treated as no filter."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 10
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?role=")

    assert response.status_code == 200
    count_call_args = mock_count.call_args[0]
    assert count_call_args[2] is None  # No roles filter


def test_users_list_filters_with_pagination(test_admin_user, mocker, override_auth):
    """Test users list filters work with pagination."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 100
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?role=admin&status=active&page=2&size=50")

    assert response.status_code == 200
    count_call_args = mock_count.call_args[0]
    assert count_call_args[2] == ["admin"]
    assert count_call_args[3] == ["active"]
    list_call_args = mock_list.call_args[0]
    assert list_call_args[4] == 2  # page
    assert list_call_args[5] == 50  # page_size
    assert list_call_args[7] == ["admin"]  # roles
    assert list_call_args[8] == ["active"]  # statuses


def test_users_list_all_three_statuses(test_admin_user, mocker, override_auth):
    """Test users list with all three status values."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 20
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?status=active,inactivated,anonymized")

    assert response.status_code == 200
    count_call_args = mock_count.call_args[0]
    assert set(count_call_args[3]) == {"active", "inactivated", "anonymized"}


def test_users_list_all_three_roles(test_admin_user, mocker, override_auth):
    """Test users list with all three role values."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 20
    mock_list.return_value = []

    client = TestClient(app)
    response = client.get("/users/list?role=member,admin,super_admin")

    assert response.status_code == 200
    count_call_args = mock_count.call_args[0]
    assert set(count_call_args[2]) == {"member", "admin", "super_admin"}


def test_users_list_passes_auth_method_fields_to_template(test_admin_user, mocker, override_auth):
    """Test that auth method fields from list_users_raw are passed to the template."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 4
    mock_list.return_value = [
        {
            "id": "user-1",
            "first_name": "Alice",
            "last_name": "SSO",
            "role": "member",
            "email": "alice@example.com",
            "created_at": "2024-01-01",
            "last_login": None,
            "last_activity_at": None,
            "is_inactivated": False,
            "is_anonymized": False,
            "saml_idp_id": "idp-1",
            "saml_idp_name": "Okta",
            "require_platform_mfa": False,
            "has_password": False,
            "mfa_enabled": False,
            "mfa_method": None,
        },
        {
            "id": "user-2",
            "first_name": "Bob",
            "last_name": "Password",
            "role": "admin",
            "email": "bob@example.com",
            "created_at": "2024-01-02",
            "last_login": None,
            "last_activity_at": None,
            "is_inactivated": False,
            "is_anonymized": False,
            "saml_idp_id": None,
            "saml_idp_name": None,
            "require_platform_mfa": None,
            "has_password": True,
            "mfa_enabled": True,
            "mfa_method": "totp",
        },
        {
            "id": "user-3",
            "first_name": "Carol",
            "last_name": "Unverified",
            "role": "member",
            "email": "carol@example.com",
            "created_at": "2024-01-03",
            "last_login": None,
            "last_activity_at": None,
            "is_inactivated": False,
            "is_anonymized": False,
            "saml_idp_id": None,
            "saml_idp_name": None,
            "require_platform_mfa": None,
            "has_password": False,
            "mfa_enabled": False,
            "mfa_method": None,
        },
        {
            "id": "user-4",
            "first_name": "Dave",
            "last_name": "SSO-MFA",
            "role": "member",
            "email": "dave@example.com",
            "created_at": "2024-01-04",
            "last_login": None,
            "last_activity_at": None,
            "is_inactivated": False,
            "is_anonymized": False,
            "saml_idp_id": "idp-2",
            "saml_idp_name": "Entra ID",
            "require_platform_mfa": True,
            "has_password": False,
            "mfa_enabled": True,
            "mfa_method": "totp",
        },
    ]

    client = TestClient(app)
    response = client.get("/users/list")

    assert response.status_code == 200

    # Verify template was called with user data containing auth method fields
    # TemplateResponse(request, name, context) - context is the 3rd positional arg
    template_call_args = mock_template.call_args[0]
    context = template_call_args[2]
    users = context["users"]

    assert len(users) == 4
    # SSO without platform MFA
    assert users[0]["saml_idp_id"] == "idp-1"
    assert users[0]["saml_idp_name"] == "Okta"
    assert users[0]["require_platform_mfa"] is False
    # Password + TOTP
    assert users[1]["has_password"] is True
    assert users[1]["mfa_method"] == "totp"
    # Unverified
    assert users[2]["has_password"] is False
    assert users[2]["saml_idp_id"] is None
    # SSO with platform MFA
    assert users[3]["saml_idp_name"] == "Entra ID"
    assert users[3]["require_platform_mfa"] is True
    assert users[3]["mfa_method"] == "totp"


def test_users_list_with_auth_method_filter(test_admin_user, mocker, override_auth):
    """Test users list with auth_method filter parameter."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")
    mock_auth_opts = mocker.patch(f"{SERVICES_USERS}.get_auth_method_options")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 2
    mock_list.return_value = []
    mock_auth_opts.return_value = [
        {
            "auth_method_key": "password_email",
            "auth_method_label": "Password + Email",
        },
    ]

    client = TestClient(app)
    response = client.get("/users/list?auth_method=password_email")

    assert response.status_code == 200

    # Verify auth_methods was passed to count_users
    count_call_args = mock_count.call_args[0]
    assert count_call_args[4] == ["password_email"]

    # Verify auth_methods was passed to list_users_raw
    list_call_args = mock_list.call_args[0]
    assert list_call_args[9] == ["password_email"]

    # Verify auth_method_options in template context
    template_call_args = mock_template.call_args[0]
    context = template_call_args[2]
    assert context["auth_methods"] == ["password_email"]
    assert context["auth_method_options"] == mock_auth_opts.return_value


def test_users_list_template_context_includes_auth_method_options(
    test_admin_user, mocker, override_auth
):
    """Test that auth_method_options is always included in template context."""
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_LISTING}.templates.TemplateResponse")
    mock_count = mocker.patch(f"{SERVICES_USERS}.count_users")
    mock_list = mocker.patch(f"{SERVICES_USERS}.list_users_raw")
    mock_auth_opts = mocker.patch(f"{SERVICES_USERS}.get_auth_method_options")

    mock_template.return_value = HTMLResponse(content="<html>Users List</html>")
    mock_count.return_value = 0
    mock_list.return_value = []
    mock_auth_opts.return_value = []

    client = TestClient(app)
    response = client.get("/users/list")

    assert response.status_code == 200
    template_call_args = mock_template.call_args[0]
    context = template_call_args[2]
    assert "auth_method_options" in context
    assert "auth_methods" in context
    assert context["auth_methods"] == []


def test_create_user_privileged_domain_creates_event_log(
    test_admin_user, test_tenant, mocker, override_auth
):
    """Verify event log created when creating user via HTML router with privileged domain."""
    from uuid import uuid4

    import database

    override_auth(test_admin_user)

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
    mocker.patch(f"{USERS_CREATION}.send_new_user_privileged_domain_notification")
    mocker.patch(f"{SERVICES_ACTIVITY}.cache.get", return_value=None)
    mocker.patch(f"{SERVICES_ACTIVITY}.cache.set", return_value=True)

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

    # Verify redirect indicates success
    assert response.status_code == 303
    assert "success=user_created" in response.headers["location"]

    # Extract user_id from redirect URL
    location = response.headers["location"]
    user_id = location.split("/users/")[1].split("/")[0]

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


def test_create_user_non_privileged_domain_creates_event_log(
    test_admin_user, test_tenant, mocker, override_auth
):
    """Verify event log created when creating user via HTML router with non-privileged domain."""
    from uuid import uuid4

    import database

    override_auth(test_admin_user)

    # Use a non-privileged domain (no entry in privileged_domains table)
    domain = "nonprivileged.com"

    # Create user via HTML router
    unique_suffix = str(uuid4())[:8]
    new_email = f"newuser-{unique_suffix}@{domain}"

    # Mock email sending and cache to avoid warnings
    mocker.patch(f"{USERS_CREATION}.send_new_user_invitation")
    mocker.patch(f"{SERVICES_ACTIVITY}.cache.get", return_value=None)
    mocker.patch(f"{SERVICES_ACTIVITY}.cache.set", return_value=True)

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

    # Verify redirect indicates success
    assert response.status_code == 303
    assert "success=user_created" in response.headers["location"]

    # Extract user_id from redirect URL
    location = response.headers["location"]
    user_id = location.split("/users/")[1].split("/")[0]

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


def test_password_set_link_format_privileged_domain(
    test_admin_user, test_tenant, mocker, override_auth
):
    """Test password set URL format for privileged domain users."""
    from uuid import UUID, uuid4

    import database

    override_auth(test_admin_user)

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
    mock_send = mocker.patch(f"{USERS_CREATION}.send_new_user_privileged_domain_notification")

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


def test_update_user_idp_success(test_super_admin_user, mocker, override_auth):
    """Test super_admin can assign user to an IdP."""
    override_auth(test_super_admin_user)

    mock_assign = mocker.patch(f"{USERS_DETAIL}.saml_service.assign_user_idp")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-idp",
        data={"saml_idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/profile?success=idp_updated" in response.headers["location"]
    mock_assign.assert_called_once()
    call_args = mock_assign.call_args
    assert call_args[1]["user_id"] == "user-123"
    assert call_args[1]["saml_idp_id"] == "idp-456"


def test_update_user_idp_remove_idp(test_super_admin_user, mocker, override_auth):
    """Test super_admin can remove user from IdP (set to password-only)."""
    override_auth(test_super_admin_user)

    mock_assign = mocker.patch(f"{USERS_DETAIL}.saml_service.assign_user_idp")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-idp",
        data={"saml_idp_id": ""},  # Empty = password-only
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=idp_updated" in response.headers["location"]
    mock_assign.assert_called_once()
    # Empty string should be converted to None
    assert mock_assign.call_args[1]["saml_idp_id"] is None


def test_update_user_idp_denied_for_admin(test_admin_user, mocker, override_auth):
    """Test admin cannot assign user to IdP (super_admin only)."""
    override_auth(test_admin_user)

    mock_assign = mocker.patch(f"{USERS_DETAIL}.saml_service.assign_user_idp")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-idp",
        data={"saml_idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_assign.assert_not_called()


def test_update_user_idp_denied_for_member(test_user, mocker, override_auth):
    """Test member cannot assign user to IdP."""
    override_auth(test_user)

    mock_assign = mocker.patch(f"{USERS_DETAIL}.saml_service.assign_user_idp")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-idp",
        data={"saml_idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_assign.assert_not_called()


def test_update_user_idp_user_not_found(test_super_admin_user, mocker, override_auth):
    """Test update IdP returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(test_super_admin_user)

    mock_assign = mocker.patch(f"{USERS_DETAIL}.saml_service.assign_user_idp")
    mock_assign.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-idp",
        data={"saml_idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/profile?error=user_not_found" in response.headers["location"]


def test_update_user_idp_idp_not_found(test_super_admin_user, mocker, override_auth):
    """Test update IdP returns error when IdP not found."""
    from services.exceptions import NotFoundError

    override_auth(test_super_admin_user)

    mock_assign = mocker.patch(f"{USERS_DETAIL}.saml_service.assign_user_idp")
    mock_assign.side_effect = NotFoundError(message="IdP not found", code="idp_not_found")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-idp",
        data={"saml_idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/profile?error=idp_not_found" in response.headers["location"]


def test_update_user_idp_validation_error(test_super_admin_user, mocker, override_auth):
    """Test update IdP returns error on validation failure."""
    from services.exceptions import ValidationError

    override_auth(test_super_admin_user)

    mock_assign = mocker.patch(f"{USERS_DETAIL}.saml_service.assign_user_idp")
    mock_assign.side_effect = ValidationError(
        message="Cannot assign to disabled IdP", code="idp_disabled"
    )

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-idp",
        data={"saml_idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/profile?error=idp_disabled" in response.headers["location"]


def test_update_user_idp_service_error(test_super_admin_user, mocker, override_auth):
    """Test update IdP renders error page on service error."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user)

    mock_assign = mocker.patch(f"{USERS_DETAIL}.saml_service.assign_user_idp")
    mock_error_page = mocker.patch(f"{USERS_DETAIL}.render_error_page")

    mock_assign.side_effect = ServiceError(message="Database error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-idp",
        data={"saml_idp_id": "idp-456"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error_page.assert_called_once()


# =============================================================================
# Inactivation Route Tests (inactivate_user_route)
# =============================================================================


def test_inactivate_user_success(test_admin_user, mocker, override_auth):
    """Test admin can inactivate a user."""
    override_auth(test_admin_user)

    mock_inactivate = mocker.patch(f"{USERS_LIFECYCLE}.users_service.inactivate_user")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/inactivate",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/danger?success=user_inactivated" in response.headers["location"]
    mock_inactivate.assert_called_once()


def test_inactivate_user_denied_for_member(test_user, mocker, override_auth):
    """Test member cannot inactivate a user."""
    override_auth(test_user)

    mock_inactivate = mocker.patch(f"{USERS_LIFECYCLE}.users_service.inactivate_user")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/inactivate",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_inactivate.assert_not_called()


def test_inactivate_user_not_found(test_admin_user, mocker, override_auth):
    """Test inactivate returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mock_inactivate = mocker.patch(f"{USERS_LIFECYCLE}.users_service.inactivate_user")
    mock_inactivate.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/inactivate",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/list?error=user_not_found" in response.headers["location"]


def test_inactivate_user_validation_error(test_admin_user, mocker, override_auth):
    """Test inactivate returns error on validation failure (e.g., already inactivated)."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user)

    mock_inactivate = mocker.patch(f"{USERS_LIFECYCLE}.users_service.inactivate_user")
    mock_inactivate.side_effect = ValidationError(
        message="User already inactivated", code="already_inactivated"
    )

    client = TestClient(app)
    response = client.post(
        "/users/user-123/inactivate",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/danger?error=already_inactivated" in response.headers["location"]


def test_inactivate_user_service_error(test_admin_user, mocker, override_auth):
    """Test inactivate renders error page on service error."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mock_inactivate = mocker.patch(f"{USERS_LIFECYCLE}.users_service.inactivate_user")
    mock_error_page = mocker.patch(f"{USERS_LIFECYCLE}.render_error_page")

    mock_inactivate.side_effect = ServiceError(message="Database error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/inactivate",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error_page.assert_called_once()


# =============================================================================
# Reactivation Route Tests (reactivate_user_route)
# =============================================================================


def test_reactivate_user_success(test_admin_user, mocker, override_auth):
    """Test admin can reactivate a user."""
    override_auth(test_admin_user)

    mock_reactivate = mocker.patch(f"{USERS_LIFECYCLE}.users_service.reactivate_user")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reactivate",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/danger?success=user_reactivated" in response.headers["location"]
    mock_reactivate.assert_called_once()


def test_reactivate_user_denied_for_member(test_user, mocker, override_auth):
    """Test member cannot reactivate a user."""
    override_auth(test_user)

    mock_reactivate = mocker.patch(f"{USERS_LIFECYCLE}.users_service.reactivate_user")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reactivate",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_reactivate.assert_not_called()


def test_reactivate_user_not_found(test_admin_user, mocker, override_auth):
    """Test reactivate returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mock_reactivate = mocker.patch(f"{USERS_LIFECYCLE}.users_service.reactivate_user")
    mock_reactivate.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reactivate",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/list?error=user_not_found" in response.headers["location"]


def test_reactivate_user_validation_error(test_admin_user, mocker, override_auth):
    """Test reactivate returns error on validation failure (e.g., already active)."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user)

    mock_reactivate = mocker.patch(f"{USERS_LIFECYCLE}.users_service.reactivate_user")
    mock_reactivate.side_effect = ValidationError(
        message="User is already active", code="already_active"
    )

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reactivate",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/danger?error=already_active" in response.headers["location"]


def test_reactivate_user_service_error(test_admin_user, mocker, override_auth):
    """Test reactivate renders error page on service error."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mock_reactivate = mocker.patch(f"{USERS_LIFECYCLE}.users_service.reactivate_user")
    mock_error_page = mocker.patch(f"{USERS_LIFECYCLE}.render_error_page")

    mock_reactivate.side_effect = ServiceError(message="Database error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reactivate",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error_page.assert_called_once()


# =============================================================================
# Anonymization Route Tests (anonymize_user_route)
# =============================================================================


def test_anonymize_user_success(test_super_admin_user, mocker, override_auth):
    """Test super_admin can anonymize a user."""
    override_auth(test_super_admin_user)

    mock_anonymize = mocker.patch(f"{USERS_LIFECYCLE}.users_service.anonymize_user")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/anonymize",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/danger?success=user_anonymized" in response.headers["location"]
    mock_anonymize.assert_called_once()


def test_anonymize_user_denied_for_admin(test_admin_user, mocker, override_auth):
    """Test admin cannot anonymize a user (super_admin only)."""
    override_auth(test_admin_user)

    mock_anonymize = mocker.patch(f"{USERS_LIFECYCLE}.users_service.anonymize_user")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/anonymize",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_anonymize.assert_not_called()


def test_anonymize_user_denied_for_member(test_user, mocker, override_auth):
    """Test member cannot anonymize a user."""
    override_auth(test_user)

    mock_anonymize = mocker.patch(f"{USERS_LIFECYCLE}.users_service.anonymize_user")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/anonymize",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_anonymize.assert_not_called()


def test_anonymize_user_not_found(test_super_admin_user, mocker, override_auth):
    """Test anonymize returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(test_super_admin_user)

    mock_anonymize = mocker.patch(f"{USERS_LIFECYCLE}.users_service.anonymize_user")
    mock_anonymize.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/anonymize",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/list?error=user_not_found" in response.headers["location"]


def test_anonymize_user_validation_error(test_super_admin_user, mocker, override_auth):
    """Test anonymize returns error on validation failure (e.g., cannot anonymize self)."""
    from services.exceptions import ValidationError

    override_auth(test_super_admin_user)

    mock_anonymize = mocker.patch(f"{USERS_LIFECYCLE}.users_service.anonymize_user")
    mock_anonymize.side_effect = ValidationError(
        message="Cannot anonymize your own account", code="cannot_anonymize_self"
    )

    client = TestClient(app)
    response = client.post(
        "/users/user-123/anonymize",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/danger?error=cannot_anonymize_self" in response.headers["location"]


def test_anonymize_user_service_error(test_super_admin_user, mocker, override_auth):
    """Test anonymize renders error page on service error."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user)

    mock_anonymize = mocker.patch(f"{USERS_LIFECYCLE}.users_service.anonymize_user")
    mock_error_page = mocker.patch(f"{USERS_LIFECYCLE}.render_error_page")

    mock_anonymize.side_effect = ServiceError(message="Database error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/anonymize",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error_page.assert_called_once()


# =============================================================================
# Reset MFA Tests
# =============================================================================


def test_reset_mfa_success(test_admin_user, mocker, override_auth):
    """Test admin can reset MFA for a user."""
    override_auth(test_admin_user)

    mock_reset = mocker.patch(f"{USERS_LIFECYCLE}.mfa_service.reset_user_mfa")
    mocker.patch(
        f"{USERS_LIFECYCLE}.emails_service.get_primary_email", return_value="user@example.com"
    )
    mock_email = mocker.patch(f"{USERS_LIFECYCLE}.send_mfa_reset_notification")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reset-mfa",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/danger?success=mfa_reset" in response.headers["location"]
    mock_reset.assert_called_once()
    mock_email.assert_called_once()
    # Verify email recipient (1st positional arg)
    email_recipient = mock_email.call_args[0][0]
    assert email_recipient == "user@example.com"


def test_reset_mfa_denied_for_member(test_user, mocker, override_auth):
    """Test member cannot reset MFA for a user."""
    override_auth(test_user)

    mock_reset = mocker.patch(f"{USERS_LIFECYCLE}.mfa_service.reset_user_mfa")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reset-mfa",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_reset.assert_not_called()


def test_reset_mfa_user_not_found(test_admin_user, mocker, override_auth):
    """Test reset MFA returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mock_reset = mocker.patch(f"{USERS_LIFECYCLE}.mfa_service.reset_user_mfa")
    mock_reset.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reset-mfa",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/list?error=user_not_found" in response.headers["location"]


def test_reset_mfa_validation_error(test_admin_user, mocker, override_auth):
    """Test reset MFA returns error on validation failure."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user)

    mock_reset = mocker.patch(f"{USERS_LIFECYCLE}.mfa_service.reset_user_mfa")
    mock_reset.side_effect = ValidationError(message="MFA not enabled", code="mfa_not_enabled")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reset-mfa",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/danger?error=mfa_not_enabled" in response.headers["location"]


def test_reset_mfa_service_error(test_admin_user, mocker, override_auth):
    """Test reset MFA renders error page on service error."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mock_reset = mocker.patch(f"{USERS_LIFECYCLE}.mfa_service.reset_user_mfa")
    mock_error_page = mocker.patch(f"{USERS_LIFECYCLE}.render_error_page")

    mock_reset.side_effect = ServiceError(message="Database error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reset-mfa",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error_page.assert_called_once()


def test_reset_mfa_email_includes_admin_name_and_timestamp(test_admin_user, mocker, override_auth):
    """Test email notification includes admin name and formatted timestamp."""
    override_auth(test_admin_user)

    mocker.patch(f"{USERS_LIFECYCLE}.mfa_service.reset_user_mfa")
    mocker.patch(
        f"{USERS_LIFECYCLE}.emails_service.get_primary_email", return_value="user@example.com"
    )
    mock_email = mocker.patch(f"{USERS_LIFECYCLE}.send_mfa_reset_notification")

    client = TestClient(app)
    client.post("/users/user-123/reset-mfa", follow_redirects=False)

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


def test_reset_mfa_no_email_notification_when_no_primary_email(
    test_admin_user, mocker, override_auth
):
    """Test no email notification sent when user has no primary email."""
    override_auth(test_admin_user)

    mock_reset = mocker.patch(f"{USERS_LIFECYCLE}.mfa_service.reset_user_mfa")
    mocker.patch(f"{USERS_LIFECYCLE}.emails_service.get_primary_email", return_value=None)
    mock_email = mocker.patch(f"{USERS_LIFECYCLE}.send_mfa_reset_notification")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/reset-mfa",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/danger?success=mfa_reset" in response.headers["location"]
    mock_reset.assert_called_once()
    mock_email.assert_not_called()


# =============================================================================
# Users Index Permission & Fallback Tests
# =============================================================================


def test_users_index_no_permission_redirects_to_account(test_user, mocker, override_auth):
    """Test users index redirects to /account when user has no /users access."""
    override_auth(test_user)

    # Mock has_page_access to return False for /users
    mocker.patch(f"{USERS_LISTING}.has_page_access", return_value=False)

    client = TestClient(app)
    response = client.get("/users/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/account"


def test_users_index_fallback_to_account(test_user, mocker, override_auth):
    """Test users index falls back to /account when no children are accessible."""
    override_auth(test_user)

    mocker.patch(f"{USERS_LISTING}.has_page_access", return_value=True)
    mocker.patch(f"{USERS_LISTING}.get_first_accessible_child", return_value=None)

    client = TestClient(app)
    response = client.get("/users/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/account"


# =============================================================================
# Update User Name Error Path Tests
# =============================================================================


def test_update_user_name_not_found(test_admin_user, mocker, override_auth):
    """Test update name returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mock_update = mocker.patch(f"{SERVICES_USERS}.update_user")
    mock_update.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-name",
        data={"first_name": "New", "last_name": "Name"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/list?error=user_not_found" in response.headers["location"]


def test_update_user_name_service_error(test_admin_user, mocker, override_auth):
    """Test update name renders error page on service error."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mock_update = mocker.patch(f"{SERVICES_USERS}.update_user")
    mock_error_page = mocker.patch(f"{USERS_DETAIL}.render_error_page")

    mock_update.side_effect = ServiceError(message="Database error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-name",
        data={"first_name": "New", "last_name": "Name"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error_page.assert_called_once()


def test_update_user_name_denied_for_member(test_user, mocker, override_auth):
    """Test member cannot update user name."""
    override_auth(test_user)

    mock_update = mocker.patch(f"{SERVICES_USERS}.update_user")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-name",
        data={"first_name": "New", "last_name": "Name"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_update.assert_not_called()


# =============================================================================
# Update User Role Error Path Tests
# =============================================================================


def test_update_user_role_not_found(test_super_admin_user, mocker, override_auth):
    """Test update role returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(test_super_admin_user)

    mock_update = mocker.patch(f"{SERVICES_USERS}.update_user")
    mock_update.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-role",
        data={"role": "admin"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/list?error=user_not_found" in response.headers["location"]


def test_update_user_role_last_super_admin(test_super_admin_user, mocker, override_auth):
    """Test update role prevents demoting last super_admin."""
    from services.exceptions import ValidationError

    override_auth(test_super_admin_user)

    mock_update = mocker.patch(f"{SERVICES_USERS}.update_user")
    mock_update.side_effect = ValidationError(
        message="Cannot demote last super admin", code="last_super_admin"
    )

    client = TestClient(app)
    response = client.post(
        "/users/other-user/update-role",
        data={"role": "member"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=cannot_demote_last_super_admin" in response.headers["location"]


def test_update_user_role_validation_error(test_super_admin_user, mocker, override_auth):
    """Test update role renders error page on other validation errors."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ValidationError

    override_auth(test_super_admin_user)

    mock_update = mocker.patch(f"{SERVICES_USERS}.update_user")
    mock_error_page = mocker.patch(f"{USERS_DETAIL}.render_error_page")

    mock_update.side_effect = ValidationError(message="Some other error", code="other_error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/users/other-user/update-role",
        data={"role": "admin"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error_page.assert_called_once()


def test_update_user_role_service_error(test_super_admin_user, mocker, override_auth):
    """Test update role renders error page on service error."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user)

    mock_update = mocker.patch(f"{SERVICES_USERS}.update_user")
    mock_error_page = mocker.patch(f"{USERS_DETAIL}.render_error_page")

    mock_update.side_effect = ServiceError(message="Database error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/users/other-user/update-role",
        data={"role": "admin"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error_page.assert_called_once()


# =============================================================================
# Add User Email Error Path Tests
# =============================================================================


def test_add_user_email_denied_for_member(test_user, mocker, override_auth):
    """Test member cannot add email to other users."""
    override_auth(test_user)

    mock_add = mocker.patch(f"{SERVICES_EMAILS}.add_user_email")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/add-email",
        data={"email": "new@example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_add.assert_not_called()


def test_add_user_email_not_found(test_admin_user, mocker, override_auth):
    """Test add email returns error when user not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain", return_value=True)
    mock_add = mocker.patch(f"{SERVICES_EMAILS}.add_user_email")
    mock_add.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/add-email",
        data={"email": "new@privileged.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/list?error=user_not_found" in response.headers["location"]


def test_add_user_email_service_error(test_admin_user, mocker, override_auth):
    """Test add email renders error page on service error."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain", return_value=True)
    mock_add = mocker.patch(f"{SERVICES_EMAILS}.add_user_email")
    mock_error_page = mocker.patch(f"{USERS_EMAILS}.render_error_page")

    mock_add.side_effect = ServiceError(message="Database error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/add-email",
        data={"email": "new@privileged.com"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error_page.assert_called_once()


# =============================================================================
# Remove User Email Error Path Tests
# =============================================================================


def test_remove_user_email_denied_for_member(test_user, mocker, override_auth):
    """Test member cannot remove emails from other users."""
    override_auth(test_user)

    mock_delete = mocker.patch(f"{SERVICES_EMAILS}.delete_user_email")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/remove-email/email-456",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_delete.assert_not_called()


def test_remove_user_email_service_error(test_admin_user, mocker, override_auth):
    """Test remove email renders error page on service error."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id", return_value="old@example.com")
    mock_delete = mocker.patch(f"{SERVICES_EMAILS}.delete_user_email")
    mock_error_page = mocker.patch(f"{USERS_EMAILS}.render_error_page")

    mock_delete.side_effect = ServiceError(message="Database error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/remove-email/email-456",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error_page.assert_called_once()


# =============================================================================
# Promote User Email Error Path Tests
# =============================================================================


def test_promote_user_email_denied_for_member(test_user, mocker, override_auth):
    """Test member cannot promote emails for other users."""
    override_auth(test_user)

    mock_promote = mocker.patch(f"{SERVICES_EMAILS}.set_primary_email")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/promote-email/email-456",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_promote.assert_not_called()


def test_promote_user_email_not_verified(test_admin_user, mocker, override_auth):
    """Test promote email returns error when email not verified."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user)

    mocker.patch(f"{SERVICES_EMAILS}.get_primary_email", return_value="old@example.com")
    mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id", return_value="new@example.com")
    mock_promote = mocker.patch(f"{SERVICES_EMAILS}.set_primary_email")
    mock_promote.side_effect = ValidationError(
        message="Email not verified", code="email_not_verified"
    )

    client = TestClient(app)
    response = client.post(
        "/users/user-123/promote-email/email-456",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=email_not_verified" in response.headers["location"]


def test_promote_user_email_validation_error(test_admin_user, mocker, override_auth):
    """Test promote email renders error page on other validation errors."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ValidationError

    override_auth(test_admin_user)

    mocker.patch(f"{SERVICES_EMAILS}.get_primary_email", return_value="old@example.com")
    mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id", return_value="new@example.com")
    mock_promote = mocker.patch(f"{SERVICES_EMAILS}.set_primary_email")
    mock_error_page = mocker.patch(f"{USERS_EMAILS}.render_error_page")

    mock_promote.side_effect = ValidationError(message="Other error", code="other_error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/promote-email/email-456",
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error_page.assert_called_once()


def test_promote_user_email_service_error(test_admin_user, mocker, override_auth):
    """Test promote email renders error page on service error."""
    from fastapi.responses import HTMLResponse
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mocker.patch(f"{SERVICES_EMAILS}.get_primary_email", return_value="old@example.com")
    mocker.patch(f"{SERVICES_EMAILS}.get_email_address_by_id", return_value="new@example.com")
    mock_promote = mocker.patch(f"{SERVICES_EMAILS}.set_primary_email")
    mock_error_page = mocker.patch(f"{USERS_EMAILS}.render_error_page")

    mock_promote.side_effect = ServiceError(message="Database error")
    mock_error_page.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/users/user-123/promote-email/email-456",
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error_page.assert_called_once()


# =============================================================================
# User Group Membership Route Tests
# =============================================================================


def test_add_user_to_group_success(test_admin_user, mocker, override_auth):
    """Test admin can add a user to a group."""
    override_auth(test_admin_user)

    mock_add = mocker.patch(f"{USERS_GROUPS}.groups_service.add_member")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/groups/add",
        data={"group_id": "group-456", "csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/groups?success=group_added" in response.headers["location"]
    mock_add.assert_called_once()


def test_add_user_to_group_already_member(test_admin_user, mocker, override_auth):
    """Test adding user to group they are already in returns conflict error."""
    from services.exceptions import ConflictError

    override_auth(test_admin_user)

    mock_add = mocker.patch(f"{USERS_GROUPS}.groups_service.add_member")
    mock_add.side_effect = ConflictError(message="Already a member", code="already_member")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/groups/add",
        data={"group_id": "group-456", "csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=already_member" in response.headers["location"]


def test_add_user_to_group_denied_for_regular_user(test_user, mocker, override_auth):
    """Test regular user cannot add a user to a group."""
    override_auth(test_user)

    mock_add = mocker.patch(f"{USERS_GROUPS}.groups_service.add_member")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/groups/add",
        data={"group_id": "group-456", "csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_add.assert_not_called()


def test_bulk_add_user_to_groups_success(test_admin_user, mocker, override_auth):
    """Test admin can bulk add a user to multiple groups."""
    override_auth(test_admin_user)

    mock_bulk = mocker.patch(f"{USERS_GROUPS}.groups_service.bulk_add_user_to_groups")
    mock_bulk.return_value = 3

    client = TestClient(app)
    response = client.post(
        "/users/user-123/groups/bulk",
        data={"group_ids": ["g1", "g2", "g3"], "csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=groups_bulk_added" in response.headers["location"]
    assert "count=3" in response.headers["location"]
    mock_bulk.assert_called_once()


def test_remove_user_from_group_success(test_admin_user, mocker, override_auth):
    """Test admin can remove a user from a group."""
    override_auth(test_admin_user)

    mock_remove = mocker.patch(f"{USERS_GROUPS}.groups_service.remove_member")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/groups/group-456/remove",
        data={"csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/groups?success=group_removed" in response.headers["location"]
    mock_remove.assert_called_once()


def test_remove_user_from_group_not_found(test_admin_user, mocker, override_auth):
    """Test removing user from group returns error when not a member."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mock_remove = mocker.patch(f"{USERS_GROUPS}.groups_service.remove_member")
    mock_remove.side_effect = NotFoundError(message="Not a member", code="not_a_member")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/groups/group-456/remove",
        data={"csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_a_member" in response.headers["location"]


def test_user_detail_loads_group_data(test_admin_user, mocker, override_auth):
    """Test user groups tab loads group memberships and available groups."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse
    from schemas.api import UserDetail
    from schemas.groups import EffectiveMembership, EffectiveMembershipList

    override_auth(test_admin_user)

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

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mocker.patch(f"{USERS_DETAIL}.sp_service")

    mock_template.return_value = HTMLResponse(content="<html>User Detail</html>")
    mock_get.return_value = target_user

    mock_memberships = EffectiveMembershipList(
        items=[
            EffectiveMembership(
                id="group-1",
                name="Engineering",
                description=None,
                group_type="weftid",
                idp_id=None,
                idp_name=None,
                is_direct=True,
            ),
        ]
    )
    mock_groups = mocker.patch(f"{USERS_DETAIL}.groups_service.get_effective_memberships")
    mock_available = mocker.patch(f"{USERS_DETAIL}.groups_service.list_available_groups_for_user")
    mock_groups.return_value = mock_memberships
    mock_available.return_value = [
        {"id": "group-2", "name": "Sales"},
    ]

    client = TestClient(app)
    response = client.get("/users/user-123/groups")

    assert response.status_code == 200

    # Verify template was called with group data in context
    template_call_args = mock_template.call_args[0]
    context = template_call_args[2]
    assert "user_groups" in context
    assert "available_groups" in context
    assert context["user_groups"] == mock_memberships
    assert len(context["available_groups"]) == 1


def test_user_detail_apps_tab(test_admin_user, mocker, override_auth):
    """Test user detail apps tab renders with accessible apps."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse
    from schemas.api import UserDetail
    from schemas.service_providers import (
        GrantingGroup,
        UserAccessibleApp,
        UserAccessibleAppList,
    )

    override_auth(test_admin_user)

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

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mocker.patch(f"{USERS_DETAIL}.groups_service")

    mock_apps = UserAccessibleAppList(
        items=[
            UserAccessibleApp(
                id="sp-1",
                name="Test App",
                description="A test app",
                entity_id="https://app.example.com",
                available_to_all=False,
                granting_groups=[GrantingGroup(id="g-1", name="Engineering")],
            ),
        ],
        total=1,
    )
    mock_sp_svc = mocker.patch(f"{USERS_DETAIL}.sp_service")
    mock_sp_svc.get_user_accessible_apps_admin.return_value = mock_apps

    mock_template.return_value = HTMLResponse(content="<html>Apps Tab</html>")
    mock_get.return_value = target_user

    client = TestClient(app)
    response = client.get("/users/user-123/apps")

    assert response.status_code == 200
    template_call_args = mock_template.call_args[0]
    assert template_call_args[1] == "user_detail_tab_apps.html"
    context = template_call_args[2]
    assert "accessible_apps" in context
    assert context["accessible_apps"] == mock_apps
    assert context["active_tab"] == "apps"


def test_user_detail_danger_tab(test_admin_user, mocker, override_auth):
    """Test user detail danger tab renders."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse
    from schemas.api import UserDetail

    override_auth(test_admin_user)

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

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mocker.patch(f"{USERS_DETAIL}.groups_service")
    mocker.patch(f"{USERS_DETAIL}.sp_service")
    mocker.patch(f"{USERS_DETAIL}.saml_service.idp_requires_platform_mfa", return_value=False)

    mock_template.return_value = HTMLResponse(content="<html>Danger Tab</html>")
    mock_get.return_value = target_user

    client = TestClient(app)
    response = client.get("/users/user-123/danger")

    assert response.status_code == 200
    template_call_args = mock_template.call_args[0]
    assert template_call_args[1] == "user_detail_tab_danger.html"
    context = template_call_args[2]
    assert context["active_tab"] == "danger"


def test_user_detail_apps_tab_denied_for_regular_user(test_user, override_auth):
    """Regular user cannot access user detail apps tab."""
    override_auth(test_user)

    client = TestClient(app)
    response = client.get("/users/user-123/apps", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_user_detail_danger_tab_denied_for_regular_user(test_user, override_auth):
    """Regular user cannot access user detail danger tab."""
    override_auth(test_user)

    client = TestClient(app)
    response = client.get("/users/user-123/danger", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# User Detail Tab Error Paths
# =============================================================================


def test_user_detail_profile_service_error(test_admin_user, mocker, override_auth):
    """Test profile tab returns error page on generic ServiceError."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mock_get.side_effect = ServiceError(message="Internal error", code="internal_error")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/users/user-123/profile")

    assert response.status_code == 500


def test_user_detail_profile_group_count_error(test_admin_user, mocker, override_auth):
    """Test profile tab renders even when group count service call fails."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse
    from schemas.api import UserDetail
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

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

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mocker.patch(f"{DATABASE_SETTINGS}.list_privileged_domains", return_value=[])
    mock_groups = mocker.patch(f"{USERS_DETAIL}.groups_service.get_effective_memberships")
    mock_sp = mocker.patch(f"{USERS_DETAIL}.sp_service")

    mock_template.return_value = HTMLResponse(content="<html>ok</html>")
    mock_get.return_value = target_user
    mock_groups.side_effect = ServiceError(message="Error", code="error")
    mock_sp.get_user_accessible_apps_admin.return_value = type("R", (), {"total": 0, "items": []})()

    client = TestClient(app)
    response = client.get("/users/user-123/profile")

    assert response.status_code == 200
    context = mock_template.call_args[0][2]
    assert context["group_count"] == 0


def test_user_detail_profile_app_count_error(test_admin_user, mocker, override_auth):
    """Test profile tab renders even when app count service call fails."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse
    from schemas.api import UserDetail
    from schemas.groups import EffectiveMembershipList
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

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

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mocker.patch(f"{DATABASE_SETTINGS}.list_privileged_domains", return_value=[])
    mocker.patch(
        f"{USERS_DETAIL}.groups_service.get_effective_memberships",
        return_value=EffectiveMembershipList(items=[]),
    )
    mock_sp = mocker.patch(f"{USERS_DETAIL}.sp_service")

    mock_template.return_value = HTMLResponse(content="<html>ok</html>")
    mock_get.return_value = target_user
    mock_sp.get_user_accessible_apps_admin.side_effect = ServiceError(message="Error", code="error")

    client = TestClient(app)
    response = client.get("/users/user-123/profile")

    assert response.status_code == 200
    context = mock_template.call_args[0][2]
    assert context["app_count"] == 0


def test_user_detail_profile_super_admin_idp_error(test_super_admin_user, mocker, override_auth):
    """Test profile tab renders even when IdP list fails for super_admin."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse
    from schemas.api import UserDetail
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user)

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

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mocker.patch(f"{DATABASE_SETTINGS}.list_privileged_domains", return_value=[])
    mocker.patch(f"{USERS_DETAIL}.groups_service")
    mocker.patch(f"{USERS_DETAIL}.sp_service")
    mock_idp = mocker.patch(f"{USERS_DETAIL}.saml_service.list_identity_providers")
    mock_idp.side_effect = ServiceError(message="Error", code="error")

    mock_template.return_value = HTMLResponse(content="<html>ok</html>")
    mock_get.return_value = target_user

    client = TestClient(app)
    response = client.get("/users/user-123/profile")

    assert response.status_code == 200
    context = mock_template.call_args[0][2]
    assert context["idps"] == []


def test_user_detail_groups_tab_not_found(test_admin_user, mocker, override_auth):
    """Test groups tab redirects when user not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mock_get.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.get("/users/user-123/groups", follow_redirects=False)

    assert response.status_code == 303
    assert "/users/list" in response.headers["location"]


def test_user_detail_groups_tab_memberships_error(test_admin_user, mocker, override_auth):
    """Test groups tab renders with empty data when memberships fail."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse
    from schemas.api import UserDetail
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

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

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mocker.patch(f"{USERS_DETAIL}.sp_service")
    mock_memberships = mocker.patch(f"{USERS_DETAIL}.groups_service.get_effective_memberships")

    mock_template.return_value = HTMLResponse(content="<html>ok</html>")
    mock_get.return_value = target_user
    mock_memberships.side_effect = ServiceError(message="Error", code="error")

    client = TestClient(app)
    response = client.get("/users/user-123/groups")

    assert response.status_code == 200
    context = mock_template.call_args[0][2]
    assert context["user_groups"] is None


def test_user_detail_apps_tab_service_error(test_admin_user, mocker, override_auth):
    """Test apps tab renders with None when accessible_apps service fails."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse
    from schemas.api import UserDetail
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

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

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mocker.patch(f"{USERS_DETAIL}.groups_service")
    mock_sp = mocker.patch(f"{USERS_DETAIL}.sp_service")

    mock_template.return_value = HTMLResponse(content="<html>ok</html>")
    mock_get.return_value = target_user
    mock_sp.get_user_accessible_apps_admin.side_effect = ServiceError(message="Error", code="error")

    client = TestClient(app)
    response = client.get("/users/user-123/apps")

    assert response.status_code == 200
    context = mock_template.call_args[0][2]
    assert context["accessible_apps"] is None


def test_user_detail_danger_tab_with_idp_user(test_admin_user, mocker, override_auth):
    """Test danger tab checks idp_requires_platform_mfa for IdP users."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse
    from schemas.api import UserDetail

    override_auth(test_admin_user)

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
        saml_idp_id="idp-abc",
    )

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mock_get = mocker.patch(f"{SERVICES_USERS}.get_user")
    mocker.patch(f"{USERS_DETAIL}.groups_service")
    mocker.patch(f"{USERS_DETAIL}.sp_service")
    mock_mfa = mocker.patch(f"{USERS_DETAIL}.saml_service.idp_requires_platform_mfa")
    mock_mfa.return_value = True

    mock_template.return_value = HTMLResponse(content="<html>ok</html>")
    mock_get.return_value = target_user

    client = TestClient(app)
    response = client.get("/users/user-123/danger")

    assert response.status_code == 200
    context = mock_template.call_args[0][2]
    assert context["idp_requires_mfa"] is True
    mock_mfa.assert_called_once()


# =============================================================================
# User Groups Route Error Paths
# =============================================================================


def test_add_user_to_group_service_error(test_admin_user, mocker, override_auth):
    """Test add_user_to_group renders error page on generic ServiceError."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mock_add = mocker.patch(f"{USERS_GROUPS}.groups_service.add_member")
    mock_add.side_effect = ServiceError(message="Unexpected error", code="unexpected")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/users/user-123/groups/add",
        data={"group_id": "group-456", "csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 500


def test_bulk_add_user_to_groups_denied_for_regular_user(test_user, mocker, override_auth):
    """Test regular user cannot bulk add a user to groups."""
    override_auth(test_user)

    mock_bulk = mocker.patch(f"{USERS_GROUPS}.groups_service.bulk_add_user_to_groups")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/groups/bulk",
        data={"group_ids": ["g1", "g2"], "csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_bulk.assert_not_called()


def test_bulk_add_user_to_groups_not_found(test_admin_user, mocker, override_auth):
    """Test bulk add returns error when user or group not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user)

    mock_bulk = mocker.patch(f"{USERS_GROUPS}.groups_service.bulk_add_user_to_groups")
    mock_bulk.side_effect = NotFoundError(message="User not found", code="user_not_found")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/groups/bulk",
        data={"group_ids": ["g1", "g2"], "csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=user_not_found" in response.headers["location"]


def test_bulk_add_user_to_groups_forbidden(test_admin_user, mocker, override_auth):
    """Test bulk add returns error when user lacks permission."""
    from services.exceptions import ForbiddenError

    override_auth(test_admin_user)

    mock_bulk = mocker.patch(f"{USERS_GROUPS}.groups_service.bulk_add_user_to_groups")
    mock_bulk.side_effect = ForbiddenError(message="Not allowed", code="forbidden")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/groups/bulk",
        data={"group_ids": ["g1"], "csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=forbidden" in response.headers["location"]


def test_bulk_add_user_to_groups_service_error(test_admin_user, mocker, override_auth):
    """Test bulk add renders error page on generic ServiceError."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mock_bulk = mocker.patch(f"{USERS_GROUPS}.groups_service.bulk_add_user_to_groups")
    mock_bulk.side_effect = ServiceError(message="Unexpected", code="unexpected")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/users/user-123/groups/bulk",
        data={"group_ids": ["g1"], "csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 500


def test_remove_user_from_group_denied_for_regular_user(test_user, mocker, override_auth):
    """Test regular user cannot remove a user from a group."""
    override_auth(test_user)

    mock_remove = mocker.patch(f"{USERS_GROUPS}.groups_service.remove_member")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/groups/group-456/remove",
        data={"csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    mock_remove.assert_not_called()


def test_remove_user_from_group_service_error(test_admin_user, mocker, override_auth):
    """Test remove renders error page on generic ServiceError."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user)

    mock_remove = mocker.patch(f"{USERS_GROUPS}.groups_service.remove_member")
    mock_remove.side_effect = ServiceError(message="Unexpected", code="unexpected")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/users/user-123/groups/group-456/remove",
        data={"csrf_token": "test"},
        follow_redirects=False,
    )

    assert response.status_code == 500
