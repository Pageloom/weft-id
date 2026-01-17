"""Unit tests for user service layer functions.

These tests use mocks to isolate the service layer from the database.
For integration tests that use a real database, see tests/integration/.
"""

from unittest.mock import patch
from uuid import uuid4

import pytest
from schemas.api import UserCreate, UserProfileUpdate, UserUpdate
from services.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationError

# =============================================================================
# List Users Tests
# =============================================================================


def test_list_users_as_admin_success(make_requesting_user, make_user_dict):
    """Test that an admin can list users."""
    from services import users as users_service

    tenant_id = str(uuid4())
    admin = make_user_dict(tenant_id=tenant_id, role="admin")
    member = make_user_dict(tenant_id=tenant_id, role="member")

    requesting_user = make_requesting_user(user_id=admin["id"], tenant_id=tenant_id, role="admin")

    with patch("services.users.database") as mock_db, patch("services.users.track_activity"):
        mock_db.users.list_users.return_value = [admin, member]
        mock_db.users.count_users.return_value = 2

        result = users_service.list_users(requesting_user)

        assert result.total == 2
        assert len(result.items) == 2
        assert result.page == 1
        mock_db.users.list_users.assert_called_once()
        mock_db.users.count_users.assert_called_once()


def test_list_users_as_super_admin_success(make_requesting_user, make_user_dict):
    """Test that a super_admin can list users."""
    from services import users as users_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")

    with patch("services.users.database") as mock_db, patch("services.users.track_activity"):
        mock_db.users.list_users.return_value = [make_user_dict(), make_user_dict()]
        mock_db.users.count_users.return_value = 2

        result = users_service.list_users(requesting_user)

        assert result.total == 2
        assert len(result.items) == 2


def test_list_users_as_member_forbidden(make_requesting_user):
    """Test that a regular member cannot list users."""
    from services import users as users_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.list_users(requesting_user)

    assert exc_info.value.code == "admin_required"


def test_list_users_with_pagination(make_requesting_user, make_user_dict):
    """Test user list pagination."""
    from services import users as users_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.users.database") as mock_db, patch("services.users.track_activity"):
        mock_db.users.list_users.return_value = [make_user_dict()]
        mock_db.users.count_users.return_value = 10

        result = users_service.list_users(requesting_user, page=1, limit=1)

        assert result.page == 1
        assert result.limit == 1
        assert len(result.items) == 1
        assert result.total == 10


def test_list_users_empty_result(make_requesting_user):
    """Test listing users with search that matches nothing."""
    from services import users as users_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.users.database") as mock_db, patch("services.users.track_activity"):
        mock_db.users.list_users.return_value = []
        mock_db.users.count_users.return_value = 0

        result = users_service.list_users(requesting_user, search="nonexistent12345xyz")

        assert result.total == 0
        assert len(result.items) == 0


# =============================================================================
# Get User Tests
# =============================================================================


def test_get_user_as_admin_success(make_requesting_user, make_user_dict, make_email_dict):
    """Test that an admin can get user details."""
    from services import users as users_service

    tenant_id = str(uuid4())
    target_user_id = str(uuid4())
    target_user = make_user_dict(
        user_id=target_user_id,
        tenant_id=tenant_id,
        first_name="Test",
        last_name="User",
    )
    target_email = make_email_dict(user_id=target_user_id, email="test@example.com")

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.users.database") as mock_db, patch("services.users.track_activity"):
        mock_db.users.get_user_by_id.return_value = target_user
        mock_db.user_emails.get_primary_email.return_value = target_email
        mock_db.user_emails.list_user_emails.return_value = [target_email]
        mock_db.users.is_service_user.return_value = False

        result = users_service.get_user(requesting_user, target_user_id)

        assert result.id == target_user_id
        assert result.first_name == "Test"
        assert result.last_name == "User"
        assert len(result.emails) == 1


def test_get_user_as_super_admin_success(make_requesting_user, make_user_dict, make_email_dict):
    """Test that a super_admin can get user details."""
    from services import users as users_service

    tenant_id = str(uuid4())
    target_user_id = str(uuid4())
    target_user = make_user_dict(user_id=target_user_id, tenant_id=tenant_id)
    target_email = make_email_dict(user_id=target_user_id)

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")

    with patch("services.users.database") as mock_db, patch("services.users.track_activity"):
        mock_db.users.get_user_by_id.return_value = target_user
        mock_db.user_emails.get_primary_email.return_value = target_email
        mock_db.user_emails.list_user_emails.return_value = [target_email]
        mock_db.users.is_service_user.return_value = False

        result = users_service.get_user(requesting_user, target_user_id)

        assert result.id == target_user_id


def test_get_user_as_member_forbidden(make_requesting_user):
    """Test that a member cannot get other users' details."""
    from services import users as users_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.get_user(requesting_user, str(uuid4()))

    assert exc_info.value.code == "admin_required"


def test_get_user_not_found(make_requesting_user):
    """Test getting a non-existent user."""
    from services import users as users_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    fake_user_id = str(uuid4())

    with patch("services.users.database") as mock_db, patch("services.users.track_activity"):
        mock_db.users.get_user_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            users_service.get_user(requesting_user, fake_user_id)

        assert exc_info.value.code == "user_not_found"


def test_get_user_includes_emails(make_requesting_user, make_user_dict, make_email_dict):
    """Test that get_user includes the user's email list."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user = make_user_dict(user_id=user_id, tenant_id=tenant_id)
    primary_email = make_email_dict(user_id=user_id, is_primary=True)
    secondary_email = make_email_dict(
        user_id=user_id, is_primary=False, email="secondary@example.com"
    )

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.users.database") as mock_db, patch("services.users.track_activity"):
        mock_db.users.get_user_by_id.return_value = user
        mock_db.user_emails.get_primary_email.return_value = primary_email
        mock_db.user_emails.list_user_emails.return_value = [primary_email, secondary_email]
        mock_db.users.is_service_user.return_value = False

        result = users_service.get_user(requesting_user, user_id)

        assert len(result.emails) == 2
        assert any(e.is_primary for e in result.emails)


def test_get_user_service_user_flag(make_requesting_user, make_user_dict, make_email_dict):
    """Test that is_service_user flag is set correctly."""
    from services import users as users_service

    tenant_id = str(uuid4())
    service_user_id = str(uuid4())
    service_user = make_user_dict(user_id=service_user_id, tenant_id=tenant_id)
    email = make_email_dict(user_id=service_user_id)

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.users.database") as mock_db, patch("services.users.track_activity"):
        mock_db.users.get_user_by_id.return_value = service_user
        mock_db.user_emails.get_primary_email.return_value = email
        mock_db.user_emails.list_user_emails.return_value = [email]
        mock_db.users.is_service_user.return_value = True

        result = users_service.get_user(requesting_user, service_user_id)

        assert result.is_service_user is True


# =============================================================================
# Create User Tests
# =============================================================================


def test_create_user_as_admin_success(make_requesting_user, make_user_dict, make_email_dict):
    """Test that an admin can create a regular member user."""
    from services import users as users_service

    tenant_id = str(uuid4())
    new_user_id = str(uuid4())
    email = f"newuser-{uuid4().hex[:8]}@example.com"

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    user_data = UserCreate(
        first_name="New",
        last_name="User",
        email=email,
        role="member",
    )

    created_user = make_user_dict(
        user_id=new_user_id,
        tenant_id=tenant_id,
        first_name="New",
        last_name="User",
        role="member",
        email=email,
    )
    created_email = make_email_dict(user_id=new_user_id, email=email, is_primary=True)

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.user_emails.email_exists.return_value = False
        mock_db.users.create_user.return_value = {"user_id": new_user_id}
        mock_db.users.get_user_by_id.return_value = created_user
        mock_db.user_emails.list_user_emails.return_value = [created_email]

        result = users_service.create_user(requesting_user, user_data)

        assert result.first_name == "New"
        assert result.last_name == "User"
        assert result.role == "member"
        assert len(result.emails) == 1
        assert result.emails[0].is_primary is True

        mock_db.user_emails.email_exists.assert_called_once_with(tenant_id, email)
        mock_db.users.create_user.assert_called_once()


def test_create_user_as_admin_creates_admin_forbidden(make_requesting_user):
    """Test that a regular admin cannot create admin users (role escalation)."""
    from services import users as users_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    user_data = UserCreate(
        first_name="Admin",
        last_name="User",
        email=f"adminuser-{uuid4().hex[:8]}@example.com",
        role="admin",
    )

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.create_user(requesting_user, user_data)

    assert exc_info.value.code == "role_escalation_denied"


def test_create_user_as_super_admin_creates_admin(
    make_requesting_user, make_user_dict, make_email_dict
):
    """Test that a super_admin can create admin users."""
    from services import users as users_service

    tenant_id = str(uuid4())
    new_user_id = str(uuid4())
    email = f"newadmin-{uuid4().hex[:8]}@example.com"

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
    user_data = UserCreate(
        first_name="New",
        last_name="Admin",
        email=email,
        role="admin",
    )

    created_user = make_user_dict(
        user_id=new_user_id,
        tenant_id=tenant_id,
        first_name="New",
        last_name="Admin",
        role="admin",
        email=email,
    )
    created_email = make_email_dict(user_id=new_user_id, email=email)

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.user_emails.email_exists.return_value = False
        mock_db.users.create_user.return_value = {"user_id": new_user_id}
        mock_db.users.get_user_by_id.return_value = created_user
        mock_db.user_emails.list_user_emails.return_value = [created_email]

        result = users_service.create_user(requesting_user, user_data)

        assert result.role == "admin"


def test_create_user_as_super_admin_creates_super_admin(
    make_requesting_user, make_user_dict, make_email_dict
):
    """Test that a super_admin can create other super_admin users."""
    from services import users as users_service

    tenant_id = str(uuid4())
    new_user_id = str(uuid4())
    email = f"newsuperadmin-{uuid4().hex[:8]}@example.com"

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
    user_data = UserCreate(
        first_name="New",
        last_name="SuperAdmin",
        email=email,
        role="super_admin",
    )

    created_user = make_user_dict(
        user_id=new_user_id,
        tenant_id=tenant_id,
        first_name="New",
        last_name="SuperAdmin",
        role="super_admin",
        email=email,
    )
    created_email = make_email_dict(user_id=new_user_id, email=email)

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.user_emails.email_exists.return_value = False
        mock_db.users.create_user.return_value = {"user_id": new_user_id}
        mock_db.users.get_user_by_id.return_value = created_user
        mock_db.user_emails.list_user_emails.return_value = [created_email]

        result = users_service.create_user(requesting_user, user_data)

        assert result.role == "super_admin"


def test_create_user_email_already_exists(make_requesting_user):
    """Test that creating a user with an existing email fails."""
    from services import users as users_service

    tenant_id = str(uuid4())
    existing_email = "existing@example.com"

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    user_data = UserCreate(
        first_name="Duplicate",
        last_name="Email",
        email=existing_email,
        role="member",
    )

    with patch("services.users.database") as mock_db:
        mock_db.user_emails.email_exists.return_value = True

        with pytest.raises(ConflictError) as exc_info:
            users_service.create_user(requesting_user, user_data)

        assert exc_info.value.code == "email_exists"


def test_create_user_as_member_forbidden(make_requesting_user):
    """Test that a regular member cannot create users."""
    from services import users as users_service

    requesting_user = make_requesting_user(role="member")
    user_data = UserCreate(
        first_name="New",
        last_name="User",
        email=f"newuser-{uuid4().hex[:8]}@example.com",
        role="member",
    )

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.create_user(requesting_user, user_data)

    assert exc_info.value.code == "admin_required"


def test_create_user_emits_event_log(make_requesting_user, make_user_dict, make_email_dict):
    """Test that creating a user emits an event log."""
    from services import users as users_service

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    new_user_id = str(uuid4())
    email = f"eventtest-{uuid4().hex[:8]}@example.com"

    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")
    user_data = UserCreate(
        first_name="Event",
        last_name="Test",
        email=email,
        role="member",
    )

    created_user = make_user_dict(
        user_id=new_user_id,
        tenant_id=tenant_id,
        first_name="Event",
        last_name="Test",
        role="member",
        email=email,
    )
    created_email = make_email_dict(user_id=new_user_id, email=email)

    with patch("services.users.database") as mock_db, patch("services.users.log_event") as mock_log:
        mock_db.user_emails.email_exists.return_value = False
        mock_db.users.create_user.return_value = {"user_id": new_user_id}
        mock_db.users.get_user_by_id.return_value = created_user
        mock_db.user_emails.list_user_emails.return_value = [created_email]

        users_service.create_user(requesting_user, user_data)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["event_type"] == "user_created"
        assert call_kwargs["artifact_id"] == str(new_user_id)
        assert call_kwargs["artifact_type"] == "user"
        assert call_kwargs["actor_user_id"] == admin_id
        assert call_kwargs["metadata"]["email"] == email
        assert call_kwargs["metadata"]["role"] == "member"


# =============================================================================
# Update User Tests
# =============================================================================


def test_update_user_name_as_admin(make_requesting_user, make_user_dict, make_email_dict):
    """Test that an admin can update a user's name."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    original_user = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="Original",
        last_name="Name",
    )
    updated_user = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="Updated",
        last_name="Name",
    )
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    update_data = UserUpdate(first_name="Updated", last_name="Name")

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.users.get_user_by_id.side_effect = [original_user, updated_user]
        mock_db.user_emails.get_primary_email.return_value = email
        mock_db.user_emails.list_user_emails.return_value = [email]
        mock_db.users.is_service_user.return_value = False

        result = users_service.update_user(requesting_user, user_id, update_data)

        assert result.first_name == "Updated"
        assert result.last_name == "Name"


def test_update_user_role_as_admin(make_requesting_user, make_user_dict, make_email_dict):
    """Test that an admin can update a member's role (keeping as member)."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user = make_user_dict(user_id=user_id, tenant_id=tenant_id, role="member")
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    update_data = UserUpdate(role="member")

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.users.get_user_by_id.return_value = user
        mock_db.user_emails.get_primary_email.return_value = email
        mock_db.user_emails.list_user_emails.return_value = [email]
        mock_db.users.is_service_user.return_value = False

        result = users_service.update_user(requesting_user, user_id, update_data)

        assert result.role == "member"


def test_update_user_role_as_admin_to_admin_forbidden(make_requesting_user, make_user_dict):
    """Test that an admin cannot escalate a user to admin role."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user = make_user_dict(user_id=user_id, tenant_id=tenant_id, role="member")

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    update_data = UserUpdate(role="admin")

    with patch("services.users.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = user

        with pytest.raises(ForbiddenError) as exc_info:
            users_service.update_user(requesting_user, user_id, update_data)

        assert exc_info.value.code == "super_admin_role_change_denied"


def test_update_user_role_as_super_admin_to_admin(
    make_requesting_user, make_user_dict, make_email_dict
):
    """Test that a super_admin can promote a user to admin."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    original_user = make_user_dict(user_id=user_id, tenant_id=tenant_id, role="member")
    updated_user = make_user_dict(user_id=user_id, tenant_id=tenant_id, role="admin")
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
    update_data = UserUpdate(role="admin")

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.users.get_user_by_id.side_effect = [original_user, updated_user]
        mock_db.user_emails.get_primary_email.return_value = email
        mock_db.user_emails.list_user_emails.return_value = [email]
        mock_db.users.is_service_user.return_value = False

        result = users_service.update_user(requesting_user, user_id, update_data)

        assert result.role == "admin"


def test_update_user_demote_last_super_admin_fails(make_requesting_user, make_user_dict):
    """Test that demoting the last super_admin is blocked."""
    from services import users as users_service

    tenant_id = str(uuid4())
    super_admin_id = str(uuid4())
    super_admin = make_user_dict(user_id=super_admin_id, tenant_id=tenant_id, role="super_admin")

    requesting_user = make_requesting_user(
        user_id=super_admin_id, tenant_id=tenant_id, role="super_admin"
    )
    update_data = UserUpdate(role="admin")

    with patch("services.users.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = super_admin
        # Return only this one super_admin
        mock_db.users.list_users.return_value = [super_admin]

        with pytest.raises(ValidationError) as exc_info:
            users_service.update_user(requesting_user, super_admin_id, update_data)

        assert exc_info.value.code == "last_super_admin"


def test_update_user_not_found(make_requesting_user):
    """Test updating a non-existent user."""
    from services import users as users_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    update_data = UserUpdate(first_name="Ghost")
    fake_user_id = str(uuid4())

    with patch("services.users.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            users_service.update_user(requesting_user, fake_user_id, update_data)

        assert exc_info.value.code == "user_not_found"


def test_update_user_as_member_forbidden(make_requesting_user):
    """Test that a member cannot update other users."""
    from services import users as users_service

    requesting_user = make_requesting_user(role="member")
    update_data = UserUpdate(first_name="Hacker")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.update_user(requesting_user, str(uuid4()), update_data)

    assert exc_info.value.code == "admin_required"


def test_update_user_no_changes_no_event(make_requesting_user, make_user_dict, make_email_dict):
    """Test that updating a user with no changes doesn't emit an event."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="Test",
        last_name="User",
    )
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    update_data = UserUpdate(first_name="Test", last_name="User")

    with patch("services.users.database") as mock_db, patch("services.users.log_event") as mock_log:
        mock_db.users.get_user_by_id.return_value = user
        mock_db.user_emails.get_primary_email.return_value = email
        mock_db.user_emails.list_user_emails.return_value = [email]
        mock_db.users.is_service_user.return_value = False

        users_service.update_user(requesting_user, user_id, update_data)

        mock_log.assert_not_called()


def test_update_user_tracks_changes_metadata(make_requesting_user, make_user_dict, make_email_dict):
    """Test that update_user includes change tracking in event metadata."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    original_user = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="Original",
        last_name="Name",
    )
    updated_user = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="Changed",
        last_name="Name",
    )
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    update_data = UserUpdate(first_name="Changed")

    with patch("services.users.database") as mock_db, patch("services.users.log_event") as mock_log:
        mock_db.users.get_user_by_id.side_effect = [original_user, updated_user]
        mock_db.user_emails.get_primary_email.return_value = email
        mock_db.user_emails.list_user_emails.return_value = [email]
        mock_db.users.is_service_user.return_value = False

        users_service.update_user(requesting_user, user_id, update_data)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert "changes" in call_kwargs["metadata"]
        assert "first_name" in call_kwargs["metadata"]["changes"]
        assert call_kwargs["metadata"]["changes"]["first_name"]["old"] == "Original"
        assert call_kwargs["metadata"]["changes"]["first_name"]["new"] == "Changed"


# =============================================================================
# Delete User Tests
# =============================================================================


def test_delete_user_as_admin_success(make_requesting_user, make_user_dict, make_email_dict):
    """Test that an admin can delete a user."""
    from services import users as users_service

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user_to_delete_id = str(uuid4())
    user_to_delete = make_user_dict(
        user_id=user_to_delete_id,
        tenant_id=tenant_id,
        role="member",
    )
    email = make_email_dict(user_id=user_to_delete_id, email="deleteme@example.com")

    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")

    with patch("services.users.database") as mock_db, patch("services.users.log_event") as mock_log:
        mock_db.users.get_user_by_id.return_value = user_to_delete
        mock_db.users.is_service_user.return_value = False
        mock_db.user_emails.get_primary_email.return_value = email

        users_service.delete_user(requesting_user, user_to_delete_id)

        mock_db.users.delete_user.assert_called_once_with(tenant_id, user_to_delete_id)
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["event_type"] == "user_deleted"


def test_delete_user_as_super_admin_success(make_requesting_user, make_user_dict, make_email_dict):
    """Test that a super_admin can delete a user."""
    from services import users as users_service

    tenant_id = str(uuid4())
    super_admin_id = str(uuid4())
    user_to_delete_id = str(uuid4())
    user_to_delete = make_user_dict(
        user_id=user_to_delete_id,
        tenant_id=tenant_id,
        role="member",
    )
    email = make_email_dict(user_id=user_to_delete_id)

    requesting_user = make_requesting_user(
        user_id=super_admin_id, tenant_id=tenant_id, role="super_admin"
    )

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.users.get_user_by_id.return_value = user_to_delete
        mock_db.users.is_service_user.return_value = False
        mock_db.user_emails.get_primary_email.return_value = email

        users_service.delete_user(requesting_user, user_to_delete_id)

        mock_db.users.delete_user.assert_called_once()


def test_delete_user_as_member_forbidden(make_requesting_user):
    """Test that a member cannot delete users."""
    from services import users as users_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.delete_user(requesting_user, str(uuid4()))

    assert exc_info.value.code == "admin_required"


def test_delete_user_not_found(make_requesting_user):
    """Test deleting a non-existent user."""
    from services import users as users_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    fake_user_id = str(uuid4())

    with patch("services.users.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            users_service.delete_user(requesting_user, fake_user_id)

        assert exc_info.value.code == "user_not_found"


def test_delete_user_self_deletion_fails(make_requesting_user, make_user_dict):
    """Test that a user cannot delete themselves."""
    from services import users as users_service

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    admin = make_user_dict(user_id=admin_id, tenant_id=tenant_id, role="admin")

    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")

    with patch("services.users.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = admin
        mock_db.users.is_service_user.return_value = False

        with pytest.raises(ValidationError) as exc_info:
            users_service.delete_user(requesting_user, admin_id)

        assert exc_info.value.code == "self_deletion"


def test_delete_user_service_user_fails(make_requesting_user, make_user_dict):
    """Test that service users cannot be deleted directly."""
    from services import users as users_service

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    service_user_id = str(uuid4())
    service_user = make_user_dict(user_id=service_user_id, tenant_id=tenant_id)

    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")

    with patch("services.users.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = service_user
        mock_db.users.is_service_user.return_value = True

        with pytest.raises(ValidationError) as exc_info:
            users_service.delete_user(requesting_user, service_user_id)

        assert exc_info.value.code == "service_user_deletion"


def test_delete_user_captures_user_info_before_deletion(
    make_requesting_user, make_user_dict, make_email_dict
):
    """Test that user info is captured in event metadata before deletion."""
    from services import users as users_service

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user_to_delete_id = str(uuid4())
    email = "capture@example.com"
    user_to_delete = make_user_dict(
        user_id=user_to_delete_id,
        tenant_id=tenant_id,
        first_name="Capture",
        last_name="Info",
        role="member",
    )
    user_email = make_email_dict(user_id=user_to_delete_id, email=email)

    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")

    with patch("services.users.database") as mock_db, patch("services.users.log_event") as mock_log:
        mock_db.users.get_user_by_id.return_value = user_to_delete
        mock_db.users.is_service_user.return_value = False
        mock_db.user_emails.get_primary_email.return_value = user_email

        users_service.delete_user(requesting_user, user_to_delete_id)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["event_type"] == "user_deleted"
        assert "deleted_user_name" in call_kwargs["metadata"]
        assert "deleted_user_email" in call_kwargs["metadata"]
        assert "deleted_user_role" in call_kwargs["metadata"]
        assert call_kwargs["metadata"]["deleted_user_name"] == "Capture Info"
        assert call_kwargs["metadata"]["deleted_user_email"] == email


# =============================================================================
# Current User Profile Tests
# =============================================================================


def test_get_current_user_profile_success(make_requesting_user, make_user_dict):
    """Test that any authenticated user can get their own profile."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_data = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="Test",
        last_name="User",
        email="test@example.com",
    )

    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")

    with patch("services.users.track_activity"):
        result = users_service.get_current_user_profile(requesting_user, user_data)

        assert result.id == user_id
        assert result.first_name == "Test"
        assert result.last_name == "User"


def test_update_current_user_profile_name(make_requesting_user, make_user_dict, make_email_dict):
    """Test that a user can update their own name."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    original_user = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="Original",
        last_name="Name",
        email="test@example.com",
    )
    updated_user = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="NewFirst",
        last_name="NewLast",
        email="test@example.com",
    )
    email = make_email_dict(user_id=user_id, email="test@example.com")

    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")
    profile_update = UserProfileUpdate(first_name="NewFirst", last_name="NewLast")

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.users.get_user_by_id.return_value = updated_user
        mock_db.user_emails.get_primary_email.return_value = email

        result = users_service.update_current_user_profile(
            requesting_user, original_user, profile_update
        )

        assert result.first_name == "NewFirst"
        assert result.last_name == "NewLast"


def test_update_current_user_profile_timezone(
    make_requesting_user, make_user_dict, make_email_dict
):
    """Test that a user can update their timezone."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_data = make_user_dict(user_id=user_id, tenant_id=tenant_id, tz=None)
    updated_user = make_user_dict(user_id=user_id, tenant_id=tenant_id, tz="America/New_York")
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")
    profile_update = UserProfileUpdate(timezone="America/New_York")

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.users.get_user_by_id.return_value = updated_user
        mock_db.user_emails.get_primary_email.return_value = email

        result = users_service.update_current_user_profile(
            requesting_user, user_data, profile_update
        )

        assert result.timezone == "America/New_York"


def test_update_current_user_profile_locale(make_requesting_user, make_user_dict, make_email_dict):
    """Test that a user can update their locale."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_data = make_user_dict(user_id=user_id, tenant_id=tenant_id, locale=None)
    updated_user = make_user_dict(user_id=user_id, tenant_id=tenant_id, locale="en")
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")
    profile_update = UserProfileUpdate(locale="en")

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.users.get_user_by_id.return_value = updated_user
        mock_db.user_emails.get_primary_email.return_value = email

        result = users_service.update_current_user_profile(
            requesting_user, user_data, profile_update
        )

        assert result.locale == "en"


def test_update_current_user_profile_timezone_and_locale(
    make_requesting_user, make_user_dict, make_email_dict
):
    """Test that a user can update both timezone and locale together."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_data = make_user_dict(user_id=user_id, tenant_id=tenant_id, tz=None, locale=None)
    updated_user = make_user_dict(
        user_id=user_id, tenant_id=tenant_id, tz="Europe/Stockholm", locale="sv"
    )
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")
    profile_update = UserProfileUpdate(timezone="Europe/Stockholm", locale="sv")

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.users.get_user_by_id.return_value = updated_user
        mock_db.user_emails.get_primary_email.return_value = email

        result = users_service.update_current_user_profile(
            requesting_user, user_data, profile_update
        )

        assert result.timezone == "Europe/Stockholm"
        assert result.locale == "sv"


def test_update_current_user_profile_full_posix_locale(
    make_requesting_user, make_user_dict, make_email_dict
):
    """Test that a user can update locale using full POSIX format (e.g., en_US, sv_SE)."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_data = make_user_dict(user_id=user_id, tenant_id=tenant_id)
    updated_user = make_user_dict(
        user_id=user_id, tenant_id=tenant_id, tz="America/New_York", locale="en_US"
    )
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")
    profile_update = UserProfileUpdate(timezone="America/New_York", locale="en_US")

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.users.get_user_by_id.return_value = updated_user
        mock_db.user_emails.get_primary_email.return_value = email

        result = users_service.update_current_user_profile(
            requesting_user, user_data, profile_update
        )

        assert result.timezone == "America/New_York"
        assert result.locale == "en_US"


def test_update_current_user_profile_no_changes_no_event(
    make_requesting_user, make_user_dict, make_email_dict
):
    """Test that no event is logged when profile isn't actually changed."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_data = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="Test",
        last_name="User",
    )
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")
    profile_update = UserProfileUpdate(first_name="Test", last_name="User")

    with patch("services.users.database") as mock_db, patch("services.users.log_event") as mock_log:
        mock_db.users.get_user_by_id.return_value = user_data
        mock_db.user_emails.get_primary_email.return_value = email

        users_service.update_current_user_profile(requesting_user, user_data, profile_update)

        mock_log.assert_not_called()


def test_update_current_user_profile_tracks_changes(
    make_requesting_user, make_user_dict, make_email_dict
):
    """Test that profile update includes change tracking in metadata."""
    from services import users as users_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    original_user = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="Original",
        last_name="Name",
    )
    updated_user = make_user_dict(
        user_id=user_id,
        tenant_id=tenant_id,
        first_name="TrackedChange",
        last_name="Name",
    )
    email = make_email_dict(user_id=user_id)

    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")
    profile_update = UserProfileUpdate(first_name="TrackedChange")

    with patch("services.users.database") as mock_db, patch("services.users.log_event") as mock_log:
        mock_db.users.get_user_by_id.return_value = updated_user
        mock_db.user_emails.get_primary_email.return_value = email

        users_service.update_current_user_profile(requesting_user, original_user, profile_update)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert "changes" in call_kwargs["metadata"]
        assert "first_name" in call_kwargs["metadata"]["changes"]
        assert call_kwargs["metadata"]["changes"]["first_name"]["old"] == "Original"
        assert call_kwargs["metadata"]["changes"]["first_name"]["new"] == "TrackedChange"


# =============================================================================
# Auto Create Email Tests
# =============================================================================


def test_create_user_with_auto_create_email_false(make_requesting_user, make_user_dict):
    """Test create_user with auto_create_email=False does not create email record."""
    from services import users as users_service

    tenant_id = str(uuid4())
    new_user_id = str(uuid4())
    email = "noemail@example.com"

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
    user_data = UserCreate(
        first_name="Test",
        last_name="NoEmail",
        email=email,
        role="member",
    )

    created_user = make_user_dict(
        user_id=new_user_id,
        tenant_id=tenant_id,
        first_name="Test",
        last_name="NoEmail",
        role="member",
        email=email,
    )

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.user_emails.email_exists.return_value = False
        mock_db.users.create_user.return_value = {"user_id": new_user_id}
        mock_db.users.get_user_by_id.return_value = created_user
        mock_db.user_emails.list_user_emails.return_value = []  # No emails created

        result = users_service.create_user(
            requesting_user=requesting_user,
            user_data=user_data,
            auto_create_email=False,
        )

        assert result.id is not None
        assert result.first_name == "Test"
        assert result.last_name == "NoEmail"

        # Verify add_verified_email was NOT called
        mock_db.user_emails.add_verified_email.assert_not_called()


def test_create_user_with_auto_create_email_true_default(
    make_requesting_user, make_user_dict, make_email_dict
):
    """Test create_user without auto_create_email creates verified email."""
    from services import users as users_service

    tenant_id = str(uuid4())
    new_user_id = str(uuid4())
    email = "withemail@example.com"

    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
    user_data = UserCreate(
        first_name="Test",
        last_name="WithEmail",
        email=email,
        role="member",
    )

    created_user = make_user_dict(
        user_id=new_user_id,
        tenant_id=tenant_id,
        first_name="Test",
        last_name="WithEmail",
        role="member",
        email=email,
    )
    created_email = make_email_dict(user_id=new_user_id, email=email, is_primary=True)

    with patch("services.users.database") as mock_db, patch("services.users.log_event"):
        mock_db.user_emails.email_exists.return_value = False
        mock_db.users.create_user.return_value = {"user_id": new_user_id}
        mock_db.users.get_user_by_id.return_value = created_user
        mock_db.user_emails.list_user_emails.return_value = [created_email]

        result = users_service.create_user(
            requesting_user=requesting_user,
            user_data=user_data,
            # auto_create_email not specified, defaults to True
        )

        assert result.id is not None
        assert len(result.emails) == 1
        assert result.emails[0].email == email
        assert result.emails[0].is_primary is True

        # Verify add_verified_email WAS called
        mock_db.user_emails.add_verified_email.assert_called_once()
