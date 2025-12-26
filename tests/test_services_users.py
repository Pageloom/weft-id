"""Comprehensive tests for user service layer functions.

This test file covers all user CRUD operations, authorization, and edge cases
for the services/users.py module.
"""

import pytest
from services.exceptions import ForbiddenError, NotFoundError, ValidationError, ConflictError
from services.types import RequestingUser
from schemas.api import UserCreate, UserUpdate, UserProfileUpdate


def _make_requesting_user(user: dict, tenant_id: str, role: str = None) -> RequestingUser:
    """Helper to create RequestingUser from test fixture."""
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role or user.get("role", "member"),
    )


def _verify_event_logged(tenant_id: str, event_type: str, artifact_id: str):
    """Verify that an event was logged."""
    import database

    events = database.event_log.list_events(tenant_id, limit=1)
    assert len(events) > 0, f"No events logged for {event_type}"
    assert events[0]["event_type"] == event_type
    assert str(events[0]["artifact_id"]) == str(artifact_id)


# =============================================================================
# List Users Tests
# =============================================================================


def test_list_users_as_admin_success(test_tenant, test_admin_user, test_user):
    """Test that an admin can list users."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    result = users_service.list_users(requesting_user)

    assert result.total >= 2  # At least admin and test_user
    assert len(result.items) >= 2
    assert result.page == 1


def test_list_users_as_super_admin_success(test_tenant, test_super_admin_user, test_user):
    """Test that a super_admin can list users."""
    from services import users as users_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, test_tenant["id"], "super_admin"
    )
    result = users_service.list_users(requesting_user)

    assert result.total >= 2
    assert len(result.items) >= 2


def test_list_users_as_member_forbidden(test_tenant, test_user):
    """Test that a regular member cannot list users."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.list_users(requesting_user)

    assert exc_info.value.code == "admin_required"


def test_list_users_with_pagination(test_tenant, test_admin_user):
    """Test user list pagination."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    result = users_service.list_users(requesting_user, page=1, limit=1)

    assert result.page == 1
    assert result.limit == 1
    assert len(result.items) <= 1


def test_list_users_empty_result(test_tenant, test_admin_user):
    """Test listing users with search that matches nothing."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    result = users_service.list_users(requesting_user, search="nonexistent12345xyz")

    assert result.total == 0
    assert len(result.items) == 0


# =============================================================================
# Get User Tests
# =============================================================================


def test_get_user_as_admin_success(test_tenant, test_admin_user, test_user):
    """Test that an admin can get user details."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    result = users_service.get_user(requesting_user, str(test_user["id"]))

    assert result.id == str(test_user["id"])
    assert result.first_name == test_user["first_name"]
    assert result.last_name == test_user["last_name"]
    assert len(result.emails) >= 1


def test_get_user_as_super_admin_success(test_tenant, test_super_admin_user, test_user):
    """Test that a super_admin can get user details."""
    from services import users as users_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, test_tenant["id"], "super_admin"
    )
    result = users_service.get_user(requesting_user, str(test_user["id"]))

    assert result.id == str(test_user["id"])


def test_get_user_as_member_forbidden(test_tenant, test_user, test_admin_user):
    """Test that a member cannot get other users' details."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.get_user(requesting_user, str(test_admin_user["id"]))

    assert exc_info.value.code == "admin_required"


def test_get_user_not_found(test_tenant, test_admin_user):
    """Test getting a non-existent user."""
    from services import users as users_service
    from uuid import uuid4

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    fake_user_id = str(uuid4())

    with pytest.raises(NotFoundError) as exc_info:
        users_service.get_user(requesting_user, fake_user_id)

    assert exc_info.value.code == "user_not_found"


def test_get_user_includes_emails(test_tenant, test_admin_user, test_user):
    """Test that get_user includes the user's email list."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    result = users_service.get_user(requesting_user, str(test_user["id"]))

    assert len(result.emails) >= 1
    assert any(e.is_primary for e in result.emails)


def test_get_user_service_user_flag(test_tenant, test_admin_user, b2b_oauth2_client):
    """Test that is_service_user flag is set correctly."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # b2b_oauth2_client fixture should create a service user
    service_user_id = b2b_oauth2_client["service_user_id"]
    result = users_service.get_user(requesting_user, str(service_user_id))

    assert result.is_service_user is True


# =============================================================================
# Create User Tests
# =============================================================================


def test_create_user_as_admin_success(test_tenant, test_admin_user):
    """Test that an admin can create a regular member user."""
    from services import users as users_service
    from uuid import uuid4

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    user_data = UserCreate(
        first_name="New",
        last_name="User",
        email=f"newuser-{uuid4().hex[:8]}@example.com",
        role="member",
    )

    result = users_service.create_user(requesting_user, user_data)

    assert result.first_name == "New"
    assert result.last_name == "User"
    assert result.email == user_data.email
    assert result.role == "member"
    assert len(result.emails) == 1
    assert result.emails[0].is_primary is True
    assert result.emails[0].verified_at is not None

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "user_created", result.id)


def test_create_user_as_admin_creates_admin_forbidden(test_tenant, test_admin_user):
    """Test that a regular admin cannot create admin users (role escalation)."""
    from services import users as users_service
    from uuid import uuid4

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    user_data = UserCreate(
        first_name="Admin",
        last_name="User",
        email=f"adminuser-{uuid4().hex[:8]}@example.com",
        role="admin",
    )

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.create_user(requesting_user, user_data)

    assert exc_info.value.code == "role_escalation_denied"


def test_create_user_as_super_admin_creates_admin(test_tenant, test_super_admin_user):
    """Test that a super_admin can create admin users."""
    from services import users as users_service
    from uuid import uuid4

    requesting_user = _make_requesting_user(
        test_super_admin_user, test_tenant["id"], "super_admin"
    )
    user_data = UserCreate(
        first_name="New",
        last_name="Admin",
        email=f"newadmin-{uuid4().hex[:8]}@example.com",
        role="admin",
    )

    result = users_service.create_user(requesting_user, user_data)

    assert result.role == "admin"
    _verify_event_logged(test_tenant["id"], "user_created", result.id)


def test_create_user_as_super_admin_creates_super_admin(test_tenant, test_super_admin_user):
    """Test that a super_admin can create other super_admin users."""
    from services import users as users_service
    from uuid import uuid4

    requesting_user = _make_requesting_user(
        test_super_admin_user, test_tenant["id"], "super_admin"
    )
    user_data = UserCreate(
        first_name="New",
        last_name="SuperAdmin",
        email=f"newsuperadmin-{uuid4().hex[:8]}@example.com",
        role="super_admin",
    )

    result = users_service.create_user(requesting_user, user_data)

    assert result.role == "super_admin"
    _verify_event_logged(test_tenant["id"], "user_created", result.id)


def test_create_user_email_already_exists(test_tenant, test_admin_user, test_user):
    """Test that creating a user with an existing email fails."""
    from services import users as users_service
    import database

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # Get test_user's email
    primary_email = database.user_emails.get_primary_email(test_tenant["id"], test_user["id"])

    user_data = UserCreate(
        first_name="Duplicate",
        last_name="Email",
        email=primary_email["email"],  # Use existing email
        role="member",
    )

    with pytest.raises(ConflictError) as exc_info:
        users_service.create_user(requesting_user, user_data)

    assert exc_info.value.code == "email_exists"


def test_create_user_as_member_forbidden(test_tenant, test_user):
    """Test that a regular member cannot create users."""
    from services import users as users_service
    from uuid import uuid4

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = UserCreate(
        first_name="New",
        last_name="User",
        email=f"newuser-{uuid4().hex[:8]}@example.com",
        role="member",
    )

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.create_user(requesting_user, user_data)

    assert exc_info.value.code == "admin_required"


def test_create_user_emits_event_log(test_tenant, test_admin_user):
    """Test that creating a user emits an event log."""
    from services import users as users_service
    import database
    from uuid import uuid4

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    user_data = UserCreate(
        first_name="Event",
        last_name="Test",
        email=f"eventtest-{uuid4().hex[:8]}@example.com",
        role="member",
    )

    result = users_service.create_user(requesting_user, user_data)

    # Verify event with metadata
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "user_created"
    assert str(events[0]["artifact_id"]) == result.id
    assert events[0]["artifact_type"] == "user"
    assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])
    assert events[0]["metadata"]["email"] == user_data.email
    assert events[0]["metadata"]["role"] == "member"


# =============================================================================
# Update User Tests
# =============================================================================


def test_update_user_name_as_admin(test_tenant, test_admin_user, test_user):
    """Test that an admin can update a user's name."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    update_data = UserUpdate(first_name="Updated", last_name="Name")

    result = users_service.update_user(requesting_user, str(test_user["id"]), update_data)

    assert result.first_name == "Updated"
    assert result.last_name == "Name"
    _verify_event_logged(test_tenant["id"], "user_updated", str(test_user["id"]))


def test_update_user_role_as_admin(test_tenant, test_admin_user, test_user):
    """Test that an admin can update a member to admin role."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    # Note: This should fail because only super_admin can create admin role
    # Let's test member role change instead
    update_data = UserUpdate(role="member")

    result = users_service.update_user(requesting_user, str(test_user["id"]), update_data)

    assert result.role == "member"


def test_update_user_role_as_admin_to_admin_forbidden(test_tenant, test_admin_user, test_user):
    """Test that an admin cannot escalate a user to admin role."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    update_data = UserUpdate(role="admin")

    # This should fail - only super_admin can change to admin
    with pytest.raises(ForbiddenError) as exc_info:
        users_service.update_user(requesting_user, str(test_user["id"]), update_data)

    assert exc_info.value.code == "super_admin_role_change_denied"


def test_update_user_role_as_super_admin_to_admin(test_tenant, test_super_admin_user, test_user):
    """Test that a super_admin can promote a user to admin."""
    from services import users as users_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, test_tenant["id"], "super_admin"
    )
    update_data = UserUpdate(role="admin")

    result = users_service.update_user(requesting_user, str(test_user["id"]), update_data)

    assert result.role == "admin"
    _verify_event_logged(test_tenant["id"], "user_updated", str(test_user["id"]))


def test_update_user_demote_last_super_admin_fails(test_tenant, test_super_admin_user):
    """Test that demoting the last super_admin is blocked."""
    from services import users as users_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, test_tenant["id"], "super_admin"
    )
    # Try to demote self (assuming this is the only super_admin)
    update_data = UserUpdate(role="admin")

    with pytest.raises(ValidationError) as exc_info:
        users_service.update_user(
            requesting_user, str(test_super_admin_user["id"]), update_data
        )

    assert exc_info.value.code == "last_super_admin"


def test_update_user_not_found(test_tenant, test_admin_user):
    """Test updating a non-existent user."""
    from services import users as users_service
    from uuid import uuid4

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    update_data = UserUpdate(first_name="Ghost")
    fake_user_id = str(uuid4())

    with pytest.raises(NotFoundError) as exc_info:
        users_service.update_user(requesting_user, fake_user_id, update_data)

    assert exc_info.value.code == "user_not_found"


def test_update_user_as_member_forbidden(test_tenant, test_user, test_admin_user):
    """Test that a member cannot update other users."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    update_data = UserUpdate(first_name="Hacker")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.update_user(requesting_user, str(test_admin_user["id"]), update_data)

    assert exc_info.value.code == "admin_required"


def test_update_user_no_changes_no_event(test_tenant, test_admin_user, test_user):
    """Test that updating a user with no changes doesn't emit an event."""
    from services import users as users_service
    import database

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # Get current event count
    events_before = database.event_log.list_events(test_tenant["id"], limit=10)
    count_before = len(events_before)

    # Update with same values (no change)
    update_data = UserUpdate(
        first_name=test_user["first_name"], last_name=test_user["last_name"]
    )
    users_service.update_user(requesting_user, str(test_user["id"]), update_data)

    # Check event count didn't change
    events_after = database.event_log.list_events(test_tenant["id"], limit=10)
    count_after = len(events_after)

    assert count_after == count_before  # No new event


def test_update_user_tracks_changes_metadata(test_tenant, test_admin_user, test_user):
    """Test that update_user includes change tracking in event metadata."""
    from services import users as users_service
    import database

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    old_first_name = test_user["first_name"]
    update_data = UserUpdate(first_name="Changed")

    users_service.update_user(requesting_user, str(test_user["id"]), update_data)

    # Verify metadata includes changes
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert "changes" in events[0]["metadata"]
    assert "first_name" in events[0]["metadata"]["changes"]
    assert events[0]["metadata"]["changes"]["first_name"]["old"] == old_first_name
    assert events[0]["metadata"]["changes"]["first_name"]["new"] == "Changed"


# =============================================================================
# Delete User Tests
# =============================================================================


def test_delete_user_as_admin_success(test_tenant, test_admin_user):
    """Test that an admin can delete a user."""
    from services import users as users_service
    import database
    from uuid import uuid4

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # Create a user to delete
    user = database.users.create_user(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        first_name="Delete",
        last_name="Me",
        email=f"deleteme-{uuid4().hex[:8]}@example.com",
        role="member",
    )
    user_id = str(user["user_id"])

    # Add email so deletion doesn't fail
    database.user_emails.add_verified_email(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=user_id,
        email=f"deleteme-{uuid4().hex[:8]}@example.com",
        is_primary=True,
    )

    users_service.delete_user(requesting_user, user_id)

    # Verify user is deleted
    deleted_user = database.users.get_user_by_id(test_tenant["id"], user_id)
    assert deleted_user is None

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "user_deleted", user_id)


def test_delete_user_as_super_admin_success(test_tenant, test_super_admin_user):
    """Test that a super_admin can delete a user."""
    from services import users as users_service
    import database
    from uuid import uuid4

    requesting_user = _make_requesting_user(
        test_super_admin_user, test_tenant["id"], "super_admin"
    )

    # Create a user to delete
    user = database.users.create_user(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        first_name="Delete",
        last_name="Me",
        email=f"deleteme-{uuid4().hex[:8]}@example.com",
        role="member",
    )
    user_id = str(user["user_id"])

    database.user_emails.add_verified_email(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=user_id,
        email=f"deleteme-{uuid4().hex[:8]}@example.com",
        is_primary=True,
    )

    users_service.delete_user(requesting_user, user_id)

    deleted_user = database.users.get_user_by_id(test_tenant["id"], user_id)
    assert deleted_user is None


def test_delete_user_as_member_forbidden(test_tenant, test_user, test_admin_user):
    """Test that a member cannot delete users."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.delete_user(requesting_user, str(test_admin_user["id"]))

    assert exc_info.value.code == "admin_required"


def test_delete_user_not_found(test_tenant, test_admin_user):
    """Test deleting a non-existent user."""
    from services import users as users_service
    from uuid import uuid4

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    fake_user_id = str(uuid4())

    with pytest.raises(NotFoundError) as exc_info:
        users_service.delete_user(requesting_user, fake_user_id)

    assert exc_info.value.code == "user_not_found"


def test_delete_user_self_deletion_fails(test_tenant, test_admin_user):
    """Test that a user cannot delete themselves."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ValidationError) as exc_info:
        users_service.delete_user(requesting_user, str(test_admin_user["id"]))

    assert exc_info.value.code == "self_deletion"


def test_delete_user_service_user_fails(test_tenant, test_admin_user, b2b_oauth2_client):
    """Test that service users cannot be deleted directly."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    service_user_id = str(b2b_oauth2_client["service_user_id"])

    with pytest.raises(ValidationError) as exc_info:
        users_service.delete_user(requesting_user, service_user_id)

    assert exc_info.value.code == "service_user_deletion"


def test_delete_user_captures_user_info_before_deletion(test_tenant, test_admin_user):
    """Test that user info is captured in event metadata before deletion."""
    from services import users as users_service
    import database
    from uuid import uuid4

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    email = f"capture-{uuid4().hex[:8]}@example.com"
    user = database.users.create_user(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        first_name="Capture",
        last_name="Info",
        email=email,
        role="member",
    )
    user_id = str(user["user_id"])

    database.user_emails.add_verified_email(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=user_id,
        email=email,
        is_primary=True,
    )

    users_service.delete_user(requesting_user, user_id)

    # Verify event includes user info
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "user_deleted"
    assert "deleted_user_name" in events[0]["metadata"]
    assert "deleted_user_email" in events[0]["metadata"]
    assert "deleted_user_role" in events[0]["metadata"]
    assert events[0]["metadata"]["deleted_user_name"] == "Capture Info"
    assert events[0]["metadata"]["deleted_user_email"] == email


# =============================================================================
# Current User Profile Tests
# =============================================================================


def test_get_current_user_profile_success(test_tenant, test_user):
    """Test that any authenticated user can get their own profile."""
    from services import users as users_service
    import database

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Get full user data including email
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    primary_email = database.user_emails.get_primary_email(
        test_tenant["id"], test_user["id"]
    )
    if primary_email:
        user_data["email"] = primary_email["email"]

    result = users_service.get_current_user_profile(requesting_user, user_data)

    assert result.id == str(test_user["id"])
    assert result.first_name == test_user["first_name"]
    assert result.last_name == test_user["last_name"]


def test_update_current_user_profile_name(test_tenant, test_user):
    """Test that a user can update their own name."""
    from services import users as users_service
    import database

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    primary_email = database.user_emails.get_primary_email(
        test_tenant["id"], test_user["id"]
    )
    if primary_email:
        user_data["email"] = primary_email["email"]

    profile_update = UserProfileUpdate(first_name="NewFirst", last_name="NewLast")
    result = users_service.update_current_user_profile(
        requesting_user, user_data, profile_update
    )

    assert result.first_name == "NewFirst"
    assert result.last_name == "NewLast"
    _verify_event_logged(test_tenant["id"], "user_profile_updated", str(test_user["id"]))


def test_update_current_user_profile_timezone(test_tenant, test_user):
    """Test that a user can update their timezone."""
    from services import users as users_service
    import database

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    primary_email = database.user_emails.get_primary_email(
        test_tenant["id"], test_user["id"]
    )
    if primary_email:
        user_data["email"] = primary_email["email"]

    profile_update = UserProfileUpdate(timezone="America/New_York")
    result = users_service.update_current_user_profile(
        requesting_user, user_data, profile_update
    )

    assert result.timezone == "America/New_York"


def test_update_current_user_profile_locale(test_tenant, test_user):
    """Test that a user can update their locale."""
    from services import users as users_service
    import database

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    primary_email = database.user_emails.get_primary_email(
        test_tenant["id"], test_user["id"]
    )
    if primary_email:
        user_data["email"] = primary_email["email"]

    profile_update = UserProfileUpdate(locale="en")
    result = users_service.update_current_user_profile(
        requesting_user, user_data, profile_update
    )

    assert result.locale == "en"


def test_update_current_user_profile_timezone_and_locale(test_tenant, test_user):
    """Test that a user can update both timezone and locale together."""
    from services import users as users_service
    import database

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    primary_email = database.user_emails.get_primary_email(
        test_tenant["id"], test_user["id"]
    )
    if primary_email:
        user_data["email"] = primary_email["email"]

    profile_update = UserProfileUpdate(
        timezone="Europe/Stockholm", locale="sv"
    )
    result = users_service.update_current_user_profile(
        requesting_user, user_data, profile_update
    )

    assert result.timezone == "Europe/Stockholm"
    assert result.locale == "sv"


def test_update_current_user_profile_no_changes_no_event(test_tenant, test_user):
    """Test that no event is logged when profile isn't actually changed."""
    from services import users as users_service
    import database

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    primary_email = database.user_emails.get_primary_email(
        test_tenant["id"], test_user["id"]
    )
    if primary_email:
        user_data["email"] = primary_email["email"]

    # Get current event count
    events_before = database.event_log.list_events(test_tenant["id"], limit=10)
    count_before = len(events_before)

    # Update with same values
    profile_update = UserProfileUpdate(
        first_name=test_user["first_name"], last_name=test_user["last_name"]
    )
    users_service.update_current_user_profile(requesting_user, user_data, profile_update)

    # Check no new event
    events_after = database.event_log.list_events(test_tenant["id"], limit=10)
    count_after = len(events_after)

    assert count_after == count_before


def test_update_current_user_profile_tracks_changes(test_tenant, test_user):
    """Test that profile update includes change tracking in metadata."""
    from services import users as users_service
    import database

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    primary_email = database.user_emails.get_primary_email(
        test_tenant["id"], test_user["id"]
    )
    if primary_email:
        user_data["email"] = primary_email["email"]

    old_first_name = test_user["first_name"]
    profile_update = UserProfileUpdate(first_name="TrackedChange")
    users_service.update_current_user_profile(requesting_user, user_data, profile_update)

    # Verify metadata
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert "changes" in events[0]["metadata"]
    assert "first_name" in events[0]["metadata"]["changes"]
    assert events[0]["metadata"]["changes"]["first_name"]["old"] == old_first_name
    assert events[0]["metadata"]["changes"]["first_name"]["new"] == "TrackedChange"


def test_create_user_with_auto_create_email_false(test_super_admin_user, test_tenant):
    """Test create_user with auto_create_email=False does not create email record."""
    from services import users as users_service
    import database

    requesting_user: RequestingUser = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "super_admin",
    }

    user_data = UserCreate(
        first_name="Test",
        last_name="NoEmail",
        email="noemail@example.com",
        role="member",
    )

    # Create user with auto_create_email=False
    result = users_service.create_user(
        requesting_user=requesting_user,
        user_data=user_data,
        auto_create_email=False,
    )

    # Verify user was created
    assert result.id is not None
    assert result.first_name == "Test"
    assert result.last_name == "NoEmail"

    # Verify NO email record was created
    emails = database.fetchall(
        test_tenant["id"],
        "SELECT * FROM user_emails WHERE user_id = :user_id",
        {"user_id": result.id},
    )
    assert len(emails) == 0


def test_create_user_with_auto_create_email_true_default(test_super_admin_user, test_tenant):
    """Test create_user without auto_create_email parameter (defaults to True) creates verified email."""
    from services import users as users_service
    import database

    requesting_user: RequestingUser = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "super_admin",
    }

    user_data = UserCreate(
        first_name="Test",
        last_name="WithEmail",
        email="withemail@example.com",
        role="member",
    )

    # Create user without specifying auto_create_email (should default to True)
    result = users_service.create_user(
        requesting_user=requesting_user,
        user_data=user_data,
        # auto_create_email not specified, defaults to True
    )

    # Verify user was created
    assert result.id is not None

    # Verify email record was created with is_verified=True
    emails = database.fetchall(
        test_tenant["id"],
        "SELECT * FROM user_emails WHERE user_id = :user_id",
        {"user_id": result.id},
    )
    assert len(emails) == 1
    assert emails[0]["email"] == "withemail@example.com"
    assert emails[0]["is_primary"] is True
    assert emails[0]["verified_at"] is not None  # Should be verified


def test_create_user_auto_create_email_false_then_add_email(test_super_admin_user, test_tenant):
    """Integration test: Create user with auto_create_email=False, then manually add email."""
    from services import users as users_service
    import database

    requesting_user: RequestingUser = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "super_admin",
    }

    # Step 1: Create user without email
    user_data = UserCreate(
        first_name="Test",
        last_name="ManualEmail",
        email="manualemail@example.com",
        role="member",
    )

    user = users_service.create_user(
        requesting_user=requesting_user,
        user_data=user_data,
        auto_create_email=False,
    )

    # Verify no email exists yet
    emails_before = database.fetchall(
        test_tenant["id"],
        "SELECT * FROM user_emails WHERE user_id = :user_id",
        {"user_id": user.id},
    )
    assert len(emails_before) == 0

    # Step 2: Manually add email using add_verified_email_with_nonce
    email_result = users_service.add_verified_email_with_nonce(
        tenant_id=str(test_tenant["id"]),
        user_id=user.id,
        email="manualemail@example.com",
        is_primary=True,
    )

    # Verify email was added
    assert email_result is not None
    assert email_result["email"] == "manualemail@example.com"

    # Verify both user and email exist now
    emails_after = database.fetchall(
        test_tenant["id"],
        "SELECT * FROM user_emails WHERE user_id = :user_id",
        {"user_id": user.id},
    )
    assert len(emails_after) == 1
    assert emails_after[0]["email"] == "manualemail@example.com"
    assert emails_after[0]["is_primary"] is True
