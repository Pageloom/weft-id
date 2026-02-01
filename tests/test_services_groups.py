"""Unit tests for group service layer functions.

These tests use mocks to isolate the service layer from the database.
"""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from schemas.groups import GroupCreate, GroupUpdate
from services.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationError

# =============================================================================
# List Groups Tests
# =============================================================================


def test_list_groups_as_admin_success(make_requesting_user):
    """Test that an admin can list groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_groups = [
        {
            "id": uuid4(),
            "name": "Engineering",
            "description": "Eng team",
            "group_type": "weftid",
            "is_valid": True,
            "member_count": 5,
            "created_at": datetime.now(UTC),
        },
        {
            "id": uuid4(),
            "name": "Marketing",
            "description": None,
            "group_type": "weftid",
            "is_valid": True,
            "member_count": 3,
            "created_at": datetime.now(UTC),
        },
    ]

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.count_groups.return_value = 2
        mock_db.groups.list_groups.return_value = mock_groups

        result = groups_service.list_groups(requesting_user)

        assert result.total == 2
        assert len(result.items) == 2
        assert result.page == 1
        mock_db.groups.list_groups.assert_called_once()
        mock_db.groups.count_groups.assert_called_once()


def test_list_groups_as_super_admin_success(make_requesting_user):
    """Test that a super_admin can list groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.count_groups.return_value = 0
        mock_db.groups.list_groups.return_value = []

        result = groups_service.list_groups(requesting_user)

        assert result.total == 0
        assert len(result.items) == 0


def test_list_groups_as_member_forbidden(make_requesting_user):
    """Test that a regular member cannot list groups."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        groups_service.list_groups(requesting_user)

    assert exc_info.value.code == "admin_required"


def test_list_groups_with_pagination(make_requesting_user):
    """Test group list pagination."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {
        "id": uuid4(),
        "name": "Test",
        "description": None,
        "group_type": "weftid",
        "is_valid": True,
        "member_count": 0,
        "created_at": datetime.now(UTC),
    }

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.count_groups.return_value = 10
        mock_db.groups.list_groups.return_value = [mock_group]

        result = groups_service.list_groups(requesting_user, page=2, page_size=5)

        assert result.page == 2
        assert result.limit == 5


# =============================================================================
# Get Group Tests
# =============================================================================


def test_get_group_as_admin_success(make_requesting_user):
    """Test that an admin can get group details."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {
        "id": group_id,
        "name": "Engineering",
        "description": "Eng team",
        "group_type": "weftid",
        "idp_id": None,
        "is_valid": True,
        "member_count": 5,
        "parent_count": 1,
        "child_count": 2,
        "created_by": str(uuid4()),
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group

        result = groups_service.get_group(requesting_user, group_id)

        assert result.id == group_id
        assert result.name == "Engineering"
        assert result.member_count == 5
        assert result.parent_count == 1
        assert result.child_count == 2


def test_get_group_not_found(make_requesting_user):
    """Test that getting a non-existent group raises NotFoundError."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")
    group_id = str(uuid4())

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.get_group(requesting_user, group_id)

        assert exc_info.value.code == "group_not_found"


def test_get_group_as_member_forbidden(make_requesting_user):
    """Test that a regular member cannot get group details."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        groups_service.get_group(requesting_user, str(uuid4()))

    assert exc_info.value.code == "admin_required"


# =============================================================================
# Create Group Tests
# =============================================================================


def test_create_group_success(make_requesting_user):
    """Test creating a group successfully."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=user_id, tenant_id=tenant_id, role="admin"
    )

    group_data = GroupCreate(name="Engineering", description="Eng team")

    mock_created = {"id": group_id}
    mock_group = {
        "id": group_id,
        "name": "Engineering",
        "description": "Eng team",
        "group_type": "weftid",
        "idp_id": None,
        "is_valid": True,
        "member_count": 0,
        "parent_count": 0,
        "child_count": 0,
        "created_by": user_id,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
    ):
        mock_db.groups.get_weftid_group_by_name.return_value = None
        mock_db.groups.create_group.return_value = mock_created
        mock_db.groups.get_group_by_id.return_value = mock_group

        result = groups_service.create_group(requesting_user, group_data)

        assert result.id == group_id
        assert result.name == "Engineering"
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_created"
        assert call_kwargs["artifact_type"] == "group"


def test_create_group_name_required(make_requesting_user):
    """Test that creating a group requires a name."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")
    group_data = GroupCreate(name="   ")  # Whitespace only

    with pytest.raises(ValidationError) as exc_info:
        groups_service.create_group(requesting_user, group_data)

    assert exc_info.value.code == "name_required"


def test_create_group_duplicate_name(make_requesting_user):
    """Test that creating a group with duplicate name fails."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")
    group_data = GroupCreate(name="Engineering")

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_name.return_value = {"id": str(uuid4())}

        with pytest.raises(ConflictError) as exc_info:
            groups_service.create_group(requesting_user, group_data)

        assert exc_info.value.code == "group_name_exists"


def test_create_group_as_member_forbidden(make_requesting_user):
    """Test that a regular member cannot create groups."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")
    group_data = GroupCreate(name="Test")

    with pytest.raises(ForbiddenError) as exc_info:
        groups_service.create_group(requesting_user, group_data)

    assert exc_info.value.code == "admin_required"


# =============================================================================
# Update Group Tests
# =============================================================================


def test_update_group_success(make_requesting_user):
    """Test updating a group successfully."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    group_data = GroupUpdate(name="Updated Name", description="New description")

    mock_existing = {
        "id": group_id,
        "name": "Old Name",
        "description": "Old description",
        "group_type": "weftid",
        "idp_id": None,
        "is_valid": True,
        "member_count": 0,
        "parent_count": 0,
        "child_count": 0,
        "created_by": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    mock_updated = {**mock_existing, "name": "Updated Name", "description": "New description"}

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.side_effect = [mock_existing, mock_updated]
        mock_db.groups.get_weftid_group_by_name.return_value = None
        mock_db.groups.update_group.return_value = 1

        result = groups_service.update_group(requesting_user, group_id, group_data)

        assert result.name == "Updated Name"
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_updated"


def test_update_group_not_found(make_requesting_user):
    """Test updating a non-existent group fails."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")
    group_data = GroupUpdate(name="New Name")

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.update_group(requesting_user, str(uuid4()), group_data)

        assert exc_info.value.code == "group_not_found"


def test_update_group_duplicate_name(make_requesting_user):
    """Test that updating to a duplicate name fails."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    group_data = GroupUpdate(name="Taken Name")

    mock_existing = {
        "id": group_id,
        "name": "Original Name",
        "description": None,
        "group_type": "weftid",
        "idp_id": None,
        "is_valid": True,
        "member_count": 0,
        "parent_count": 0,
        "child_count": 0,
        "created_by": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_existing
        mock_db.groups.get_group_by_name.return_value = {"id": str(uuid4())}

        with pytest.raises(ConflictError) as exc_info:
            groups_service.update_group(requesting_user, group_id, group_data)

        assert exc_info.value.code == "group_name_exists"


# =============================================================================
# Delete Group Tests
# =============================================================================


def test_delete_group_success(make_requesting_user):
    """Test deleting a group successfully."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_existing = {
        "id": group_id,
        "name": "To Delete",
        "description": None,
        "group_type": "weftid",
        "idp_id": None,
        "is_valid": True,
        "member_count": 0,
        "parent_count": 0,
        "child_count": 0,
        "created_by": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_existing
        mock_db.groups.delete_group.return_value = 1

        groups_service.delete_group(requesting_user, group_id)

        mock_db.groups.delete_group.assert_called_once()
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_deleted"


def test_delete_group_not_found(make_requesting_user):
    """Test deleting a non-existent group fails."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.delete_group(requesting_user, str(uuid4()))

        assert exc_info.value.code == "group_not_found"


# =============================================================================
# Member Operations Tests
# =============================================================================


def test_list_members_success(make_requesting_user):
    """Test listing group members."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test"}
    mock_members = [
        {
            "id": str(uuid4()),
            "user_id": str(uuid4()),
            "email": "user@example.com",
            "first_name": "Test",
            "last_name": "User",
            "created_at": datetime.now(UTC),
        }
    ]

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.count_group_members.return_value = 1
        mock_db.groups.get_group_members.return_value = mock_members

        result = groups_service.list_members(requesting_user, group_id)

        assert result.total == 1
        assert len(result.items) == 1
        assert result.items[0].email == "user@example.com"


def test_add_member_success(make_requesting_user):
    """Test adding a member to a group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test Group"}
    mock_user = {"id": user_id, "first_name": "Test", "last_name": "User"}

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.users.get_user_by_id.return_value = mock_user
        mock_db.groups.is_group_member.return_value = False
        mock_db.groups.add_group_member.return_value = {"id": str(uuid4())}

        groups_service.add_member(requesting_user, group_id, user_id)

        mock_db.groups.add_group_member.assert_called_once()
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_member_added"


def test_add_member_already_member(make_requesting_user):
    """Test adding a member who is already in the group fails."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test Group"}
    mock_user = {"id": user_id}

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.users.get_user_by_id.return_value = mock_user
        mock_db.groups.is_group_member.return_value = True

        with pytest.raises(ConflictError) as exc_info:
            groups_service.add_member(requesting_user, group_id, user_id)

        assert exc_info.value.code == "already_member"


def test_remove_member_success(make_requesting_user):
    """Test removing a member from a group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test Group"}

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.remove_group_member.return_value = 1

        groups_service.remove_member(requesting_user, group_id, user_id)

        mock_db.groups.remove_group_member.assert_called_once()
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_member_removed"


def test_remove_member_not_a_member(make_requesting_user):
    """Test removing a user who is not a member fails."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test Group"}

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.remove_group_member.return_value = 0

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.remove_member(requesting_user, group_id, str(uuid4()))

        assert exc_info.value.code == "not_a_member"


# =============================================================================
# Relationship Operations Tests
# =============================================================================


def test_list_parents_success(make_requesting_user):
    """Test listing parent groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Child"}
    mock_parents = [
        {
            "id": str(uuid4()),
            "group_id": str(uuid4()),
            "name": "Parent",
            "group_type": "weftid",
            "member_count": 5,
            "created_at": datetime.now(UTC),
        }
    ]

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.get_group_parents.return_value = mock_parents

        result = groups_service.list_parents(requesting_user, group_id)

        assert result.total == 1
        assert len(result.items) == 1
        assert result.items[0].name == "Parent"


def test_list_children_success(make_requesting_user):
    """Test listing child groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Parent"}
    mock_children = [
        {
            "id": str(uuid4()),
            "group_id": str(uuid4()),
            "name": "Child",
            "group_type": "weftid",
            "member_count": 3,
            "created_at": datetime.now(UTC),
        }
    ]

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.get_group_children.return_value = mock_children

        result = groups_service.list_children(requesting_user, group_id)

        assert result.total == 1
        assert len(result.items) == 1
        assert result.items[0].name == "Child"


def test_add_child_success(make_requesting_user):
    """Test adding a child group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    parent_id = str(uuid4())
    child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_parent = {"id": parent_id, "name": "Parent"}
    mock_child = {"id": child_id, "name": "Child"}

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.side_effect = [mock_parent, mock_child]
        mock_db.groups.relationship_exists.return_value = False
        mock_db.groups.would_create_cycle.return_value = False
        mock_db.groups.add_group_relationship.return_value = {"id": str(uuid4())}

        groups_service.add_child(requesting_user, parent_id, child_id)

        mock_db.groups.add_group_relationship.assert_called_once()
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_relationship_created"


def test_add_child_self_reference(make_requesting_user):
    """Test that adding self as child fails."""
    from services import groups as groups_service

    group_id = str(uuid4())
    requesting_user = make_requesting_user(role="admin")

    with pytest.raises(ValidationError) as exc_info:
        groups_service.add_child(requesting_user, group_id, group_id)

    assert exc_info.value.code == "self_reference"


def test_add_child_would_create_cycle(make_requesting_user):
    """Test that adding a child that would create a cycle fails."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    parent_id = str(uuid4())
    child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_parent = {"id": parent_id, "name": "Parent"}
    mock_child = {"id": child_id, "name": "Child"}

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.side_effect = [mock_parent, mock_child]
        mock_db.groups.relationship_exists.return_value = False
        mock_db.groups.would_create_cycle.return_value = True

        with pytest.raises(ValidationError) as exc_info:
            groups_service.add_child(requesting_user, parent_id, child_id)

        assert exc_info.value.code == "would_create_cycle"


def test_add_child_relationship_exists(make_requesting_user):
    """Test that adding an existing relationship fails."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    parent_id = str(uuid4())
    child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_parent = {"id": parent_id, "name": "Parent"}
    mock_child = {"id": child_id, "name": "Child"}

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.side_effect = [mock_parent, mock_child]
        mock_db.groups.relationship_exists.return_value = True

        with pytest.raises(ConflictError) as exc_info:
            groups_service.add_child(requesting_user, parent_id, child_id)

        assert exc_info.value.code == "relationship_exists"


def test_remove_child_success(make_requesting_user):
    """Test removing a child group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    parent_id = str(uuid4())
    child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_parent = {"id": parent_id, "name": "Parent"}
    mock_child = {"id": child_id, "name": "Child"}

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.side_effect = [mock_parent, mock_child]
        mock_db.groups.remove_group_relationship.return_value = 1

        groups_service.remove_child(requesting_user, parent_id, child_id)

        mock_db.groups.remove_group_relationship.assert_called_once()
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_relationship_deleted"


def test_remove_child_not_found(make_requesting_user):
    """Test removing a non-existent relationship fails."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = {"id": str(uuid4()), "name": "Test"}
        mock_db.groups.remove_group_relationship.return_value = 0

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.remove_child(requesting_user, str(uuid4()), str(uuid4()))

        assert exc_info.value.code == "relationship_not_found"


# =============================================================================
# Utility Functions Tests
# =============================================================================


def test_get_user_group_ids():
    """Test getting user's group IDs."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())

    mock_groups = [
        {"id": uuid4(), "name": "Group 1"},
        {"id": uuid4(), "name": "Group 2"},
    ]

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_user_groups.return_value = mock_groups

        result = groups_service.get_user_group_ids(tenant_id, user_id)

        assert len(result) == 2
        mock_db.groups.get_user_groups.assert_called_once_with(tenant_id, user_id)


# =============================================================================
# Dropdown/Selection Functions Tests
# =============================================================================


def test_list_available_users_for_group_success(make_requesting_user):
    """Test listing available users for group membership dropdown."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    user1_id = uuid4()
    user2_id = uuid4()
    member_user_id = uuid4()

    mock_users = [
        {"id": user1_id, "email": "user1@test.com", "first_name": "User", "last_name": "One"},
        {"id": user2_id, "email": "user2@test.com", "first_name": "User", "last_name": "Two"},
        {
            "id": member_user_id,
            "email": "member@test.com",
            "first_name": "Existing",
            "last_name": "Member",
        },
    ]

    mock_members = [{"user_id": member_user_id}]

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = {"id": group_id, "name": "Test Group"}
        mock_db.users.list_users.return_value = mock_users
        mock_db.groups.get_group_members.return_value = mock_members

        result = groups_service.list_available_users_for_group(requesting_user, group_id)

        # Should filter out the existing member
        assert len(result) == 2
        result_ids = {r.id for r in result}
        assert str(user1_id) in result_ids
        assert str(user2_id) in result_ids
        assert str(member_user_id) not in result_ids


def test_list_available_users_for_group_not_found(make_requesting_user):
    """Test listing available users for non-existent group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.list_available_users_for_group(requesting_user, group_id)

        assert exc_info.value.code == "group_not_found"


def test_list_available_users_for_group_forbidden(make_requesting_user):
    """Test that non-admins cannot list available users."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="user")

    with pytest.raises(ForbiddenError):
        groups_service.list_available_users_for_group(requesting_user, group_id)


def test_list_available_parents_success(make_requesting_user):
    """Test listing available parent groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    parent1_id = uuid4()
    parent2_id = uuid4()

    mock_available_parents = [
        {"id": parent1_id, "name": "Parent Group 1", "group_type": "weftid"},
        {"id": parent2_id, "name": "Parent Group 2", "group_type": "weftid"},
    ]

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = {"id": group_id, "name": "Test Group"}
        mock_db.groups.get_groups_for_parent_select.return_value = mock_available_parents

        result = groups_service.list_available_parents(requesting_user, group_id)

        assert len(result) == 2
        assert result[0].id == str(parent1_id)
        assert result[0].name == "Parent Group 1"
        mock_db.groups.get_groups_for_parent_select.assert_called_once_with(tenant_id, group_id)


def test_list_available_parents_not_found(make_requesting_user):
    """Test listing available parents for non-existent group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.list_available_parents(requesting_user, group_id)

        assert exc_info.value.code == "group_not_found"


def test_list_available_children_success(make_requesting_user):
    """Test listing available child groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    child1_id = uuid4()
    child2_id = uuid4()

    mock_available_children = [
        {"id": child1_id, "name": "Child Group 1", "group_type": "weftid"},
        {"id": child2_id, "name": "Child Group 2", "group_type": "weftid"},
    ]

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = {"id": group_id, "name": "Test Group"}
        mock_db.groups.get_groups_for_child_select.return_value = mock_available_children

        result = groups_service.list_available_children(requesting_user, group_id)

        assert len(result) == 2
        assert result[0].id == str(child1_id)
        assert result[0].name == "Child Group 1"
        mock_db.groups.get_groups_for_child_select.assert_called_once_with(tenant_id, group_id)


def test_list_available_children_not_found(make_requesting_user):
    """Test listing available children for non-existent group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.list_available_children(requesting_user, group_id)

        assert exc_info.value.code == "group_not_found"


# =============================================================================
# IdP Group Tests
# =============================================================================


def test_create_idp_base_group_success():
    """Test creating a base group when IdP is created."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    idp_name = "Okta Corporate"
    group_id = str(uuid4())

    mock_created = {"id": group_id}
    mock_group = {
        "id": group_id,
        "name": idp_name,
        "description": f"All users authenticating via {idp_name}",
        "group_type": "idp",
        "idp_id": idp_id,
        "idp_name": idp_name,
        "is_valid": True,
        "member_count": 0,
        "parent_count": 0,
        "child_count": 0,
        "created_by": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
        patch("services.groups.system_context"),
    ):
        # No existing group with this name for this IdP
        mock_db.groups.get_group_by_idp_and_name.return_value = None
        mock_db.groups.create_idp_group.return_value = mock_created
        mock_db.groups.get_group_by_id.return_value = mock_group

        result = groups_service.create_idp_base_group(tenant_id, idp_id, idp_name)

        assert result.name == idp_name
        assert result.group_type == "idp"
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "idp_group_created"
        assert call_kwargs["metadata"]["idp_name"] == idp_name


def test_sync_user_idp_groups_adds_new_groups():
    """Test that sync adds user to new IdP groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_email = "user@example.com"
    idp_id = str(uuid4())
    idp_name = "Okta"
    group_id = str(uuid4())

    mock_existing_group = {
        "id": group_id,
        "name": "Engineering",
        "group_type": "idp",
        "idp_id": idp_id,
    }

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
        patch("services.groups.system_context"),
    ):
        # User is not in any IdP groups yet
        mock_db.groups.get_user_idp_group_ids.return_value = []
        # Group already exists
        mock_db.groups.get_group_by_idp_and_name.return_value = mock_existing_group
        mock_db.groups.get_group_by_id.return_value = mock_existing_group
        mock_db.groups.bulk_add_user_to_groups.return_value = None

        result = groups_service.sync_user_idp_groups(
            tenant_id, user_id, user_email, idp_id, idp_name, ["Engineering"]
        )

        assert "Engineering" in result["added"]
        assert len(result["removed"]) == 0
        mock_db.groups.bulk_add_user_to_groups.assert_called_once()


def test_sync_user_idp_groups_removes_old_groups():
    """Test that sync removes user from old IdP groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_email = "user@example.com"
    idp_id = str(uuid4())
    idp_name = "Okta"
    old_group_id = str(uuid4())

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
        patch("services.groups.system_context"),
    ):
        # User was in a group but no longer
        mock_db.groups.get_user_idp_group_ids.return_value = [old_group_id]
        mock_db.groups.bulk_remove_user_from_groups.return_value = None

        result = groups_service.sync_user_idp_groups(
            tenant_id, user_id, user_email, idp_id, idp_name, []
        )

        assert len(result["added"]) == 0
        assert len(result["removed"]) == 1
        mock_db.groups.bulk_remove_user_from_groups.assert_called_once()


def test_sync_user_idp_groups_creates_discovered_groups():
    """Test that sync creates groups discovered during authentication."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_email = "user@example.com"
    idp_id = str(uuid4())
    idp_name = "Okta"
    new_group_id = str(uuid4())

    mock_created = {"id": new_group_id}
    mock_new_group = {
        "id": new_group_id,
        "name": "New Team",
        "group_type": "idp",
        "idp_id": idp_id,
    }

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
        patch("services.groups.system_context"),
    ):
        mock_db.groups.get_user_idp_group_ids.return_value = []
        # Group doesn't exist yet
        mock_db.groups.get_group_by_idp_and_name.return_value = None
        mock_db.groups.create_idp_group.return_value = mock_created
        mock_db.groups.get_group_by_id.return_value = mock_new_group
        mock_db.groups.bulk_add_user_to_groups.return_value = None

        result = groups_service.sync_user_idp_groups(
            tenant_id, user_id, user_email, idp_id, idp_name, ["New Team"]
        )

        assert "New Team" in result["created"]
        # Created and added
        mock_db.groups.create_idp_group.assert_called_once()


def test_sync_logs_with_idp_attribution():
    """Test that sync logs use SYSTEM_ACTOR_ID with IdP metadata."""
    from services.event_log import SYSTEM_ACTOR_ID
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_email = "user@example.com"
    idp_id = str(uuid4())
    idp_name = "Okta Corporate"
    group_id = str(uuid4())

    mock_group = {
        "id": group_id,
        "name": "Engineering",
        "group_type": "idp",
        "idp_id": idp_id,
    }

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
        patch("services.groups.system_context"),
    ):
        mock_db.groups.get_user_idp_group_ids.return_value = []
        mock_db.groups.get_group_by_idp_and_name.return_value = mock_group
        mock_db.groups.bulk_add_user_to_groups.return_value = None

        groups_service.sync_user_idp_groups(
            tenant_id, user_id, user_email, idp_id, idp_name, ["Engineering"]
        )

        # Check log_event was called with SYSTEM_ACTOR_ID and IdP metadata
        mock_log.assert_called()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["actor_user_id"] == SYSTEM_ACTOR_ID
        assert call_kwargs["metadata"]["idp_id"] == idp_id
        assert call_kwargs["metadata"]["idp_name"] == idp_name
        assert call_kwargs["metadata"]["sync_source"] == "saml_authentication"


def test_add_member_to_idp_group_forbidden(make_requesting_user):
    """Test that adding member to IdP group is forbidden."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_idp_group = {
        "id": group_id,
        "name": "Okta Engineering",
        "group_type": "idp",
        "idp_id": str(uuid4()),
        "is_valid": True,
    }

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_idp_group

        with pytest.raises(ForbiddenError) as exc_info:
            groups_service.add_member(requesting_user, group_id, user_id)

        assert exc_info.value.code == "idp_group_readonly"


def test_remove_member_from_idp_group_forbidden(make_requesting_user):
    """Test that removing member from IdP group is forbidden."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_idp_group = {
        "id": group_id,
        "name": "Okta Engineering",
        "group_type": "idp",
        "idp_id": str(uuid4()),
        "is_valid": True,
    }

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_idp_group

        with pytest.raises(ForbiddenError) as exc_info:
            groups_service.remove_member(requesting_user, group_id, user_id)

        assert exc_info.value.code == "idp_group_readonly"


def test_update_idp_group_forbidden(make_requesting_user):
    """Test that updating an IdP group is forbidden."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    group_data = GroupUpdate(name="New Name")

    mock_idp_group = {
        "id": group_id,
        "name": "Okta Engineering",
        "description": None,
        "group_type": "idp",
        "idp_id": str(uuid4()),
        "is_valid": True,
        "member_count": 0,
        "parent_count": 0,
        "child_count": 0,
        "created_by": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_idp_group

        with pytest.raises(ForbiddenError) as exc_info:
            groups_service.update_group(requesting_user, group_id, group_data)

        assert exc_info.value.code == "idp_group_readonly"


def test_delete_valid_idp_group_forbidden(make_requesting_user):
    """Test that deleting a valid IdP group is forbidden."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_idp_group = {
        "id": group_id,
        "name": "Okta Engineering",
        "description": None,
        "group_type": "idp",
        "idp_id": str(uuid4()),
        "is_valid": True,  # Still valid (IdP exists)
        "member_count": 0,
        "parent_count": 0,
        "child_count": 0,
        "created_by": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_idp_group

        with pytest.raises(ForbiddenError) as exc_info:
            groups_service.delete_group(requesting_user, group_id)

        assert exc_info.value.code == "idp_group_active"


def test_delete_invalid_idp_group_allowed(make_requesting_user):
    """Test that deleting an invalid IdP group is allowed."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_invalid_idp_group = {
        "id": group_id,
        "name": "Okta Engineering",
        "description": None,
        "group_type": "idp",
        "idp_id": None,  # IdP was deleted
        "is_valid": False,  # Marked invalid
        "member_count": 0,
        "parent_count": 0,
        "child_count": 0,
        "created_by": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_invalid_idp_group
        mock_db.groups.delete_group.return_value = 1

        # Should not raise
        groups_service.delete_group(requesting_user, group_id)

        mock_db.groups.delete_group.assert_called_once()
        mock_log.assert_called_once()


def test_add_idp_group_as_child_allowed(make_requesting_user):
    """Test that IdP groups can be added as children of WeftID groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    parent_id = str(uuid4())
    idp_group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_parent = {"id": parent_id, "name": "All Engineering", "group_type": "weftid"}
    mock_idp_child = {
        "id": idp_group_id,
        "name": "Okta Engineering",
        "group_type": "idp",
        "idp_id": str(uuid4()),
    }

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.side_effect = [mock_parent, mock_idp_child]
        mock_db.groups.relationship_exists.return_value = False
        mock_db.groups.would_create_cycle.return_value = False
        mock_db.groups.add_group_relationship.return_value = {"id": str(uuid4())}

        # Should not raise
        groups_service.add_child(requesting_user, parent_id, idp_group_id)

        mock_db.groups.add_group_relationship.assert_called_once()


def test_add_idp_group_as_parent_forbidden(make_requesting_user):
    """Test that IdP groups cannot have children (cannot be parents)."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_group_id = str(uuid4())
    child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_idp_parent = {
        "id": idp_group_id,
        "name": "Okta Engineering",
        "group_type": "idp",
        "idp_id": str(uuid4()),
    }
    mock_child = {"id": child_id, "name": "Some Child", "group_type": "weftid"}

    with patch("services.groups.database") as mock_db:
        mock_db.groups.get_group_by_id.side_effect = [mock_idp_parent, mock_child]
        mock_db.groups.relationship_exists.return_value = False

        with pytest.raises(ValidationError) as exc_info:
            groups_service.add_child(requesting_user, idp_group_id, child_id)

        assert exc_info.value.code == "idp_cannot_be_parent"


def test_invalidate_idp_groups_on_deletion():
    """Test that IdP groups are invalidated when IdP is deleted."""
    from services.event_log import SYSTEM_ACTOR_ID
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    idp_name = "Okta Corporate"
    group1_id = str(uuid4())
    group2_id = str(uuid4())

    mock_groups = [
        {"id": group1_id, "name": "Engineering", "is_valid": True},
        {"id": group2_id, "name": "Sales", "is_valid": True},
    ]

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.log_event") as mock_log,
        patch("services.groups.system_context"),
    ):
        # Get groups returns the groups to be invalidated
        mock_db.groups.get_groups_by_idp.return_value = mock_groups
        mock_db.groups.invalidate_groups_by_idp.return_value = 2

        count = groups_service.invalidate_idp_groups(tenant_id, idp_id, idp_name)

        assert count == 2
        mock_db.groups.invalidate_groups_by_idp.assert_called_once()
        # Log should be called once per group
        assert mock_log.call_count == 2
        # Check the first call
        call_kwargs = mock_log.call_args_list[0][1]
        assert call_kwargs["event_type"] == "idp_group_invalidated"
        assert call_kwargs["actor_user_id"] == SYSTEM_ACTOR_ID
        assert call_kwargs["metadata"]["idp_name"] == idp_name


def test_list_groups_for_idp_success(make_requesting_user):
    """Test listing groups belonging to an IdP."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_groups = [
        {
            "id": uuid4(),
            "name": "Okta Engineering",
            "description": None,
            "group_type": "idp",
            "idp_id": idp_id,
            "idp_name": "Okta",
            "is_valid": True,
            "member_count": 5,
            "created_at": datetime.now(UTC),
        },
        {
            "id": uuid4(),
            "name": "Okta Sales",
            "description": None,
            "group_type": "idp",
            "idp_id": idp_id,
            "idp_name": "Okta",
            "is_valid": True,
            "member_count": 3,
            "created_at": datetime.now(UTC),
        },
    ]

    with (
        patch("services.groups.database") as mock_db,
        patch("services.groups.track_activity"),
    ):
        mock_db.groups.get_groups_by_idp.return_value = mock_groups

        result = groups_service.list_groups_for_idp(requesting_user, idp_id)

        assert len(result) == 2
        assert result[0].group_type == "idp"
        mock_db.groups.get_groups_by_idp.assert_called_once_with(tenant_id, idp_id)
