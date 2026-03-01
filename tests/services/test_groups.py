"""Unit tests for group service layer functions.

These tests use mocks to isolate the service layer from the database.
"""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from schemas.groups import GroupCreate, GroupDetail, GroupUpdate
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
            "sp_count": 2,
            "created_at": datetime.now(UTC),
        },
        {
            "id": uuid4(),
            "name": "Marketing",
            "description": None,
            "group_type": "weftid",
            "is_valid": True,
            "member_count": 3,
            "sp_count": 0,
            "created_at": datetime.now(UTC),
        },
    ]

    with (
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.track_activity"),
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
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.track_activity"),
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
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.track_activity"),
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
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.track_activity"),
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
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.track_activity"),
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
    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="admin")

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
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.log_event") as mock_log,
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

    with patch("services.groups.crud.database") as mock_db:
        mock_db.groups.get_weftid_group_by_name.return_value = {"id": str(uuid4())}

        with pytest.raises(ValidationError) as exc_info:
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


def test_create_group_db_creation_fails(make_requesting_user):
    """DB returning None from create_group raises ValidationError."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")
    group_data = GroupCreate(name="Engineering")

    with patch("services.groups.crud.database") as mock_db:
        mock_db.groups.get_weftid_group_by_name.return_value = None
        mock_db.groups.create_group.return_value = None

        with pytest.raises(ValidationError) as exc_info:
            groups_service.create_group(requesting_user, group_data)

        assert exc_info.value.code == "creation_failed"


def test_create_group_fetch_after_create_fails(make_requesting_user):
    """DB returning None from get_group_by_id after create raises ValidationError."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="admin")
    group_data = GroupCreate(name="Engineering")

    with patch("services.groups.crud.database") as mock_db:
        mock_db.groups.get_weftid_group_by_name.return_value = None
        mock_db.groups.create_group.return_value = {"id": str(uuid4())}
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(ValidationError) as exc_info:
            groups_service.create_group(requesting_user, group_data)

        assert exc_info.value.code == "fetch_failed"


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
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.log_event") as mock_log,
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

    with patch("services.groups.crud.database") as mock_db:
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

    with patch("services.groups.crud.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_existing
        mock_db.groups.get_weftid_group_by_name.return_value = {"id": str(uuid4())}

        with pytest.raises(ValidationError) as exc_info:
            groups_service.update_group(requesting_user, group_id, group_data)

        assert exc_info.value.code == "group_name_exists"


def test_update_group_name_whitespace_only(make_requesting_user):
    """Updating a group with a whitespace-only name raises ValidationError."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    group_data = GroupUpdate(name="   ")

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

    with patch("services.groups.crud.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_existing

        with pytest.raises(ValidationError) as exc_info:
            groups_service.update_group(requesting_user, group_id, group_data)

        assert exc_info.value.code == "name_required"


def test_update_group_fetch_after_update_fails(make_requesting_user):
    """DB returning None from get_group_by_id after update raises NotFoundError."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
    group_data = GroupUpdate(description="New description")

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

    with patch("services.groups.crud.database") as mock_db:
        mock_db.groups.get_group_by_id.side_effect = [mock_existing, None]
        mock_db.groups.update_group.return_value = 1

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.update_group(requesting_user, group_id, group_data)

        assert exc_info.value.code == "group_not_found"


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
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_existing
        mock_db.groups.get_group_parents.return_value = []
        mock_db.groups.get_group_children.return_value = []
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

    with patch("services.groups.crud.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.delete_group(requesting_user, str(uuid4()))

        assert exc_info.value.code == "group_not_found"


def test_delete_group_blocked_by_relationships(make_requesting_user):
    """Test that delete_group raises ValidationError when relationships exist."""
    from services import groups as groups_service
    from services.exceptions import ValidationError

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_existing = {
        "id": group_id,
        "name": "Has Children",
        "group_type": "weftid",
        "idp_id": None,
        "is_valid": True,
        "created_by": None,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    mock_child = {"group_id": str(uuid4()), "name": "Child Group"}

    with patch("services.groups.crud.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_existing
        mock_db.groups.get_group_parents.return_value = []
        mock_db.groups.get_group_children.return_value = [mock_child]

        with pytest.raises(ValidationError) as exc_info:
            groups_service.delete_group(requesting_user, group_id)

        assert exc_info.value.code == "has_relationships"


def test_remove_all_relationships_success(make_requesting_user):
    """Test removing all relationships from a group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Center Group"}
    mock_parent = {"group_id": str(uuid4()), "name": "Parent Group"}
    mock_child = {"group_id": str(uuid4()), "name": "Child Group"}

    with (
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.get_group_parents.return_value = [mock_parent]
        mock_db.groups.get_group_children.return_value = [mock_child]
        mock_db.groups.remove_group_relationship.return_value = 1

        count = groups_service.remove_all_relationships(requesting_user, group_id)

        assert count == 2
        assert mock_db.groups.remove_group_relationship.call_count == 2
        assert mock_log.call_count == 2


def test_remove_all_relationships_no_relationships(make_requesting_user):
    """Test remove_all_relationships on a group with no relationships returns 0."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Isolated Group"}

    with (
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.log_event"),
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.get_group_parents.return_value = []
        mock_db.groups.get_group_children.return_value = []

        count = groups_service.remove_all_relationships(requesting_user, group_id)

        assert count == 0
        mock_db.groups.remove_group_relationship.assert_not_called()


def test_remove_all_relationships_group_not_found(make_requesting_user):
    """Test remove_all_relationships raises NotFoundError for missing group."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")

    with patch("services.groups.hierarchy.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.remove_all_relationships(requesting_user, str(uuid4()))

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
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity"),
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
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.log_event") as mock_log,
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
        assert call_kwargs["artifact_id"] == group_id


def test_add_member_already_member(make_requesting_user):
    """Test adding a member who is already in the group fails."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test Group"}
    mock_user = {"id": user_id}

    with patch("services.groups.membership.database") as mock_db:
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
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.remove_group_member.return_value = 1

        groups_service.remove_member(requesting_user, group_id, user_id)

        mock_db.groups.remove_group_member.assert_called_once()
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_member_removed"
        assert call_kwargs["artifact_id"] == group_id


def test_remove_member_not_a_member(make_requesting_user):
    """Test removing a user who is not a member fails."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test Group"}

    with patch("services.groups.membership.database") as mock_db:
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
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.track_activity"),
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
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.get_group_children.return_value = mock_children

        result = groups_service.list_children(requesting_user, group_id)

        assert result.total == 1
        assert len(result.items) == 1
        assert result.items[0].name == "Child"


def test_list_parents_group_not_found(make_requesting_user):
    """list_parents raises NotFoundError when the group doesn't exist."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with (
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.list_parents(requesting_user, str(uuid4()))

        assert exc_info.value.code == "group_not_found"


def test_list_children_group_not_found(make_requesting_user):
    """list_children raises NotFoundError when the group doesn't exist."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with (
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.list_children(requesting_user, str(uuid4()))

        assert exc_info.value.code == "group_not_found"


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
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.log_event") as mock_log,
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
        assert call_kwargs["artifact_id"] == parent_id


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

    with patch("services.groups.hierarchy.database") as mock_db:
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

    with patch("services.groups.hierarchy.database") as mock_db:
        mock_db.groups.get_group_by_id.side_effect = [mock_parent, mock_child]
        mock_db.groups.relationship_exists.return_value = True

        with pytest.raises(ConflictError) as exc_info:
            groups_service.add_child(requesting_user, parent_id, child_id)

        assert exc_info.value.code == "relationship_exists"


def test_add_child_parent_not_found(make_requesting_user):
    """add_child raises NotFoundError when the parent group doesn't exist."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    parent_id = str(uuid4())
    child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.groups.hierarchy.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.add_child(requesting_user, parent_id, child_id)

        assert exc_info.value.code == "parent_not_found"


def test_add_child_child_not_found(make_requesting_user):
    """add_child raises NotFoundError when the child group doesn't exist."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    parent_id = str(uuid4())
    child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_parent = {"id": parent_id, "name": "Parent", "group_type": "weftid", "idp_id": None}

    with patch("services.groups.hierarchy.database") as mock_db:
        mock_db.groups.get_group_by_id.side_effect = [mock_parent, None]

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.add_child(requesting_user, parent_id, child_id)

        assert exc_info.value.code == "child_not_found"


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
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.side_effect = [mock_parent, mock_child]
        mock_db.groups.remove_group_relationship.return_value = 1

        groups_service.remove_child(requesting_user, parent_id, child_id)

        mock_db.groups.remove_group_relationship.assert_called_once()
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_relationship_deleted"
        assert call_kwargs["artifact_id"] == parent_id


def test_remove_child_not_found(make_requesting_user):
    """Test removing a non-existent relationship fails."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.groups.hierarchy.database") as mock_db:
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

    with patch("services.groups.utilities.database") as mock_db:
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
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
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
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
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
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
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
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
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
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
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
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
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
        "description": (
            f"This group was created automatically when setting up {idp_name}. "
            f"It contains every user who authenticates through this identity provider. "
            f"Groups reported by the IdP during authentication appear as children of this group."
        ),
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
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
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


def test_get_idp_base_group_success():
    """Test fetching the base group for an IdP."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    idp_name = "Okta Corporate"
    group_id = str(uuid4())

    mock_group = {
        "id": group_id,
        "name": idp_name,
        "description": "base group description",
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

    with patch("services.groups.idp.database") as mock_db:
        mock_db.groups.get_idp_base_group_id.return_value = group_id
        mock_db.groups.get_group_by_id.return_value = mock_group

        result = groups_service.get_idp_base_group(tenant_id, idp_id)

        assert result is not None
        assert result.id == group_id
        assert result.group_type == "idp"
        mock_db.groups.get_idp_base_group_id.assert_called_once_with(tenant_id, idp_id)
        mock_db.groups.get_group_by_id.assert_called_once_with(tenant_id, group_id)


def test_get_idp_base_group_not_found():
    """Test that get_idp_base_group returns None when no base group exists."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())

    with patch("services.groups.idp.database") as mock_db:
        mock_db.groups.get_idp_base_group_id.return_value = None

        result = groups_service.get_idp_base_group(tenant_id, idp_id)

        assert result is None
        mock_db.groups.get_group_by_id.assert_not_called()


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
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
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
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
    ):
        # User was in a group but no longer
        mock_db.groups.get_user_idp_group_ids.return_value = [old_group_id]
        mock_db.groups.get_group_by_id.return_value = {"name": "Old Group"}
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
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
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
    from services import groups as groups_service
    from services.event_log import SYSTEM_ACTOR_ID

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
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        mock_db.groups.get_user_idp_group_ids.return_value = []
        mock_db.groups.get_group_by_idp_and_name.return_value = mock_group
        mock_db.groups.get_group_by_id.return_value = mock_group
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
        assert call_kwargs["artifact_id"] == group_id


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

    with patch("services.groups.membership.database") as mock_db:
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

    with patch("services.groups.membership.database") as mock_db:
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

    with patch("services.groups.crud.database") as mock_db:
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

    with patch("services.groups.crud.database") as mock_db:
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
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_invalid_idp_group
        mock_db.groups.get_group_parents.return_value = []
        mock_db.groups.get_group_children.return_value = []
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
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.log_event"),
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

    with patch("services.groups.hierarchy.database") as mock_db:
        mock_db.groups.get_group_by_id.side_effect = [mock_idp_parent, mock_child]
        mock_db.groups.relationship_exists.return_value = False

        with pytest.raises(ValidationError) as exc_info:
            groups_service.add_child(requesting_user, idp_group_id, child_id)

        assert exc_info.value.code == "idp_cannot_be_parent"


def test_invalidate_idp_groups_on_deletion():
    """Test that IdP groups are deleted when IdP is deleted."""
    from services import groups as groups_service
    from services.event_log import SYSTEM_ACTOR_ID

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
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        mock_db.groups.get_groups_by_idp.return_value = mock_groups
        mock_db.groups.delete_groups_by_idp.return_value = 2

        count = groups_service.invalidate_idp_groups(tenant_id, idp_id, idp_name)

        assert count == 2
        mock_db.groups.delete_groups_by_idp.assert_called_once()
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
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.track_activity"),
    ):
        mock_db.groups.get_groups_by_idp.return_value = mock_groups

        result = groups_service.list_groups_for_idp(requesting_user, idp_id)

        assert len(result) == 2
        assert result[0].group_type == "idp"
        mock_db.groups.get_groups_by_idp.assert_called_once_with(tenant_id, idp_id)


def test_create_idp_base_group_raises_conflict_when_duplicate():
    """Test that creating an IdP base group raises ConflictError if already exists."""
    from services import groups as groups_service
    from services.exceptions import ConflictError

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    idp_name = "Okta Corporate"
    existing_group_id = str(uuid4())

    mock_existing_group = {
        "id": existing_group_id,
        "name": idp_name,
        "group_type": "idp",
        "idp_id": idp_id,
    }

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.system_context"),
    ):
        # Group already exists for this IdP
        mock_db.groups.get_group_by_idp_and_name.return_value = mock_existing_group

        # Should raise ConflictError
        with pytest.raises(ConflictError) as exc_info:
            groups_service.create_idp_base_group(tenant_id, idp_id, idp_name)

        assert "already exists" in exc_info.value.message
        # Should NOT try to create
        mock_db.groups.create_idp_group.assert_not_called()


def test_sync_user_idp_groups_no_op_when_already_in_sync():
    """Test that sync is a no-op when user is already in all provided groups."""
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
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        # User is already in the Engineering group
        mock_db.groups.get_user_idp_group_ids.return_value = [group_id]
        # Group exists
        mock_db.groups.get_group_by_idp_and_name.return_value = mock_existing_group

        result = groups_service.sync_user_idp_groups(
            tenant_id, user_id, user_email, idp_id, idp_name, ["Engineering"]
        )

        # No additions, no removals
        assert len(result["added"]) == 0
        assert len(result["removed"]) == 0
        assert len(result["created"]) == 0
        # Should NOT call bulk_add or bulk_remove
        mock_db.groups.bulk_add_user_to_groups.assert_not_called()
        mock_db.groups.bulk_remove_user_from_groups.assert_not_called()
        # Should NOT log any events
        mock_log.assert_not_called()


def test_invalidate_idp_groups_returns_zero_when_idp_has_no_groups():
    """Test that invalidating groups for IdP with no groups returns 0 without DB call."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    idp_name = "Empty IdP"

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        # IdP has no groups
        mock_db.groups.get_groups_by_idp.return_value = []

        count = groups_service.invalidate_idp_groups(tenant_id, idp_id, idp_name)

        assert count == 0
        # Should NOT call invalidate (short-circuits when no groups)
        mock_db.groups.invalidate_groups_by_idp.assert_not_called()
        # Should NOT log any events (no groups to invalidate)
        mock_log.assert_not_called()


def test_idp_group_can_have_multiple_weftid_parents(make_requesting_user):
    """Test that IdP groups can have multiple WeftID groups as parents."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_group_id = str(uuid4())
    parent1_id = str(uuid4())
    parent2_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_idp_group = {
        "id": idp_group_id,
        "name": "Okta Engineering",
        "group_type": "idp",
        "idp_id": str(uuid4()),
    }
    mock_parent1 = {"id": parent1_id, "name": "All Engineering", "group_type": "weftid"}
    mock_parent2 = {"id": parent2_id, "name": "All Teams", "group_type": "weftid"}

    with (
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.log_event") as mock_log,
    ):
        # First parent addition
        mock_db.groups.get_group_by_id.side_effect = [mock_parent1, mock_idp_group]
        mock_db.groups.relationship_exists.return_value = False
        mock_db.groups.would_create_cycle.return_value = False
        mock_db.groups.add_group_relationship.return_value = {"id": str(uuid4())}

        # Add first parent
        groups_service.add_child(requesting_user, parent1_id, idp_group_id)
        mock_db.groups.add_group_relationship.assert_called_once()

        # Reset mocks for second parent
        mock_db.groups.reset_mock()
        mock_log.reset_mock()

        # Second parent addition
        mock_db.groups.get_group_by_id.side_effect = [mock_parent2, mock_idp_group]
        mock_db.groups.relationship_exists.return_value = False
        mock_db.groups.would_create_cycle.return_value = False
        mock_db.groups.add_group_relationship.return_value = {"id": str(uuid4())}

        # Add second parent - should not raise
        groups_service.add_child(requesting_user, parent2_id, idp_group_id)
        mock_db.groups.add_group_relationship.assert_called_once()


# =============================================================================
# My Groups Tests
# =============================================================================


def test_get_my_groups_any_role(make_requesting_user):
    """Test that any authenticated user can get their own groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")

    mock_rows = [
        {
            "id": uuid4(),
            "name": "Engineering",
            "description": "Eng team",
            "group_type": "weftid",
            "joined_at": datetime.now(UTC),
            "parent_names": "All Teams",
        },
    ]

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity") as mock_track,
    ):
        mock_db.groups.get_user_groups_with_context.return_value = mock_rows

        result = groups_service.get_my_groups(requesting_user)

        assert len(result.items) == 1
        assert result.items[0].name == "Engineering"
        assert result.items[0].parent_names == "All Teams"
        mock_track.assert_called_once_with(tenant_id, user_id)


def test_get_my_groups_empty(make_requesting_user):
    """Test get_my_groups returns empty when user has no groups."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity"),
    ):
        mock_db.groups.get_user_groups_with_context.return_value = []

        result = groups_service.get_my_groups(requesting_user)

        assert len(result.items) == 0


# =============================================================================
# Effective Memberships Tests
# =============================================================================


def test_get_effective_memberships_as_admin(make_requesting_user):
    """Test admin can get effective memberships for any user."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    target_user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_rows = [
        {
            "id": uuid4(),
            "name": "Direct Group",
            "description": None,
            "group_type": "weftid",
            "idp_id": None,
            "idp_name": None,
            "is_direct": True,
        },
        {
            "id": uuid4(),
            "name": "Inherited Group",
            "description": None,
            "group_type": "weftid",
            "idp_id": None,
            "idp_name": None,
            "is_direct": False,
        },
    ]

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity"),
    ):
        mock_db.groups.get_effective_memberships.return_value = mock_rows

        result = groups_service.get_effective_memberships(requesting_user, target_user_id)

        assert len(result.items) == 2
        assert result.items[0].is_direct is True
        assert result.items[1].is_direct is False


def test_get_effective_memberships_self(make_requesting_user):
    """Test user can get their own effective memberships."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity"),
    ):
        mock_db.groups.get_effective_memberships.return_value = []

        result = groups_service.get_effective_memberships(requesting_user, user_id)

        assert len(result.items) == 0


def test_get_effective_memberships_other_user_forbidden(make_requesting_user):
    """Test regular user cannot get another user's effective memberships."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")
    other_user_id = str(uuid4())

    with pytest.raises(ForbiddenError) as exc_info:
        groups_service.get_effective_memberships(requesting_user, other_user_id)

    assert exc_info.value.code == "forbidden"


# =============================================================================
# Effective Members Tests
# =============================================================================


def test_get_effective_members_as_admin(make_requesting_user):
    """Test admin can get effective members of a group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test"}
    mock_members = [
        {
            "user_id": uuid4(),
            "email": "user@example.com",
            "first_name": "Test",
            "last_name": "User",
            "is_direct": True,
        },
    ]

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity") as mock_track,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.count_effective_members.return_value = 1
        mock_db.groups.get_effective_members.return_value = mock_members

        result = groups_service.get_effective_members(requesting_user, group_id)

        assert result.total == 1
        assert len(result.items) == 1
        assert result.items[0].is_direct is True
        mock_track.assert_called_once()


def test_get_effective_members_group_not_found(make_requesting_user):
    """Test effective members raises NotFoundError for missing group."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.get_effective_members(requesting_user, str(uuid4()))

        assert exc_info.value.code == "group_not_found"


def test_get_effective_members_forbidden_for_member(make_requesting_user):
    """Test regular user cannot get effective members."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError):
        groups_service.get_effective_members(requesting_user, str(uuid4()))


# =============================================================================
# Bulk Add Members Tests
# =============================================================================


def test_bulk_add_members_success(make_requesting_user):
    """Test bulk adding members to a group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    user_ids = [str(uuid4()), str(uuid4())]
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test Group", "group_type": "weftid"}

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.bulk_add_group_members.return_value = 2

        count = groups_service.bulk_add_members(requesting_user, group_id, user_ids)

        assert count == 2
        mock_db.groups.bulk_add_group_members.assert_called_once()
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_members_bulk_added"
        assert call_kwargs["metadata"]["count"] == 2


def test_bulk_add_members_idp_group_blocked(make_requesting_user):
    """Test bulk adding members to IdP group is forbidden."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "IdP Group", "group_type": "idp"}

    with patch("services.groups.membership.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_group

        with pytest.raises(ForbiddenError) as exc_info:
            groups_service.bulk_add_members(requesting_user, group_id, [str(uuid4())])

        assert exc_info.value.code == "idp_group_readonly"


def test_bulk_add_members_no_event_when_zero_added(make_requesting_user):
    """Test that no event is logged when all users are already members."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test Group", "group_type": "weftid"}

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.bulk_add_group_members.return_value = 0

        count = groups_service.bulk_add_members(requesting_user, group_id, [str(uuid4())])

        assert count == 0
        mock_log.assert_not_called()


def test_bulk_add_members_group_not_found(make_requesting_user):
    """Test bulk add to non-existent group raises NotFoundError."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")

    with patch("services.groups.membership.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.bulk_add_members(requesting_user, str(uuid4()), [str(uuid4())])

        assert exc_info.value.code == "group_not_found"


# =============================================================================
# List Members Filtered Tests
# =============================================================================


def test_list_members_filtered_success(make_requesting_user):
    """Test listing members with search, filters, sorting, and pagination."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Engineering", "group_type": "weftid"}
    mock_rows = [
        {
            "id": str(uuid4()),
            "user_id": str(uuid4()),
            "email": "user@example.com",
            "first_name": "Test",
            "last_name": "User",
            "role": "member",
            "is_inactivated": False,
            "is_anonymized": False,
            "created_at": datetime.now(UTC),
            "last_activity_at": datetime.now(UTC),
        }
    ]

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.count_group_members_filtered.return_value = 1
        mock_db.groups.search_group_members.return_value = mock_rows

        result = groups_service.list_members_filtered(
            requesting_user,
            group_id,
            search="test",
            roles=["member"],
            statuses=["active"],
            sort_field="name",
            sort_order="asc",
            page=1,
            page_size=25,
        )

        assert result.total == 1
        assert len(result.items) == 1
        assert result.items[0].email == "user@example.com"
        assert result.items[0].role == "member"
        assert result.items[0].last_activity_at is not None
        assert result.page == 1
        assert result.limit == 25
        mock_db.groups.search_group_members.assert_called_once()
        mock_db.groups.count_group_members_filtered.assert_called_once()


def test_list_members_filtered_group_not_found(make_requesting_user):
    """Test listing members for non-existent group raises NotFoundError."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.list_members_filtered(requesting_user, str(uuid4()))

        assert exc_info.value.code == "group_not_found"


def test_list_members_filtered_requires_admin(make_requesting_user):
    """Test listing members requires admin role."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError):
        groups_service.list_members_filtered(requesting_user, str(uuid4()))


def test_list_members_filtered_forwards_all_params(make_requesting_user):
    """Test that all search/filter/sort/pagination params are forwarded to database."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Engineering", "group_type": "weftid"}

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.count_group_members_filtered.return_value = 0
        mock_db.groups.search_group_members.return_value = []

        groups_service.list_members_filtered(
            requesting_user,
            group_id,
            search="john",
            roles=["admin", "member"],
            statuses=["active"],
            sort_field="email",
            sort_order="desc",
            page=3,
            page_size=50,
        )

        # Verify count call got search/roles/statuses
        mock_db.groups.count_group_members_filtered.assert_called_once_with(
            tenant_id, group_id, "john", ["admin", "member"], ["active"]
        )

        # Verify search call got all params
        mock_db.groups.search_group_members.assert_called_once_with(
            tenant_id,
            group_id,
            "john",
            ["admin", "member"],
            ["active"],
            "email",
            "desc",
            3,
            50,
        )


# =============================================================================
# Bulk Remove Members Tests
# =============================================================================


def test_bulk_remove_members_success(make_requesting_user):
    """Test bulk removing members from a group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    user_ids = [str(uuid4()), str(uuid4())]
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test Group", "group_type": "weftid"}

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.bulk_remove_group_members.return_value = 2

        count = groups_service.bulk_remove_members(requesting_user, group_id, user_ids)

        assert count == 2
        mock_db.groups.bulk_remove_group_members.assert_called_once()
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "group_members_bulk_removed"
        assert call_kwargs["metadata"]["count"] == 2


def test_bulk_remove_members_idp_group_blocked(make_requesting_user):
    """Test bulk removing members from IdP group is forbidden."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "IdP Group", "group_type": "idp"}

    with patch("services.groups.membership.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = mock_group

        with pytest.raises(ForbiddenError) as exc_info:
            groups_service.bulk_remove_members(requesting_user, group_id, [str(uuid4())])

        assert exc_info.value.code == "idp_group_readonly"


def test_bulk_remove_members_no_event_when_zero_removed(make_requesting_user):
    """Test that no event is logged when no members are removed."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Test Group", "group_type": "weftid"}

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.bulk_remove_group_members.return_value = 0

        count = groups_service.bulk_remove_members(requesting_user, group_id, [str(uuid4())])

        assert count == 0
        mock_log.assert_not_called()


def test_bulk_remove_members_group_not_found(make_requesting_user):
    """Test bulk remove from non-existent group raises NotFoundError."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")

    with patch("services.groups.membership.database") as mock_db:
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.bulk_remove_members(requesting_user, str(uuid4()), [str(uuid4())])

        assert exc_info.value.code == "group_not_found"


# =============================================================================
# List Available Users Paginated Tests
# =============================================================================


def test_list_available_users_paginated_success(make_requesting_user):
    """Test listing available users for a group with pagination."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Engineering", "group_type": "weftid"}
    mock_rows = [
        {
            "id": str(uuid4()),
            "email": "available@example.com",
            "first_name": "Available",
            "last_name": "User",
            "role": "member",
            "is_inactivated": False,
            "is_anonymized": False,
            "last_activity_at": datetime.now(UTC),
        }
    ]

    with (
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.count_available_users.return_value = 1
        mock_db.groups.search_available_users.return_value = mock_rows

        result = groups_service.list_available_users_paginated(
            requesting_user,
            group_id,
            search="available",
            page=1,
            page_size=25,
        )

        assert result.total == 1
        assert len(result.items) == 1
        assert result.items[0].email == "available@example.com"
        assert result.items[0].role == "member"
        assert result.items[0].last_activity_at is not None
        assert result.page == 1
        assert result.limit == 25
        mock_db.groups.search_available_users.assert_called_once()


def test_list_available_users_paginated_group_not_found(make_requesting_user):
    """Test available users for non-existent group raises NotFoundError."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="admin")

    with (
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.list_available_users_paginated(requesting_user, str(uuid4()))

        assert exc_info.value.code == "group_not_found"


def test_list_available_users_paginated_requires_admin(make_requesting_user):
    """Test available users requires admin role."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError):
        groups_service.list_available_users_paginated(requesting_user, str(uuid4()))


def test_list_available_users_paginated_forwards_all_params(make_requesting_user):
    """Test that all search/filter/sort/pagination params are forwarded to database."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {"id": group_id, "name": "Engineering", "group_type": "weftid"}

    with (
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = mock_group
        mock_db.groups.count_available_users.return_value = 0
        mock_db.groups.search_available_users.return_value = []

        groups_service.list_available_users_paginated(
            requesting_user,
            group_id,
            search="jane",
            roles=["member"],
            statuses=["active", "inactivated"],
            sort_field="role",
            sort_order="desc",
            page=2,
            page_size=10,
        )

        # Verify count call got search/roles/statuses
        mock_db.groups.count_available_users.assert_called_once_with(
            tenant_id, group_id, "jane", ["member"], ["active", "inactivated"]
        )

        # Verify search call got all params
        mock_db.groups.search_available_users.assert_called_once_with(
            tenant_id,
            group_id,
            "jane",
            ["member"],
            ["active", "inactivated"],
            "role",
            "desc",
            2,
            10,
        )


# =============================================================================
# List Available Groups for User Tests
# =============================================================================


def test_list_available_groups_for_user_as_admin(make_requesting_user):
    """Test that an admin can get available groups for a user."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    weftid_group_id = uuid4()
    idp_group_id = uuid4()

    mock_rows = [
        {"id": weftid_group_id, "name": "Engineering", "group_type": "weftid"},
        {"id": idp_group_id, "name": "Okta All", "group_type": "idp"},
    ]

    with (
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
    ):
        mock_db.users.get_user_by_id.return_value = {"id": user_id}
        mock_db.groups.get_groups_for_user_select.return_value = mock_rows

        result = groups_service.list_available_groups_for_user(requesting_user, user_id)

        # Only weftid groups should be returned
        assert len(result) == 1
        assert result[0].id == str(weftid_group_id)
        assert result[0].name == "Engineering"
        assert result[0].group_type == "weftid"


def test_list_available_groups_for_user_filters_idp_groups(make_requesting_user):
    """Test that all IdP groups are filtered out, returning empty list."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_rows = [
        {"id": uuid4(), "name": "Okta Engineering", "group_type": "idp"},
        {"id": uuid4(), "name": "Okta Sales", "group_type": "idp"},
    ]

    with (
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
    ):
        mock_db.users.get_user_by_id.return_value = {"id": user_id}
        mock_db.groups.get_groups_for_user_select.return_value = mock_rows

        result = groups_service.list_available_groups_for_user(requesting_user, user_id)

        assert len(result) == 0


def test_list_available_groups_for_user_not_found(make_requesting_user):
    """Test that listing available groups for a non-existent user raises NotFoundError."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with (
        patch("services.groups.selection.database") as mock_db,
        patch("services.groups.selection.track_activity"),
    ):
        mock_db.users.get_user_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.list_available_groups_for_user(requesting_user, user_id)

        assert exc_info.value.code == "user_not_found"


def test_list_available_groups_for_user_forbidden_for_member(make_requesting_user):
    """Test that a regular member cannot list available groups for a user."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError):
        groups_service.list_available_groups_for_user(requesting_user, str(uuid4()))


# =============================================================================
# Get Direct Memberships Tests
# =============================================================================


def test_get_direct_memberships_as_admin(make_requesting_user):
    """Test that an admin can get direct memberships for any user."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    target_user_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_rows = [
        {
            "id": uuid4(),
            "name": "Engineering",
            "description": None,
            "group_type": "weftid",
            "joined_at": datetime.now(UTC),
        },
        {
            "id": uuid4(),
            "name": "Marketing",
            "description": "Marketing team",
            "group_type": "weftid",
            "joined_at": datetime.now(UTC),
        },
    ]

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity"),
    ):
        mock_db.groups.get_user_groups.return_value = mock_rows

        result = groups_service.get_direct_memberships(requesting_user, target_user_id)

        assert len(result.items) == 2
        assert all(item.is_direct is True for item in result.items)
        assert result.items[0].name == "Engineering"
        assert result.items[1].name == "Marketing"


def test_get_direct_memberships_self(make_requesting_user):
    """Test that a user can see their own direct memberships."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")

    mock_rows = [
        {
            "id": uuid4(),
            "name": "Engineering",
            "description": None,
            "group_type": "weftid",
            "joined_at": datetime.now(UTC),
        },
    ]

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.track_activity"),
    ):
        mock_db.groups.get_user_groups.return_value = mock_rows

        result = groups_service.get_direct_memberships(requesting_user, user_id)

        assert len(result.items) == 1
        assert result.items[0].is_direct is True
        assert result.items[0].name == "Engineering"


def test_get_direct_memberships_other_user_forbidden(make_requesting_user):
    """Test that a member cannot view another user's direct memberships."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")
    other_user_id = str(uuid4())

    with pytest.raises(ForbiddenError) as exc_info:
        groups_service.get_direct_memberships(requesting_user, other_user_id)

    assert exc_info.value.code == "forbidden"


# =============================================================================
# Bulk Add User to Groups Tests
# =============================================================================


def test_bulk_add_user_to_groups_success(make_requesting_user):
    """Test admin adds a user to 2 weftid groups successfully."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    group1_id = str(uuid4())
    group2_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group1 = {"id": group1_id, "name": "Engineering", "group_type": "weftid"}
    mock_group2 = {"id": group2_id, "name": "Marketing", "group_type": "weftid"}

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.log_event") as mock_log,
    ):
        mock_db.users.get_user_by_id.return_value = {"id": user_id}
        mock_db.groups.get_group_by_id.side_effect = [mock_group1, mock_group2]
        mock_db.groups.is_group_member.return_value = False
        mock_db.groups.add_group_member.return_value = {"id": str(uuid4())}

        result = groups_service.bulk_add_user_to_groups(
            requesting_user, user_id, [group1_id, group2_id]
        )

        assert result == 2
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "user_groups_bulk_added"
        assert call_kwargs["metadata"]["count"] == 2


def test_bulk_add_user_to_groups_skips_idp_groups(make_requesting_user):
    """Test that IdP groups are skipped, only weftid groups are added."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    weftid_group_id = str(uuid4())
    idp_group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_weftid_group = {"id": weftid_group_id, "name": "Engineering", "group_type": "weftid"}
    mock_idp_group = {"id": idp_group_id, "name": "Okta All", "group_type": "idp"}

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.log_event"),
    ):
        mock_db.users.get_user_by_id.return_value = {"id": user_id}
        mock_db.groups.get_group_by_id.side_effect = [mock_idp_group, mock_weftid_group]
        mock_db.groups.is_group_member.return_value = False
        mock_db.groups.add_group_member.return_value = {"id": str(uuid4())}

        result = groups_service.bulk_add_user_to_groups(
            requesting_user, user_id, [idp_group_id, weftid_group_id]
        )

        assert result == 1


def test_bulk_add_user_to_groups_skips_existing_members(make_requesting_user):
    """Test that groups where user is already a member are skipped."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    group1_id = str(uuid4())
    group2_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group1 = {"id": group1_id, "name": "Engineering", "group_type": "weftid"}
    mock_group2 = {"id": group2_id, "name": "Marketing", "group_type": "weftid"}

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.log_event"),
    ):
        mock_db.users.get_user_by_id.return_value = {"id": user_id}
        mock_db.groups.get_group_by_id.side_effect = [mock_group1, mock_group2]
        # User is already a member of the first group but not the second
        mock_db.groups.is_group_member.side_effect = [True, False]
        mock_db.groups.add_group_member.return_value = {"id": str(uuid4())}

        result = groups_service.bulk_add_user_to_groups(
            requesting_user, user_id, [group1_id, group2_id]
        )

        assert result == 1


def test_bulk_add_user_to_groups_user_not_found(make_requesting_user):
    """Test that adding to groups for a non-existent user raises NotFoundError."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.groups.membership.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            groups_service.bulk_add_user_to_groups(requesting_user, str(uuid4()), [str(uuid4())])

        assert exc_info.value.code == "user_not_found"


def test_bulk_add_user_to_groups_no_event_when_zero_added(make_requesting_user):
    """Test that no event is logged when all groups are IdP (zero added)."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    idp_group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_idp_group = {"id": idp_group_id, "name": "Okta All", "group_type": "idp"}

    with (
        patch("services.groups.membership.database") as mock_db,
        patch("services.groups.membership.log_event") as mock_log,
    ):
        mock_db.users.get_user_by_id.return_value = {"id": user_id}
        mock_db.groups.get_group_by_id.return_value = mock_idp_group

        result = groups_service.bulk_add_user_to_groups(requesting_user, user_id, [idp_group_id])

        assert result == 0
        mock_log.assert_not_called()


def test_bulk_add_user_to_groups_forbidden_for_member(make_requesting_user):
    """Test that a regular member cannot bulk add a user to groups."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError):
        groups_service.bulk_add_user_to_groups(requesting_user, str(uuid4()), [str(uuid4())])


# =============================================================================
# Base Group Membership Helpers
# =============================================================================


def test_ensure_user_in_base_group_adds_membership():
    """Test that ensure_user_in_base_group adds user to IdP base group."""
    from services import groups as groups_service
    from services.event_log import SYSTEM_ACTOR_ID

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_email = "user@example.com"
    idp_id = str(uuid4())
    idp_name = "Okta Corporate"
    base_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        mock_db.groups.get_idp_base_group_id.return_value = base_group_id
        mock_db.groups.is_group_member.return_value = False
        mock_db.groups.bulk_add_user_to_groups.return_value = 1

        groups_service.ensure_user_in_base_group(tenant_id, user_id, user_email, idp_id, idp_name)

        mock_db.groups.bulk_add_user_to_groups.assert_called_once_with(
            tenant_id, tenant_id, user_id, [base_group_id]
        )
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["actor_user_id"] == SYSTEM_ACTOR_ID
        assert call_kwargs["event_type"] == "idp_group_member_added"
        assert call_kwargs["metadata"]["sync_source"] == "idp_assignment"
        assert call_kwargs["metadata"]["group_id"] == base_group_id
        assert call_kwargs["artifact_id"] == base_group_id


def test_ensure_user_in_base_group_already_member_no_op():
    """Test that ensure_user_in_base_group is a no-op when already a member."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    idp_id = str(uuid4())
    base_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        mock_db.groups.get_idp_base_group_id.return_value = base_group_id
        mock_db.groups.is_group_member.return_value = True

        groups_service.ensure_user_in_base_group(
            tenant_id, user_id, "user@example.com", idp_id, "Okta"
        )

        mock_db.groups.bulk_add_user_to_groups.assert_not_called()
        mock_log.assert_not_called()


def test_ensure_user_in_base_group_auto_creates_missing_base_group():
    """Test that ensure_user_in_base_group auto-creates the base group when missing."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    idp_id = str(uuid4())
    new_group_id = str(uuid4())

    mock_group = GroupDetail(
        id=new_group_id,
        name="Test IdP",
        group_type="idp",
        idp_id=idp_id,
        member_count=0,
        parent_count=0,
        child_count=0,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
        patch("services.groups.idp.create_idp_base_group", return_value=mock_group) as mock_create,
    ):
        mock_db.groups.get_idp_base_group_id.return_value = None
        mock_db.groups.is_group_member.return_value = False

        groups_service.ensure_user_in_base_group(
            tenant_id, user_id, "user@example.com", idp_id, "Test IdP"
        )

        mock_create.assert_called_once_with(tenant_id, idp_id, "Test IdP")
        mock_db.groups.bulk_add_user_to_groups.assert_called_once_with(
            tenant_id, tenant_id, user_id, [new_group_id]
        )


def test_ensure_user_in_base_group_auto_create_handles_race_condition():
    """Test race condition: another request creates the base group between check and create."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    idp_id = str(uuid4())
    recovered_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
        patch(
            "services.groups.idp.create_idp_base_group",
            side_effect=ConflictError(message="exists"),
        ),
    ):
        # First call returns None (triggers create), second call returns recovered ID
        mock_db.groups.get_idp_base_group_id.side_effect = [None, recovered_id]
        mock_db.groups.is_group_member.return_value = False

        groups_service.ensure_user_in_base_group(
            tenant_id, user_id, "user@example.com", idp_id, "Test IdP"
        )

        mock_db.groups.bulk_add_user_to_groups.assert_called_once_with(
            tenant_id, tenant_id, user_id, [recovered_id]
        )


def test_ensure_user_in_base_group_auto_create_unrecoverable_raises():
    """ValidationError raised when base group creation and re-query both fail."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    idp_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
        patch(
            "services.groups.idp.create_idp_base_group",
            side_effect=ConflictError(message="exists"),
        ),
    ):
        # Both lookups return None
        mock_db.groups.get_idp_base_group_id.return_value = None

        with pytest.raises(ValidationError, match="Failed to create or find base group"):
            groups_service.ensure_user_in_base_group(
                tenant_id, user_id, "user@example.com", idp_id, "Test IdP"
            )


def test_ensure_users_in_base_group_auto_creates_missing_base_group():
    """Test that ensure_users_in_base_group auto-creates the base group when missing."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_ids = [str(uuid4()), str(uuid4())]
    idp_id = str(uuid4())
    new_group_id = str(uuid4())

    mock_group = GroupDetail(
        id=new_group_id,
        name="Test IdP",
        group_type="idp",
        idp_id=idp_id,
        member_count=0,
        parent_count=0,
        child_count=0,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
        patch("services.groups.idp.create_idp_base_group", return_value=mock_group) as mock_create,
    ):
        mock_db.groups.get_idp_base_group_id.return_value = None
        mock_db.groups.bulk_add_user_to_groups.return_value = 1

        count = groups_service.ensure_users_in_base_group(tenant_id, user_ids, idp_id, "Test IdP")

        mock_create.assert_called_once_with(tenant_id, idp_id, "Test IdP")
        assert count == 2
        assert mock_db.groups.bulk_add_user_to_groups.call_count == 2


def test_remove_user_from_base_group_removes_membership():
    """Test that remove_user_from_base_group removes user from IdP base group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_email = "user@example.com"
    idp_id = str(uuid4())
    idp_name = "Okta Corporate"
    base_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        mock_db.groups.get_idp_base_group_id.return_value = base_group_id
        mock_db.groups.bulk_remove_user_from_groups.return_value = 1

        groups_service.remove_user_from_base_group(tenant_id, user_id, user_email, idp_id, idp_name)

        mock_db.groups.bulk_remove_user_from_groups.assert_called_once_with(
            tenant_id, user_id, [base_group_id]
        )
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "idp_group_member_removed"
        assert call_kwargs["metadata"]["sync_source"] == "idp_reassignment"
        assert call_kwargs["artifact_id"] == base_group_id


def test_sync_user_idp_groups_does_not_remove_base_group():
    """Test that sync_user_idp_groups protects the base group from removal."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_email = "user@example.com"
    idp_id = str(uuid4())
    idp_name = "Okta"
    base_group_id = str(uuid4())
    sub_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
    ):
        # User is in base group and a sub-group, assertion has no groups
        mock_db.groups.get_user_idp_group_ids.return_value = [base_group_id, sub_group_id]
        mock_db.groups.get_idp_base_group_id.return_value = base_group_id
        mock_db.groups.get_group_by_id.return_value = {"name": "Sub Group"}
        mock_db.groups.bulk_remove_user_from_groups.return_value = 1

        result = groups_service.sync_user_idp_groups(
            tenant_id, user_id, user_email, idp_id, idp_name, []
        )

        # Sub-group should be removed, but base group should not
        assert len(result["removed"]) == 1
        mock_db.groups.bulk_remove_user_from_groups.assert_called_once()
        removed_ids = mock_db.groups.bulk_remove_user_from_groups.call_args[0][2]
        assert base_group_id not in removed_ids
        assert sub_group_id in removed_ids


def test_remove_user_from_all_idp_groups_removes_base_and_sub_groups():
    """Test that remove_user_from_all_idp_groups removes all IdP groups."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    user_email = "user@example.com"
    idp_id = str(uuid4())
    idp_name = "Okta"
    base_group_id = str(uuid4())
    sub_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        mock_db.groups.get_user_idp_group_ids.return_value = [base_group_id, sub_group_id]
        mock_db.groups.get_group_by_id.side_effect = [
            {"name": "Okta"},
            {"name": "Engineering"},
        ]
        mock_db.groups.bulk_remove_user_from_groups.return_value = 2

        groups_service.remove_user_from_all_idp_groups(
            tenant_id, user_id, user_email, idp_id, idp_name
        )

        mock_db.groups.bulk_remove_user_from_groups.assert_called_once_with(
            tenant_id, user_id, [base_group_id, sub_group_id]
        )
        # Should log removal for each group
        assert mock_log.call_count == 2


def test_ensure_users_in_base_group_bulk():
    """Test that ensure_users_in_base_group adds multiple users."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_ids = [str(uuid4()), str(uuid4()), str(uuid4())]
    idp_id = str(uuid4())
    idp_name = "Okta"
    base_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        mock_db.groups.get_idp_base_group_id.return_value = base_group_id
        mock_db.groups.bulk_add_user_to_groups.return_value = 1

        count = groups_service.ensure_users_in_base_group(tenant_id, user_ids, idp_id, idp_name)

        assert count == 3
        assert mock_db.groups.bulk_add_user_to_groups.call_count == 3
        assert mock_log.call_count == 3


def test_move_users_between_idps():
    """Test moving users between IdPs updates group memberships."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_ids = [str(uuid4())]
    old_idp_id = str(uuid4())
    new_idp_id = str(uuid4())
    old_group_id = str(uuid4())
    new_base_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
    ):
        # Old IdP has one group the user is in
        mock_db.groups.get_user_idp_group_ids.return_value = [old_group_id]
        mock_db.groups.bulk_remove_user_from_groups.return_value = 1
        # New base group
        mock_db.groups.get_idp_base_group_id.return_value = new_base_group_id
        mock_db.groups.is_group_member.return_value = False
        mock_db.groups.bulk_add_user_to_groups.return_value = 1

        groups_service.move_users_between_idps(
            tenant_id, user_ids, old_idp_id, "Old IdP", new_idp_id, "New IdP"
        )

        # Should remove from old groups
        mock_db.groups.bulk_remove_user_from_groups.assert_called_once()
        # Should add to new base group (via ensure_users_in_base_group)
        mock_db.groups.bulk_add_user_to_groups.assert_called_once()


# =============================================================================
# Get Group Graph Data Tests
# =============================================================================


def test_get_group_graph_data_as_admin(make_requesting_user):
    """Admin can fetch graph data with nodes and edges."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    group_id_1 = str(uuid4())
    group_id_2 = str(uuid4())

    mock_data = {
        "groups": [
            {
                "id": group_id_1,
                "name": "Engineering",
                "group_type": "weftid",
                "member_count": 5,
                "effective_member_count": 8,
            },
            {
                "id": group_id_2,
                "name": "Frontend",
                "group_type": "weftid",
                "member_count": 3,
                "effective_member_count": 3,
            },
        ],
        "relationships": [
            {"child_group_id": group_id_2, "parent_group_id": group_id_1},
        ],
    }

    with (
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.track_activity"),
    ):
        mock_db.groups.list_all_groups_for_graph.return_value = mock_data

        result = groups_service.get_group_graph_data(requesting_user)

        assert len(result.nodes) == 2
        assert len(result.edges) == 1
        assert result.nodes[0].name == "Engineering"
        assert result.nodes[0].member_count == 5
        assert result.nodes[0].effective_member_count == 8
        assert result.nodes[1].effective_member_count == 3
        assert result.edges[0].source == str(group_id_2)
        assert result.edges[0].target == str(group_id_1)
        mock_db.groups.list_all_groups_for_graph.assert_called_once_with(tenant_id)


def test_get_group_graph_data_empty(make_requesting_user):
    """Graph data with no groups returns empty nodes and edges."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with (
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.track_activity"),
    ):
        mock_db.groups.list_all_groups_for_graph.return_value = {
            "groups": [],
            "relationships": [],
        }

        result = groups_service.get_group_graph_data(requesting_user)

        assert result.nodes == []
        assert result.edges == []


def test_get_group_graph_data_forbidden_for_member(make_requesting_user):
    """Non-admin user cannot get graph data."""
    from services import groups as groups_service
    from services.exceptions import ForbiddenError

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        groups_service.get_group_graph_data(requesting_user)

    assert exc_info.value.code == "admin_required"


def test_get_group_graph_data_includes_idp_nodes(make_requesting_user):
    """Graph data includes IdP group nodes."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    idp_group_id = str(uuid4())

    with (
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.track_activity"),
    ):
        mock_db.groups.list_all_groups_for_graph.return_value = {
            "groups": [
                {
                    "id": idp_group_id,
                    "name": "Okta Users",
                    "group_type": "idp",
                    "is_umbrella": False,
                    "member_count": 10,
                    "effective_member_count": 10,
                }
            ],
            "relationships": [],
        }

        result = groups_service.get_group_graph_data(requesting_user)

        assert len(result.nodes) == 1
        assert result.nodes[0].group_type == "idp"
        assert result.nodes[0].name == "Okta Users"


def test_get_group_graph_data_umbrella_flag_propagated(make_requesting_user):
    """Umbrella flag is passed through from database row to graph node."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    umbrella_id = str(uuid4())
    assertion_id = str(uuid4())

    with (
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.track_activity"),
    ):
        mock_db.groups.list_all_groups_for_graph.return_value = {
            "groups": [
                {
                    "id": umbrella_id,
                    "name": "Okta",
                    "group_type": "idp",
                    "is_umbrella": True,
                    "member_count": 5,
                    "effective_member_count": 8,
                },
                {
                    "id": assertion_id,
                    "name": "Okta / Engineering",
                    "group_type": "idp",
                    "is_umbrella": False,
                    "member_count": 3,
                    "effective_member_count": 3,
                },
            ],
            "relationships": [
                {"child_group_id": assertion_id, "parent_group_id": umbrella_id},
            ],
        }

        result = groups_service.get_group_graph_data(requesting_user)

        umbrella_node = next(n for n in result.nodes if n.id == umbrella_id)
        assertion_node = next(n for n in result.nodes if n.id == assertion_id)
        assert umbrella_node.is_umbrella is True
        assert assertion_node.is_umbrella is False


def test_get_group_graph_data_umbrella_defaults_false(make_requesting_user):
    """is_umbrella defaults to False when not present in database row."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    group_id = str(uuid4())

    with (
        patch("services.groups.crud.database") as mock_db,
        patch("services.groups.crud.track_activity"),
    ):
        mock_db.groups.list_all_groups_for_graph.return_value = {
            "groups": [
                {
                    "id": group_id,
                    "name": "Engineering",
                    "group_type": "weftid",
                    # is_umbrella not present — simulates old data
                    "member_count": 5,
                    "effective_member_count": 5,
                }
            ],
            "relationships": [],
        }

        result = groups_service.get_group_graph_data(requesting_user)

        assert result.nodes[0].is_umbrella is False


# =============================================================================
# Graph Layout Service Tests
# =============================================================================


def test_get_graph_layout_returns_saved_layout(make_requesting_user):
    """Admin can retrieve a saved layout."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="admin")

    node_ids = "aaa,bbb"
    positions = {"aaa": {"x": 40.0, "y": 80.0}, "bbb": {"x": 120.0, "y": 160.0}}

    with (
        patch("services.groups.layout.database") as mock_db,
        patch("services.groups.layout.track_activity"),
    ):
        mock_db.groups.get_graph_layout.return_value = {
            "node_ids": node_ids,
            "positions": positions,
        }

        result = groups_service.get_graph_layout_for_user(requesting_user)

        assert result is not None
        assert result.node_ids == node_ids
        assert result.positions["aaa"].x == 40.0
        assert result.positions["aaa"].y == 80.0
        assert result.positions["bbb"].x == 120.0
        assert result.positions["bbb"].y == 160.0
        mock_db.groups.get_graph_layout.assert_called_once_with(tenant_id, user_id)


def test_get_graph_layout_returns_none_when_no_layout(make_requesting_user):
    """Returns None when user has no saved layout."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with (
        patch("services.groups.layout.database") as mock_db,
        patch("services.groups.layout.track_activity"),
    ):
        mock_db.groups.get_graph_layout.return_value = None

        result = groups_service.get_graph_layout_for_user(requesting_user)

        assert result is None


def test_get_graph_layout_forbidden_for_non_admin(make_requesting_user):
    """Non-admin cannot retrieve graph layout."""
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        groups_service.get_graph_layout_for_user(requesting_user)

    assert exc_info.value.code == "admin_required"


def test_save_graph_layout_success(make_requesting_user):
    """Admin can save a graph layout."""
    from schemas.groups import GroupGraphLayout
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="admin")

    layout = GroupGraphLayout(
        node_ids="aaa,bbb",
        positions={"aaa": {"x": 40.0, "y": 80.0}, "bbb": {"x": 120.0, "y": 160.0}},
    )

    with (
        patch("services.groups.layout.database") as mock_db,
        patch("services.groups.layout.track_activity"),
    ):
        mock_db.groups.upsert_graph_layout.return_value = None

        groups_service.save_graph_layout(requesting_user, layout)

        mock_db.groups.upsert_graph_layout.assert_called_once_with(
            tenant_id,
            user_id,
            layout.node_ids,
            {"aaa": {"x": 40.0, "y": 80.0}, "bbb": {"x": 120.0, "y": 160.0}},
        )


def test_save_graph_layout_forbidden_for_non_admin(make_requesting_user):
    """Non-admin cannot save graph layout."""
    from schemas.groups import GroupGraphLayout
    from services import groups as groups_service

    requesting_user = make_requesting_user(role="member")
    layout = GroupGraphLayout(node_ids="aaa", positions={"aaa": {"x": 0.0, "y": 0.0}})

    with pytest.raises(ForbiddenError) as exc_info:
        groups_service.save_graph_layout(requesting_user, layout)

    assert exc_info.value.code == "admin_required"


# =============================================================================
# IdP Umbrella Relationship Wiring
# =============================================================================


def test_get_or_create_idp_group_creates_umbrella_relationship():
    """New assertion group gets wired as a child of the umbrella group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    base_group_id = str(uuid4())
    new_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        # No existing group
        mock_db.groups.get_group_by_idp_and_name.return_value = None
        # Create returns the new group
        mock_db.groups.create_idp_group.return_value = {"id": new_group_id}
        # Base group exists
        mock_db.groups.get_idp_base_group_id.return_value = base_group_id
        # Relationship doesn't exist yet
        mock_db.groups.relationship_exists.return_value = False

        result = groups_service.get_or_create_idp_group(tenant_id, idp_id, "Okta", "Engineering")

        assert result["id"] == new_group_id
        assert result["created"] is True

        # Relationship should have been created
        mock_db.groups.add_group_relationship.assert_called_once_with(
            tenant_id, tenant_id, base_group_id, new_group_id
        )

        # Two log_event calls: discovery + relationship
        assert mock_log.call_count == 2
        rel_call = mock_log.call_args_list[1]
        assert rel_call[1]["event_type"] == "idp_group_relationship_created"
        assert rel_call[1]["artifact_id"] == base_group_id


def test_get_or_create_idp_group_existing_group_ensures_relationship():
    """Existing assertion group still gets wired if relationship was missing."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    base_group_id = str(uuid4())
    existing_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event") as mock_log,
        patch("services.groups.idp.system_context"),
    ):
        # Group already exists
        mock_db.groups.get_group_by_idp_and_name.return_value = {
            "id": existing_group_id,
            "name": "Engineering",
        }
        # Base group exists
        mock_db.groups.get_idp_base_group_id.return_value = base_group_id
        # Relationship missing
        mock_db.groups.relationship_exists.return_value = False

        result = groups_service.get_or_create_idp_group(tenant_id, idp_id, "Okta", "Engineering")

        assert result["id"] == existing_group_id
        assert result["created"] is False

        # Relationship should have been created retroactively
        mock_db.groups.add_group_relationship.assert_called_once_with(
            tenant_id, tenant_id, base_group_id, existing_group_id
        )

        mock_log.assert_called_once()
        assert mock_log.call_args[1]["event_type"] == "idp_group_relationship_created"


def test_get_or_create_idp_group_relationship_idempotent():
    """No error when umbrella relationship already exists."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    base_group_id = str(uuid4())
    existing_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
    ):
        mock_db.groups.get_group_by_idp_and_name.return_value = {
            "id": existing_group_id,
            "name": "Engineering",
        }
        mock_db.groups.get_idp_base_group_id.return_value = base_group_id
        # Relationship already exists
        mock_db.groups.relationship_exists.return_value = True

        result = groups_service.get_or_create_idp_group(tenant_id, idp_id, "Okta", "Engineering")

        assert result["id"] == existing_group_id
        # Should NOT create a duplicate relationship
        mock_db.groups.add_group_relationship.assert_not_called()


def test_get_or_create_idp_group_no_base_group_skips_wiring():
    """When no umbrella group exists, wiring is skipped gracefully."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    new_group_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
    ):
        mock_db.groups.get_group_by_idp_and_name.return_value = None
        mock_db.groups.create_idp_group.return_value = {"id": new_group_id}
        # No base group
        mock_db.groups.get_idp_base_group_id.return_value = None

        result = groups_service.get_or_create_idp_group(tenant_id, idp_id, "Okta", "Engineering")

        assert result["id"] == new_group_id
        mock_db.groups.add_group_relationship.assert_not_called()


def test_sync_user_idp_groups_wires_relationships():
    """sync_user_idp_groups wires all resolved groups via get_or_create_idp_group."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    idp_id = str(uuid4())
    base_group_id = str(uuid4())
    group1_id = str(uuid4())
    group2_id = str(uuid4())

    with (
        patch("services.groups.idp.database") as mock_db,
        patch("services.groups.idp.log_event"),
        patch("services.groups.idp.system_context"),
    ):
        # Two groups to resolve
        mock_db.groups.get_group_by_idp_and_name.side_effect = [
            {"id": group1_id, "name": "Engineering"},
            {"id": group2_id, "name": "Product"},
        ]
        mock_db.groups.get_idp_base_group_id.return_value = base_group_id
        mock_db.groups.relationship_exists.return_value = False
        mock_db.groups.get_user_idp_group_ids.return_value = []
        mock_db.groups.bulk_add_user_to_groups.return_value = 2
        mock_db.groups.get_group_by_id.return_value = {"name": "test"}

        groups_service.sync_user_idp_groups(
            tenant_id,
            user_id,
            "user@example.com",
            idp_id,
            "Okta",
            ["Engineering", "Product"],
        )

        # Both groups should have been wired to the umbrella
        assert mock_db.groups.add_group_relationship.call_count == 2


# =============================================================================
# IdP Managed Relationship Protection
# =============================================================================


def test_remove_child_idp_managed_forbidden(make_requesting_user):
    """Removing an IdP-managed relationship raises ForbiddenError."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    umbrella_id = str(uuid4())
    assertion_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_umbrella = {
        "id": umbrella_id,
        "name": "Okta",
        "group_type": "idp",
        "idp_id": idp_id,
    }
    mock_assertion = {
        "id": assertion_id,
        "name": "Engineering",
        "group_type": "idp",
        "idp_id": idp_id,
    }

    with (
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups._helpers.database") as mock_helpers_db,
    ):
        mock_db.groups.get_group_by_id.side_effect = [mock_umbrella, mock_assertion]
        # _is_idp_umbrella_group needs to query the base group ID
        mock_helpers_db.groups.get_idp_base_group_id.return_value = umbrella_id

        with pytest.raises(ForbiddenError) as exc_info:
            groups_service.remove_child(requesting_user, umbrella_id, assertion_id)

        assert exc_info.value.code == "idp_managed_relationship"


def test_remove_child_non_idp_managed_allowed(make_requesting_user):
    """Normal (non-IdP-managed) removal still works."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    parent_id = str(uuid4())
    child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_parent = {"id": parent_id, "name": "Parent", "group_type": "weftid"}
    mock_child = {"id": child_id, "name": "Child", "group_type": "weftid"}

    with (
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.side_effect = [mock_parent, mock_child]
        mock_db.groups.remove_group_relationship.return_value = 1

        groups_service.remove_child(requesting_user, parent_id, child_id)

        mock_db.groups.remove_group_relationship.assert_called_once()
        mock_log.assert_called_once()


def test_remove_all_relationships_skips_idp_managed(make_requesting_user):
    """Clear relationships skips IdP-managed ones."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    umbrella_id = str(uuid4())
    assertion_id = str(uuid4())
    weftid_child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_group = {
        "id": umbrella_id,
        "name": "Okta",
        "group_type": "idp",
        "idp_id": idp_id,
    }

    with (
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.log_event") as mock_log,
        patch("services.groups._helpers.database") as mock_helpers_db,
    ):
        mock_db.groups.get_group_by_id.side_effect = lambda tid, gid: {
            umbrella_id: mock_group,
            assertion_id: {
                "id": assertion_id,
                "name": "Engineering",
                "group_type": "idp",
                "idp_id": idp_id,
            },
            weftid_child_id: {
                "id": weftid_child_id,
                "name": "Manual Child",
                "group_type": "weftid",
            },
        }.get(gid)

        mock_db.groups.get_group_parents.return_value = []
        mock_db.groups.get_group_children.return_value = [
            {"group_id": assertion_id, "name": "Engineering", "group_type": "idp"},
            {"group_id": weftid_child_id, "name": "Manual Child", "group_type": "weftid"},
        ]
        mock_db.groups.remove_group_relationship.return_value = 1
        mock_helpers_db.groups.get_idp_base_group_id.return_value = umbrella_id

        count = groups_service.remove_all_relationships(requesting_user, umbrella_id)

        # Only the weftid child should have been removed (1), not the IdP one
        assert count == 1
        mock_db.groups.remove_group_relationship.assert_called_once_with(
            tenant_id, umbrella_id, weftid_child_id
        )
        mock_log.assert_called_once()


# =============================================================================
# IdP Umbrella as Parent
# =============================================================================


def test_add_child_umbrella_as_parent_allowed(make_requesting_user):
    """Umbrella group can have children added to it."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    umbrella_id = str(uuid4())
    child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_umbrella = {
        "id": umbrella_id,
        "name": "Okta",
        "group_type": "idp",
        "idp_id": idp_id,
    }
    mock_child = {"id": child_id, "name": "Some Group", "group_type": "weftid"}

    with (
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups.hierarchy.log_event") as mock_log,
        patch("services.groups._helpers.database") as mock_helpers_db,
    ):
        mock_db.groups.get_group_by_id.side_effect = [mock_umbrella, mock_child]
        mock_db.groups.relationship_exists.return_value = False
        mock_db.groups.would_create_cycle.return_value = False
        mock_db.groups.add_group_relationship.return_value = {"id": str(uuid4())}
        # _is_idp_umbrella_group lookup
        mock_helpers_db.groups.get_idp_base_group_id.return_value = umbrella_id

        groups_service.add_child(requesting_user, umbrella_id, child_id)

        mock_db.groups.add_group_relationship.assert_called_once()
        mock_log.assert_called_once()
        assert mock_log.call_args[1]["event_type"] == "group_relationship_created"


def test_add_child_assertion_as_parent_still_blocked(make_requesting_user):
    """Assertion sub-groups still cannot be parents."""
    from services import groups as groups_service

    tenant_id = str(uuid4())
    idp_id = str(uuid4())
    umbrella_id = str(uuid4())
    assertion_id = str(uuid4())
    child_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    mock_assertion = {
        "id": assertion_id,
        "name": "Engineering",
        "group_type": "idp",
        "idp_id": idp_id,
    }
    mock_child = {"id": child_id, "name": "Some Group", "group_type": "weftid"}

    with (
        patch("services.groups.hierarchy.database") as mock_db,
        patch("services.groups._helpers.database") as mock_helpers_db,
    ):
        mock_db.groups.get_group_by_id.side_effect = [mock_assertion, mock_child]
        # This assertion group is NOT the umbrella
        mock_helpers_db.groups.get_idp_base_group_id.return_value = umbrella_id

        with pytest.raises(ValidationError) as exc_info:
            groups_service.add_child(requesting_user, assertion_id, child_id)

        assert exc_info.value.code == "idp_cannot_be_parent"
