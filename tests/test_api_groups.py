"""Unit tests for Group Management API endpoints.

These tests use FastAPI dependency overrides and mocks to isolate the API layer.
"""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

from main import app
from schemas.groups import (
    GroupChildrenList,
    GroupDetail,
    GroupListResponse,
    GroupMemberDetail,
    GroupMemberDetailList,
    GroupParentsList,
    GroupRelationship,
    GroupSummary,
)
from services.exceptions import ConflictError, NotFoundError, ValidationError
from starlette.testclient import TestClient

# =============================================================================
# List Groups Tests
# =============================================================================


def test_list_groups_as_admin(make_user_dict, override_api_auth):
    """Admin can list groups."""
    admin = make_user_dict(role="admin")

    mock_response = GroupListResponse(
        items=[
            GroupSummary(
                id=str(uuid4()),
                name="Engineering",
                description="Eng team",
                group_type="weftid",
                is_valid=True,
                member_count=5,
                created_at=datetime.now(UTC),
            )
        ],
        total=1,
        page=1,
        limit=25,
    )

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_groups.return_value = mock_response

        client = TestClient(app)
        response = client.get("/api/v1/groups")

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["name"] == "Engineering"


def test_list_groups_with_filters(make_user_dict, override_api_auth):
    """Test list groups with search and type filters."""
    admin = make_user_dict(role="admin")

    mock_response = GroupListResponse(items=[], total=0, page=1, limit=25)

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_groups.return_value = mock_response

        client = TestClient(app)
        response = client.get(
            "/api/v1/groups?search=eng&group_type=weftid&sort_field=name&sort_order=asc"
        )

        assert response.status_code == 200
        mock_svc.list_groups.assert_called_once()
        call_args = mock_svc.list_groups.call_args
        # Check that filters were passed
        assert call_args.kwargs.get("search") == "eng"
        assert call_args.kwargs.get("group_type") == "weftid"


# =============================================================================
# Create Group Tests
# =============================================================================


def test_create_group_success(make_user_dict, override_api_auth):
    """Admin can create a group."""
    admin = make_user_dict(role="admin")

    mock_group = GroupDetail(
        id=str(uuid4()),
        name="New Group",
        description="A new group",
        group_type="weftid",
        is_valid=True,
        member_count=0,
        parent_count=0,
        child_count=0,
        created_by=str(admin["id"]),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.create_group.return_value = mock_group

        client = TestClient(app)
        response = client.post(
            "/api/v1/groups",
            json={"name": "New Group", "description": "A new group"},
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "New Group"
        assert data["description"] == "A new group"


def test_create_group_duplicate_name(make_user_dict, override_api_auth):
    """Creating a group with duplicate name returns 409."""
    admin = make_user_dict(role="admin")

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.create_group.side_effect = ConflictError(
            message="Group name exists", code="group_name_exists"
        )

        client = TestClient(app)
        response = client.post("/api/v1/groups", json={"name": "Existing"})

        assert response.status_code == 409


def test_create_group_name_required(make_user_dict, override_api_auth):
    """Creating a group without name returns 400."""
    admin = make_user_dict(role="admin")

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.create_group.side_effect = ValidationError(
            message="Name required", code="name_required", field="name"
        )

        client = TestClient(app)
        response = client.post("/api/v1/groups", json={"name": "   "})

        assert response.status_code == 400


# =============================================================================
# Get Group Tests
# =============================================================================


def test_get_group_success(make_user_dict, override_api_auth):
    """Admin can get a group by ID."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_group = GroupDetail(
        id=group_id,
        name="Engineering",
        description="Eng team",
        group_type="weftid",
        is_valid=True,
        member_count=5,
        parent_count=1,
        child_count=2,
        created_by=str(uuid4()),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.get_group.return_value = mock_group

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == group_id
        assert data["name"] == "Engineering"
        assert data["member_count"] == 5


def test_get_group_not_found(make_user_dict, override_api_auth):
    """Getting non-existent group returns 404."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.get_group.side_effect = NotFoundError(
            message="Group not found", code="group_not_found"
        )

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}")

        assert response.status_code == 404


# =============================================================================
# Update Group Tests
# =============================================================================


def test_update_group_success(make_user_dict, override_api_auth):
    """Admin can update a group."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_group = GroupDetail(
        id=group_id,
        name="Updated Name",
        description="Updated description",
        group_type="weftid",
        is_valid=True,
        member_count=0,
        parent_count=0,
        child_count=0,
        created_by=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.update_group.return_value = mock_group

        client = TestClient(app)
        response = client.patch(
            f"/api/v1/groups/{group_id}",
            json={"name": "Updated Name", "description": "Updated description"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Name"


# =============================================================================
# Delete Group Tests
# =============================================================================


def test_delete_group_success(make_user_dict, override_api_auth):
    """Admin can delete a group."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.delete_group.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/groups/{group_id}")

        assert response.status_code == 204


def test_delete_group_not_found(make_user_dict, override_api_auth):
    """Deleting non-existent group returns 404."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.delete_group.side_effect = NotFoundError(
            message="Group not found", code="group_not_found"
        )

        client = TestClient(app)
        response = client.delete(f"/api/v1/groups/{group_id}")

        assert response.status_code == 404


# =============================================================================
# Member Operations Tests
# =============================================================================


def test_list_members_success(make_user_dict, override_api_auth):
    """Admin can list group members with search/filter/sort."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_response = GroupMemberDetailList(
        items=[
            GroupMemberDetail(
                id=str(uuid4()),
                user_id=str(uuid4()),
                email="user@example.com",
                first_name="Test",
                last_name="User",
                role="member",
                is_inactivated=False,
                is_anonymized=False,
                created_at=datetime.now(UTC),
            )
        ],
        total=1,
        page=1,
        limit=25,
    )

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_members_filtered.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/members")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["role"] == "member"


def test_add_member_success(make_user_dict, override_api_auth):
    """Admin can add a member to a group."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())
    user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_member.return_value = None

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{group_id}/members",
            json={"user_id": user_id},
        )

        assert response.status_code == 201
        assert response.json()["status"] == "ok"


def test_add_member_already_member(make_user_dict, override_api_auth):
    """Adding existing member returns 409."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())
    user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_member.side_effect = ConflictError(
            message="Already a member", code="already_member"
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{group_id}/members",
            json={"user_id": user_id},
        )

        assert response.status_code == 409


def test_remove_member_success(make_user_dict, override_api_auth):
    """Admin can remove a member from a group."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())
    user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.remove_member.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/groups/{group_id}/members/{user_id}")

        assert response.status_code == 204


# =============================================================================
# Relationship Operations Tests
# =============================================================================


def test_list_parents_success(make_user_dict, override_api_auth):
    """Admin can list parent groups."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_response = GroupParentsList(
        items=[
            GroupRelationship(
                id=str(uuid4()),
                group_id=str(uuid4()),
                name="Parent Group",
                group_type="weftid",
                member_count=5,
                created_at=datetime.now(UTC),
            )
        ],
        total=1,
    )

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_parents.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/parents")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1


def test_list_children_success(make_user_dict, override_api_auth):
    """Admin can list child groups."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_response = GroupChildrenList(
        items=[
            GroupRelationship(
                id=str(uuid4()),
                group_id=str(uuid4()),
                name="Child Group",
                group_type="weftid",
                member_count=3,
                created_at=datetime.now(UTC),
            )
        ],
        total=1,
    )

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_children.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/children")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1


def test_add_parent_success(make_user_dict, override_api_auth):
    """Admin can add a parent group."""
    admin = make_user_dict(role="admin")
    parent_id = str(uuid4())
    child_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_parent.return_value = None

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{child_id}/parents",
            json={"parent_group_id": parent_id},
        )

        assert response.status_code == 201
        assert response.json()["status"] == "ok"

def test_add_parent_would_create_cycle(make_user_dict, override_api_auth):
    """Adding parent that would create cycle returns 400."""
    admin = make_user_dict(role="admin")
    parent_id = str(uuid4())
    child_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_child.side_effect = ValidationError(
            message="Would create cycle", code="would_create_cycle"
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{child_id}/parents",
            json={"parent_group_id": parent_id},
        )
        assert response.status_code == 400


def test_remove_parent_success(make_user_dict, override_api_auth):
    """Admin can remove a child parent group."""
    admin = make_user_dict(role="admin")
    parent_id = str(uuid4())
    child_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.remove_child.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/groups/{child_id}/parents/{parent_id}")

        assert response.status_code == 204

def test_add_child_success(make_user_dict, override_api_auth):
    """Admin can add a child group."""
    admin = make_user_dict(role="admin")
    parent_id = str(uuid4())
    child_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_child.return_value = None

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{parent_id}/children",
            json={"child_group_id": child_id},
        )

        assert response.status_code == 201
        assert response.json()["status"] == "ok"


def test_add_child_would_create_cycle(make_user_dict, override_api_auth):
    """Adding child that would create cycle returns 400."""
    admin = make_user_dict(role="admin")
    parent_id = str(uuid4())
    child_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_child.side_effect = ValidationError(
            message="Would create cycle", code="would_create_cycle"
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{parent_id}/children",
            json={"child_group_id": child_id},
        )

        assert response.status_code == 400


def test_add_child_relationship_exists(make_user_dict, override_api_auth):
    """Adding existing relationship returns 409."""
    admin = make_user_dict(role="admin")
    parent_id = str(uuid4())
    child_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_child.side_effect = ConflictError(
            message="Relationship exists", code="relationship_exists"
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{parent_id}/children",
            json={"child_group_id": child_id},
        )

        assert response.status_code == 409


def test_remove_child_success(make_user_dict, override_api_auth):
    """Admin can remove a child group."""
    admin = make_user_dict(role="admin")
    parent_id = str(uuid4())
    child_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.remove_child.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/groups/{parent_id}/children/{child_id}")

        assert response.status_code == 204


# =============================================================================
# IdP Group API Tests
# =============================================================================


def test_api_add_member_to_idp_group_returns_403(make_user_dict, override_api_auth):
    """Adding member to IdP group returns 403."""
    from services.exceptions import ForbiddenError

    admin = make_user_dict(role="admin")
    group_id = str(uuid4())
    user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_member.side_effect = ForbiddenError(
            message="IdP groups cannot be manually modified",
            code="idp_group_readonly",
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{group_id}/members",
            json={"user_id": user_id},
        )

        assert response.status_code == 403
        data = response.json()
        assert "cannot be manually modified" in data["detail"]


# =============================================================================
# Effective Members API Tests
# =============================================================================


def test_api_list_effective_members_success(make_user_dict, override_api_auth):
    """Admin can list effective members of a group."""
    from schemas.groups import EffectiveMember, EffectiveMemberList

    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_response = EffectiveMemberList(
        items=[
            EffectiveMember(
                user_id=str(uuid4()),
                email="user@example.com",
                first_name="Test",
                last_name="User",
                is_direct=True,
            ),
            EffectiveMember(
                user_id=str(uuid4()),
                email="inherited@example.com",
                first_name="Inherited",
                last_name="User",
                is_direct=False,
            ),
        ],
        total=2,
        page=1,
        limit=50,
    )

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.get_effective_members.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/effective-members")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2
        assert data["items"][0]["is_direct"] is True
        assert data["items"][1]["is_direct"] is False


def test_api_list_effective_members_pagination(make_user_dict, override_api_auth):
    """Test effective members pagination parameters."""
    from schemas.groups import EffectiveMemberList

    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_response = EffectiveMemberList(items=[], total=0, page=2, limit=10)

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.get_effective_members.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/effective-members?page=2&limit=10")

        assert response.status_code == 200
        mock_svc.get_effective_members.assert_called_once()


def test_api_list_effective_members_not_found(make_user_dict, override_api_auth):
    """Effective members for non-existent group returns 404."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.get_effective_members.side_effect = NotFoundError(
            message="Group not found", code="group_not_found"
        )

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/effective-members")

        assert response.status_code == 404


# =============================================================================
# Bulk Add Members API Tests
# =============================================================================


def test_api_bulk_add_members_success(make_user_dict, override_api_auth):
    """Admin can bulk add members to a group."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())
    user_ids = [str(uuid4()), str(uuid4())]

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.bulk_add_members.return_value = 2

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{group_id}/members/bulk",
            json={"user_ids": user_ids},
        )

        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "ok"
        assert data["added"] == 2


def test_api_bulk_add_members_idp_forbidden(make_user_dict, override_api_auth):
    """Bulk adding to IdP group returns 403."""
    from services.exceptions import ForbiddenError

    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.bulk_add_members.side_effect = ForbiddenError(
            message="IdP groups cannot be modified", code="idp_group_readonly"
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{group_id}/members/bulk",
            json={"user_ids": [str(uuid4())]},
        )

        assert response.status_code == 403


# =============================================================================
# Bulk Remove Members API Tests
# =============================================================================


def test_api_bulk_remove_members_success(make_user_dict, override_api_auth):
    """Admin can bulk remove members from a group."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())
    user_ids = [str(uuid4()), str(uuid4())]

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.bulk_remove_members.return_value = 2

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{group_id}/members/bulk-remove",
            json={"user_ids": user_ids},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["removed"] == 2


def test_api_bulk_remove_members_idp_forbidden(make_user_dict, override_api_auth):
    """Bulk removing from IdP group returns 403."""
    from services.exceptions import ForbiddenError

    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.bulk_remove_members.side_effect = ForbiddenError(
            message="IdP groups cannot be modified", code="idp_group_readonly"
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{group_id}/members/bulk-remove",
            json={"user_ids": [str(uuid4())]},
        )

        assert response.status_code == 403


# =============================================================================
# Available Users API Tests
# =============================================================================


def test_api_list_available_users_success(make_user_dict, override_api_auth):
    """Admin can list users available to add to a group."""
    from schemas.groups import AvailableUserList, AvailableUserOption

    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_response = AvailableUserList(
        items=[
            AvailableUserOption(
                id=str(uuid4()),
                email="available@example.com",
                first_name="Available",
                last_name="User",
                role="member",
                is_inactivated=False,
                is_anonymized=False,
            )
        ],
        total=1,
        page=1,
        limit=25,
    )

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_available_users_paginated.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/available-users")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["email"] == "available@example.com"


def test_api_list_available_users_with_filters(make_user_dict, override_api_auth):
    """Available users endpoint accepts search and filter params."""
    from schemas.groups import AvailableUserList

    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_response = AvailableUserList(items=[], total=0, page=1, limit=25)

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_available_users_paginated.return_value = mock_response

        client = TestClient(app)
        response = client.get(
            f"/api/v1/groups/{group_id}/available-users"
            "?search=test&role=admin&status=active&sort_field=name&sort_order=asc"
        )

        assert response.status_code == 200
        mock_svc.list_available_users_paginated.assert_called_once()


def test_api_list_members_comma_separated_filters(make_user_dict, override_api_auth):
    """Test that comma-separated role/status filters are parsed into lists."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_response = GroupMemberDetailList(items=[], total=0, page=1, limit=25)

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_members_filtered.return_value = mock_response

        client = TestClient(app)
        response = client.get(
            f"/api/v1/groups/{group_id}/members"
            "?search=x&role=member,admin&status=active&sort_field=name&sort_order=asc"
        )

        assert response.status_code == 200
        call_kwargs = mock_svc.list_members_filtered.call_args[1]
        assert sorted(call_kwargs["roles"]) == ["admin", "member"]
        assert call_kwargs["statuses"] == ["active"]
        assert call_kwargs["search"] == "x"
        assert call_kwargs["sort_field"] == "name"
        assert call_kwargs["sort_order"] == "asc"


def test_api_list_available_users_comma_separated_filters(make_user_dict, override_api_auth):
    """Test that available-users endpoint parses comma-separated filters."""
    from schemas.groups import AvailableUserList

    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    mock_response = AvailableUserList(items=[], total=0, page=1, limit=25)

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_available_users_paginated.return_value = mock_response

        client = TestClient(app)
        response = client.get(
            f"/api/v1/groups/{group_id}/available-users"
            "?search=jane&role=member,super_admin&status=active,inactivated"
            "&sort_field=email&sort_order=desc"
        )

        assert response.status_code == 200
        call_kwargs = mock_svc.list_available_users_paginated.call_args[1]
        assert sorted(call_kwargs["roles"]) == ["member", "super_admin"]
        assert sorted(call_kwargs["statuses"]) == ["active", "inactivated"]
        assert call_kwargs["search"] == "jane"
        assert call_kwargs["sort_field"] == "email"
        assert call_kwargs["sort_order"] == "desc"


def test_api_list_available_users_not_found(make_user_dict, override_api_auth):
    """Available users for non-existent group returns 404."""
    admin = make_user_dict(role="admin")
    group_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_available_users_paginated.side_effect = NotFoundError(
            message="Group not found", code="group_not_found"
        )

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/available-users")

        assert response.status_code == 404


# =============================================================================
# User Effective Groups API Tests
# =============================================================================


def test_api_get_user_effective_groups_as_admin(make_user_dict, override_api_auth):
    """Admin can get effective groups for any user."""
    from schemas.groups import EffectiveMembership, EffectiveMembershipList

    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    mock_response = EffectiveMembershipList(
        items=[
            EffectiveMembership(
                id=str(uuid4()),
                name="Engineering",
                description=None,
                group_type="weftid",
                idp_id=None,
                idp_name=None,
                is_direct=True,
            ),
        ]
    )

    override_api_auth(admin, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.get_effective_memberships.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{user_id}/effective-groups")

        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["name"] == "Engineering"
        assert data["items"][0]["is_direct"] is True


def test_api_get_user_effective_groups_self(make_user_dict, override_api_auth):
    """User can get their own effective groups."""
    from schemas.groups import EffectiveMembershipList

    user_id = str(uuid4())
    user = make_user_dict(user_id=user_id, role="member")

    mock_response = EffectiveMembershipList(items=[])

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.get_effective_memberships.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{user_id}/effective-groups")

        assert response.status_code == 200


def test_api_get_user_effective_groups_forbidden(make_user_dict, override_api_auth):
    """Regular user cannot get another user's effective groups."""
    from services.exceptions import ForbiddenError

    user = make_user_dict(role="member")
    other_user_id = str(uuid4())

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.get_effective_memberships.side_effect = ForbiddenError(
            message="Forbidden", code="forbidden"
        )

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{other_user_id}/effective-groups")

        assert response.status_code == 403


# =============================================================================
# IdP Group API Tests
# =============================================================================


def test_api_list_idp_groups(make_user_dict, override_api_auth):
    """Admin can list groups for an IdP."""
    admin = make_user_dict(role="admin")
    idp_id = str(uuid4())

    mock_groups = [
        GroupSummary(
            id=str(uuid4()),
            name="Okta Engineering",
            description=None,
            group_type="idp",
            idp_id=idp_id,
            idp_name="Okta Corporate",
            is_valid=True,
            member_count=5,
            created_at=datetime.now(UTC),
        ),
        GroupSummary(
            id=str(uuid4()),
            name="Okta Sales",
            description=None,
            group_type="idp",
            idp_id=idp_id,
            idp_name="Okta Corporate",
            is_valid=True,
            member_count=3,
            created_at=datetime.now(UTC),
        ),
    ]

    override_api_auth(admin)

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_groups_for_idp.return_value = mock_groups

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/idp/{idp_id}")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["group_type"] == "idp"
        assert data[0]["idp_id"] == idp_id


# =============================================================================
# User Direct Groups API Tests
# =============================================================================


def test_api_get_user_direct_groups_as_admin(make_user_dict, override_api_auth):
    """Admin can get direct groups for any user."""
    from schemas.groups import EffectiveMembership, EffectiveMembershipList

    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    mock_response = EffectiveMembershipList(
        items=[
            EffectiveMembership(
                id=str(uuid4()),
                name="Engineering",
                description=None,
                group_type="weftid",
                idp_id=None,
                idp_name=None,
                is_direct=True,
            ),
        ]
    )

    override_api_auth(admin, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.get_direct_memberships.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{user_id}/groups")

        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["name"] == "Engineering"
        assert data["items"][0]["is_direct"] is True


def test_api_get_user_direct_groups_self(make_user_dict, override_api_auth):
    """User can get their own direct groups."""
    from schemas.groups import EffectiveMembershipList

    user_id = str(uuid4())
    user = make_user_dict(user_id=user_id, role="member")

    mock_response = EffectiveMembershipList(items=[])

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.get_direct_memberships.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{user_id}/groups")

        assert response.status_code == 200


def test_api_get_user_direct_groups_forbidden(make_user_dict, override_api_auth):
    """Regular user cannot get another user's direct groups."""
    from services.exceptions import ForbiddenError

    user = make_user_dict(role="member")
    other_user_id = str(uuid4())

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.get_direct_memberships.side_effect = ForbiddenError(
            message="Forbidden", code="forbidden"
        )

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{other_user_id}/groups")

        assert response.status_code == 403


def test_api_add_user_to_single_group(make_user_dict, override_api_auth):
    """Admin can add a user to a single group via API."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())
    group_id = str(uuid4())

    override_api_auth(admin, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.add_member.return_value = None

        client = TestClient(app)
        response = client.post(
            f"/api/v1/users/{user_id}/groups",
            json={"group_ids": [group_id]},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["added"] == 1
        mock_svc.add_member.assert_called_once()


def test_api_add_user_to_multiple_groups(make_user_dict, override_api_auth):
    """Admin can add a user to multiple groups via API."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())
    group_ids = [str(uuid4()), str(uuid4())]

    override_api_auth(admin, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.bulk_add_user_to_groups.return_value = 2

        client = TestClient(app)
        response = client.post(
            f"/api/v1/users/{user_id}/groups",
            json={"group_ids": group_ids},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["added"] == 2
        mock_svc.bulk_add_user_to_groups.assert_called_once()


def test_api_add_user_to_groups_not_found(make_user_dict, override_api_auth):
    """Adding user to non-existent group returns 404."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    override_api_auth(admin, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.add_member.side_effect = NotFoundError(
            message="Group not found", code="group_not_found"
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/users/{user_id}/groups",
            json={"group_ids": [str(uuid4())]},
        )

        assert response.status_code == 404


def test_api_remove_user_from_group(make_user_dict, override_api_auth):
    """Admin can remove a user from a group via API."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())
    group_id = str(uuid4())

    override_api_auth(admin, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.remove_member.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/users/{user_id}/groups/{group_id}")

        assert response.status_code == 204
        mock_svc.remove_member.assert_called_once()


def test_api_remove_user_from_group_not_found(make_user_dict, override_api_auth):
    """Removing user from non-existent group returns 404."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())
    group_id = str(uuid4())

    override_api_auth(admin, level="user")

    with patch("routers.api.v1.users.groups_service") as mock_svc:
        mock_svc.remove_member.side_effect = NotFoundError(
            message="Not a member", code="not_a_member"
        )

        client = TestClient(app)
        response = client.delete(f"/api/v1/users/{user_id}/groups/{group_id}")

        assert response.status_code == 404
