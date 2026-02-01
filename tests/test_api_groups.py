"""Unit tests for Group Management API endpoints.

These tests use FastAPI dependency overrides and mocks to isolate the API layer.
"""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

from api_dependencies import require_admin_api
from dependencies import get_tenant_id_from_request
from main import app
from schemas.groups import (
    GroupChildrenList,
    GroupDetail,
    GroupListResponse,
    GroupMember,
    GroupMemberList,
    GroupParentsList,
    GroupRelationship,
    GroupSummary,
)
from services.exceptions import ConflictError, NotFoundError, ValidationError
from starlette.testclient import TestClient

# =============================================================================
# List Groups Tests
# =============================================================================


def test_list_groups_as_admin(make_user_dict):
    """Admin can list groups."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]

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

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_groups.return_value = mock_response

        client = TestClient(app)
        response = client.get("/api/v1/groups")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["name"] == "Engineering"


def test_list_groups_with_filters(make_user_dict):
    """Test list groups with search and type filters."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]

    mock_response = GroupListResponse(items=[], total=0, page=1, limit=25)

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_groups.return_value = mock_response

        client = TestClient(app)
        response = client.get(
            "/api/v1/groups?search=eng&group_type=weftid&sort_field=name&sort_order=asc"
        )

        app.dependency_overrides.clear()

        assert response.status_code == 200
        mock_svc.list_groups.assert_called_once()
        call_args = mock_svc.list_groups.call_args
        # Check that filters were passed
        assert call_args.kwargs.get("search") == "eng"
        assert call_args.kwargs.get("group_type") == "weftid"


# =============================================================================
# Create Group Tests
# =============================================================================


def test_create_group_success(make_user_dict):
    """Admin can create a group."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]

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

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.create_group.return_value = mock_group

        client = TestClient(app)
        response = client.post(
            "/api/v1/groups",
            json={"name": "New Group", "description": "A new group"},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "New Group"
        assert data["description"] == "A new group"


def test_create_group_duplicate_name(make_user_dict):
    """Creating a group with duplicate name returns 409."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.create_group.side_effect = ConflictError(
            message="Group name exists", code="group_name_exists"
        )

        client = TestClient(app)
        response = client.post("/api/v1/groups", json={"name": "Existing"})

        app.dependency_overrides.clear()

        assert response.status_code == 409


def test_create_group_name_required(make_user_dict):
    """Creating a group without name returns 400."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.create_group.side_effect = ValidationError(
            message="Name required", code="name_required", field="name"
        )

        client = TestClient(app)
        response = client.post("/api/v1/groups", json={"name": "   "})

        app.dependency_overrides.clear()

        assert response.status_code == 400


# =============================================================================
# Get Group Tests
# =============================================================================


def test_get_group_success(make_user_dict):
    """Admin can get a group by ID."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
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

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.get_group.return_value = mock_group

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == group_id
        assert data["name"] == "Engineering"
        assert data["member_count"] == 5


def test_get_group_not_found(make_user_dict):
    """Getting non-existent group returns 404."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    group_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.get_group.side_effect = NotFoundError(
            message="Group not found", code="group_not_found"
        )

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 404


# =============================================================================
# Update Group Tests
# =============================================================================


def test_update_group_success(make_user_dict):
    """Admin can update a group."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
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

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.update_group.return_value = mock_group

        client = TestClient(app)
        response = client.patch(
            f"/api/v1/groups/{group_id}",
            json={"name": "Updated Name", "description": "Updated description"},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Name"


# =============================================================================
# Delete Group Tests
# =============================================================================


def test_delete_group_success(make_user_dict):
    """Admin can delete a group."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    group_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.delete_group.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/groups/{group_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 204


def test_delete_group_not_found(make_user_dict):
    """Deleting non-existent group returns 404."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    group_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.delete_group.side_effect = NotFoundError(
            message="Group not found", code="group_not_found"
        )

        client = TestClient(app)
        response = client.delete(f"/api/v1/groups/{group_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 404


# =============================================================================
# Member Operations Tests
# =============================================================================


def test_list_members_success(make_user_dict):
    """Admin can list group members."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    group_id = str(uuid4())

    mock_response = GroupMemberList(
        items=[
            GroupMember(
                id=str(uuid4()),
                user_id=str(uuid4()),
                email="user@example.com",
                first_name="Test",
                last_name="User",
                created_at=datetime.now(UTC),
            )
        ],
        total=1,
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_members.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/members")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1


def test_add_member_success(make_user_dict):
    """Admin can add a member to a group."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    group_id = str(uuid4())
    user_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_member.return_value = None

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{group_id}/members",
            json={"user_id": user_id},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 201
        assert response.json()["status"] == "ok"


def test_add_member_already_member(make_user_dict):
    """Adding existing member returns 409."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    group_id = str(uuid4())
    user_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_member.side_effect = ConflictError(
            message="Already a member", code="already_member"
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{group_id}/members",
            json={"user_id": user_id},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 409


def test_remove_member_success(make_user_dict):
    """Admin can remove a member from a group."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    group_id = str(uuid4())
    user_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.remove_member.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/groups/{group_id}/members/{user_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 204


# =============================================================================
# Relationship Operations Tests
# =============================================================================


def test_list_parents_success(make_user_dict):
    """Admin can list parent groups."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
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

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_parents.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/parents")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1


def test_list_children_success(make_user_dict):
    """Admin can list child groups."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
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

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_children.return_value = mock_response

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/{group_id}/children")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1


def test_add_child_success(make_user_dict):
    """Admin can add a child group."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    parent_id = str(uuid4())
    child_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_child.return_value = None

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{parent_id}/children",
            json={"child_group_id": child_id},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 201
        assert response.json()["status"] == "ok"


def test_add_child_would_create_cycle(make_user_dict):
    """Adding child that would create cycle returns 400."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    parent_id = str(uuid4())
    child_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_child.side_effect = ValidationError(
            message="Would create cycle", code="would_create_cycle"
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{parent_id}/children",
            json={"child_group_id": child_id},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 400


def test_add_child_relationship_exists(make_user_dict):
    """Adding existing relationship returns 409."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    parent_id = str(uuid4())
    child_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.add_child.side_effect = ConflictError(
            message="Relationship exists", code="relationship_exists"
        )

        client = TestClient(app)
        response = client.post(
            f"/api/v1/groups/{parent_id}/children",
            json={"child_group_id": child_id},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 409


def test_remove_child_success(make_user_dict):
    """Admin can remove a child group."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    parent_id = str(uuid4())
    child_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.remove_child.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/groups/{parent_id}/children/{child_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 204


# =============================================================================
# IdP Group API Tests
# =============================================================================


def test_api_add_member_to_idp_group_returns_403(make_user_dict):
    """Adding member to IdP group returns 403."""
    from services.exceptions import ForbiddenError

    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    group_id = str(uuid4())
    user_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

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

        app.dependency_overrides.clear()

        assert response.status_code == 403
        data = response.json()
        assert "cannot be manually modified" in data["detail"]


def test_api_list_idp_groups(make_user_dict):
    """Admin can list groups for an IdP."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
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

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.groups.groups_service") as mock_svc:
        mock_svc.list_groups_for_idp.return_value = mock_groups

        client = TestClient(app)
        response = client.get(f"/api/v1/groups/idp/{idp_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["group_type"] == "idp"
        assert data[0]["idp_id"] == idp_id
