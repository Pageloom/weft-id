"""Tests for routers/groups.py endpoints (frontend group management)."""

from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app


def _setup_admin_overrides(admin_user):
    """Set up dependency overrides for admin access."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(admin_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: admin_user
    app.dependency_overrides[get_current_user] = lambda: admin_user


def _setup_member_overrides(member_user):
    """Set up dependency overrides for non-admin access (should be blocked)."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_admin

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(member_user["tenant_id"])
    app.dependency_overrides[require_admin] = lambda: member_user
    app.dependency_overrides[get_current_user] = lambda: member_user


def _make_group_list_response(items=None, total=0, page=1, limit=25):
    """Create a mock GroupListResponse."""
    from schemas.groups import GroupListResponse

    if items is None:
        items = []
    return GroupListResponse(items=items, total=total, page=page, limit=limit)


def _make_group_summary(group_id=None, name="Test Group", description=None, group_type="weftid"):
    """Create a mock GroupSummary."""
    from schemas.groups import GroupSummary

    return GroupSummary(
        id=group_id or str(uuid4()),
        name=name,
        description=description,
        group_type=group_type,
        is_valid=True,
        member_count=0,
        created_at=datetime.now(UTC),
    )


def _make_group_detail(group_id=None, name="Test Group", description=None, group_type="weftid"):
    """Create a mock GroupDetail."""
    from schemas.groups import GroupDetail

    return GroupDetail(
        id=group_id or str(uuid4()),
        name=name,
        description=description,
        group_type=group_type,
        idp_id=None,
        is_valid=True,
        member_count=0,
        parent_count=0,
        child_count=0,
        created_by=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _make_member_list(items=None):
    """Create a mock GroupMemberList."""
    from schemas.groups import GroupMemberList

    return GroupMemberList(items=items or [], total=len(items) if items else 0)


def _make_relationship_list(items=None, list_type="parents"):
    """Create a mock GroupParentsList or GroupChildrenList."""
    from schemas.groups import GroupChildrenList, GroupParentsList

    if list_type == "parents":
        return GroupParentsList(items=items or [], total=len(items) if items else 0)
    return GroupChildrenList(items=items or [], total=len(items) if items else 0)


# Module path constant for cleaner patch targets
GROUPS_MODULE = "routers.groups"


# =============================================================================
# Index Redirect Tests
# =============================================================================


def test_groups_index_redirects_to_list(test_admin_user):
    """Test groups index redirects to list page."""
    _setup_admin_overrides(test_admin_user)

    client = TestClient(app)
    response = client.get("/admin/groups/", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/groups/list"


def test_groups_index_fallback_when_no_children(test_admin_user, mocker):
    """Test groups index falls back to /admin when no accessible children."""
    _setup_admin_overrides(test_admin_user)

    mock_first = mocker.patch(f"{GROUPS_MODULE}.get_first_accessible_child")
    mock_first.return_value = None

    client = TestClient(app)
    response = client.get("/admin/groups/", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/admin"


# =============================================================================
# Groups List Tests
# =============================================================================


def test_groups_list_renders(test_admin_user, mocker):
    """Test groups list page renders successfully."""
    _setup_admin_overrides(test_admin_user)

    mock_list = mocker.patch(f"{GROUPS_MODULE}.groups_service.list_groups")
    mock_ctx = mocker.patch(f"{GROUPS_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{GROUPS_MODULE}.templates.TemplateResponse")

    mock_list.return_value = _make_group_list_response()
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>groups</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    mock_list.assert_called_once()
    mock_tmpl.assert_called_once()
    assert mock_tmpl.call_args[0][0] == "groups_list.html"


def test_groups_list_with_search(test_admin_user, mocker):
    """Test groups list page with search parameter."""
    _setup_admin_overrides(test_admin_user)

    mock_list = mocker.patch(f"{GROUPS_MODULE}.groups_service.list_groups")
    mock_ctx = mocker.patch(f"{GROUPS_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{GROUPS_MODULE}.templates.TemplateResponse")

    mock_list.return_value = _make_group_list_response()
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>groups</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list?search=engineering")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    call_kwargs = mock_list.call_args[1]
    assert call_kwargs["search"] == "engineering"


def test_groups_list_with_pagination(test_admin_user, mocker):
    """Test groups list page with pagination parameters."""
    _setup_admin_overrides(test_admin_user)

    mock_list = mocker.patch(f"{GROUPS_MODULE}.groups_service.list_groups")
    mock_ctx = mocker.patch(f"{GROUPS_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{GROUPS_MODULE}.templates.TemplateResponse")

    mock_list.return_value = _make_group_list_response()
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>groups</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list?page=2&size=50")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    call_kwargs = mock_list.call_args[1]
    assert call_kwargs["page"] == 2
    assert call_kwargs["page_size"] == 50


def test_groups_list_with_groups(test_admin_user, mocker):
    """Test groups list page renders with group data."""
    _setup_admin_overrides(test_admin_user)

    mock_groups = [
        _make_group_summary(name="Engineering"),
        _make_group_summary(name="Sales"),
    ]

    mock_list = mocker.patch(f"{GROUPS_MODULE}.groups_service.list_groups")
    mock_ctx = mocker.patch(f"{GROUPS_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{GROUPS_MODULE}.templates.TemplateResponse")

    mock_list.return_value = _make_group_list_response(items=mock_groups, total=2)
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>groups</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["groups"] == mock_groups


def test_groups_list_shows_success_message(test_admin_user, mocker):
    """Test groups list page shows success query param."""
    _setup_admin_overrides(test_admin_user)

    mock_list = mocker.patch(f"{GROUPS_MODULE}.groups_service.list_groups")
    mock_ctx = mocker.patch(f"{GROUPS_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{GROUPS_MODULE}.templates.TemplateResponse")

    mock_list.return_value = _make_group_list_response()
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>groups</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list?success=deleted")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["success"] == "deleted"


def test_groups_list_service_error(test_admin_user, mocker):
    """Test groups list handles service errors gracefully."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    mock_list = mocker.patch(f"{GROUPS_MODULE}.groups_service.list_groups")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_list.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list")

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_groups_list_non_admin_redirects(test_user):
    """Test non-admin user gets redirected from groups list.

    Note: We don't override require_admin, so the router-level check blocks the request.
    The require_admin dependency redirects unauthenticated/unauthorized users to /login.
    """
    from dependencies import get_current_user, get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_user["tenant_id"])
    app.dependency_overrides[get_current_user] = lambda: test_user
    # Don't override require_admin - let it actually check

    client = TestClient(app)
    response = client.get("/admin/groups/list", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    # require_admin redirects to /login when user is not admin
    assert response.headers["location"] == "/login"


# =============================================================================
# New Group Form Tests
# =============================================================================


def test_new_group_form_renders(test_admin_user, mocker):
    """Test new group form renders successfully."""
    _setup_admin_overrides(test_admin_user)

    mock_ctx = mocker.patch(f"{GROUPS_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{GROUPS_MODULE}.templates.TemplateResponse")

    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>new group</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/new")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    mock_tmpl.assert_called_once()
    assert mock_tmpl.call_args[0][0] == "groups_new.html"


def test_new_group_form_preserves_values_on_error(test_admin_user, mocker):
    """Test new group form preserves values when redirected with error."""
    _setup_admin_overrides(test_admin_user)

    mock_ctx = mocker.patch(f"{GROUPS_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{GROUPS_MODULE}.templates.TemplateResponse")

    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>new group</html>")

    client = TestClient(app)
    response = client.get(
        "/admin/groups/new?error=duplicate_name&name=Engineering&description=Team"
    )

    app.dependency_overrides.clear()

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["error"] == "duplicate_name"
    assert ctx_kwargs["name"] == "Engineering"
    assert ctx_kwargs["description"] == "Team"


# =============================================================================
# Create Group Tests
# =============================================================================


def test_create_group_success(test_admin_user, mocker):
    """Test creating a group succeeds."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_create = mocker.patch(f"{GROUPS_MODULE}.groups_service.create_group")
    mock_create.return_value = mock_group

    client = TestClient(app)
    response = client.post(
        "/admin/groups/new",
        data={"name": "Engineering", "description": "Engineering team"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}" in response.headers["location"]
    assert "success=created" in response.headers["location"]
    mock_create.assert_called_once()


def test_create_group_without_description(test_admin_user, mocker):
    """Test creating a group without description."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Sales")

    mock_create = mocker.patch(f"{GROUPS_MODULE}.groups_service.create_group")
    mock_create.return_value = mock_group

    client = TestClient(app)
    response = client.post(
        "/admin/groups/new",
        data={"name": "Sales", "description": ""},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "success=created" in response.headers["location"]


def test_create_group_validation_error(test_admin_user, mocker):
    """Test creating a group with validation error redirects back to form."""
    from services.exceptions import ValidationError

    _setup_admin_overrides(test_admin_user)

    mock_create = mocker.patch(f"{GROUPS_MODULE}.groups_service.create_group")
    mock_create.side_effect = ValidationError("Name too short", code="name_too_short")

    client = TestClient(app)
    response = client.post(
        "/admin/groups/new",
        data={"name": "E", "description": ""},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=name_too_short" in response.headers["location"]
    assert "name=E" in response.headers["location"]


def test_create_group_conflict_error(test_admin_user, mocker):
    """Test creating a group with duplicate name redirects with error."""
    from services.exceptions import ConflictError

    _setup_admin_overrides(test_admin_user)

    mock_create = mocker.patch(f"{GROUPS_MODULE}.groups_service.create_group")
    mock_create.side_effect = ConflictError("Group already exists", code="duplicate_name")

    client = TestClient(app)
    response = client.post(
        "/admin/groups/new",
        data={"name": "Engineering", "description": ""},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=duplicate_name" in response.headers["location"]


def test_create_group_service_error(test_admin_user, mocker):
    """Test creating a group with service error renders error page."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    mock_create = mocker.patch(f"{GROUPS_MODULE}.groups_service.create_group")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_create.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        "/admin/groups/new",
        data={"name": "Engineering", "description": ""},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Group Detail Tests
# =============================================================================


@pytest.fixture
def mock_group_detail_deps(mocker):
    """Fixture to set up common mocks for group detail page."""
    mocks = {
        "get_group": mocker.patch(f"{GROUPS_MODULE}.groups_service.get_group"),
        "list_members": mocker.patch(f"{GROUPS_MODULE}.groups_service.list_members"),
        "list_parents": mocker.patch(f"{GROUPS_MODULE}.groups_service.list_parents"),
        "list_children": mocker.patch(f"{GROUPS_MODULE}.groups_service.list_children"),
        "list_available_users": mocker.patch(
            f"{GROUPS_MODULE}.groups_service.list_available_users_for_group"
        ),
        "list_available_parents": mocker.patch(
            f"{GROUPS_MODULE}.groups_service.list_available_parents"
        ),
        "list_available_children": mocker.patch(
            f"{GROUPS_MODULE}.groups_service.list_available_children"
        ),
        "get_context": mocker.patch(f"{GROUPS_MODULE}.get_template_context"),
        "template": mocker.patch(f"{GROUPS_MODULE}.templates.TemplateResponse"),
    }
    return mocks


def test_group_detail_renders(test_admin_user, mock_group_detail_deps):
    """Test group detail page renders successfully."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_group_detail_deps["get_group"].return_value = mock_group
    mock_group_detail_deps["list_members"].return_value = _make_member_list()
    mock_group_detail_deps["list_parents"].return_value = _make_relationship_list(list_type="parents")
    mock_group_detail_deps["list_children"].return_value = _make_relationship_list(list_type="children")
    mock_group_detail_deps["list_available_users"].return_value = []
    mock_group_detail_deps["list_available_parents"].return_value = []
    mock_group_detail_deps["list_available_children"].return_value = []
    mock_group_detail_deps["get_context"].return_value = {"request": MagicMock()}
    mock_group_detail_deps["template"].return_value = HTMLResponse(content="<html>detail</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    mock_group_detail_deps["template"].assert_called_once()
    assert mock_group_detail_deps["template"].call_args[0][0] == "groups_detail.html"


def test_group_detail_not_found(test_admin_user, mocker):
    """Test group detail page handles not found error."""
    from services.exceptions import NotFoundError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())

    mock_get = mocker.patch(f"{GROUPS_MODULE}.groups_service.get_group")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_get.side_effect = NotFoundError("Group not found")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}")

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_group_detail_service_error(test_admin_user, mocker):
    """Test group detail page handles generic service errors."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_get = mocker.patch(f"{GROUPS_MODULE}.groups_service.get_group")
    mock_members = mocker.patch(f"{GROUPS_MODULE}.groups_service.list_members")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    # get_group succeeds, but list_members raises ServiceError
    mock_get.return_value = mock_group
    mock_members.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}")

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_group_detail_shows_success_message(test_admin_user, mock_group_detail_deps):
    """Test group detail page shows success query param."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_group_detail_deps["get_group"].return_value = mock_group
    mock_group_detail_deps["list_members"].return_value = _make_member_list()
    mock_group_detail_deps["list_parents"].return_value = _make_relationship_list(list_type="parents")
    mock_group_detail_deps["list_children"].return_value = _make_relationship_list(list_type="children")
    mock_group_detail_deps["list_available_users"].return_value = []
    mock_group_detail_deps["list_available_parents"].return_value = []
    mock_group_detail_deps["list_available_children"].return_value = []
    mock_group_detail_deps["get_context"].return_value = {"request": MagicMock()}
    mock_group_detail_deps["template"].return_value = HTMLResponse(content="<html>detail</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}?success=updated")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    ctx_kwargs = mock_group_detail_deps["get_context"].call_args[1]
    assert ctx_kwargs["success"] == "updated"


# =============================================================================
# Update Group Tests
# =============================================================================


def test_update_group_success(test_admin_user, mocker):
    """Test updating a group succeeds."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())

    mock_update = mocker.patch(f"{GROUPS_MODULE}.groups_service.update_group")
    mock_update.return_value = _make_group_detail(group_id=group_id, name="Updated Name")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/edit",
        data={"name": "Updated Name", "description": "New description"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}" in response.headers["location"]
    assert "success=updated" in response.headers["location"]


def test_update_group_validation_error(test_admin_user, mocker):
    """Test updating a group with validation error redirects with error."""
    from services.exceptions import ValidationError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())

    mock_update = mocker.patch(f"{GROUPS_MODULE}.groups_service.update_group")
    # Service can reject names for other reasons (e.g., invalid characters)
    mock_update.side_effect = ValidationError("Invalid name format", code="invalid_name")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/edit",
        data={"name": "Valid Name", "description": ""},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_name" in response.headers["location"]


def test_update_group_not_found(test_admin_user, mocker):
    """Test updating a non-existent group redirects with error."""
    from services.exceptions import NotFoundError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())

    mock_update = mocker.patch(f"{GROUPS_MODULE}.groups_service.update_group")
    mock_update.side_effect = NotFoundError("Group not found", code="group_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/edit",
        data={"name": "New Name", "description": ""},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=group_not_found" in response.headers["location"]


def test_update_group_conflict_error(test_admin_user, mocker):
    """Test updating a group to duplicate name redirects with error."""
    from services.exceptions import ConflictError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())

    mock_update = mocker.patch(f"{GROUPS_MODULE}.groups_service.update_group")
    mock_update.side_effect = ConflictError("Name already exists", code="duplicate_name")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/edit",
        data={"name": "Engineering", "description": ""},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=duplicate_name" in response.headers["location"]


def test_update_group_service_error(test_admin_user, mocker):
    """Test updating a group with service error renders error page."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())

    mock_update = mocker.patch(f"{GROUPS_MODULE}.groups_service.update_group")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_update.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/edit",
        data={"name": "New Name", "description": ""},
    )

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Delete Group Tests
# =============================================================================


def test_delete_group_success(test_admin_user, mocker):
    """Test deleting a group succeeds."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())

    mock_delete = mocker.patch(f"{GROUPS_MODULE}.groups_service.delete_group")
    mock_delete.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/delete",
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "/admin/groups/list" in response.headers["location"]
    assert "success=deleted" in response.headers["location"]


def test_delete_group_not_found(test_admin_user, mocker):
    """Test deleting a non-existent group redirects with error."""
    from services.exceptions import NotFoundError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())

    mock_delete = mocker.patch(f"{GROUPS_MODULE}.groups_service.delete_group")
    mock_delete.side_effect = NotFoundError("Group not found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/delete",
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "/admin/groups/list" in response.headers["location"]
    assert "error=group_not_found" in response.headers["location"]


def test_delete_group_service_error(test_admin_user, mocker):
    """Test deleting a group with service error renders error page."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())

    mock_delete = mocker.patch(f"{GROUPS_MODULE}.groups_service.delete_group")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_delete.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(f"/admin/groups/{group_id}/delete")

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Member Management Tests
# =============================================================================


def test_add_member_success(test_admin_user, mocker):
    """Test adding a member to a group succeeds."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_member")
    mock_add.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={"user_id": user_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}" in response.headers["location"]
    assert "success=member_added" in response.headers["location"]
    mock_add.assert_called_once()


def test_add_member_not_found(test_admin_user, mocker):
    """Test adding a member to non-existent group redirects with error."""
    from services.exceptions import NotFoundError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_member")
    mock_add.side_effect = NotFoundError("Group not found", code="group_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={"user_id": user_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=group_not_found" in response.headers["location"]


def test_add_member_user_not_found(test_admin_user, mocker):
    """Test adding a non-existent user redirects with error."""
    from services.exceptions import NotFoundError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_member")
    mock_add.side_effect = NotFoundError("User not found", code="user_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={"user_id": user_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=user_not_found" in response.headers["location"]


def test_add_member_already_member(test_admin_user, mocker):
    """Test adding an existing member redirects with error."""
    from services.exceptions import ConflictError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_member")
    mock_add.side_effect = ConflictError("Already a member", code="already_member")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={"user_id": user_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=already_member" in response.headers["location"]


def test_add_member_service_error(test_admin_user, mocker):
    """Test adding a member with service error renders error page."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_member")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_add.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={"user_id": user_id},
    )

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_remove_member_success(test_admin_user, mocker):
    """Test removing a member from a group succeeds."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_remove = mocker.patch(f"{GROUPS_MODULE}.groups_service.remove_member")
    mock_remove.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/{user_id}/remove",
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}" in response.headers["location"]
    assert "success=member_removed" in response.headers["location"]


def test_remove_member_not_found(test_admin_user, mocker):
    """Test removing a non-member redirects with error."""
    from services.exceptions import NotFoundError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_remove = mocker.patch(f"{GROUPS_MODULE}.groups_service.remove_member")
    mock_remove.side_effect = NotFoundError("Not a member", code="not_a_member")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/{user_id}/remove",
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=not_a_member" in response.headers["location"]


def test_remove_member_service_error(test_admin_user, mocker):
    """Test removing a member with service error renders error page."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_remove = mocker.patch(f"{GROUPS_MODULE}.groups_service.remove_member")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_remove.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(f"/admin/groups/{group_id}/members/{user_id}/remove")

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Child Relationship Management Tests
# =============================================================================


def test_add_child_success(test_admin_user, mocker):
    """Test adding a child group succeeds."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_child")
    mock_add.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/add",
        data={"child_group_id": child_group_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}" in response.headers["location"]
    assert "success=child_added" in response.headers["location"]
    mock_add.assert_called_once()


def test_add_child_not_found(test_admin_user, mocker):
    """Test adding a non-existent child redirects with error."""
    from services.exceptions import NotFoundError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = NotFoundError("Child group not found", code="child_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/add",
        data={"child_group_id": child_group_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=child_not_found" in response.headers["location"]


def test_add_child_would_create_cycle(test_admin_user, mocker):
    """Test adding a child that would create a cycle redirects with error."""
    from services.exceptions import ValidationError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = ValidationError("Would create cycle", code="would_create_cycle")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/add",
        data={"child_group_id": child_group_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=would_create_cycle" in response.headers["location"]


def test_add_child_already_exists(test_admin_user, mocker):
    """Test adding an existing child redirects with error."""
    from services.exceptions import ConflictError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = ConflictError("Already a child", code="relationship_exists")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/add",
        data={"child_group_id": child_group_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=relationship_exists" in response.headers["location"]


def test_add_child_service_error(test_admin_user, mocker):
    """Test adding a child with service error renders error page."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_child")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_add.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/add",
        data={"child_group_id": child_group_id},
    )

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_remove_child_success(test_admin_user, mocker):
    """Test removing a child group succeeds."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{GROUPS_MODULE}.groups_service.remove_child")
    mock_remove.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/{child_group_id}/remove",
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}" in response.headers["location"]
    assert "success=child_removed" in response.headers["location"]


def test_remove_child_not_found(test_admin_user, mocker):
    """Test removing a non-existent child redirects with error."""
    from services.exceptions import NotFoundError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{GROUPS_MODULE}.groups_service.remove_child")
    mock_remove.side_effect = NotFoundError(
        "Relationship not found", code="relationship_not_found"
    )

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/{child_group_id}/remove",
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=relationship_not_found" in response.headers["location"]


def test_remove_child_service_error(test_admin_user, mocker):
    """Test removing a child with service error renders error page."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{GROUPS_MODULE}.groups_service.remove_child")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_remove.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(f"/admin/groups/{group_id}/children/{child_group_id}/remove")

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Parent Relationship Management Tests
# =============================================================================


def test_add_parent_success(test_admin_user, mocker):
    """Test adding a parent group succeeds."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_child")
    mock_add.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/add",
        data={"parent_group_id": parent_group_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}" in response.headers["location"]
    assert "success=parent_added" in response.headers["location"]
    # Should call add_child with parent as parent and group as child
    mock_add.assert_called_once()


def test_add_parent_not_found(test_admin_user, mocker):
    """Test adding a non-existent parent redirects with error."""
    from services.exceptions import NotFoundError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = NotFoundError("Parent group not found", code="parent_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/add",
        data={"parent_group_id": parent_group_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=parent_not_found" in response.headers["location"]


def test_add_parent_would_create_cycle(test_admin_user, mocker):
    """Test adding a parent that would create a cycle redirects with error."""
    from services.exceptions import ValidationError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = ValidationError("Would create cycle", code="would_create_cycle")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/add",
        data={"parent_group_id": parent_group_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=would_create_cycle" in response.headers["location"]


def test_add_parent_already_exists(test_admin_user, mocker):
    """Test adding an existing parent redirects with error."""
    from services.exceptions import ConflictError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = ConflictError("Already a parent", code="relationship_exists")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/add",
        data={"parent_group_id": parent_group_id},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=relationship_exists" in response.headers["location"]


def test_add_parent_service_error(test_admin_user, mocker):
    """Test adding a parent with service error renders error page."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_add = mocker.patch(f"{GROUPS_MODULE}.groups_service.add_child")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_add.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/add",
        data={"parent_group_id": parent_group_id},
    )

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_remove_parent_success(test_admin_user, mocker):
    """Test removing a parent group succeeds."""
    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{GROUPS_MODULE}.groups_service.remove_child")
    mock_remove.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/{parent_group_id}/remove",
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}" in response.headers["location"]
    assert "success=parent_removed" in response.headers["location"]


def test_remove_parent_not_found(test_admin_user, mocker):
    """Test removing a non-existent parent redirects with error."""
    from services.exceptions import NotFoundError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{GROUPS_MODULE}.groups_service.remove_child")
    mock_remove.side_effect = NotFoundError(
        "Relationship not found", code="relationship_not_found"
    )

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/{parent_group_id}/remove",
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=relationship_not_found" in response.headers["location"]


def test_remove_parent_service_error(test_admin_user, mocker):
    """Test removing a parent with service error renders error page."""
    from services.exceptions import ServiceError

    _setup_admin_overrides(test_admin_user)

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{GROUPS_MODULE}.groups_service.remove_child")
    mock_error = mocker.patch(f"{GROUPS_MODULE}.render_error_page")

    mock_remove.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(f"/admin/groups/{group_id}/parents/{parent_group_id}/remove")

    app.dependency_overrides.clear()

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()
