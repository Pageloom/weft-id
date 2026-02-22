"""Tests for routers/groups/ package endpoints (frontend group management)."""

from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app


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


# Module path constants for patch targets (one per sub-module)
LISTING_MODULE = "routers.groups.listing"
CREATION_MODULE = "routers.groups.creation"
DETAIL_MODULE = "routers.groups.detail"
MEMBERS_MODULE = "routers.groups.members"
RELATIONSHIPS_MODULE = "routers.groups.relationships"


# =============================================================================
# Index Redirect Tests
# =============================================================================


def test_groups_index_redirects_to_list(test_admin_user, override_auth):
    """Test groups index redirects to list page."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.get("/admin/groups/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/groups/list"


def test_groups_index_fallback_when_no_children(test_admin_user, override_auth, mocker):
    """Test groups index falls back to /admin when no accessible children."""
    override_auth(test_admin_user, level="admin")

    mock_first = mocker.patch(f"{LISTING_MODULE}.get_first_accessible_child")
    mock_first.return_value = None

    client = TestClient(app)
    response = client.get("/admin/groups/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/admin"


# =============================================================================
# Groups List Tests
# =============================================================================


def test_groups_list_renders(test_admin_user, override_auth, mocker):
    """Test groups list page renders successfully."""
    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch(f"{LISTING_MODULE}.groups_service.list_groups")
    mock_ctx = mocker.patch(f"{LISTING_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{LISTING_MODULE}.templates.TemplateResponse")

    mock_list.return_value = _make_group_list_response()
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>groups</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list")

    assert response.status_code == 200
    mock_list.assert_called_once()
    mock_tmpl.assert_called_once()
    template_name = mock_tmpl.call_args[0][0]
    assert template_name == "groups_list.html"


def test_groups_list_with_search(test_admin_user, override_auth, mocker):
    """Test groups list page with search parameter."""
    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch(f"{LISTING_MODULE}.groups_service.list_groups")
    mock_ctx = mocker.patch(f"{LISTING_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{LISTING_MODULE}.templates.TemplateResponse")

    mock_list.return_value = _make_group_list_response()
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>groups</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list?search=engineering")

    assert response.status_code == 200
    call_kwargs = mock_list.call_args[1]
    assert call_kwargs["search"] == "engineering"


def test_groups_list_with_pagination(test_admin_user, override_auth, mocker):
    """Test groups list page with pagination parameters."""
    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch(f"{LISTING_MODULE}.groups_service.list_groups")
    mock_ctx = mocker.patch(f"{LISTING_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{LISTING_MODULE}.templates.TemplateResponse")

    mock_list.return_value = _make_group_list_response()
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>groups</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list?page=2&size=50")

    assert response.status_code == 200
    call_kwargs = mock_list.call_args[1]
    assert call_kwargs["page"] == 2
    assert call_kwargs["page_size"] == 50


def test_groups_list_with_groups(test_admin_user, override_auth, mocker):
    """Test groups list page renders with group data."""
    override_auth(test_admin_user, level="admin")

    mock_groups = [
        _make_group_summary(name="Engineering"),
        _make_group_summary(name="Sales"),
    ]

    mock_list = mocker.patch(f"{LISTING_MODULE}.groups_service.list_groups")
    mock_ctx = mocker.patch(f"{LISTING_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{LISTING_MODULE}.templates.TemplateResponse")

    mock_list.return_value = _make_group_list_response(items=mock_groups, total=2)
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>groups</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list")

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["groups"] == mock_groups


def test_groups_list_shows_success_message(test_admin_user, override_auth, mocker):
    """Test groups list page shows success query param."""
    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch(f"{LISTING_MODULE}.groups_service.list_groups")
    mock_ctx = mocker.patch(f"{LISTING_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{LISTING_MODULE}.templates.TemplateResponse")

    mock_list.return_value = _make_group_list_response()
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>groups</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list?success=deleted")

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["success"] == "deleted"


def test_groups_list_service_error(test_admin_user, override_auth, mocker):
    """Test groups list handles service errors gracefully."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mock_list = mocker.patch(f"{LISTING_MODULE}.groups_service.list_groups")
    mock_error = mocker.patch(f"{LISTING_MODULE}.render_error_page")

    mock_list.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/list")

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_groups_list_non_admin_redirects(test_user, override_auth):
    """Test non-admin user gets redirected from groups list.

    Note: We use level="user" so require_admin is NOT overridden,
    letting the router-level check block the request.
    The require_admin dependency redirects unauthenticated/unauthorized users to /login.
    """
    override_auth(test_user)

    client = TestClient(app)
    response = client.get("/admin/groups/list", follow_redirects=False)

    assert response.status_code == 303
    # require_admin redirects to /login when user is not admin
    assert response.headers["location"] == "/login"


# =============================================================================
# New Group Form Tests
# =============================================================================


def test_new_group_form_renders(test_admin_user, override_auth, mocker):
    """Test new group form renders successfully."""
    override_auth(test_admin_user, level="admin")

    mock_ctx = mocker.patch(f"{CREATION_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{CREATION_MODULE}.templates.TemplateResponse")

    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>new group</html>")

    client = TestClient(app)
    response = client.get("/admin/groups/new")

    assert response.status_code == 200
    mock_tmpl.assert_called_once()
    template_name = mock_tmpl.call_args[0][0]
    assert template_name == "groups_new.html"


def test_new_group_form_preserves_values_on_error(test_admin_user, override_auth, mocker):
    """Test new group form preserves values when redirected with error."""
    override_auth(test_admin_user, level="admin")

    mock_ctx = mocker.patch(f"{CREATION_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{CREATION_MODULE}.templates.TemplateResponse")

    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>new group</html>")

    client = TestClient(app)
    response = client.get(
        "/admin/groups/new?error=duplicate_name&name=Engineering&description=Team"
    )

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["error"] == "duplicate_name"
    assert ctx_kwargs["name"] == "Engineering"
    assert ctx_kwargs["description"] == "Team"


# =============================================================================
# Create Group Tests
# =============================================================================


def test_create_group_success(test_admin_user, override_auth, mocker):
    """Test creating a group succeeds."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_create = mocker.patch(f"{CREATION_MODULE}.groups_service.create_group")
    mock_create.return_value = mock_group

    client = TestClient(app)
    response = client.post(
        "/admin/groups/new",
        data={"name": "Engineering", "description": "Engineering team"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}" in response.headers["location"]
    assert "success=created" in response.headers["location"]
    mock_create.assert_called_once()


def test_create_group_without_description(test_admin_user, override_auth, mocker):
    """Test creating a group without description."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Sales")

    mock_create = mocker.patch(f"{CREATION_MODULE}.groups_service.create_group")
    mock_create.return_value = mock_group

    client = TestClient(app)
    response = client.post(
        "/admin/groups/new",
        data={"name": "Sales", "description": ""},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=created" in response.headers["location"]


def test_create_group_validation_error(test_admin_user, override_auth, mocker):
    """Test creating a group with validation error redirects back to form."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user, level="admin")

    mock_create = mocker.patch(f"{CREATION_MODULE}.groups_service.create_group")
    mock_create.side_effect = ValidationError("Name too short", code="name_too_short")

    client = TestClient(app)
    response = client.post(
        "/admin/groups/new",
        data={"name": "E", "description": ""},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=name_too_short" in response.headers["location"]
    assert "name=E" in response.headers["location"]


def test_create_group_conflict_error(test_admin_user, override_auth, mocker):
    """Test creating a group with duplicate name redirects with error."""
    from services.exceptions import ConflictError

    override_auth(test_admin_user, level="admin")

    mock_create = mocker.patch(f"{CREATION_MODULE}.groups_service.create_group")
    mock_create.side_effect = ConflictError("Group already exists", code="duplicate_name")

    client = TestClient(app)
    response = client.post(
        "/admin/groups/new",
        data={"name": "Engineering", "description": ""},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=duplicate_name" in response.headers["location"]


def test_create_group_service_error(test_admin_user, override_auth, mocker):
    """Test creating a group with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mock_create = mocker.patch(f"{CREATION_MODULE}.groups_service.create_group")
    mock_error = mocker.patch(f"{CREATION_MODULE}.render_error_page")

    mock_create.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        "/admin/groups/new",
        data={"name": "Engineering", "description": ""},
        follow_redirects=False,
    )

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
        "get_group": mocker.patch(f"{DETAIL_MODULE}.groups_service.get_group"),
        "list_parents": mocker.patch(f"{DETAIL_MODULE}.groups_service.list_parents"),
        "list_children": mocker.patch(f"{DETAIL_MODULE}.groups_service.list_children"),
        "list_available_parents": mocker.patch(
            f"{DETAIL_MODULE}.groups_service.list_available_parents"
        ),
        "list_available_children": mocker.patch(
            f"{DETAIL_MODULE}.groups_service.list_available_children"
        ),
        "get_effective_members": mocker.patch(
            f"{DETAIL_MODULE}.groups_service.get_effective_members"
        ),
        "sp_service": mocker.patch(f"{DETAIL_MODULE}.sp_service"),
        "get_context": mocker.patch(f"{DETAIL_MODULE}.get_template_context"),
        "template": mocker.patch(f"{DETAIL_MODULE}.templates.TemplateResponse"),
    }
    return mocks


def test_group_detail_redirects_to_details_tab(test_admin_user, override_auth):
    """Test GET /admin/groups/{id} redirects to the details tab."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == f"/admin/groups/{group_id}/details"


def test_group_tab_details_renders(test_admin_user, override_auth, mock_group_detail_deps):
    """Test group details tab renders successfully."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_group_detail_deps["get_group"].return_value = mock_group
    mock_group_detail_deps["list_parents"].return_value = _make_relationship_list(
        list_type="parents"
    )
    mock_group_detail_deps["list_children"].return_value = _make_relationship_list(
        list_type="children"
    )
    mock_group_detail_deps["list_available_parents"].return_value = []
    mock_group_detail_deps["list_available_children"].return_value = []
    mock_group_detail_deps["get_context"].return_value = {"request": MagicMock()}
    mock_group_detail_deps["template"].return_value = HTMLResponse(content="<html>detail</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/details")

    assert response.status_code == 200
    mock_group_detail_deps["template"].assert_called_once()
    template_name = mock_group_detail_deps["template"].call_args[0][0]
    assert template_name == "groups_detail_tab_details.html"


def test_group_tab_membership_renders(test_admin_user, override_auth, mock_group_detail_deps):
    """Test group membership tab renders successfully."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_group_detail_deps["get_group"].return_value = mock_group
    mock_group_detail_deps["list_parents"].return_value = _make_relationship_list(
        list_type="parents"
    )
    mock_group_detail_deps["list_children"].return_value = _make_relationship_list(
        list_type="children"
    )
    mock_group_detail_deps["list_available_parents"].return_value = []
    mock_group_detail_deps["list_available_children"].return_value = []
    mock_group_detail_deps["get_context"].return_value = {"request": MagicMock()}
    mock_group_detail_deps["template"].return_value = HTMLResponse(
        content="<html>membership</html>"
    )

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/membership")

    assert response.status_code == 200
    template_name = mock_group_detail_deps["template"].call_args[0][0]
    assert template_name == "groups_detail_tab_membership.html"


def test_group_tab_applications_renders(test_admin_user, override_auth, mock_group_detail_deps):
    """Test group applications tab renders successfully."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_group_detail_deps["get_group"].return_value = mock_group
    mock_group_detail_deps["list_parents"].return_value = _make_relationship_list(
        list_type="parents"
    )
    mock_group_detail_deps["list_children"].return_value = _make_relationship_list(
        list_type="children"
    )
    mock_group_detail_deps["list_available_parents"].return_value = []
    mock_group_detail_deps["list_available_children"].return_value = []
    mock_group_detail_deps["get_context"].return_value = {"request": MagicMock()}
    mock_group_detail_deps["template"].return_value = HTMLResponse(
        content="<html>applications</html>"
    )

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/applications")

    assert response.status_code == 200
    template_name = mock_group_detail_deps["template"].call_args[0][0]
    assert template_name == "groups_detail_tab_applications.html"


def test_group_tab_relationships_renders(test_admin_user, override_auth, mock_group_detail_deps):
    """Test group relationships tab renders successfully."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_group_detail_deps["get_group"].return_value = mock_group
    mock_group_detail_deps["list_parents"].return_value = _make_relationship_list(
        list_type="parents"
    )
    mock_group_detail_deps["list_children"].return_value = _make_relationship_list(
        list_type="children"
    )
    mock_group_detail_deps["list_available_parents"].return_value = []
    mock_group_detail_deps["list_available_children"].return_value = []
    mock_group_detail_deps["get_context"].return_value = {"request": MagicMock()}
    mock_group_detail_deps["template"].return_value = HTMLResponse(
        content="<html>relationships</html>"
    )

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/relationships")

    assert response.status_code == 200
    template_name = mock_group_detail_deps["template"].call_args[0][0]
    assert template_name == "groups_detail_tab_relationships.html"


def test_group_tab_danger_renders(test_admin_user, override_auth, mock_group_detail_deps):
    """Test group danger tab renders successfully."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_group_detail_deps["get_group"].return_value = mock_group
    mock_group_detail_deps["list_parents"].return_value = _make_relationship_list(
        list_type="parents"
    )
    mock_group_detail_deps["list_children"].return_value = _make_relationship_list(
        list_type="children"
    )
    mock_group_detail_deps["list_available_parents"].return_value = []
    mock_group_detail_deps["list_available_children"].return_value = []
    mock_group_detail_deps["get_context"].return_value = {"request": MagicMock()}
    mock_group_detail_deps["template"].return_value = HTMLResponse(content="<html>danger</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/danger")

    assert response.status_code == 200
    template_name = mock_group_detail_deps["template"].call_args[0][0]
    assert template_name == "groups_detail_tab_danger.html"


def test_group_tab_details_not_found(test_admin_user, override_auth, mocker):
    """Test group details tab handles not found error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_get = mocker.patch(f"{DETAIL_MODULE}.groups_service.get_group")
    mock_error = mocker.patch(f"{DETAIL_MODULE}.render_error_page")

    mock_get.side_effect = NotFoundError("Group not found")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/details")

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_group_tab_details_service_error(test_admin_user, override_auth, mocker):
    """Test group details tab handles generic service errors."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_get = mocker.patch(f"{DETAIL_MODULE}.groups_service.get_group")
    mock_parents = mocker.patch(f"{DETAIL_MODULE}.groups_service.list_parents")
    mock_error = mocker.patch(f"{DETAIL_MODULE}.render_error_page")

    # get_group succeeds, but list_parents raises ServiceError
    mock_get.return_value = mock_group
    mock_parents.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/details")

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_group_tab_details_shows_success_message(
    test_admin_user, override_auth, mock_group_detail_deps
):
    """Test group details tab shows success query param."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_group_detail_deps["get_group"].return_value = mock_group
    mock_group_detail_deps["list_parents"].return_value = _make_relationship_list(
        list_type="parents"
    )
    mock_group_detail_deps["list_children"].return_value = _make_relationship_list(
        list_type="children"
    )
    mock_group_detail_deps["list_available_parents"].return_value = []
    mock_group_detail_deps["list_available_children"].return_value = []
    mock_group_detail_deps["get_context"].return_value = {"request": MagicMock()}
    mock_group_detail_deps["template"].return_value = HTMLResponse(content="<html>detail</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/details?success=updated")

    assert response.status_code == 200
    ctx_kwargs = mock_group_detail_deps["get_context"].call_args[1]
    assert ctx_kwargs["success"] == "updated"


# =============================================================================
# Update Group Tests
# =============================================================================


def test_update_group_success(test_admin_user, override_auth, mocker):
    """Test updating a group succeeds."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_update = mocker.patch(f"{DETAIL_MODULE}.groups_service.update_group")
    mock_update.return_value = _make_group_detail(group_id=group_id, name="Updated Name")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/edit",
        data={"name": "Updated Name", "description": "New description"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/admin/groups/{group_id}/details?success=updated"


def test_update_group_validation_error(test_admin_user, override_auth, mocker):
    """Test updating a group with validation error redirects with error."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_update = mocker.patch(f"{DETAIL_MODULE}.groups_service.update_group")
    # Service can reject names for other reasons (e.g., invalid characters)
    mock_update.side_effect = ValidationError("Invalid name format", code="invalid_name")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/edit",
        data={"name": "Valid Name", "description": ""},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=invalid_name" in response.headers["location"]


def test_update_group_not_found(test_admin_user, override_auth, mocker):
    """Test updating a non-existent group redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_update = mocker.patch(f"{DETAIL_MODULE}.groups_service.update_group")
    mock_update.side_effect = NotFoundError("Group not found", code="group_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/edit",
        data={"name": "New Name", "description": ""},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=group_not_found" in response.headers["location"]


def test_update_group_conflict_error(test_admin_user, override_auth, mocker):
    """Test updating a group to duplicate name redirects with error."""
    from services.exceptions import ConflictError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_update = mocker.patch(f"{DETAIL_MODULE}.groups_service.update_group")
    mock_update.side_effect = ConflictError("Name already exists", code="duplicate_name")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/edit",
        data={"name": "Engineering", "description": ""},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=duplicate_name" in response.headers["location"]


def test_update_group_service_error(test_admin_user, override_auth, mocker):
    """Test updating a group with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_update = mocker.patch(f"{DETAIL_MODULE}.groups_service.update_group")
    mock_error = mocker.patch(f"{DETAIL_MODULE}.render_error_page")

    mock_update.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/edit",
        data={"name": "New Name", "description": ""},
    )

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Delete Group Tests
# =============================================================================


def test_delete_group_success(test_admin_user, override_auth, mocker):
    """Test deleting a group succeeds."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_delete = mocker.patch(f"{DETAIL_MODULE}.groups_service.delete_group")
    mock_delete.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/delete",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/admin/groups/list" in response.headers["location"]
    assert "success=deleted" in response.headers["location"]


def test_delete_group_not_found(test_admin_user, override_auth, mocker):
    """Test deleting a non-existent group redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_delete = mocker.patch(f"{DETAIL_MODULE}.groups_service.delete_group")
    mock_delete.side_effect = NotFoundError("Group not found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/delete",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/admin/groups/list" in response.headers["location"]
    assert "error=group_not_found" in response.headers["location"]


def test_delete_group_validation_error_redirects_to_danger(test_admin_user, override_auth, mocker):
    """Test that delete with has_relationships error redirects to danger tab."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_delete = mocker.patch(f"{DETAIL_MODULE}.groups_service.delete_group")
    mock_delete.side_effect = ValidationError("Has relationships", code="has_relationships")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/delete",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}/danger" in response.headers["location"]
    assert "error=has_relationships" in response.headers["location"]


def test_delete_group_service_error(test_admin_user, override_auth, mocker):
    """Test deleting a group with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_delete = mocker.patch(f"{DETAIL_MODULE}.groups_service.delete_group")
    mock_error = mocker.patch(f"{DETAIL_MODULE}.render_error_page")

    mock_delete.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(f"/admin/groups/{group_id}/delete")

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_clear_relationships_success(test_admin_user, override_auth, mocker):
    """Test clearing all relationships redirects to danger tab with success."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_clear = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.remove_all_relationships")
    mock_clear.return_value = 2

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/relationships/clear",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}/danger" in response.headers["location"]
    assert "success=relationships_cleared" in response.headers["location"]


def test_clear_relationships_not_found(test_admin_user, override_auth, mocker):
    """Test clearing relationships for a missing group redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_clear = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.remove_all_relationships")
    mock_clear.side_effect = NotFoundError("Group not found", code="group_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/relationships/clear",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}/danger" in response.headers["location"]
    assert "error=group_not_found" in response.headers["location"]


# =============================================================================
# Member List Page Tests
# =============================================================================


def test_member_list_renders(test_admin_user, override_auth, mocker):
    """Test member list page renders successfully."""
    from schemas.groups import GroupMemberDetail, GroupMemberDetailList

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_result = GroupMemberDetailList(
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

    mock_get = mocker.patch(f"{MEMBERS_MODULE}.groups_service.get_group")
    mock_list = mocker.patch(f"{MEMBERS_MODULE}.groups_service.list_members_filtered")
    mock_template = mocker.patch(f"{MEMBERS_MODULE}.templates.TemplateResponse")
    mocker.patch(f"{MEMBERS_MODULE}.get_template_context", return_value={"request": MagicMock()})

    mock_get.return_value = mock_group
    mock_list.return_value = mock_result
    mock_template.return_value = HTMLResponse(content="<html>members</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members")

    assert response.status_code == 200
    mock_template.assert_called_once()
    template_name = mock_template.call_args[0][0]
    assert template_name == "groups_members.html"


def test_member_list_with_search(test_admin_user, override_auth, mocker):
    """Test member list page with search query."""
    from schemas.groups import GroupMemberDetailList

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")
    mock_result = GroupMemberDetailList(items=[], total=0, page=1, limit=25)

    mock_get = mocker.patch(f"{MEMBERS_MODULE}.groups_service.get_group")
    mock_list = mocker.patch(f"{MEMBERS_MODULE}.groups_service.list_members_filtered")
    mock_template = mocker.patch(f"{MEMBERS_MODULE}.templates.TemplateResponse")
    mocker.patch(f"{MEMBERS_MODULE}.get_template_context", return_value={"request": MagicMock()})

    mock_get.return_value = mock_group
    mock_list.return_value = mock_result
    mock_template.return_value = HTMLResponse(content="<html>members</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members?search=test&sort=name&order=asc")

    assert response.status_code == 200
    mock_list.assert_called_once()
    call_kwargs = mock_list.call_args
    assert call_kwargs[1]["search"] == "test"
    assert call_kwargs[1]["sort_field"] == "name"
    assert call_kwargs[1]["sort_order"] == "asc"


def test_member_list_not_found(test_admin_user, override_auth, mocker):
    """Test member list page handles group not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_get = mocker.patch(f"{MEMBERS_MODULE}.groups_service.get_group")
    mock_error = mocker.patch(f"{MEMBERS_MODULE}.render_error_page")

    mock_get.side_effect = NotFoundError("Group not found")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members")

    assert response.status_code == 200
    mock_error.assert_called_once()


def test_member_list_service_error(test_admin_user, override_auth, mocker):
    """Test member list page handles service error."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_get = mocker.patch(f"{MEMBERS_MODULE}.groups_service.get_group")
    mock_list = mocker.patch(f"{MEMBERS_MODULE}.groups_service.list_members_filtered")
    mock_error = mocker.patch(f"{MEMBERS_MODULE}.render_error_page")

    mock_get.return_value = mock_group
    mock_list.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members")

    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Add Members Page Tests
# =============================================================================


def test_add_members_page_renders(test_admin_user, override_auth, mocker):
    """Test add members page renders successfully."""
    from schemas.groups import AvailableUserList, AvailableUserOption

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Engineering")

    mock_result = AvailableUserList(
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

    mock_get = mocker.patch(f"{MEMBERS_MODULE}.groups_service.get_group")
    mock_list = mocker.patch(f"{MEMBERS_MODULE}.groups_service.list_available_users_paginated")
    mock_template = mocker.patch(f"{MEMBERS_MODULE}.templates.TemplateResponse")
    mocker.patch(f"{MEMBERS_MODULE}.get_template_context", return_value={"request": MagicMock()})

    mock_get.return_value = mock_group
    mock_list.return_value = mock_result
    mock_template.return_value = HTMLResponse(content="<html>add members</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members/add")

    assert response.status_code == 200
    mock_template.assert_called_once()
    template_name = mock_template.call_args[0][0]
    assert template_name == "groups_members_add.html"


def test_add_members_page_not_found(test_admin_user, override_auth, mocker):
    """Test add members page handles group not found."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_get = mocker.patch(f"{MEMBERS_MODULE}.groups_service.get_group")
    mock_error = mocker.patch(f"{MEMBERS_MODULE}.render_error_page")

    mock_get.side_effect = NotFoundError("Group not found")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members/add")

    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Member Management Tests
# =============================================================================


def test_add_members_submit_success(test_admin_user, override_auth, mocker):
    """Test adding members to a group succeeds and redirects back to add page."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    user_ids = [str(uuid4()), str(uuid4())]

    mock_bulk = mocker.patch(f"{MEMBERS_MODULE}.groups_service.bulk_add_members")
    mock_bulk.return_value = 2

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={"user_ids": user_ids},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers["location"]
    assert f"/admin/groups/{group_id}/members/add" in location
    assert "success=members_added" in location
    assert "count=2" in location
    mock_bulk.assert_called_once()


def test_add_members_submit_not_found(test_admin_user, override_auth, mocker):
    """Test adding members to non-existent group redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_bulk = mocker.patch(f"{MEMBERS_MODULE}.groups_service.bulk_add_members")
    mock_bulk.side_effect = NotFoundError("Group not found", code="group_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={"user_ids": [str(uuid4())]},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=group_not_found" in response.headers["location"]


def test_add_members_submit_forbidden(test_admin_user, override_auth, mocker):
    """Test adding members to IdP group redirects with error."""
    from services.exceptions import ForbiddenError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_bulk = mocker.patch(f"{MEMBERS_MODULE}.groups_service.bulk_add_members")
    mock_bulk.side_effect = ForbiddenError("IdP group", code="idp_group_read_only")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={"user_ids": [str(uuid4())]},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=idp_group_read_only" in response.headers["location"]


def test_add_members_submit_service_error(test_admin_user, override_auth, mocker):
    """Test adding members with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_bulk = mocker.patch(f"{MEMBERS_MODULE}.groups_service.bulk_add_members")
    mock_error = mocker.patch(f"{MEMBERS_MODULE}.render_error_page")

    mock_bulk.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={"user_ids": [str(uuid4())]},
    )

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_remove_member_success(test_admin_user, override_auth, mocker):
    """Test removing a member from a group succeeds."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_remove = mocker.patch(f"{MEMBERS_MODULE}.groups_service.remove_member")
    mock_remove.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/{user_id}/remove",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}" in response.headers["location"]
    assert "success=member_removed" in response.headers["location"]


def test_remove_member_not_found(test_admin_user, override_auth, mocker):
    """Test removing a non-member redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_remove = mocker.patch(f"{MEMBERS_MODULE}.groups_service.remove_member")
    mock_remove.side_effect = NotFoundError("Not a member", code="not_a_member")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/{user_id}/remove",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=not_a_member" in response.headers["location"]


def test_remove_member_service_error(test_admin_user, override_auth, mocker):
    """Test removing a member with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    user_id = str(uuid4())

    mock_remove = mocker.patch(f"{MEMBERS_MODULE}.groups_service.remove_member")
    mock_error = mocker.patch(f"{MEMBERS_MODULE}.render_error_page")

    mock_remove.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(f"/admin/groups/{group_id}/members/{user_id}/remove")

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Child Relationship Management Tests
# =============================================================================


def test_add_child_success(test_admin_user, override_auth, mocker):
    """Test adding a child group succeeds."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_add = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.add_child")
    mock_add.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/add",
        data={"child_group_id": child_group_id},
        follow_redirects=False,
    )

    assert response.status_code == 303
    expected = f"/admin/groups/{group_id}/relationships?success=child_added"
    assert response.headers["location"] == expected
    mock_add.assert_called_once()


def test_add_child_not_found(test_admin_user, override_auth, mocker):
    """Test adding a non-existent child redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_add = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = NotFoundError("Child group not found", code="child_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/add",
        data={"child_group_id": child_group_id},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=child_not_found" in response.headers["location"]


def test_add_child_would_create_cycle(test_admin_user, override_auth, mocker):
    """Test adding a child that would create a cycle redirects with error."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_add = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = ValidationError("Would create cycle", code="would_create_cycle")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/add",
        data={"child_group_id": child_group_id},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=would_create_cycle" in response.headers["location"]


def test_add_child_already_exists(test_admin_user, override_auth, mocker):
    """Test adding an existing child redirects with error."""
    from services.exceptions import ConflictError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_add = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = ConflictError("Already a child", code="relationship_exists")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/add",
        data={"child_group_id": child_group_id},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=relationship_exists" in response.headers["location"]


def test_add_child_service_error(test_admin_user, override_auth, mocker):
    """Test adding a child with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_add = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.add_child")
    mock_error = mocker.patch(f"{RELATIONSHIPS_MODULE}.render_error_page")

    mock_add.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/add",
        data={"child_group_id": child_group_id},
    )

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_remove_child_success(test_admin_user, override_auth, mocker):
    """Test removing a child group succeeds."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.remove_child")
    mock_remove.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/{child_group_id}/remove",
        follow_redirects=False,
    )

    assert response.status_code == 303
    expected = f"/admin/groups/{group_id}/relationships?success=child_removed"
    assert response.headers["location"] == expected


def test_remove_child_not_found(test_admin_user, override_auth, mocker):
    """Test removing a non-existent child redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.remove_child")
    mock_remove.side_effect = NotFoundError("Relationship not found", code="relationship_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/children/{child_group_id}/remove",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=relationship_not_found" in response.headers["location"]


def test_remove_child_service_error(test_admin_user, override_auth, mocker):
    """Test removing a child with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    child_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.remove_child")
    mock_error = mocker.patch(f"{RELATIONSHIPS_MODULE}.render_error_page")

    mock_remove.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(f"/admin/groups/{group_id}/children/{child_group_id}/remove")

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Parent Relationship Management Tests
# =============================================================================


def test_add_parent_success(test_admin_user, override_auth, mocker):
    """Test adding a parent group succeeds."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_add = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.add_child")
    mock_add.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/add",
        data={"parent_group_id": parent_group_id},
        follow_redirects=False,
    )

    assert response.status_code == 303
    expected = f"/admin/groups/{group_id}/relationships?success=parent_added"
    assert response.headers["location"] == expected
    # Should call add_child with parent as parent and group as child
    mock_add.assert_called_once()


def test_add_parent_not_found(test_admin_user, override_auth, mocker):
    """Test adding a non-existent parent redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_add = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = NotFoundError("Parent group not found", code="parent_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/add",
        data={"parent_group_id": parent_group_id},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=parent_not_found" in response.headers["location"]


def test_add_parent_would_create_cycle(test_admin_user, override_auth, mocker):
    """Test adding a parent that would create a cycle redirects with error."""
    from services.exceptions import ValidationError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_add = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = ValidationError("Would create cycle", code="would_create_cycle")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/add",
        data={"parent_group_id": parent_group_id},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=would_create_cycle" in response.headers["location"]


def test_add_parent_already_exists(test_admin_user, override_auth, mocker):
    """Test adding an existing parent redirects with error."""
    from services.exceptions import ConflictError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_add = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.add_child")
    mock_add.side_effect = ConflictError("Already a parent", code="relationship_exists")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/add",
        data={"parent_group_id": parent_group_id},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=relationship_exists" in response.headers["location"]


def test_add_parent_service_error(test_admin_user, override_auth, mocker):
    """Test adding a parent with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_add = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.add_child")
    mock_error = mocker.patch(f"{RELATIONSHIPS_MODULE}.render_error_page")

    mock_add.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/add",
        data={"parent_group_id": parent_group_id},
    )

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


def test_remove_parent_success(test_admin_user, override_auth, mocker):
    """Test removing a parent group succeeds."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.remove_child")
    mock_remove.return_value = None

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/{parent_group_id}/remove",
        follow_redirects=False,
    )

    assert response.status_code == 303
    expected = f"/admin/groups/{group_id}/relationships?success=parent_removed"
    assert response.headers["location"] == expected


def test_remove_parent_not_found(test_admin_user, override_auth, mocker):
    """Test removing a non-existent parent redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.remove_child")
    mock_remove.side_effect = NotFoundError("Relationship not found", code="relationship_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/parents/{parent_group_id}/remove",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=relationship_not_found" in response.headers["location"]


def test_remove_parent_service_error(test_admin_user, override_auth, mocker):
    """Test removing a parent with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    parent_group_id = str(uuid4())

    mock_remove = mocker.patch(f"{RELATIONSHIPS_MODULE}.groups_service.remove_child")
    mock_error = mocker.patch(f"{RELATIONSHIPS_MODULE}.render_error_page")

    mock_remove.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(f"/admin/groups/{group_id}/parents/{parent_group_id}/remove")

    # Should render error page
    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# Effective Members Display Tests
# =============================================================================


def test_group_detail_with_effective_members(
    test_admin_user, override_auth, mock_group_detail_deps
):
    """Test group details tab shows effective member count when group has children."""
    from schemas.groups import EffectiveMemberList

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Parent Group")
    # Set child_count > 0 so effective member count is fetched
    mock_group.child_count = 2

    mock_effective = EffectiveMemberList(
        items=[],
        total=5,
        page=1,
        limit=1,
    )

    mock_group_detail_deps["get_group"].return_value = mock_group
    mock_group_detail_deps["list_parents"].return_value = _make_relationship_list(
        list_type="parents"
    )
    mock_group_detail_deps["list_children"].return_value = _make_relationship_list(
        list_type="children"
    )
    mock_group_detail_deps["list_available_parents"].return_value = []
    mock_group_detail_deps["list_available_children"].return_value = []
    mock_group_detail_deps["get_context"].return_value = {"request": MagicMock()}
    mock_group_detail_deps["template"].return_value = HTMLResponse(content="<html>detail</html>")

    mock_group_detail_deps["get_effective_members"].return_value = mock_effective

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/details")

    assert response.status_code == 200
    mock_group_detail_deps["get_effective_members"].assert_called_once()
    ctx_kwargs = mock_group_detail_deps["get_context"].call_args[1]
    assert ctx_kwargs["effective_member_count"] == 5


def test_group_detail_no_effective_members_without_children(
    test_admin_user, override_auth, mock_group_detail_deps
):
    """Test group details tab does not fetch effective members when no children."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    mock_group = _make_group_detail(group_id=group_id, name="Leaf Group")
    # child_count = 0, so effective members should not be fetched

    mock_group_detail_deps["get_group"].return_value = mock_group
    mock_group_detail_deps["list_parents"].return_value = _make_relationship_list(
        list_type="parents"
    )
    mock_group_detail_deps["list_children"].return_value = _make_relationship_list(
        list_type="children"
    )
    mock_group_detail_deps["list_available_parents"].return_value = []
    mock_group_detail_deps["list_available_children"].return_value = []
    mock_group_detail_deps["get_context"].return_value = {"request": MagicMock()}
    mock_group_detail_deps["template"].return_value = HTMLResponse(content="<html>detail</html>")

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/details")

    assert response.status_code == 200
    ctx_kwargs = mock_group_detail_deps["get_context"].call_args[1]
    assert ctx_kwargs["effective_member_count"] is None


# =============================================================================
# Bulk Remove Members Route Tests
# =============================================================================


def test_bulk_remove_members_success(test_admin_user, override_auth, mocker):
    """Test bulk removing members succeeds."""
    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())
    user_ids = [str(uuid4()), str(uuid4())]

    mock_bulk = mocker.patch(f"{MEMBERS_MODULE}.groups_service.bulk_remove_members")
    mock_bulk.return_value = 2

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/bulk-remove",
        data={"user_ids": user_ids},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/admin/groups/{group_id}/members" in response.headers["location"]
    assert "success=members_removed" in response.headers["location"]
    mock_bulk.assert_called_once()


def test_bulk_remove_members_not_found(test_admin_user, override_auth, mocker):
    """Test bulk removing members from non-existent group redirects with error."""
    from services.exceptions import NotFoundError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_bulk = mocker.patch(f"{MEMBERS_MODULE}.groups_service.bulk_remove_members")
    mock_bulk.side_effect = NotFoundError("Group not found", code="group_not_found")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/bulk-remove",
        data={"user_ids": [str(uuid4())]},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=group_not_found" in response.headers["location"]


def test_bulk_remove_members_idp_forbidden(test_admin_user, override_auth, mocker):
    """Test bulk removing from IdP group redirects with error."""
    from services.exceptions import ForbiddenError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_bulk = mocker.patch(f"{MEMBERS_MODULE}.groups_service.bulk_remove_members")
    mock_bulk.side_effect = ForbiddenError("IdP group", code="idp_group_read_only")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/bulk-remove",
        data={"user_ids": [str(uuid4())]},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=idp_group_read_only" in response.headers["location"]


def test_bulk_remove_members_service_error(test_admin_user, override_auth, mocker):
    """Test bulk removing members with service error renders error page."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    group_id = str(uuid4())

    mock_bulk = mocker.patch(f"{MEMBERS_MODULE}.groups_service.bulk_remove_members")
    mock_error = mocker.patch(f"{MEMBERS_MODULE}.render_error_page")

    mock_bulk.side_effect = ServiceError("Database error")
    mock_error.return_value = HTMLResponse(content="<html>error</html>")

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/bulk-remove",
        data={"user_ids": [str(uuid4())]},
    )

    assert response.status_code == 200
    mock_error.assert_called_once()


# =============================================================================
# _parse_member_query_params Unit Tests
# =============================================================================


class TestParseMemberQueryParams:
    """Direct unit tests for _parse_member_query_params helper."""

    @staticmethod
    def _make_request(params: dict | None = None):
        """Create a mock Request with given query params."""
        from starlette.datastructures import QueryParams

        request = MagicMock()
        request.query_params = QueryParams(params or {})
        return request

    def test_defaults(self):
        """No params returns correct defaults."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request())

        assert result["page"] == 1
        assert result["page_size"] == 25
        assert result["sort_field"] == "name"
        assert result["sort_order"] == "asc"
        assert result["roles"] is None
        assert result["statuses"] is None
        assert result["search"] == ""

    @pytest.mark.parametrize("bad_page", ["abc", "0", "-5", "1.5", ""])
    def test_invalid_page(self, bad_page):
        """Invalid page values fall back to 1."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"page": bad_page}))
        assert result["page"] == 1

    @pytest.mark.parametrize("bad_size", ["15", "abc", "0", "-1", "200", ""])
    def test_invalid_page_size(self, bad_size):
        """Invalid page_size values fall back to 25."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"size": bad_size}))
        assert result["page_size"] == 25

    @pytest.mark.parametrize("valid_size", [10, 25, 50, 100])
    def test_valid_page_size(self, valid_size):
        """Allowed page_size values are accepted."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"size": str(valid_size)}))
        assert result["page_size"] == valid_size

    def test_invalid_sort_field(self):
        """Invalid sort field falls back to 'name'."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"sort": "invalid_field"}))
        assert result["sort_field"] == "name"

    def test_invalid_sort_order(self):
        """Invalid sort order falls back to 'asc'."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"order": "random"}))
        assert result["sort_order"] == "asc"

    def test_valid_sort_fields(self):
        """All allowed sort fields are accepted."""
        from routers.groups.members import _parse_member_query_params

        for field in ["name", "email", "role", "status", "created_at", "last_activity_at"]:
            result = _parse_member_query_params(self._make_request({"sort": field}))
            assert result["sort_field"] == field

    def test_role_filter_valid(self):
        """Comma-separated valid roles are parsed into a list."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"role": "member,admin"}))
        assert sorted(result["roles"]) == ["admin", "member"]

    def test_role_filter_all_invalid(self):
        """All-invalid roles result in None."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"role": "invalid,bogus"}))
        assert result["roles"] is None

    def test_role_filter_mixed_valid_invalid(self):
        """Mixed valid/invalid roles keep only valid ones."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"role": "member,bogus,admin"}))
        assert sorted(result["roles"]) == ["admin", "member"]

    def test_status_filter_valid(self):
        """Comma-separated valid statuses are parsed into a list."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"status": "active,inactivated"}))
        assert sorted(result["statuses"]) == ["active", "inactivated"]

    def test_status_filter_all_invalid(self):
        """All-invalid statuses result in None."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"status": "bogus"}))
        assert result["statuses"] is None

    def test_status_filter_includes_anonymized(self):
        """'anonymized' is a valid status value."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"status": "anonymized"}))
        assert result["statuses"] == ["anonymized"]

    def test_search_trimmed(self):
        """Search value is whitespace-trimmed."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"search": "  test  "}))
        assert result["search"] == "test"

    def test_valid_page_preserved(self):
        """Valid page number is preserved."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"page": "3"}))
        assert result["page"] == 3

    def test_desc_sort_order(self):
        """'desc' sort order is accepted."""
        from routers.groups.members import _parse_member_query_params

        result = _parse_member_query_params(self._make_request({"order": "desc"}))
        assert result["sort_order"] == "desc"


# =============================================================================
# Pagination Metadata Tests
# =============================================================================


def _setup_member_list_mocks(mocker, group_id, total, page=1, page_size=25):
    """Helper to set up mocks for member list pagination tests."""
    from schemas.groups import GroupMemberDetailList

    mock_group = _make_group_detail(group_id=group_id, name="Engineering")
    mock_result = GroupMemberDetailList(items=[], total=total, page=page, limit=page_size)

    mock_get = mocker.patch(f"{MEMBERS_MODULE}.groups_service.get_group")
    mock_list = mocker.patch(f"{MEMBERS_MODULE}.groups_service.list_members_filtered")
    mock_template = mocker.patch(f"{MEMBERS_MODULE}.templates.TemplateResponse")
    mock_ctx = mocker.patch(
        f"{MEMBERS_MODULE}.get_template_context", return_value={"request": MagicMock()}
    )

    mock_get.return_value = mock_group
    mock_list.return_value = mock_result
    mock_template.return_value = HTMLResponse(content="<html>members</html>")

    return mock_ctx


def test_member_list_pagination_metadata_middle_page(test_admin_user, override_auth, mocker):
    """Test pagination metadata for a middle page (has_previous=True, has_next=True)."""
    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_ctx = _setup_member_list_mocks(mocker, group_id, total=53)

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members?page=2&size=25")

    assert response.status_code == 200
    pagination = mock_ctx.call_args[1]["pagination"]
    assert pagination["page"] == 2
    assert pagination["has_previous"] is True
    assert pagination["has_next"] is True
    assert pagination["start_index"] == 26
    assert pagination["end_index"] == 50
    assert pagination["total_count"] == 53
    assert pagination["total_pages"] == 3


def test_member_list_pagination_empty_results(test_admin_user, override_auth, mocker):
    """Test pagination metadata with zero results."""
    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_ctx = _setup_member_list_mocks(mocker, group_id, total=0)

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members")

    assert response.status_code == 200
    pagination = mock_ctx.call_args[1]["pagination"]
    assert pagination["start_index"] == 0
    assert pagination["end_index"] == 0
    assert pagination["has_previous"] is False
    assert pagination["has_next"] is False
    assert pagination["total_pages"] == 1


def test_member_list_pagination_last_page(test_admin_user, override_auth, mocker):
    """Test pagination metadata for the last page (has_next=False, partial page)."""
    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_ctx = _setup_member_list_mocks(mocker, group_id, total=53)

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members?page=3&size=25")

    assert response.status_code == 200
    pagination = mock_ctx.call_args[1]["pagination"]
    assert pagination["page"] == 3
    assert pagination["has_next"] is False
    assert pagination["has_previous"] is True
    assert pagination["end_index"] == 53
    assert pagination["start_index"] == 51


def test_member_list_page_clamped_to_total(test_admin_user, override_auth, mocker):
    """Test that page is clamped when requested page exceeds total pages."""
    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_ctx = _setup_member_list_mocks(mocker, group_id, total=10)

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members?page=99&size=25")

    assert response.status_code == 200
    pagination = mock_ctx.call_args[1]["pagination"]
    # total=10, page_size=25 => total_pages=1, page clamped to 1
    assert pagination["page"] == 1
    assert pagination["has_previous"] is False
    assert pagination["has_next"] is False


# =============================================================================
# Filter/Sort Param Pass-Through Tests
# =============================================================================


def test_member_list_passes_filters_to_service(test_admin_user, override_auth, mocker):
    """Test that role and status filters are correctly parsed and forwarded."""
    from schemas.groups import GroupMemberDetailList

    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_group = _make_group_detail(group_id=group_id, name="Engineering")
    mock_result = GroupMemberDetailList(items=[], total=0, page=1, limit=25)

    mock_get = mocker.patch(f"{MEMBERS_MODULE}.groups_service.get_group")
    mock_list = mocker.patch(f"{MEMBERS_MODULE}.groups_service.list_members_filtered")
    mocker.patch(f"{MEMBERS_MODULE}.templates.TemplateResponse", return_value=HTMLResponse(""))
    mocker.patch(f"{MEMBERS_MODULE}.get_template_context", return_value={"request": MagicMock()})

    mock_get.return_value = mock_group
    mock_list.return_value = mock_result

    client = TestClient(app)
    response = client.get(
        f"/admin/groups/{group_id}/members"
        "?role=member,admin&status=active&sort=email&order=desc&page=2&size=50"
    )

    assert response.status_code == 200
    call_kwargs = mock_list.call_args[1]
    assert sorted(call_kwargs["roles"]) == ["admin", "member"]
    assert call_kwargs["statuses"] == ["active"]
    assert call_kwargs["sort_field"] == "email"
    assert call_kwargs["sort_order"] == "desc"
    assert call_kwargs["page"] == 2
    assert call_kwargs["page_size"] == 50


def test_add_members_page_passes_filters_to_service(test_admin_user, override_auth, mocker):
    """Test that add members page correctly forwards filter params to service."""
    from schemas.groups import AvailableUserList

    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_group = _make_group_detail(group_id=group_id, name="Engineering")
    mock_result = AvailableUserList(items=[], total=0, page=1, limit=25)

    mock_get = mocker.patch(f"{MEMBERS_MODULE}.groups_service.get_group")
    mock_list = mocker.patch(f"{MEMBERS_MODULE}.groups_service.list_available_users_paginated")
    mocker.patch(f"{MEMBERS_MODULE}.templates.TemplateResponse", return_value=HTMLResponse(""))
    mocker.patch(f"{MEMBERS_MODULE}.get_template_context", return_value={"request": MagicMock()})

    mock_get.return_value = mock_group
    mock_list.return_value = mock_result

    client = TestClient(app)
    response = client.get(
        f"/admin/groups/{group_id}/members/add"
        "?role=super_admin&status=active,inactivated&sort=role&order=desc&size=10"
    )

    assert response.status_code == 200
    call_kwargs = mock_list.call_args[1]
    assert call_kwargs["roles"] == ["super_admin"]
    assert sorted(call_kwargs["statuses"]) == ["active", "inactivated"]
    assert call_kwargs["sort_field"] == "role"
    assert call_kwargs["sort_order"] == "desc"
    assert call_kwargs["page_size"] == 10


# =============================================================================
# add_members_submit Return State Preservation Tests
# =============================================================================


def test_add_members_submit_preserves_return_state(test_admin_user, override_auth, mocker):
    """Test that POST add members preserves return state params in redirect URL."""
    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_bulk = mocker.patch(f"{MEMBERS_MODULE}.groups_service.bulk_add_members")
    mock_bulk.return_value = 2

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={
            "user_ids": [str(uuid4())],
            "r_page": "2",
            "r_size": "50",
            "r_sort": "email",
            "r_order": "desc",
            "r_search": "test",
            "r_role": "admin",
            "r_status": "active",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers["location"]
    assert "page=2" in location
    assert "size=50" in location
    assert "sort=email" in location
    assert "order=desc" in location
    assert "search=test" in location
    assert "role=admin" in location
    assert "status=active" in location
    assert "success=members_added" in location
    assert "count=2" in location


def test_add_members_submit_omits_empty_search_and_filters(test_admin_user, override_auth, mocker):
    """Test that empty search/role/status are omitted from redirect URL."""
    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_bulk = mocker.patch(f"{MEMBERS_MODULE}.groups_service.bulk_add_members")
    mock_bulk.return_value = 1

    client = TestClient(app)
    response = client.post(
        f"/admin/groups/{group_id}/members/add",
        data={
            "user_ids": [str(uuid4())],
            "r_page": "1",
            "r_size": "25",
            "r_sort": "name",
            "r_order": "asc",
            "r_search": "",
            "r_role": "",
            "r_status": "",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers["location"]
    assert "search=" not in location
    assert "role=" not in location
    assert "status=" not in location
    assert "success=members_added" in location


# =============================================================================
# Flash Message Pass-Through Tests
# =============================================================================


def test_member_list_success_message(test_admin_user, override_auth, mocker):
    """Test that success/error query params are passed to template context."""
    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_ctx = _setup_member_list_mocks(mocker, group_id, total=5)

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members?success=members_removed&count=3")

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["success"] == "members_removed"


def test_member_list_error_message(test_admin_user, override_auth, mocker):
    """Test that error query param is passed to template context."""
    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_ctx = _setup_member_list_mocks(mocker, group_id, total=5)

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members?error=idp_group_read_only")

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["error"] == "idp_group_read_only"


def test_add_members_page_success_count(test_admin_user, override_auth, mocker):
    """Test that add members page passes success_count to template context."""
    from schemas.groups import AvailableUserList

    override_auth(test_admin_user, level="admin")
    group_id = str(uuid4())

    mock_group = _make_group_detail(group_id=group_id, name="Engineering")
    mock_result = AvailableUserList(items=[], total=0, page=1, limit=25)

    mock_get = mocker.patch(f"{MEMBERS_MODULE}.groups_service.get_group")
    mock_list = mocker.patch(f"{MEMBERS_MODULE}.groups_service.list_available_users_paginated")
    mocker.patch(f"{MEMBERS_MODULE}.templates.TemplateResponse", return_value=HTMLResponse(""))
    mock_ctx = mocker.patch(
        f"{MEMBERS_MODULE}.get_template_context", return_value={"request": MagicMock()}
    )

    mock_get.return_value = mock_group
    mock_list.return_value = mock_result

    client = TestClient(app)
    response = client.get(f"/admin/groups/{group_id}/members/add?success=members_added&count=5")

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["success"] == "members_added"
    assert ctx_kwargs["success_count"] == "5"
