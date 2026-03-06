"""Group API endpoints."""

from typing import Annotated

from api_dependencies import require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query, Request, UploadFile
from schemas.groups import (
    AvailableUserList,
    BulkMemberAdd,
    BulkMemberRemove,
    EffectiveMemberList,
    GroupChildAdd,
    GroupChildrenList,
    GroupCreate,
    GroupDetail,
    GroupGraphData,
    GroupGraphLayout,
    GroupListResponse,
    GroupMemberAdd,
    GroupMemberDetailList,
    GroupParentAdd,
    GroupParentsList,
    GroupSummary,
    GroupUpdate,
)
from schemas.service_providers import GroupSPAssignmentList
from services import branding as branding_service
from services import groups as groups_service
from services import service_providers as sp_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/groups", tags=["Groups"])


# =============================================================================
# Group CRUD
# =============================================================================


@router.get("", response_model=GroupListResponse)
def list_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    search: Annotated[str | None, Query(description="Search term")] = None,
    group_type: Annotated[str | None, Query(description="Filter by type: weftid or idp")] = None,
    sort_field: Annotated[
        str, Query(description="Sort by: name, created_at, member_count")
    ] = "created_at",
    sort_order: Annotated[str, Query(description="Sort order: asc or desc")] = "desc",
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    limit: Annotated[int, Query(ge=1, le=100, description="Page size")] = 25,
):
    """
    List groups for the tenant.

    Requires admin role.

    Returns:
        Paginated list of groups
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.list_groups(
            requesting_user,
            search=search,
            group_type=group_type,
            sort_field=sort_field,
            sort_order=sort_order,
            page=page,
            page_size=limit,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("", response_model=GroupDetail, status_code=201)
def create_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_data: GroupCreate,
):
    """
    Create a new group.

    Requires admin role.

    Returns:
        The created group
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.create_group(requesting_user, group_data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/graph", response_model=GroupGraphData)
def get_group_graph(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
):
    """
    Get all groups and relationships for graph rendering.

    Requires admin role.

    Returns:
        Graph nodes and edges for Cytoscape.js
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.get_group_graph_data(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/graph/layout", response_model=GroupGraphLayout | None)
def get_graph_layout(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
):
    """
    Get saved graph layout for the current user.

    Requires admin role.

    Returns:
        Saved node positions, or null if no layout has been saved
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.get_graph_layout_for_user(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.put("/graph/layout", status_code=204)
def save_graph_layout(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    layout_data: GroupGraphLayout,
):
    """
    Save graph layout for the current user.

    Requires admin role.

    Request body:
        node_ids: Sorted comma-separated node UUIDs (string)
        positions: Node positions keyed by node ID (dict of {id: {x, y}})
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        groups_service.save_graph_layout(requesting_user, layout_data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{group_id}", response_model=GroupDetail)
def get_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
):
    """
    Get a group by ID.

    Requires admin role.

    Returns:
        Group details including member/relationship counts
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.get_group(requesting_user, group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.patch("/{group_id}", response_model=GroupDetail)
def update_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    group_data: GroupUpdate,
):
    """
    Update a group.

    Requires admin role.

    Request body (all fields optional):
        name: Group name
        description: Group description (empty string to clear)

    Returns:
        Updated group details
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.update_group(requesting_user, group_id, group_data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{group_id}", status_code=204)
def delete_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
):
    """
    Delete a group.

    Children become orphaned (keep other parents if any).

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        groups_service.delete_group(requesting_user, group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Group Members
# =============================================================================


@router.get("/{group_id}/members", response_model=GroupMemberDetailList)
def list_members(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    search: Annotated[str | None, Query(description="Search by name or email")] = None,
    role: Annotated[str | None, Query(description="Filter by roles (comma-separated)")] = None,
    status: Annotated[str | None, Query(description="Filter by statuses (comma-separated)")] = None,
    sort_field: Annotated[
        str, Query(description="Sort by: name, email, role, status, created_at")
    ] = "created_at",
    sort_order: Annotated[str, Query(description="Sort order: asc or desc")] = "desc",
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
):
    """
    List members of a group with search, filtering, sorting, and pagination.

    Requires admin role.

    Returns:
        Paginated list of group members with extended user details
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    # Parse comma-separated filters
    roles = [r.strip() for r in role.split(",") if r.strip()] if role else None
    statuses = [s.strip() for s in status.split(",") if s.strip()] if status else None

    try:
        return groups_service.list_members_filtered(
            requesting_user,
            group_id,
            search=search,
            roles=roles,
            statuses=statuses,
            sort_field=sort_field,
            sort_order=sort_order,
            page=page,
            page_size=limit,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{group_id}/members", status_code=201)
def add_member(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    member_data: GroupMemberAdd,
):
    """
    Add a user to a group.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        groups_service.add_member(requesting_user, group_id, member_data.user_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    return {"status": "ok"}


@router.delete("/{group_id}/members/{user_id}", status_code=204)
def remove_member(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    user_id: str,
):
    """
    Remove a user from a group.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        groups_service.remove_member(requesting_user, group_id, user_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{group_id}/effective-members", response_model=EffectiveMemberList)
def list_effective_members(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
):
    """
    List effective members of a group (direct + inherited via descendants).

    Requires admin role.

    Returns:
        Paginated list of effective group members with is_direct flag
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.get_effective_members(requesting_user, group_id, page, limit)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{group_id}/members/bulk", status_code=201)
def bulk_add_members(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    member_data: BulkMemberAdd,
):
    """
    Add multiple users to a group in bulk.

    Requires admin role.

    Returns:
        Count of new memberships created
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        count = groups_service.bulk_add_members(requesting_user, group_id, member_data.user_ids)
        return {"status": "ok", "added": count}
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{group_id}/members/bulk-remove", status_code=200)
def bulk_remove_members(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    member_data: BulkMemberRemove,
):
    """
    Remove multiple users from a group in bulk.

    Requires admin role.

    Returns:
        Count of memberships removed
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        count = groups_service.bulk_remove_members(requesting_user, group_id, member_data.user_ids)
        return {"status": "ok", "removed": count}
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{group_id}/available-users", response_model=AvailableUserList)
def list_available_users(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    search: Annotated[str | None, Query(description="Search by name or email")] = None,
    role: Annotated[str | None, Query(description="Filter by roles (comma-separated)")] = None,
    status: Annotated[str | None, Query(description="Filter by statuses (comma-separated)")] = None,
    sort_field: Annotated[
        str, Query(description="Sort by: name, email, role, status, created_at")
    ] = "name",
    sort_order: Annotated[str, Query(description="Sort order: asc or desc")] = "asc",
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
):
    """
    List users available to add to a group (not already members).

    Excludes service accounts.
    Requires admin role.

    Returns:
        Paginated list of available users
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    # Parse comma-separated filters
    roles = [r.strip() for r in role.split(",") if r.strip()] if role else None
    statuses = [s.strip() for s in status.split(",") if s.strip()] if status else None

    try:
        return groups_service.list_available_users_paginated(
            requesting_user,
            group_id,
            search=search,
            roles=roles,
            statuses=statuses,
            sort_field=sort_field,
            sort_order=sort_order,
            page=page,
            page_size=limit,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Group Relationships
# =============================================================================


@router.get("/{group_id}/parents", response_model=GroupParentsList)
def list_parents(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
):
    """
    List parent groups of a group.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.list_parents(requesting_user, group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{group_id}/parents", status_code=201)
def add_parent(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    relationship_data: GroupParentAdd,
):
    """
    Add a parent group.

    Requires admin role.

    Raises:
        400: If would create a cycle or self-reference
        409: If relationship already exists
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        groups_service.add_child(requesting_user, relationship_data.parent_group_id, group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    return {"status": "ok"}


@router.delete("/{group_id}/parents/{parent_group_id}", status_code=204)
def remove_parent(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    parent_group_id: str,
):
    """
    Remove a parent group.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        groups_service.remove_child(requesting_user, parent_group_id, group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    return {"status": "ok"}


@router.get("/{group_id}/children", response_model=GroupChildrenList)
def list_children(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
):
    """
    List child groups of a group.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.list_children(requesting_user, group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{group_id}/children", status_code=201)
def add_child(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    relationship_data: GroupChildAdd,
):
    """
    Add a child group.

    Requires admin role.

    Raises:
        400: If would create a cycle or self-reference
        409: If relationship already exists
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        groups_service.add_child(requesting_user, group_id, relationship_data.child_group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    return {"status": "ok"}


@router.delete("/{group_id}/children/{child_group_id}", status_code=204)
def remove_child(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    child_group_id: str,
):
    """
    Remove a child group.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        groups_service.remove_child(requesting_user, group_id, child_group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# IdP Groups
# =============================================================================


@router.get("/idp/{idp_id}", response_model=list[GroupSummary])
def list_idp_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    idp_id: str,
):
    """
    List groups belonging to an identity provider.

    Returns all groups that were auto-created or discovered from the specified IdP.

    Requires admin role.

    Returns:
        List of group summaries for the IdP
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.list_groups_for_idp(requesting_user, idp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Group SP Assignments
# =============================================================================


@router.get("/{group_id}/service-providers", response_model=GroupSPAssignmentList)
def list_group_service_providers(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
):
    """
    List service providers assigned to a group.

    Requires admin role.

    Returns:
        List of SP assignments for the group
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return sp_service.list_group_sp_assignments(requesting_user, group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Group Logo
# =============================================================================


@router.post("/{group_id}/logo", status_code=201)
async def upload_group_logo(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    file: UploadFile,
):
    """Upload a custom logo for a group.

    Requires admin role.
    Accepts PNG (square, min 48x48) or SVG (square viewBox) up to 256KB.
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        data = await file.read()
        branding_service.upload_group_logo(
            requesting_user,
            group_id=group_id,
            data=data,
            filename=file.filename,
        )
        return None
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{group_id}/logo", status_code=204)
def delete_group_logo(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
):
    """Remove a custom logo from a group.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        branding_service.delete_group_logo(requesting_user, group_id=group_id)
        return None
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
