"""Group API endpoints."""

from typing import Annotated

from api_dependencies import require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query, Request
from schemas.groups import (
    GroupChildrenList,
    GroupCreate,
    GroupDetail,
    GroupListResponse,
    GroupMemberAdd,
    GroupMemberList,
    GroupParentsList,
    GroupRelationshipAdd,
    GroupSummary,
    GroupUpdate,
)
from services import groups as groups_service
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


@router.get("/{group_id}/members", response_model=GroupMemberList)
def list_members(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    group_id: str,
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
):
    """
    List members of a group.

    Requires admin role.

    Returns:
        List of group members with user details
    """
    requesting_user = build_requesting_user(admin, tenant_id, request)

    try:
        return groups_service.list_members(requesting_user, group_id, page, limit)
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
    relationship_data: GroupRelationshipAdd,
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
