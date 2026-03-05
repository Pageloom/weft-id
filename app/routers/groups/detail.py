"""Group detail, update, and delete routes."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from routers.groups.members import _parse_member_query_params
from schemas.groups import GroupUpdate
from services import groups as groups_service
from services import service_providers as sp_service
from services.exceptions import (
    ConflictError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/admin/groups",
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)


def _load_group_common(requesting_user, group_id):
    """Load all group data needed across tabs."""
    group = groups_service.get_group(requesting_user, group_id)
    parents = groups_service.list_parents(requesting_user, group_id)
    children = groups_service.list_children(requesting_user, group_id)

    available_parents = groups_service.list_available_parents(requesting_user, group_id)
    available_children = groups_service.list_available_children(requesting_user, group_id)

    effective_member_count = None
    if group.child_count > 0:
        eff = groups_service.get_effective_members(requesting_user, group_id, page=1, page_size=1)
        effective_member_count = eff.total

    assigned_sps = []
    try:
        sp_result = sp_service.list_group_sp_assignments(requesting_user, group_id)
        assigned_sps = sp_result.items
    except ServiceError:
        pass

    def _logo_version(ts) -> int:
        return int(ts.timestamp()) if ts else 0

    neighborhood_data = {
        "group": {
            "id": group.id,
            "name": group.name,
            "group_type": group.group_type,
            "parent_count": group.parent_count,
            "child_count": group.child_count,
            "has_logo": group.has_logo,
            "logo_version": _logo_version(group.logo_updated_at),
        },
        "parents": [
            {
                "id": p.group_id,
                "name": p.name,
                "group_type": p.group_type,
                "has_logo": p.has_logo,
                "logo_version": _logo_version(p.logo_updated_at),
            }
            for p in parents.items
        ],
        "children": [
            {
                "id": c.group_id,
                "name": c.name,
                "group_type": c.group_type,
                "member_count": c.member_count,
                "has_logo": c.has_logo,
                "logo_version": _logo_version(c.logo_updated_at),
            }
            for c in children.items
        ],
    }

    return dict(
        group=group,
        parents=parents.items,
        children=children.items,
        available_parents=available_parents,
        available_children=available_children,
        effective_member_count=effective_member_count,
        assigned_sps=assigned_sps,
        neighborhood_data=neighborhood_data,
    )


@router.get("/{group_id}", response_class=HTMLResponse)
def group_detail_redirect(
    group_id: str,
):
    """Redirect to the details tab."""
    return RedirectResponse(url=f"/admin/groups/{group_id}/details", status_code=303)


@router.get("/{group_id}/details", response_class=HTMLResponse)
def group_tab_details(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Display the Details tab for a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        ctx = _load_group_common(requesting_user, group_id)
    except NotFoundError:
        return render_error_page(
            request,
            tenant_id,
            NotFoundError(message="Group not found", code="group_not_found"),
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return templates.TemplateResponse(
        request,
        "groups_detail_tab_details.html",
        get_template_context(
            request,
            tenant_id,
            **ctx,
            active_tab="details",
            success=request.query_params.get("success"),
            error=request.query_params.get("error"),
        ),
    )


@router.get("/{group_id}/membership", response_class=HTMLResponse)
def group_tab_membership(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Display the Members tab for a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    params = _parse_member_query_params(request)

    try:
        ctx = _load_group_common(requesting_user, group_id)
        result = groups_service.list_members_filtered(
            requesting_user,
            group_id,
            search=params["search"] or None,
            roles=params["roles"],
            statuses=params["statuses"],
            sort_field=params["sort_field"],
            sort_order=params["sort_order"],
            page=params["page"],
            page_size=params["page_size"],
        )
    except NotFoundError:
        return render_error_page(
            request,
            tenant_id,
            NotFoundError(message="Group not found", code="group_not_found"),
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    total_count = result.total
    page_size = params["page_size"]
    page = params["page"]
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    page = min(page, total_pages)
    offset = (page - 1) * page_size

    pagination = {
        "page": page,
        "page_size": page_size,
        "total_count": total_count,
        "total_pages": total_pages,
        "has_previous": page > 1,
        "has_next": page < total_pages,
        "start_index": offset + 1 if total_count > 0 else 0,
        "end_index": min(offset + page_size, total_count),
    }

    inherited_members = []
    if ctx["group"].child_count > 0:
        eff = groups_service.get_effective_members(requesting_user, group_id, page=1, page_size=500)
        inherited_members = [m for m in eff.items if not m.is_direct]

    return templates.TemplateResponse(
        request,
        "groups_detail_tab_membership.html",
        get_template_context(
            request,
            tenant_id,
            **ctx,
            active_tab="membership",
            members=result.items,
            pagination=pagination,
            search=params["search"],
            sort_field=params["sort_field"],
            sort_order=params["sort_order"],
            roles=params["roles"] or [],
            statuses=params["statuses"] or [],
            inherited_members=inherited_members,
            success=request.query_params.get("success"),
            error=request.query_params.get("error"),
        ),
    )


@router.get("/{group_id}/applications", response_class=HTMLResponse)
def group_tab_applications(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Display the Applications tab for a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        ctx = _load_group_common(requesting_user, group_id)
    except NotFoundError:
        return render_error_page(
            request,
            tenant_id,
            NotFoundError(message="Group not found", code="group_not_found"),
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Build inherited SP list from direct parent groups
    direct_sp_ids = {spa.sp_id for spa in ctx["assigned_sps"]}
    inherited_sps: list[dict] = []
    seen_inherited: set[str] = set()
    for parent in ctx["parents"]:
        try:
            result = sp_service.list_group_sp_assignments(requesting_user, parent.group_id)
            for spa in result.items:
                if spa.sp_id not in direct_sp_ids and spa.sp_id not in seen_inherited:
                    inherited_sps.append(
                        {
                            "sp": spa,
                            "from_group_name": parent.name,
                            "from_group_id": parent.group_id,
                            "from_group_type": parent.group_type,
                        }
                    )
                    seen_inherited.add(spa.sp_id)
        except ServiceError:
            pass

    available_sps: list[dict] = []
    try:
        available_sps = sp_service.list_available_sps_for_group(requesting_user, group_id)
    except ServiceError:
        pass

    return templates.TemplateResponse(
        request,
        "groups_detail_tab_applications.html",
        get_template_context(
            request,
            tenant_id,
            **ctx,
            active_tab="applications",
            inherited_sps=inherited_sps,
            available_sps=available_sps,
            success=request.query_params.get("success"),
            error=request.query_params.get("error"),
        ),
    )


@router.get("/{group_id}/relationships", response_class=HTMLResponse)
def group_tab_relationships(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Display the Relationships tab for a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        ctx = _load_group_common(requesting_user, group_id)
    except NotFoundError:
        return render_error_page(
            request,
            tenant_id,
            NotFoundError(message="Group not found", code="group_not_found"),
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    group = ctx["group"]
    idp_umbrella_group = None
    if group.group_type == "idp" and group.idp_id and group.name != group.idp_name:
        idp_umbrella_group = groups_service.get_idp_base_group(tenant_id, group.idp_id)

    return templates.TemplateResponse(
        request,
        "groups_detail_tab_relationships.html",
        get_template_context(
            request,
            tenant_id,
            **ctx,
            active_tab="relationships",
            idp_umbrella_group=idp_umbrella_group,
            success=request.query_params.get("success"),
            error=request.query_params.get("error"),
        ),
    )


@router.get("/{group_id}/delete", response_class=HTMLResponse)
def group_tab_delete(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Display the Delete tab for a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        ctx = _load_group_common(requesting_user, group_id)
    except NotFoundError:
        return render_error_page(
            request,
            tenant_id,
            NotFoundError(message="Group not found", code="group_not_found"),
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return templates.TemplateResponse(
        request,
        "groups_detail_tab_delete.html",
        get_template_context(
            request,
            tenant_id,
            **ctx,
            active_tab="delete",
            success=request.query_params.get("success"),
            error=request.query_params.get("error"),
        ),
    )


@router.post("/{group_id}/edit")
def update_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
):
    """Update group details."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        group_data = GroupUpdate(name=name, description=description)
        groups_service.update_group(requesting_user, group_id, group_data)
    except (ValidationError, ConflictError, NotFoundError) as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}/details?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}/details?success=updated",
        status_code=303,
    )


@router.post("/{group_id}/delete")
def delete_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Delete a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        groups_service.delete_group(requesting_user, group_id)
    except NotFoundError:
        return RedirectResponse(
            url="/admin/groups/list?error=group_not_found",
            status_code=303,
        )
    except ValidationError as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}/delete?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/groups/list?success=deleted",
        status_code=303,
    )
