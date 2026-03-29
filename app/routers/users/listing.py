"""User listing routes."""

from datetime import date
from typing import Annotated

from dependencies import get_current_user, get_tenant_id_from_request, require_current_user
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import get_first_accessible_child, has_page_access
from services import users as users_service
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_current_user)],
    include_in_schema=False,
)


@router.get("/", response_class=HTMLResponse)
def users_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible users page."""
    # Check if user has permission to access settings
    if not has_page_access("/users", user.get("role")):
        return RedirectResponse(url="/account", status_code=303)

    # Get first accessible child page
    first_child = get_first_accessible_child("/users", user.get("role"))

    if first_child:
        return RedirectResponse(url=first_child, status_code=303)

    # Fallback if no accessible children (shouldn't happen)
    return RedirectResponse(url="/account", status_code=303)


@router.get("/list", response_class=HTMLResponse)
def users_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display a list of users in the tenant with sorting, pagination, and search."""
    # Get user's locale for locale-aware sorting
    user_locale = user.get("locale")
    # Determine collation for locale-aware text sorting
    # We'll validate this exists in the database to avoid errors
    collation = None
    if user_locale:
        # PostgreSQL ICU collation format: "sv-SE-x-icu", "en-US-x-icu", etc.
        icu_collation = f"{user_locale.replace('_', '-')}-x-icu"

        # Check if this collation exists in the database
        if users_service.check_collation_exists(tenant_id, icu_collation):
            collation = icu_collation

    # Parse query parameters
    search = request.query_params.get("search", "").strip()
    sort_field = request.query_params.get("sort", "created_at")
    sort_order = request.query_params.get("order", "desc")

    # Parse role filter (with optional ! negation prefix)
    role_param = request.query_params.get("role", "").strip()
    role_negate = role_param.startswith("!")
    if role_negate:
        role_param = role_param[1:]
    roles: list[str] | None = None
    if role_param:
        allowed_roles = {"member", "admin", "super_admin"}
        roles = [r.strip() for r in role_param.split(",") if r.strip() in allowed_roles]
        if not roles:
            roles = None
            role_negate = False

    # Parse status filter (with optional ! negation prefix)
    status_param = request.query_params.get("status", "").strip()
    status_negate = status_param.startswith("!")
    if status_negate:
        status_param = status_param[1:]
    statuses: list[str] | None = None
    if status_param:
        allowed_statuses = {"active", "inactivated", "anonymized"}
        statuses = [s.strip() for s in status_param.split(",") if s.strip() in allowed_statuses]
        if not statuses:
            statuses = None
            status_negate = False

    # Parse auth method filter (with optional ! negation prefix)
    auth_method_param = request.query_params.get("auth_method", "").strip()
    auth_method_negate = auth_method_param.startswith("!")
    if auth_method_negate:
        auth_method_param = auth_method_param[1:]
    auth_methods: list[str] | None = None
    if auth_method_param:
        auth_methods = [m.strip() for m in auth_method_param.split(",") if m.strip()]
        if not auth_methods:
            auth_methods = None
            auth_method_negate = False

    # Parse domain filter (with optional ! negation prefix)
    domain_raw = request.query_params.get("domain", "").strip()
    domain_negate = domain_raw.startswith("!")
    if domain_negate:
        domain_raw = domain_raw[1:]
    domain = domain_raw or None
    if not domain:
        domain_negate = False

    # Parse group filter (with optional ! negation prefix)
    group_raw = request.query_params.get("group_id", "").strip()
    group_negate = group_raw.startswith("!")
    if group_negate:
        group_raw = group_raw[1:]
    group_id = group_raw or None
    if not group_id:
        group_negate = False

    # Parse group hierarchy flag (default: include children)
    group_include_children = request.query_params.get("group_children", "1") != "0"

    # Parse secondary email filter (yes/no or domain:X)
    secondary_param = request.query_params.get("has_secondary_email", "").strip()
    has_secondary_email: bool | str | None = None
    if secondary_param == "yes":
        has_secondary_email = True
    elif secondary_param == "no":
        has_secondary_email = False
    elif secondary_param.startswith("domain:"):
        has_secondary_email = secondary_param

    # Parse activity date range
    activity_start: date | None = None
    activity_end: date | None = None
    try:
        activity_start_str = request.query_params.get("activity_start", "").strip()
        if activity_start_str:
            activity_start = date.fromisoformat(activity_start_str)
    except ValueError:
        pass
    try:
        activity_end_str = request.query_params.get("activity_end", "").strip()
        if activity_end_str:
            activity_end = date.fromisoformat(activity_end_str)
    except ValueError:
        pass

    try:
        page = max(1, int(request.query_params.get("page", "1")))
    except ValueError:
        page = 1

    try:
        page_size = int(request.query_params.get("size", "25"))
        if page_size not in [25, 50, 100, 250]:
            page_size = 25
    except ValueError:
        page_size = 25

    # Validate sort field and order
    allowed_sort_fields = ["name", "email", "role", "status", "last_activity_at", "created_at"]
    if sort_field not in allowed_sort_fields:
        sort_field = "created_at"

    # Validate sort order
    if sort_order not in ["asc", "desc"]:
        sort_order = "desc"

    # Get filter options
    auth_method_options = users_service.get_auth_method_options(tenant_id)
    domain_options = users_service.get_domain_filter_options(tenant_id)
    group_options = users_service.get_group_filter_options(tenant_id)

    # Get total count for pagination
    total_count = users_service.count_users(
        tenant_id,
        search if search else None,
        roles,
        statuses,
        auth_methods,
        domain=domain,
        group_id=group_id,
        has_secondary_email=has_secondary_email,
        activity_start=activity_start,
        activity_end=activity_end,
        role_negate=role_negate,
        status_negate=status_negate,
        auth_method_negate=auth_method_negate,
        domain_negate=domain_negate,
        group_negate=group_negate,
        group_include_children=group_include_children,
    )
    total_pages = max(1, (total_count + page_size - 1) // page_size)

    # Ensure page is within bounds
    page = min(page, total_pages)

    # Fetch users with pagination
    users = users_service.list_users_raw(
        tenant_id,
        search if search else None,
        sort_field,
        sort_order,
        page,
        page_size,
        collation,
        roles,
        statuses,
        auth_methods,
        domain=domain,
        group_id=group_id,
        has_secondary_email=has_secondary_email,
        activity_start=activity_start,
        activity_end=activity_end,
        role_negate=role_negate,
        status_negate=status_negate,
        auth_method_negate=auth_method_negate,
        domain_negate=domain_negate,
        group_negate=group_negate,
        group_include_children=group_include_children,
    )

    # Calculate offset for pagination metadata
    offset = (page - 1) * page_size

    # Pagination metadata
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

    # Build filter criteria for "select all matching"
    filter_criteria: dict = {}
    if search:
        filter_criteria["search"] = search
    if roles:
        val = ",".join(roles)
        filter_criteria["roles"] = f"!{val}" if role_negate else val
    if statuses:
        val = ",".join(statuses)
        filter_criteria["statuses"] = f"!{val}" if status_negate else val
    if auth_methods:
        val = ",".join(auth_methods)
        filter_criteria["auth_methods"] = f"!{val}" if auth_method_negate else val
    if domain:
        filter_criteria["domain"] = f"!{domain}" if domain_negate else domain
    if group_id:
        filter_criteria["group_id"] = f"!{group_id}" if group_negate else group_id
        if not group_include_children:
            filter_criteria["group_children"] = "0"
    if has_secondary_email is not None:
        if isinstance(has_secondary_email, str):
            filter_criteria["has_secondary_email"] = has_secondary_email
        else:
            filter_criteria["has_secondary_email"] = "yes" if has_secondary_email else "no"
    if activity_start:
        filter_criteria["activity_start"] = activity_start.isoformat()
    if activity_end:
        filter_criteria["activity_end"] = activity_end.isoformat()

    return templates.TemplateResponse(
        request,
        "users_list.html",
        get_template_context(
            request,
            tenant_id,
            users=users,
            pagination=pagination,
            search=search,
            sort_field=sort_field,
            sort_order=sort_order,
            roles=roles or [],
            statuses=statuses or [],
            auth_methods=auth_methods or [],
            auth_method_options=auth_method_options,
            domain=domain,
            domain_options=domain_options,
            group_id=group_id,
            group_options=group_options,
            group_include_children=group_include_children,
            has_secondary_email=has_secondary_email,
            activity_start=activity_start.isoformat() if activity_start else "",
            activity_end=activity_end.isoformat() if activity_end else "",
            role_negate=role_negate,
            status_negate=status_negate,
            auth_method_negate=auth_method_negate,
            domain_negate=domain_negate,
            group_negate=group_negate,
            filter_criteria=filter_criteria,
        ),
    )
