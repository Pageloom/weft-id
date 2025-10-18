"""User management routes."""

from typing import Annotated

import database
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child, has_page_access
from utils.auth import get_current_user
from utils.template_context import get_template_context

router = APIRouter(prefix="/users", tags=["users"])
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
def users_index(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Redirect to the first accessible users page."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

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
def users_list(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Display a list of users in the tenant with sorting, pagination, and search."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Get user's locale for locale-aware sorting
    user_locale = user.get("locale")
    # Determine collation for locale-aware text sorting
    # We'll validate this exists in the database to avoid errors
    collation = None
    if user_locale:
        # PostgreSQL ICU collation format: "sv-SE-x-icu", "en-US-x-icu", etc.
        icu_collation = f"{user_locale.replace('_', '-')}-x-icu"

        # Check if this collation exists in the database
        collation_exists = database.fetchone(
            tenant_id,
            "select 1 from pg_collation where collname = %(collation)s",
            {"collation": icu_collation},
        )

        if collation_exists:
            collation = icu_collation

    # Parse query parameters
    search = request.query_params.get("search", "").strip()
    sort_field = request.query_params.get("sort", "created_at")
    sort_order = request.query_params.get("order", "desc")

    try:
        page = max(1, int(request.query_params.get("page", "1")))
    except ValueError:
        page = 1

    try:
        page_size = int(request.query_params.get("size", "25"))
        if page_size not in [10, 25, 50, 100]:
            page_size = 25
    except ValueError:
        page_size = 25

    # Whitelist allowed sort fields to prevent SQL injection
    # For name, we need to apply the sort order to both fields
    # For text fields, add COLLATE clause if user has a locale set
    # Note: role is an ENUM type and cannot use COLLATE
    collate_clause = f' COLLATE "{collation}"' if collation else ""
    sort_field_map = {
        "name": f"u.last_name{collate_clause} {{order}}, u.first_name{collate_clause} {{order}}",
        "email": f"ue.email{collate_clause} {{order}}",
        "role": "u.role {order}",  # ENUM type - cannot use COLLATE
        "last_login": "u.last_login {order}",
        "created_at": "u.created_at {order}",
    }

    if sort_field not in sort_field_map:
        sort_field = "created_at"

    # Validate sort order
    if sort_order not in ["asc", "desc"]:
        sort_order = "desc"

    # Build WHERE clause for search
    where_clause = ""
    params = {}
    if search:
        where_clause = """
            where u.first_name ilike %(search)s
               or u.last_name ilike %(search)s
               or ue.email ilike %(search)s
        """
        params["search"] = f"%{search}%"

    # Get total count for pagination
    count_query = f"""
        select count(distinct u.id) as count
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        {where_clause}
    """
    count_result = database.fetchone(tenant_id, count_query, params)
    total_count = count_result["count"] if count_result else 0
    total_pages = max(1, (total_count + page_size - 1) // page_size)

    # Ensure page is within bounds
    page = min(page, total_pages)

    # Build main query with sorting and pagination
    offset = (page - 1) * page_size
    # Convert to dict[str, str | int] for params
    query_params: dict[str, str | int] = {**params, "limit": page_size, "offset": offset}

    # Build ORDER BY clause with proper sort order applied
    order_by_clause = sort_field_map[sort_field].format(order=sort_order)

    users_query = f"""
        select u.id, u.first_name, u.last_name, u.role, u.created_at, u.last_login,
               ue.email
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        {where_clause}
        order by {order_by_clause}
        limit %(limit)s offset %(offset)s
    """

    users = database.fetchall(tenant_id, users_query, query_params)

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

    return templates.TemplateResponse(
        "users_list.html",
        get_template_context(
            request,
            tenant_id,
            users=users,
            pagination=pagination,
            search=search,
            sort_field=sort_field,
            sort_order=sort_order,
        ),
    )
