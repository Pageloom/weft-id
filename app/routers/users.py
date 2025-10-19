"""User management routes."""

from typing import Annotated

import database
from dependencies import get_current_user, get_tenant_id_from_request, require_current_user
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child, has_page_access
from utils.template_context import get_template_context

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_current_user)],  # All routes require authentication
)
templates = Jinja2Templates(directory="templates")


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
        if database.users.check_collation_exists(tenant_id, icu_collation):
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

    # Validate sort field and order (validation also happens in database.users.list_users)
    allowed_sort_fields = ["name", "email", "role", "last_login", "created_at"]
    if sort_field not in allowed_sort_fields:
        sort_field = "created_at"

    # Validate sort order
    if sort_order not in ["asc", "desc"]:
        sort_order = "desc"

    # Get total count for pagination
    total_count = database.users.count_users(tenant_id, search if search else None)
    total_pages = max(1, (total_count + page_size - 1) // page_size)

    # Ensure page is within bounds
    page = min(page, total_pages)

    # Fetch users with pagination
    users = database.users.list_users(
        tenant_id,
        search if search else None,
        sort_field,
        sort_order,
        page,
        page_size,
        collation,
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
