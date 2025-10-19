"""User management routes."""

from typing import Annotated

import database
from dependencies import get_current_user, get_tenant_id_from_request, require_current_user
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child, has_page_access
from utils.email import (
    send_primary_email_changed_notification,
    send_secondary_email_added_notification,
    send_secondary_email_removed_notification,
)
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


@router.get("/{user_id}", response_class=HTMLResponse)
def user_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Display detailed user information and allow admin edits."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Get target user information
    target_user = database.users.get_user_by_id(tenant_id, user_id)
    if not target_user:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)

    # Get all emails for the user
    emails = database.user_emails.list_user_emails(tenant_id, user_id)

    # Get privileged domains for email validation
    privileged_domains = database.settings.list_privileged_domains(tenant_id)

    # Get success/error messages from query params
    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "user_detail.html",
        get_template_context(
            request,
            tenant_id,
            target_user=target_user,
            emails=emails,
            privileged_domains=privileged_domains,
            success=success,
            error=error,
        ),
    )


@router.post("/{user_id}/update-name")
def update_user_name(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    first_name: Annotated[str, Form()],
    last_name: Annotated[str, Form()],
):
    """Update a user's name (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Validate inputs
    first_name = first_name.strip()
    last_name = last_name.strip()

    if not first_name or not last_name:
        return RedirectResponse(
            url=f"/users/{user_id}?error=name_required", status_code=303
        )

    # Update the user's name
    database.users.update_user_profile(tenant_id, user_id, first_name, last_name)

    return RedirectResponse(url=f"/users/{user_id}?success=name_updated", status_code=303)


@router.post("/{user_id}/update-role")
def update_user_role_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    role: Annotated[str, Form()],
):
    """Update a user's role (super_admin only)."""
    # Check super_admin permission
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    # Validate role
    if role not in ["member", "admin", "super_admin"]:
        return RedirectResponse(
            url=f"/users/{user_id}?error=invalid_role", status_code=303
        )

    # Prevent changing own role
    if user_id == user.get("id"):
        return RedirectResponse(
            url=f"/users/{user_id}?error=cannot_change_own_role", status_code=303
        )

    # Update the user's role
    database.users.update_user_role(tenant_id, user_id, role)

    return RedirectResponse(url=f"/users/{user_id}?success=role_updated", status_code=303)


@router.post("/{user_id}/add-email")
def add_user_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    email: Annotated[str, Form()],
):
    """Add a secondary email to a user (admin only, privileged domains only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Clean and validate email
    email = email.strip().lower()

    if not email or "@" not in email:
        return RedirectResponse(
            url=f"/users/{user_id}?error=invalid_email", status_code=303
        )

    # Check if email already exists
    if database.user_emails.email_exists(tenant_id, email):
        return RedirectResponse(
            url=f"/users/{user_id}?error=email_exists", status_code=303
        )

    # Extract domain and check if it's privileged
    domain = email.split("@")[1]
    if not database.settings.privileged_domain_exists(tenant_id, domain):
        return RedirectResponse(
            url=f"/users/{user_id}?error=domain_not_privileged", status_code=303
        )

    # Add the email as verified
    database.user_emails.add_verified_email(tenant_id, user_id, email, tenant_id)

    # Get primary email for notification
    primary_email_record = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email_record:
        admin_name = f"{user.get('first_name')} {user.get('last_name')}"
        send_secondary_email_added_notification(
            primary_email_record["email"], email, admin_name
        )

    return RedirectResponse(url=f"/users/{user_id}?success=email_added", status_code=303)


@router.post("/{user_id}/remove-email/{email_id}")
def remove_user_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    email_id: str,
):
    """Remove a secondary email from a user (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Get the email to be removed
    email_to_remove = database.user_emails.get_email_by_id(tenant_id, email_id, user_id)
    if not email_to_remove:
        return RedirectResponse(
            url=f"/users/{user_id}?error=email_not_found", status_code=303
        )

    # Prevent removing primary email
    if email_to_remove.get("is_primary"):
        return RedirectResponse(
            url=f"/users/{user_id}?error=cannot_remove_primary", status_code=303
        )

    # Check that user will have at least one email left
    email_count = database.user_emails.count_user_emails(tenant_id, user_id)
    if email_count <= 1:
        return RedirectResponse(
            url=f"/users/{user_id}?error=must_keep_one_email", status_code=303
        )

    # Get the email address before deleting
    all_emails = database.user_emails.list_user_emails(tenant_id, user_id)
    email_address = next(
        (e["email"] for e in all_emails if str(e["id"]) == str(email_id)), None
    )

    # Delete the email
    database.user_emails.delete_email(tenant_id, email_id)

    # Get primary email for notification
    if email_address:
        primary_email_record = database.user_emails.get_primary_email(tenant_id, user_id)
        if primary_email_record:
            admin_name = f"{user.get('first_name')} {user.get('last_name')}"
            send_secondary_email_removed_notification(
                primary_email_record["email"], email_address, admin_name
            )

    return RedirectResponse(
        url=f"/users/{user_id}?success=email_removed", status_code=303
    )


@router.post("/{user_id}/promote-email/{email_id}")
def promote_user_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    email_id: str,
):
    """Promote a secondary email to primary (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Get the email to be promoted
    email_to_promote = database.user_emails.get_email_by_id(tenant_id, email_id, user_id)
    if not email_to_promote:
        return RedirectResponse(
            url=f"/users/{user_id}?error=email_not_found", status_code=303
        )

    # Check if already primary
    if email_to_promote.get("is_primary"):
        return RedirectResponse(
            url=f"/users/{user_id}?error=already_primary", status_code=303
        )

    # Get old primary email info before changing
    old_primary_record = database.user_emails.get_primary_email(tenant_id, user_id)

    # Get the new primary email address
    all_emails = database.user_emails.list_user_emails(tenant_id, user_id)
    new_primary_email = next(
        (e["email"] for e in all_emails if str(e["id"]) == str(email_id)), None
    )

    # Update primary status
    database.user_emails.unset_primary_emails(tenant_id, user_id)
    database.user_emails.set_primary_email(tenant_id, email_id)

    # Send notification to old primary email
    if old_primary_record and new_primary_email:
        admin_name = f"{user.get('first_name')} {user.get('last_name')}"
        send_primary_email_changed_notification(
            old_primary_record["email"], new_primary_email, admin_name
        )

    return RedirectResponse(
        url=f"/users/{user_id}?success=email_promoted", status_code=303
    )
