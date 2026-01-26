"""User management routes."""

from datetime import UTC, datetime
from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_current_user,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child, has_page_access
from schemas.api import UserCreate
from services import emails as emails_service
from services import mfa as mfa_service
from services import saml as saml_service
from services import settings as settings_service
from services import users as users_service
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from services.types import RequestingUser
from utils.email import (
    send_mfa_reset_notification,
    send_new_user_invitation,
    send_new_user_privileged_domain_notification,
    send_primary_email_changed_notification,
    send_secondary_email_added_notification,
    send_secondary_email_removed_notification,
)
from utils.service_errors import render_error_page
from utils.template_context import get_template_context

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_current_user)],  # All routes require authentication
    include_in_schema=False,
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
        if users_service.check_collation_exists(tenant_id, icu_collation):
            collation = icu_collation

    # Parse query parameters
    search = request.query_params.get("search", "").strip()
    sort_field = request.query_params.get("sort", "created_at")
    sort_order = request.query_params.get("order", "desc")

    # Parse role filter (comma-separated)
    role_param = request.query_params.get("role", "").strip()
    roles: list[str] | None = None
    if role_param:
        allowed_roles = {"member", "admin", "super_admin"}
        roles = [r.strip() for r in role_param.split(",") if r.strip() in allowed_roles]
        if not roles:
            roles = None

    # Parse status filter (comma-separated)
    status_param = request.query_params.get("status", "").strip()
    statuses: list[str] | None = None
    if status_param:
        allowed_statuses = {"active", "inactivated", "anonymized"}
        statuses = [s.strip() for s in status_param.split(",") if s.strip() in allowed_statuses]
        if not statuses:
            statuses = None

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

    # Validate sort field and order
    allowed_sort_fields = ["name", "email", "role", "status", "last_activity_at", "created_at"]
    if sort_field not in allowed_sort_fields:
        sort_field = "created_at"

    # Validate sort order
    if sort_order not in ["asc", "desc"]:
        sort_order = "desc"

    # Get total count for pagination
    total_count = users_service.count_users(tenant_id, search if search else None, roles, statuses)
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
            roles=roles or [],
            statuses=statuses or [],
        ),
    )


@router.get("/new", response_class=HTMLResponse)
def new_user(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display form to create a new user."""
    # Check admin permission
    if not has_page_access("/users/new", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Get privileged domains for display via service layer
    privileged_domains = settings_service.get_privileged_domains_list(tenant_id)

    # Get success/error messages from query params
    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "users_new.html",
        get_template_context(
            request,
            tenant_id,
            privileged_domains=privileged_domains,
            success=success,
            error=error,
        ),
    )


@router.post("/new")
def create_new_user(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    email: Annotated[str, Form()] = "",
    first_name: Annotated[str, Form()] = "",
    last_name: Annotated[str, Form()] = "",
    role: Annotated[str, Form()] = "member",
):
    """Create a new user account."""
    # Check admin permission
    if not has_page_access("/users/new", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Validate inputs
    email = email.strip().lower()
    first_name = first_name.strip()
    last_name = last_name.strip()

    if not email or "@" not in email:
        return RedirectResponse(url="/users/new?error=invalid_email", status_code=303)

    if not first_name or not last_name:
        return RedirectResponse(url="/users/new?error=name_required", status_code=303)

    # Validate role
    if role not in ["member", "admin", "super_admin"]:
        return RedirectResponse(url="/users/new?error=invalid_role", status_code=303)

    # Extract domain and check if it's privileged
    domain = email.split("@")[1]
    is_privileged = settings_service.is_privileged_domain(tenant_id, domain)

    # Build RequestingUser from session
    requesting_user: RequestingUser = {
        "id": user["id"],
        "tenant_id": tenant_id,
        "role": user["role"],
    }

    # Create user via service layer (with event logging and authorization)
    try:
        user_data = UserCreate(
            first_name=first_name,
            last_name=last_name,
            email=email,
            role=role,
        )
        created_user = users_service.create_user(
            requesting_user=requesting_user,
            user_data=user_data,
            auto_create_email=False,  # Router handles email separately based on domain privilege
        )
        user_id = created_user.id
    except ForbiddenError:
        return RedirectResponse(url="/users/new?error=insufficient_permissions", status_code=303)
    except ConflictError:
        return RedirectResponse(url="/users/new?error=email_exists", status_code=303)
    except (ValidationError, ServiceError):
        return RedirectResponse(url="/users/new?error=creation_failed", status_code=303)

    # Get tenant name for email
    org_name = users_service.get_tenant_name(tenant_id)

    # Create email record and send appropriate notification
    admin_name = f"{user.get('first_name')} {user.get('last_name')}"

    if is_privileged:
        # Auto-verify email for privileged domains
        email_result = users_service.add_verified_email_with_nonce(
            tenant_id, user_id, email, is_primary=True
        )

        if not email_result:
            return RedirectResponse(url="/users/new?error=email_creation_failed", status_code=303)

        # Send welcome email with password set link
        email_id = email_result["id"]
        password_set_url = f"{request.base_url}set-password?email_id={email_id}"
        send_new_user_privileged_domain_notification(email, admin_name, org_name, password_set_url)
    else:
        # Add unverified email for non-privileged domains
        email_result = users_service.add_unverified_email_with_nonce(
            tenant_id, user_id, email, is_primary=True
        )
        if email_result:
            # Send invitation email with verification link
            verify_nonce = email_result["verify_nonce"]
            email_id = email_result["id"]
            verification_url = f"{request.base_url}verify-email/{email_id}/{verify_nonce}"
            send_new_user_invitation(email, admin_name, org_name, verification_url)

    return RedirectResponse(url=f"/users/{user_id}?success=user_created", status_code=303)


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

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        user_detail_data = users_service.get_user(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Get privileged domains for email validation (for the add-email form)
    privileged_domains = settings_service.get_privileged_domains_list(tenant_id)

    # Get IdPs list for super_admin (for auth method assignment)
    idps = []
    if user.get("role") == "super_admin":
        try:
            idp_list = saml_service.list_identity_providers(requesting_user)
            idps = idp_list.items
        except ServiceError:
            pass  # Ignore errors getting IdPs

    # Check if user's IdP requires platform MFA (for MFA reset section)
    idp_requires_mfa = False
    if user_detail_data.saml_idp_id:
        idp_requires_mfa = saml_service.idp_requires_platform_mfa(
            tenant_id, user_detail_data.saml_idp_id
        )

    # Get success/error messages from query params
    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "user_detail.html",
        get_template_context(
            request,
            tenant_id,
            target_user=user_detail_data,
            emails=user_detail_data.emails,
            privileged_domains=privileged_domains,
            idps=idps,
            idp_requires_mfa=idp_requires_mfa,
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
    first_name: Annotated[str, Form()] = "",
    last_name: Annotated[str, Form()] = "",
):
    """Update a user's name (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Validate inputs
    first_name = first_name.strip()
    last_name = last_name.strip()

    if not first_name or not last_name:
        return RedirectResponse(url=f"/users/{user_id}?error=name_required", status_code=303)

    # Update the user's name via service layer
    from schemas.api import UserUpdate

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.update_user(
            requesting_user, user_id, UserUpdate(first_name=first_name, last_name=last_name)
        )
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

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
        return RedirectResponse(url=f"/users/{user_id}?error=invalid_role", status_code=303)

    # Prevent changing own role (kept at route level for quick UI feedback)
    if str(user_id) == str(user.get("id")):
        return RedirectResponse(
            url=f"/users/{user_id}?error=cannot_change_own_role", status_code=303
        )

    # Update the user's role via service layer
    from schemas.api import UserUpdate

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.update_user(requesting_user, user_id, UserUpdate(role=role))
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        # Handle last_super_admin error
        if exc.code == "last_super_admin":
            return RedirectResponse(
                url=f"/users/{user_id}?error=cannot_demote_last_super_admin", status_code=303
            )
        return render_error_page(request, tenant_id, exc)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}?success=role_updated", status_code=303)


@router.post("/{user_id}/update-idp")
def update_user_idp_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    saml_idp_id: Annotated[str, Form()] = "",
):
    """
    Assign a user to an IdP or set them as a password-only user.

    Super_admin only. Every user must be either:
    - Password user (saml_idp_id empty) - authenticates with password
    - IdP user (saml_idp_id set) - authenticates via SAML

    Security: Assigning to IdP wipes password. Removing from IdP inactivates user.
    """
    # Check super_admin permission
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    # Convert empty string to None for password-only
    idp_id = saml_idp_id.strip() if saml_idp_id else None

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.assign_user_idp(
            requesting_user=requesting_user,
            user_id=user_id,
            saml_idp_id=idp_id,
        )
    except NotFoundError as exc:
        return RedirectResponse(
            url=f"/users/{user_id}?error={exc.code}",
            status_code=303,
        )
    except ValidationError as exc:
        return RedirectResponse(
            url=f"/users/{user_id}?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}?success=idp_updated", status_code=303)


@router.post("/{user_id}/add-email")
def add_user_email_route(
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
    email_lower = email.strip().lower()

    if not email_lower or "@" not in email_lower:
        return RedirectResponse(url=f"/users/{user_id}?error=invalid_email", status_code=303)

    # Extract domain and check if it's privileged (admin can only add privileged domains)
    domain = email_lower.split("@")[1]
    if not settings_service.is_privileged_domain(tenant_id, domain):
        return RedirectResponse(
            url=f"/users/{user_id}?error=domain_not_privileged", status_code=303
        )

    # Add the email via service layer (admin action = auto-verified)
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        emails_service.add_user_email(requesting_user, user_id, email_lower, is_admin_action=True)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ConflictError:
        return RedirectResponse(url=f"/users/{user_id}?error=email_exists", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Get primary email for notification
    primary_email = emails_service.get_primary_email(tenant_id, user_id)
    if primary_email:
        admin_name = f"{user.get('first_name')} {user.get('last_name')}"
        send_secondary_email_added_notification(primary_email, email_lower, admin_name)

    return RedirectResponse(url=f"/users/{user_id}?success=email_added", status_code=303)


@router.post("/{user_id}/remove-email/{email_id}")
def remove_user_email_route(
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

    # Get email address before deletion for notification
    email_address = emails_service.get_email_address_by_id(tenant_id, user_id, email_id)

    # Delete via service layer
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        emails_service.delete_user_email(requesting_user, user_id, email_id)
    except NotFoundError:
        return RedirectResponse(url=f"/users/{user_id}?error=email_not_found", status_code=303)
    except ValidationError as exc:
        if exc.code == "cannot_delete_primary":
            return RedirectResponse(
                url=f"/users/{user_id}?error=cannot_remove_primary", status_code=303
            )
        if exc.code == "must_keep_one_email":
            return RedirectResponse(
                url=f"/users/{user_id}?error=must_keep_one_email", status_code=303
            )
        return render_error_page(request, tenant_id, exc)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Get primary email for notification
    if email_address:
        primary_email = emails_service.get_primary_email(tenant_id, user_id)
        if primary_email:
            admin_name = f"{user.get('first_name')} {user.get('last_name')}"
            send_secondary_email_removed_notification(primary_email, email_address, admin_name)

    return RedirectResponse(url=f"/users/{user_id}?success=email_removed", status_code=303)


@router.post("/{user_id}/promote-email/{email_id}")
def promote_user_email_route(
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

    # Get old primary email info before changing (for notification)
    old_primary_email = emails_service.get_primary_email(tenant_id, user_id)

    # Get the new primary email address (for notification)
    new_primary_email = emails_service.get_email_address_by_id(tenant_id, user_id, email_id)

    # Set primary via service layer
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        emails_service.set_primary_email(requesting_user, user_id, email_id)
        # If already primary, the service returns the email without error
        # Check if it was already primary (email unchanged)
        if old_primary_email == new_primary_email:
            return RedirectResponse(url=f"/users/{user_id}?error=already_primary", status_code=303)
    except NotFoundError:
        return RedirectResponse(url=f"/users/{user_id}?error=email_not_found", status_code=303)
    except ValidationError as exc:
        if exc.code == "email_not_verified":
            return RedirectResponse(
                url=f"/users/{user_id}?error=email_not_verified", status_code=303
            )
        return render_error_page(request, tenant_id, exc)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Send notification to old primary email
    if old_primary_email and new_primary_email and old_primary_email != new_primary_email:
        admin_name = f"{user.get('first_name')} {user.get('last_name')}"
        send_primary_email_changed_notification(old_primary_email, new_primary_email, admin_name)

    return RedirectResponse(url=f"/users/{user_id}?success=email_promoted", status_code=303)


# =============================================================================
# User Inactivation & GDPR Anonymization Routes
# =============================================================================


@router.post("/{user_id}/inactivate")
def inactivate_user_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Inactivate a user account (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.inactivate_user(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/users/{user_id}?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}?success=user_inactivated", status_code=303)


@router.post("/{user_id}/reactivate")
def reactivate_user_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Reactivate an inactivated user account (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.reactivate_user(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/users/{user_id}?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}?success=user_reactivated", status_code=303)


@router.post("/{user_id}/anonymize")
def anonymize_user_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Anonymize a user account - GDPR right to be forgotten (super_admin only)."""
    # Check super_admin permission
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        users_service.anonymize_user(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/users/{user_id}?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"/users/{user_id}?success=user_anonymized", status_code=303)


@router.post("/{user_id}/reset-mfa")
def reset_mfa_route(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
):
    """Reset MFA for a user (admin only)."""
    # Check admin permission
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        mfa_service.reset_user_mfa(requesting_user, user_id)
    except NotFoundError:
        return RedirectResponse(url="/users/list?error=user_not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/users/{user_id}?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Send email notification to the user
    primary_email = emails_service.get_primary_email(tenant_id, user_id)
    if primary_email:
        admin_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
        reset_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        send_mfa_reset_notification(primary_email, admin_name, reset_time)

    return RedirectResponse(url=f"/users/{user_id}?success=mfa_reset", status_code=303)
