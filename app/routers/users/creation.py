"""User creation routes."""

from typing import Annotated

from dependencies import get_current_user, get_tenant_id_from_request, require_current_user
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import has_page_access
from schemas.api import UserCreate
from services import settings as settings_service
from services import users as users_service
from services.exceptions import ConflictError, ForbiddenError, ServiceError, ValidationError
from services.types import RequestingUser
from utils.email import send_new_user_invitation, send_new_user_privileged_domain_notification
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_current_user)],
    include_in_schema=False,
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
        request,
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
    email: Annotated[str, Form(max_length=320)] = "",
    first_name: Annotated[str, Form(max_length=255)] = "",
    last_name: Annotated[str, Form(max_length=255)] = "",
    role: Annotated[str, Form(max_length=20)] = "member",
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
    tid = requesting_user["tenant_id"]

    if is_privileged:
        # Auto-verify email for privileged domains
        email_result = users_service.add_verified_email_with_nonce(
            tenant_id, user_id, email, is_primary=True
        )

        if not email_result:
            return RedirectResponse(url="/users/new?error=email_creation_failed", status_code=303)

        # Send welcome email with password set link (includes nonce for one-time use)
        email_id = email_result["id"]
        sp_nonce = email_result["set_password_nonce"]
        password_set_url = f"{request.base_url}set-password?email_id={email_id}&nonce={sp_nonce}"
        send_new_user_privileged_domain_notification(
            email, admin_name, org_name, password_set_url, tenant_id=tid
        )

        # Auto-assign to domain-linked groups
        settings_service.auto_assign_user_to_domain_groups(tenant_id, user_id, email, user["id"])
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
            send_new_user_invitation(email, admin_name, org_name, verification_url, tenant_id=tid)

    return RedirectResponse(url=f"/users/{user_id}/profile?success=user_created", status_code=303)
