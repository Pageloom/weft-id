"""User email management API endpoints."""

from typing import Annotated

import routers.api.v1.users as _pkg
from api_dependencies import get_current_user_api, require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends
from schemas.api import (
    EmailCreate,
    EmailInfo,
    EmailList,
)
from services.exceptions import ConflictError, ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter()


# ============================================================================
# User Email Management Endpoints
# ============================================================================


@router.get("/me/emails", response_model=EmailList)
def list_current_user_emails(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    List all email addresses for the current user.

    Returns:
        List of email addresses with their verification status
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        emails = _pkg.emails_service.list_user_emails(requesting_user, str(user["id"]))
        return EmailList(items=emails)
    except ServiceError as e:
        raise translate_to_http_exception(e)


# ============================================================================
# Admin Email Management Endpoints
# ============================================================================


@router.get("/{user_id}/emails", response_model=EmailList)
def list_user_emails(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    List all email addresses for a specific user.

    Requires admin role.

    Path Parameters:
        user_id: User UUID

    Returns:
        List of email addresses with their verification status
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        emails = _pkg.emails_service.list_user_emails(requesting_user, user_id)
        return EmailList(items=emails)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/{user_id}/emails", response_model=EmailInfo, status_code=201)
def add_user_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
    email_data: EmailCreate,
):
    """
    Add a new email address to a user's account (admin operation).

    Requires admin role. Email is added as verified (no verification required).

    Path Parameters:
        user_id: User UUID

    Request Body:
        email: Email address to add

    Returns:
        Created email info (verified)

    Note:
        Sends notification to user's primary email about the added address.
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)

        # Get primary email before adding (for notification)
        primary_email = _pkg.emails_service.get_primary_email(tenant_id, user_id)

        # Add verified email via service (admin action)
        email_info = _pkg.emails_service.add_user_email(
            requesting_user,
            user_id,
            email_data.email,
            is_admin_action=True,
        )

        # Send notification to primary email
        if primary_email:
            admin_name = f"{admin['first_name']} {admin['last_name']}"
            _pkg.send_secondary_email_added_notification(
                primary_email,
                email_info.email,
                admin_name,
                tenant_id=requesting_user["tenant_id"],
            )

        return email_info
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.delete("/{user_id}/emails/{email_id}", status_code=204)
def delete_user_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
    email_id: str,
):
    """
    Delete an email address from a user's account (admin operation).

    Requires admin role.

    Path Parameters:
        user_id: User UUID
        email_id: Email UUID

    Returns:
        204 No Content on success

    Note:
        Cannot delete the primary email address.
        Sends notification to user's primary email about the removal.
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)

        # Get email address before deletion for notification
        email_address = _pkg.emails_service.get_email_address_by_id(tenant_id, user_id, email_id)

        # Delete the email (service handles validation)
        _pkg.emails_service.delete_user_email(requesting_user, user_id, email_id)

        # Send notification to primary email
        if email_address:
            primary_email = _pkg.emails_service.get_primary_email(tenant_id, user_id)
            if primary_email and primary_email != email_address:
                admin_name = f"{admin['first_name']} {admin['last_name']}"
                _pkg.send_secondary_email_removed_notification(
                    primary_email,
                    email_address,
                    admin_name,
                    tenant_id=requesting_user["tenant_id"],
                )

        return None
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/{user_id}/emails/{email_id}/set-primary", response_model=EmailInfo)
def set_user_primary_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
    email_id: str,
    confirm_routing_change: bool = False,
):
    """
    Set an email address as the primary email for a user (admin operation).

    Requires admin role.

    Path Parameters:
        user_id: User UUID
        email_id: Email UUID

    Query Parameters:
        confirm_routing_change: Set to true to acknowledge and proceed with an
            IdP routing change. Required when promoting an email whose domain
            routes to a different IdP than the user's current assignment.

    Returns:
        Updated email info

    Errors:
        409 Conflict (routing_change): Returned when the promotion would change
            the user's IdP routing and confirm_routing_change is not set. The
            response body includes current_idp_name and new_idp_name.

    Note:
        Email must be verified before it can be set as primary.
        Sends notification to the old primary email about the change.
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)

        # Check for IdP routing change before proceeding
        if not confirm_routing_change:
            email_address = _pkg.emails_service.get_email_address_by_id(
                tenant_id, user_id, email_id
            )
            if email_address:
                routing_info = _pkg.emails_service.check_routing_change(
                    tenant_id, user_id, email_address
                )
                if routing_info:
                    raise ConflictError(
                        message=("Promoting this email will change the user's IdP routing"),
                        code="routing_change",
                        details=routing_info,
                    )

        # Get current primary email for notification before change
        old_primary = _pkg.emails_service.get_primary_email(tenant_id, user_id)

        # Set new primary (service handles all validation)
        result = _pkg.emails_service.set_primary_email(requesting_user, user_id, email_id)

        # Send notification to old primary email if it changed
        if old_primary and old_primary != result.email:
            admin_name = f"{admin['first_name']} {admin['last_name']}"
            _pkg.send_primary_email_changed_notification(
                old_primary,
                result.email,
                admin_name,
                tenant_id=requesting_user["tenant_id"],
            )

        return result
    except ServiceError as e:
        raise translate_to_http_exception(e)
