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
    EmailVerifyRequest,
)
from services.exceptions import ServiceError
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


@router.post("/me/emails", response_model=EmailInfo, status_code=201)
def add_current_user_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    email_data: EmailCreate,
):
    """
    Add a new email address to the current user's account.

    The email will be unverified until the user clicks the verification link
    sent to the email address.

    Request Body:
        email: Email address to add

    Returns:
        Created email info (unverified)

    Note:
        May be restricted by tenant security settings (allow_users_add_emails).
        Super admins can always add emails.
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        user_id = str(user["id"])

        # Get tenant setting for user email add permission
        allow_add = _pkg.settings_service.can_users_add_emails(tenant_id)

        # Add email via service (user action, not admin)
        email_info = _pkg.emails_service.add_user_email(
            requesting_user,
            user_id,
            email_data.email,
            is_admin_action=False,
            allow_users_add_emails=allow_add,
        )

        # Get verification info to send email
        verification_info = _pkg.emails_service.resend_verification(
            requesting_user, user_id, email_info.id
        )

        # Send verification email
        verification_url = (
            f"/api/v1/users/me/emails/{email_info.id}/verify"
            f"?nonce={verification_info['verify_nonce']}"
        )
        _pkg.send_email_verification(email_info.email, verification_url)

        return email_info
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.delete("/me/emails/{email_id}", status_code=204)
def delete_current_user_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    email_id: str,
):
    """
    Delete an email address from the current user's account.

    Path Parameters:
        email_id: Email UUID

    Returns:
        204 No Content on success

    Note:
        Cannot delete the primary email address.
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        _pkg.emails_service.delete_user_email(requesting_user, str(user["id"]), email_id)
        return None
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/me/emails/{email_id}/set-primary", response_model=EmailInfo)
def set_current_user_primary_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    email_id: str,
):
    """
    Set an email address as the primary email for the current user.

    Path Parameters:
        email_id: Email UUID

    Returns:
        Updated email info

    Note:
        Email must be verified before it can be set as primary.
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        return _pkg.emails_service.set_primary_email(requesting_user, str(user["id"]), email_id)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/me/emails/{email_id}/resend-verification")
def resend_current_user_email_verification(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    email_id: str,
):
    """
    Resend verification email for an unverified email address.

    Path Parameters:
        email_id: Email UUID

    Returns:
        Success message
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        verification_info = _pkg.emails_service.resend_verification(
            requesting_user, str(user["id"]), email_id
        )

        # Send verification email
        verification_url = (
            f"/api/v1/users/me/emails/{verification_info['email_id']}/verify"
            f"?nonce={verification_info['verify_nonce']}"
        )
        _pkg.send_email_verification(verification_info["email"], verification_url)

        return {"message": "Verification email sent"}
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/me/emails/{email_id}/verify", response_model=EmailInfo)
def verify_current_user_email(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    email_id: str,
    verify_request: EmailVerifyRequest,
):
    """
    Verify an email address using the verification nonce.

    Path Parameters:
        email_id: Email UUID

    Request Body:
        nonce: Verification nonce from email link

    Returns:
        Verified email info
    """
    try:
        return _pkg.emails_service.verify_email(
            tenant_id, email_id, str(user["id"]), verify_request.nonce
        )
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
                primary_email, email_info.email, admin_name
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
                    primary_email, email_address, admin_name
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
):
    """
    Set an email address as the primary email for a user (admin operation).

    Requires admin role.

    Path Parameters:
        user_id: User UUID
        email_id: Email UUID

    Returns:
        Updated email info

    Note:
        Email must be verified before it can be set as primary.
        Sends notification to the old primary email about the change.
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)

        # Get current primary email for notification before change
        old_primary = _pkg.emails_service.get_primary_email(tenant_id, user_id)

        # Set new primary (service handles all validation)
        result = _pkg.emails_service.set_primary_email(requesting_user, user_id, email_id)

        # Send notification to old primary email if it changed
        if old_primary and old_primary != result.email:
            admin_name = f"{admin['first_name']} {admin['last_name']}"
            _pkg.send_primary_email_changed_notification(old_primary, result.email, admin_name)

        return result
    except ServiceError as e:
        raise translate_to_http_exception(e)
