"""User MFA management API endpoints."""

from typing import Annotated

import routers.api.v1.users as _pkg
from api_dependencies import get_current_user_api, require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends
from schemas.api import (
    BackupCodesResponse,
    BackupCodesStatusResponse,
    EmailOTPVerifyRequest,
    MFAEnableResponse,
    MFAStatus,
    TOTPSetupResponse,
    TOTPVerifyRequest,
)
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter()


# ============================================================================
# User MFA Management Endpoints
# ============================================================================


@router.get("/me/mfa", response_model=MFAStatus)
def get_current_user_mfa_status(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Get the current user's MFA status.

    Returns:
        MFA status including enabled state, method, and backup codes availability
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        return _pkg.mfa_service.get_mfa_status(requesting_user, user)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/me/mfa/totp/setup", response_model=TOTPSetupResponse)
def setup_current_user_totp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Initiate TOTP (authenticator app) setup for the current user.

    Generates a new TOTP secret and returns it along with the QR code URI.
    The secret is stored unverified until confirmed via the verify endpoint.

    Returns:
        TOTP setup details including secret (for manual entry) and URI (for QR codes)

    Note:
        If TOTP is already active, user must downgrade to email MFA first.
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        return _pkg.mfa_service.setup_totp(requesting_user, user)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/me/mfa/totp/verify", response_model=BackupCodesResponse)
def verify_current_user_totp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    verify_request: TOTPVerifyRequest,
):
    """
    Verify TOTP code and enable TOTP MFA for the current user.

    After successful verification, backup codes are generated and returned.
    These codes should be saved securely as they are only shown once.

    Request Body:
        code: 6-digit TOTP code from authenticator app

    Returns:
        Backup codes (save these securely, only shown once)
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        return _pkg.mfa_service.verify_totp_and_enable(requesting_user, user, verify_request.code)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/me/mfa/email/enable", response_model=MFAEnableResponse)
def enable_current_user_email_mfa(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Enable email-only MFA for the current user.

    If user currently has TOTP enabled, this initiates a downgrade process:
    - An email OTP is sent to the user's primary email
    - The verify-downgrade endpoint must be called with the OTP to complete

    If user has no MFA or already has email MFA, this enables/confirms email MFA directly.

    Returns:
        MFA status if enabled directly, or pending_verification=true if downgrade required
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        response, notification_info = _pkg.mfa_service.enable_email_mfa(requesting_user, user)

        # Send OTP email if downgrade is in progress
        if notification_info:
            _pkg.send_mfa_code_email(notification_info["email"], notification_info["code"])

        return response
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/me/mfa/email/verify-downgrade", response_model=MFAStatus)
def verify_current_user_mfa_downgrade(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    verify_request: EmailOTPVerifyRequest,
):
    """
    Complete TOTP to email MFA downgrade by verifying the email OTP.

    This endpoint should be called after enable_current_user_email_mfa
    returns pending_verification=true.

    Request Body:
        code: 6-digit email OTP code

    Returns:
        Updated MFA status
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        return _pkg.mfa_service.verify_mfa_downgrade(requesting_user, user, verify_request.code)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/me/mfa/disable", response_model=MFAStatus)
def disable_current_user_mfa(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Disable MFA for the current user.

    Removes all MFA protection from the account. TOTP secrets and backup codes
    are deleted.

    Returns:
        Updated MFA status
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        return _pkg.mfa_service.disable_mfa(requesting_user, user)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.get("/me/mfa/backup-codes", response_model=BackupCodesStatusResponse)
def get_current_user_backup_codes_status(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Get backup codes status for the current user.

    Returns the count and usage status of backup codes.
    For security, actual codes are not returned (only shown once when generated).

    Returns:
        Backup codes status (total, used, remaining)
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        return _pkg.mfa_service.get_backup_codes_status(requesting_user, user)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/me/mfa/backup-codes/regenerate", response_model=BackupCodesResponse)
def regenerate_current_user_backup_codes(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Regenerate backup codes for the current user.

    Deletes all existing backup codes and generates new ones.
    Save the returned codes securely as they are only shown once.

    Returns:
        New backup codes (save these securely, only shown once)

    Note:
        MFA must be enabled to regenerate backup codes.
    """
    try:
        requesting_user = build_requesting_user(user, tenant_id, None)
        return _pkg.mfa_service.regenerate_backup_codes(requesting_user, user)
    except ServiceError as e:
        raise translate_to_http_exception(e)


# ============================================================================
# Admin MFA Management Endpoints
# ============================================================================


@router.post("/{user_id}/mfa/reset", response_model=MFAStatus)
def reset_user_mfa(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    Reset MFA for a user (admin operation).

    Disables MFA and deletes all TOTP secrets and backup codes for the user.
    Use this when a user has lost access to their MFA device/codes.

    Requires admin role.

    Path Parameters:
        user_id: User UUID

    Returns:
        Updated MFA status
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        return _pkg.mfa_service.reset_user_mfa(requesting_user, user_id)
    except ServiceError as e:
        raise translate_to_http_exception(e)
