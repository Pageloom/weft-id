"""Bulk operations API endpoints for user management."""

from typing import Annotated

import routers.api.v1.users as _pkg
from api_dependencies import require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends
from schemas.api import (
    BulkAddSecondaryEmailsRequest,
    BulkChangePrimaryEmailApplyRequest,
    BulkChangePrimaryEmailPreviewRequest,
    BulkGroupAssignmentRequest,
    BulkUserIdsRequest,
)
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter()


@router.post("/bulk-ops/secondary-emails", status_code=202)
def bulk_add_secondary_emails(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: BulkAddSecondaryEmailsRequest,
):
    """
    Create a background job to add secondary emails to multiple users.

    Requires admin role. Each email is added as a verified secondary address.
    Emails that already exist in the tenant are skipped.

    Request Body:
        items: List of objects with user_id (UUID) and email (email address)

    Returns:
        202 Accepted with task_id and created_at
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        items = [{"user_id": item.user_id, "email": item.email} for item in body.items]
        result = _pkg.bg_tasks_service.create_bulk_add_emails_task(requesting_user, items)
        if result:
            return {
                "task_id": str(result["id"]),
                "created_at": result["created_at"].isoformat(),
            }
        return {"error": "Failed to create task"}
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/bulk-ops/primary-emails/preview", status_code=202)
def bulk_primary_email_preview(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: BulkChangePrimaryEmailPreviewRequest,
):
    """
    Create a dry-run job to preview bulk primary email changes.

    Requires admin role. Computes downstream impact (SP assertions, IdP routing)
    for each proposed email change without modifying any data.

    Request Body:
        items: List of objects with user_id and new_primary_email

    Returns:
        202 Accepted with task_id and created_at.
        Poll GET /api/v1/jobs/{task_id} for results.
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        items = [
            {"user_id": item.user_id, "new_primary_email": item.new_primary_email}
            for item in body.items
        ]
        result = _pkg.bg_tasks_service.create_bulk_primary_email_preview_task(
            requesting_user, items
        )
        if result:
            return {
                "task_id": str(result["id"]),
                "created_at": result["created_at"].isoformat(),
            }
        return {"error": "Failed to create task"}
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/bulk-ops/primary-emails/apply", status_code=202)
def bulk_primary_email_apply(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: BulkChangePrimaryEmailApplyRequest,
):
    """
    Create an execution job to apply bulk primary email changes.

    Requires admin role. Promotes secondary emails to primary and applies
    per-user IdP dispositions (keep, switch, remove).

    Request Body:
        items: List of objects with user_id, new_primary_email, and idp_disposition
        preview_job_id: ID of the completed preview job

    Returns:
        202 Accepted with task_id and created_at.
        Poll GET /api/v1/jobs/{task_id} for results.
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        items = [
            {
                "user_id": item.user_id,
                "new_primary_email": item.new_primary_email,
                "idp_disposition": item.idp_disposition,
            }
            for item in body.items
        ]
        result = _pkg.bg_tasks_service.create_bulk_primary_email_apply_task(
            requesting_user, items, body.preview_job_id
        )
        if result:
            return {
                "task_id": str(result["id"]),
                "created_at": result["created_at"].isoformat(),
            }
        return {"error": "Failed to create task"}
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/bulk-ops/inactivate/preview")
def preview_bulk_inactivate(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: BulkUserIdsRequest,
):
    """
    Preview which users are eligible for bulk inactivation.

    Returns eligible user IDs and a list of skipped users with reasons.
    No data is modified.

    Request Body:
        user_ids: List of user ID strings

    Returns:
        eligible_ids, eligible count, skipped list with reasons
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        return _pkg.bg_tasks_service.preview_bulk_inactivate(requesting_user, body.user_ids)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/bulk-ops/reactivate/preview")
def preview_bulk_reactivate(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: BulkUserIdsRequest,
):
    """
    Preview which users are eligible for bulk reactivation.

    Returns eligible user IDs and a list of skipped users with reasons.
    No data is modified.

    Request Body:
        user_ids: List of user ID strings

    Returns:
        eligible_ids, eligible count, skipped list with reasons
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        return _pkg.bg_tasks_service.preview_bulk_reactivate(requesting_user, body.user_ids)
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/bulk-ops/inactivate", status_code=202)
def bulk_inactivate_users(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: BulkUserIdsRequest,
):
    """
    Create a background job to inactivate multiple users.

    Requires admin role. Each user is inactivated individually with
    guardrails (last super admin, service users). OAuth tokens are
    revoked for each inactivated user.

    Request Body:
        user_ids: List of user ID strings

    Returns:
        202 Accepted with task_id and created_at
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        result = _pkg.bg_tasks_service.create_bulk_inactivate_task(requesting_user, body.user_ids)
        if result:
            return {
                "task_id": str(result["id"]),
                "created_at": result["created_at"].isoformat(),
            }
        return {"error": "Failed to create task"}
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/bulk-ops/reactivate", status_code=202)
def bulk_reactivate_users(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: BulkUserIdsRequest,
):
    """
    Create a background job to reactivate multiple users.

    Requires admin role. Each user is reactivated individually.
    Anonymized users and users that are not inactivated are skipped.

    Request Body:
        user_ids: List of user ID strings

    Returns:
        202 Accepted with task_id and created_at
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        result = _pkg.bg_tasks_service.create_bulk_reactivate_task(requesting_user, body.user_ids)
        if result:
            return {
                "task_id": str(result["id"]),
                "created_at": result["created_at"].isoformat(),
            }
        return {"error": "Failed to create task"}
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/bulk-ops/group-assignment/preview")
def preview_bulk_group_assignment(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: BulkGroupAssignmentRequest,
):
    """
    Preview which users are eligible for bulk group assignment.

    Returns eligible user IDs and a list of skipped users with reasons.
    No data is modified.

    Request Body:
        group_id: Target group UUID
        user_ids: List of user ID strings

    Returns:
        eligible_ids, eligible count, skipped list with reasons, group info
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        return _pkg.bg_tasks_service.preview_bulk_group_assignment(
            requesting_user, body.group_id, body.user_ids
        )
    except ServiceError as e:
        raise translate_to_http_exception(e)


@router.post("/bulk-ops/group-assignment", status_code=202)
def bulk_group_assignment(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: BulkGroupAssignmentRequest,
):
    """
    Create a background job to add multiple users to a group.

    Requires admin role. Each user is added individually with per-user
    error handling. IdP groups are rejected. Already-members are skipped.

    Request Body:
        group_id: Target group UUID
        user_ids: List of user ID strings

    Returns:
        202 Accepted with task_id and created_at
    """
    try:
        requesting_user = build_requesting_user(admin, tenant_id, None)
        result = _pkg.bg_tasks_service.create_bulk_group_assignment_task(
            requesting_user, body.group_id, body.user_ids
        )
        if result:
            return {
                "task_id": str(result["id"]),
                "created_at": result["created_at"].isoformat(),
            }
        return {"error": "Failed to create task"}
    except ServiceError as e:
        raise translate_to_http_exception(e)
