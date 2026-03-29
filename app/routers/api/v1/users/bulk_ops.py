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
