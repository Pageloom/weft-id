"""Exports API endpoints."""

from typing import Annotated

from api_dependencies import require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, RedirectResponse
from schemas.bg_tasks import JobListItem, JobStatus
from schemas.event_log import ExportListResponse, ExportRequest
from services import bg_tasks as bg_tasks_service
from services import exports as exports_service
from services.exceptions import ServiceError
from starlette import status
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/exports", tags=["Exports"])


@router.get("", response_model=ExportListResponse)
def list_exports(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
):
    """
    List available export files.

    Requires admin role.

    Returns list of available export files with their metadata.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return exports_service.list_exports(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("", response_model=JobListItem, status_code=status.HTTP_201_CREATED)
def create_export(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    body: ExportRequest | None = None,
):
    """
    Create a new audit log export task.

    Requires admin role.

    Creates a background task to export event logs as encrypted XLSX.

    Accepted fields:
    - start_date: Optional start date filter (inclusive), ISO 8601 (YYYY-MM-DD)
    - end_date: Optional end date filter (inclusive), ISO 8601 (YYYY-MM-DD)

    Omit both dates or send an empty body to export all events.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        start_date = body.start_date if body else None
        end_date = body.end_date if body else None
        result = bg_tasks_service.create_export_task(
            requesting_user, start_date=start_date, end_date=end_date
        )
        if not result:
            raise ServiceError(
                message="Failed to create export task",
                code="export_creation_failed",
            )
        # Return a JobListItem with the basic info
        return JobListItem(
            id=str(result["id"]),
            job_type="export_events",
            status=JobStatus.PENDING,
            created_at=result["created_at"],
            started_at=None,
            completed_at=None,
            error=None,
            result=None,
            created_by=requesting_user["id"],
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{export_id}/download")
def download_export(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    export_id: str,
):
    """
    Download an export file.

    Requires admin role.

    For cloud storage (Spaces): Returns a redirect to the signed download URL.
    For local storage: Returns the file directly.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        download_info = exports_service.get_download(requesting_user, export_id)

        if download_info["storage_type"] == "spaces":
            return RedirectResponse(
                url=download_info["url"],
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            )
        else:
            # Local storage - stream the file
            return FileResponse(
                path=download_info["path"],
                filename=download_info["filename"],
                media_type=download_info.get("content_type", "application/octet-stream"),
            )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
