"""Bulk user attribute update API endpoints."""

from typing import Annotated

from api_dependencies import require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from schemas.bg_tasks import JobListItem, JobStatus
from services import bulk_update as bulk_update_service
from services.exceptions import ServiceError, ValidationError
from starlette import status
from utils.service_errors import translate_to_http_exception

router = APIRouter(
    prefix="/api/v1/users/bulk-update",
    tags=["Bulk Update"],
)


@router.post(
    "/request-download",
    response_model=JobListItem,
    status_code=status.HTTP_201_CREATED,
)
def request_download(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
):
    """Create a background job to generate the user template spreadsheet.

    Requires admin role.

    Returns the created job information.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        result = bulk_update_service.create_download_task(requesting_user)
        if not result:
            raise ServiceError(
                message="Failed to create download task",
                code="task_creation_failed",
            )
        return JobListItem(
            id=str(result["id"]),
            job_type="export_users_template",
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


@router.get("/download/{job_id}")
def download_template(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    job_id: str,
):
    """Download the generated user template spreadsheet.

    Requires admin role.

    Returns 202 if job is still processing, the file if complete, or error.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        download_info = bulk_update_service.get_download(requesting_user, job_id)

        if download_info["storage_type"] == "spaces":
            return RedirectResponse(
                url=download_info["url"],
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            )
        else:
            return FileResponse(
                path=download_info["path"],
                filename=download_info["filename"],
                media_type=download_info.get(
                    "content_type",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ),
            )
    except ValidationError as exc:
        if exc.code == "job_pending":
            return JSONResponse(
                status_code=202,
                content={
                    "status": exc.details.get("status", "pending"),
                    "message": exc.message,
                },
            )
        raise translate_to_http_exception(exc)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/upload",
    response_model=JobListItem,
    status_code=status.HTTP_201_CREATED,
)
async def upload_spreadsheet(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    file: UploadFile,
):
    """Upload a filled-in spreadsheet for bulk user attribute updates.

    Requires admin role.

    Validates the file structure, saves it to storage, and creates a
    background task to process the rows. Returns the job information.
    Poll the job status via GET /api/v1/jobs/{id} for results.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        file_data = await file.read()
        result = bulk_update_service.create_upload_task(requesting_user, file_data)
        if not result:
            raise ServiceError(
                message="Failed to create upload task",
                code="task_creation_failed",
            )
        return JobListItem(
            id=str(result["id"]),
            job_type="bulk_update_users",
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
