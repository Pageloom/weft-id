"""Background Jobs API endpoints."""

from typing import Annotated

from api_dependencies import get_current_user_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from schemas.bg_tasks import JobDetail, JobListResponse
from services import bg_tasks as bg_tasks_service
from services.exceptions import ServiceError
from starlette import status
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/jobs", tags=["Jobs"])


class DeleteJobsRequest(BaseModel):
    """Request body for deleting jobs."""

    job_ids: list[Annotated[str, Field(min_length=1, max_length=36)]]


class DeleteJobsResponse(BaseModel):
    """Response for delete jobs endpoint."""

    deleted: int


@router.get("", response_model=JobListResponse)
def list_jobs(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    List background jobs for the authenticated user.

    Any authenticated user can list their own jobs.

    Returns list of jobs created by the user with a flag indicating
    if there are active (pending/processing) jobs for polling purposes.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return bg_tasks_service.list_user_jobs(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{job_id}", response_model=JobDetail)
def get_job(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    job_id: str,
):
    """
    Get details of a specific job.

    User can only access their own jobs.

    Returns full job details including result and error information.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return bg_tasks_service.get_job_detail(requesting_user, job_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("", response_model=DeleteJobsResponse, status_code=status.HTTP_200_OK)
def delete_jobs(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    request: DeleteJobsRequest,
):
    """
    Delete completed or failed jobs.

    User can only delete their own jobs that are in completed or failed state.
    Active (pending/processing) jobs cannot be deleted.

    Returns the number of jobs successfully deleted.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        count = bg_tasks_service.delete_jobs(requesting_user, request.job_ids)
        return DeleteJobsResponse(deleted=count)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
