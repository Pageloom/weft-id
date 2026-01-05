"""Event Log API endpoints."""

from typing import Annotated

from api_dependencies import require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query
from schemas.event_log import EventLogItem, EventLogListResponse
from services import event_log as event_log_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/events", tags=["Events"])


@router.get("", response_model=EventLogListResponse)
def list_events(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    page: Annotated[int, Query(ge=1, description="Page number (1-indexed)")] = 1,
    limit: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 50,
):
    """
    List audit log events with pagination.

    Requires admin role.

    Query Parameters:
    - page: Page number (1-indexed, default: 1)
    - limit: Items per page (1-100, default: 50)

    Returns paginated list of events, ordered by most recent first.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return event_log_service.list_events(requesting_user, page=page, limit=limit)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{event_id}", response_model=EventLogItem)
def get_event(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    event_id: str,
):
    """
    Get details of a specific audit log event.

    Requires admin role.

    Path Parameters:
    - event_id: UUID of the event

    Returns full event details including actor name, artifact details,
    and request metadata (IP address, user agent, etc.).
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return event_log_service.get_event(requesting_user, event_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
