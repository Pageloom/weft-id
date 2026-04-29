"""User attribute API endpoints (canonical + IdP-mirror).

Endpoints:

* Admin / cross-user (under ``/api/v1/users/{user_id}``):
    - ``GET    /attributes`` -- list canonical attributes
    - ``PUT    /attributes/{key}`` -- set/update one canonical attribute
    - ``DELETE /attributes/{key}`` -- clear one canonical attribute
    - ``GET    /idp-attributes`` -- read-only IdP-mirror snapshot (admin only)

* Self-service (under ``/api/v1/me``):
    - ``GET    /attributes``
    - ``PUT    /attributes/{key}``
    - ``DELETE /attributes/{key}``

Self-edit on a locked attribute returns 403 with a structured detail body
that carries ``error_code`` so clients can surface the standard
``attribute_locked`` reason.
"""

from __future__ import annotations

from typing import Annotated

from api_dependencies import get_current_user_api, require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, HTTPException
from schemas.api import UserAttributeRow, UserAttributeWrite, UserIdpAttributeRow
from services import users as users_service
from services.exceptions import ForbiddenError, ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter()
me_router = APIRouter(prefix="/api/v1/me", tags=["Me"])


def _structured_forbidden(exc: ForbiddenError) -> HTTPException:
    """Translate a ForbiddenError to a 403 with a structured body.

    Uses the standard ``{detail, error_code}`` shape so callers can
    distinguish ``attribute_locked`` from other forbiddens without
    string-matching the message.
    """
    return HTTPException(
        status_code=403,
        detail={"detail": exc.message, "error_code": exc.code},
    )


def _row_to_schema(row: dict) -> UserAttributeRow:
    return UserAttributeRow(
        attribute_key=row["attribute_key"],
        value=row["value"],
        updated_at=row["updated_at"],
    )


# =============================================================================
# Admin / cross-user endpoints (mounted at /api/v1/users/{user_id})
# =============================================================================


@router.get("/{user_id}/attributes", response_model=list[UserAttributeRow])
def list_user_attributes_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    user_id: str,
):
    """
    List canonical user attributes for a user.

    Authorization: a user can read their own attributes; admins can read
    any user in their tenant.

    Path Parameters:
        user_id: Target user UUID.

    Returns:
        List of attribute rows ordered by ``attribute_key``.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        rows = users_service.list_user_attributes(requesting_user, user_id)
    except ForbiddenError as exc:
        raise _structured_forbidden(exc)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return [_row_to_schema(row) for row in rows]


@router.put(
    "/{user_id}/attributes/{attribute_key}",
    response_model=UserAttributeRow,
)
def set_user_attribute_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    user_id: str,
    attribute_key: str,
    payload: UserAttributeWrite,
):
    """
    Set or update one canonical user attribute.

    Authorization: a user can edit their own non-locked attributes;
    admins can edit any user. Self-edit on a locked attribute returns
    403 with ``error_code="attribute_locked"``.

    Path Parameters:
        user_id: Target user UUID.
        attribute_key: One of the 14 standard attribute keys.

    Request Body:
        value: The new value (validated per attribute type).

    Returns:
        The upserted attribute row.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        row = users_service.set_user_attribute(
            requesting_user, user_id, attribute_key, payload.value
        )
    except ForbiddenError as exc:
        raise _structured_forbidden(exc)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return _row_to_schema(row)


@router.delete("/{user_id}/attributes/{attribute_key}", status_code=204)
def clear_user_attribute_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    user_id: str,
    attribute_key: str,
):
    """
    Delete one canonical user attribute row.

    Authorization: a user can clear their own non-locked attributes;
    admins can clear any user. Self-clear on a locked attribute returns
    403 with ``error_code="attribute_locked"``.

    Path Parameters:
        user_id: Target user UUID.
        attribute_key: One of the 14 standard attribute keys.

    Returns:
        204 No Content (idempotent: returns 204 even if there was nothing
        to delete).
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        users_service.clear_user_attribute(requesting_user, user_id, attribute_key)
    except ForbiddenError as exc:
        raise _structured_forbidden(exc)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return None


@router.get("/{user_id}/idp-attributes", response_model=list[UserIdpAttributeRow])
def list_user_idp_attributes_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    List IdP-mirror snapshot rows for a user.

    Read-only diagnostic surface: shows what each connected IdP last
    sent, even if the value is not mirrored into the canonical
    ``user_attributes`` store.

    Authorization: admin / super_admin only.

    Path Parameters:
        user_id: Target user UUID.

    Returns:
        List of IdP-mirror rows ordered by ``idp_id`` then
        ``attribute_key``.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        rows = users_service.list_user_idp_attributes(requesting_user, user_id)
    except ForbiddenError as exc:
        raise _structured_forbidden(exc)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return [
        UserIdpAttributeRow(
            idp_id=str(row["idp_id"]),
            attribute_key=row["attribute_key"],
            value=row["value"],
            updated_at=row["updated_at"],
        )
        for row in rows
    ]


# =============================================================================
# Self-service endpoints (mounted at /api/v1/me)
# =============================================================================


@me_router.get("/attributes", response_model=list[UserAttributeRow])
def list_my_attributes(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    List the current user's canonical attributes.

    Returns:
        List of attribute rows ordered by ``attribute_key``.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        rows = users_service.list_user_attributes(requesting_user, str(user["id"]))
    except ForbiddenError as exc:
        raise _structured_forbidden(exc)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return [_row_to_schema(row) for row in rows]


@me_router.put("/attributes/{attribute_key}", response_model=UserAttributeRow)
def set_my_attribute(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    attribute_key: str,
    payload: UserAttributeWrite,
):
    """
    Set or update one of the current user's canonical attributes.

    Locked attributes (``locked_for_users=true``) cannot be set by the
    user themselves; the response is 403 with
    ``error_code="attribute_locked"``.

    Path Parameters:
        attribute_key: One of the 14 standard attribute keys.

    Request Body:
        value: The new value (validated per attribute type).

    Returns:
        The upserted attribute row.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        row = users_service.set_user_attribute(
            requesting_user, str(user["id"]), attribute_key, payload.value
        )
    except ForbiddenError as exc:
        raise _structured_forbidden(exc)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return _row_to_schema(row)


@me_router.delete("/attributes/{attribute_key}", status_code=204)
def clear_my_attribute(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    attribute_key: str,
):
    """
    Clear one of the current user's canonical attributes.

    Locked attributes cannot be cleared by the user themselves; the
    response is 403 with ``error_code="attribute_locked"``.

    Path Parameters:
        attribute_key: One of the 14 standard attribute keys.

    Returns:
        204 No Content.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        users_service.clear_user_attribute(requesting_user, str(user["id"]), attribute_key)
    except ForbiddenError as exc:
        raise _structured_forbidden(exc)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return None
