"""Inbound SCIM Users endpoints.

- `GET  /Users[/<id>]` -- read endpoints (iteration 2).
- `POST /Users` -- create or merge (iteration 3).
- `PUT  /Users/{id}` -- full replace (iteration 3).
- `PATCH /Users/{id}` -- partial update, supports Entra batched ops (iteration 3).
- `DELETE /Users/{id}` -- soft-delete via inactivate (iteration 3).
"""

from __future__ import annotations

from typing import Annotated, Any

from api_dependencies import InboundScimContext, require_inbound_scim_auth
from fastapi import APIRouter, Body, Depends, Query, Request, Response
from schemas.scim import LIST_RESPONSE_SCHEMA
from services.scim import inbound_read
from services.scim.inbound_write import (
    ScimWriteError,
    create_or_merge_user,
    patch_user,
    replace_user,
    soft_delete_user,
)
from utils.scim_responses import scim_json_response
from utils.urls import tenant_base_url

from ._query import FilterParseError, parse_eq_filter, parse_pagination
from .errors import ScimErrorException


def _raise_from_write_error(exc: ScimWriteError) -> None:
    raise ScimErrorException(
        status_code=exc.status_code,
        detail=exc.detail,
        scim_type=exc.scim_type,
    ) from None


router = APIRouter()

# Filter attributes accepted by the Users endpoint per the iteration
# scope. The Schemas advertise these explicitly via the same allowlist.
_USER_FILTER_ATTRS = ["userName", "externalId"]


def _users_base(request: Request, idp_id: str) -> str:
    return f"{tenant_base_url(request)}/scim/v2/inbound/{idp_id}/Users"


@router.get("/Users")
def list_users(
    request: Request,
    idp_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
    filter: Annotated[str | None, Query(max_length=2048)] = None,  # noqa: A002 -- SCIM uses this
    startIndex: Annotated[int | None, Query(ge=0)] = None,  # noqa: N803 -- SCIM names
    count: Annotated[int | None, Query(ge=0, le=200)] = None,
):
    """SCIM 2.0 list Users (RFC 7644 §3.4.2).

    Filter: `userName eq "<email>"` or `externalId eq "<id>"`. Other
    operators / attributes return 400 invalidFilter.

    Pagination: `startIndex` is 1-indexed (values < 1 treated as 1).
    `count` is clamped to the iteration's documented maximum.
    """
    try:
        parsed_filter = parse_eq_filter(filter, allowed_attributes=_USER_FILTER_ATTRS)
    except FilterParseError as exc:
        raise ScimErrorException(
            status_code=400,
            detail=exc.detail,
            scim_type=exc.scim_type,
        ) from None

    user_name = external_id = None
    if parsed_filter is not None:
        attr, value = parsed_filter
        if attr == "userName":
            user_name = value
        elif attr == "externalId":
            external_id = value

    si, c = parse_pagination(startIndex, count)
    users_base = _users_base(request, idp_id)

    payloads, total = inbound_read.list_users(
        ctx["tenant_id"],
        ctx["idp_id"],
        user_name=user_name,
        external_id=external_id,
        start_index=si,
        count=c,
        location_builder=lambda user_id: f"{users_base}/{user_id}",
    )

    return scim_json_response(
        {
            "schemas": [LIST_RESPONSE_SCHEMA],
            "totalResults": total,
            "startIndex": si,
            "itemsPerPage": len(payloads),
            "Resources": payloads,
        }
    )


@router.get("/Users/{user_id}")
def get_user(
    request: Request,
    idp_id: str,
    user_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
):
    """SCIM 2.0 fetch a single User. 404 when not bound to this IdP."""
    location = f"{_users_base(request, idp_id)}/{user_id}"
    payload = inbound_read.get_user(
        ctx["tenant_id"],
        ctx["idp_id"],
        user_id,
        location=location,
    )
    if payload is None:
        raise ScimErrorException(status_code=404, detail="User not found")
    return scim_json_response(payload)


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


@router.post("/Users")
def create_user(
    request: Request,
    idp_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
    payload: Annotated[dict[str, Any], Body()],
):
    """SCIM 2.0 `POST /Users`: create or merge.

    Returns 201 on a brand-new user; 200 on merge into an existing
    user matched by upstream `externalId` (preferred) or canonical
    primary email. Body is the resulting SCIM User resource.
    """
    users_base = _users_base(request, idp_id)
    try:
        resource, created = create_or_merge_user(
            ctx["tenant_id"],
            ctx["idp_id"],
            payload,
            location_builder=lambda uid: f"{users_base}/{uid}",
        )
    except ScimWriteError as exc:
        _raise_from_write_error(exc)
        return  # pragma: no cover -- _raise_from_write_error always raises

    status = 201 if created else 200
    location = resource.get("meta", {}).get("location")
    return scim_json_response(resource, status_code=status, location=location)


@router.put("/Users/{user_id}")
def replace_user_endpoint(
    request: Request,
    idp_id: str,
    user_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
    payload: Annotated[dict[str, Any], Body()],
):
    """SCIM 2.0 `PUT /Users/{id}`: full-replace semantics."""
    users_base = _users_base(request, idp_id)
    try:
        resource = replace_user(
            ctx["tenant_id"],
            ctx["idp_id"],
            user_id,
            payload,
            location_builder=lambda uid: f"{users_base}/{uid}",
        )
    except ScimWriteError as exc:
        _raise_from_write_error(exc)
        return  # pragma: no cover
    return scim_json_response(resource)


@router.patch("/Users/{user_id}")
def patch_user_endpoint(
    request: Request,
    idp_id: str,
    user_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
    payload: Annotated[dict[str, Any], Body()],
):
    """SCIM 2.0 `PATCH /Users/{id}`: simple-path + batched-op support."""
    users_base = _users_base(request, idp_id)
    try:
        resource = patch_user(
            ctx["tenant_id"],
            ctx["idp_id"],
            user_id,
            payload,
            location_builder=lambda uid: f"{users_base}/{uid}",
        )
    except ScimWriteError as exc:
        _raise_from_write_error(exc)
        return  # pragma: no cover
    return scim_json_response(resource)


@router.delete("/Users/{user_id}")
def delete_user_endpoint(
    idp_id: str,
    user_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
):
    """SCIM 2.0 `DELETE /Users/{id}`: soft-delete via inactivate."""
    try:
        soft_delete_user(ctx["tenant_id"], ctx["idp_id"], user_id)
    except ScimWriteError as exc:
        _raise_from_write_error(exc)
        return  # pragma: no cover
    return Response(status_code=204)
