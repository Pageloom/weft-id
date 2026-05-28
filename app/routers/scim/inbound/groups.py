"""Inbound SCIM Groups endpoints.

- `GET  /Groups[/<id>]` -- read endpoints (iteration 2).
- `POST /Groups` -- create an IdP group (iteration 4).
- `PUT  /Groups/{id}` -- full replace of displayName + members (iteration 4).
- `PATCH /Groups/{id}` -- partial update with Okta + Entra patterns (iteration 4).
- `DELETE /Groups/{id}` -- remove the IdP group (iteration 4).

`weftid` (manually managed) groups are NEVER visible via this endpoint --
they are an internal organisational construct, not directory state the
IdP is allowed to enumerate or mutate.
"""

from __future__ import annotations

from typing import Annotated, Any

from api_dependencies import InboundScimContext, require_inbound_scim_auth
from fastapi import APIRouter, Body, Depends, Query, Request, Response
from schemas.scim import LIST_RESPONSE_SCHEMA
from services.scim import inbound_read
from services.scim.inbound_group_write import (
    create_group,
    delete_group,
    patch_group,
    replace_group,
)
from services.scim.inbound_write import ScimWriteError
from utils.scim_responses import scim_json_response
from utils.urls import tenant_base_url

from ._query import FilterParseError, parse_eq_filter, parse_pagination
from .errors import ScimErrorException

router = APIRouter()

_GROUP_FILTER_ATTRS = ["displayName"]


def _raise_from_write_error(exc: ScimWriteError) -> None:
    raise ScimErrorException(
        status_code=exc.status_code,
        detail=exc.detail,
        scim_type=exc.scim_type,
    ) from None


def _groups_base(request: Request, idp_id: str) -> str:
    return f"{tenant_base_url(request)}/scim/v2/inbound/{idp_id}/Groups"


def _users_base(request: Request, idp_id: str) -> str:
    return f"{tenant_base_url(request)}/scim/v2/inbound/{idp_id}/Users"


@router.get("/Groups")
def list_groups(
    request: Request,
    idp_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
    filter: Annotated[str | None, Query(max_length=2048)] = None,  # noqa: A002
    startIndex: Annotated[int | None, Query(ge=0)] = None,  # noqa: N803
    count: Annotated[int | None, Query(ge=0, le=200)] = None,
):
    """SCIM 2.0 list Groups (RFC 7644 §3.4.2)."""
    try:
        parsed_filter = parse_eq_filter(filter, allowed_attributes=_GROUP_FILTER_ATTRS)
    except FilterParseError as exc:
        raise ScimErrorException(
            status_code=400,
            detail=exc.detail,
            scim_type=exc.scim_type,
        ) from None

    display_name = None
    if parsed_filter is not None:
        _attr, value = parsed_filter
        display_name = value

    si, c = parse_pagination(startIndex, count)
    groups_base = _groups_base(request, idp_id)
    users_base = _users_base(request, idp_id)

    payloads, total = inbound_read.list_groups(
        ctx["tenant_id"],
        ctx["idp_id"],
        display_name=display_name,
        start_index=si,
        count=c,
        group_location_builder=lambda group_id: f"{groups_base}/{group_id}",
        members_base_url=users_base,
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


@router.get("/Groups/{group_id}")
def get_group(
    request: Request,
    idp_id: str,
    group_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
):
    """SCIM 2.0 fetch a single Group. 404 when not bound to this IdP."""
    location = f"{_groups_base(request, idp_id)}/{group_id}"
    users_base = _users_base(request, idp_id)
    payload = inbound_read.get_group(
        ctx["tenant_id"],
        ctx["idp_id"],
        group_id,
        location=location,
        members_base_url=users_base,
    )
    if payload is None:
        raise ScimErrorException(status_code=404, detail="Group not found")
    return scim_json_response(payload)


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------


@router.post("/Groups")
def create_group_endpoint(
    request: Request,
    idp_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
    payload: Annotated[dict[str, Any], Body()],
):
    """SCIM 2.0 `POST /Groups`: create an IdP group with optional members."""
    groups_base = _groups_base(request, idp_id)
    users_base = _users_base(request, idp_id)
    try:
        resource = create_group(
            ctx["tenant_id"],
            ctx["idp_id"],
            payload,
            group_location_builder=lambda gid: f"{groups_base}/{gid}",
            members_base_url=users_base,
        )
    except ScimWriteError as exc:
        _raise_from_write_error(exc)
        return  # pragma: no cover

    location = resource.get("meta", {}).get("location")
    return scim_json_response(resource, status_code=201, location=location)


@router.put("/Groups/{group_id}")
def replace_group_endpoint(
    request: Request,
    idp_id: str,
    group_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
    payload: Annotated[dict[str, Any], Body()],
):
    """SCIM 2.0 `PUT /Groups/{id}`: full-replace of displayName + members."""
    groups_base = _groups_base(request, idp_id)
    users_base = _users_base(request, idp_id)
    try:
        resource = replace_group(
            ctx["tenant_id"],
            ctx["idp_id"],
            group_id,
            payload,
            group_location_builder=lambda gid: f"{groups_base}/{gid}",
            members_base_url=users_base,
        )
    except ScimWriteError as exc:
        _raise_from_write_error(exc)
        return  # pragma: no cover
    return scim_json_response(resource)


@router.patch("/Groups/{group_id}")
def patch_group_endpoint(
    request: Request,
    idp_id: str,
    group_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
    payload: Annotated[dict[str, Any], Body()],
):
    """SCIM 2.0 `PATCH /Groups/{id}`: simple-path + batched-op support."""
    groups_base = _groups_base(request, idp_id)
    users_base = _users_base(request, idp_id)
    try:
        resource = patch_group(
            ctx["tenant_id"],
            ctx["idp_id"],
            group_id,
            payload,
            group_location_builder=lambda gid: f"{groups_base}/{gid}",
            members_base_url=users_base,
        )
    except ScimWriteError as exc:
        _raise_from_write_error(exc)
        return  # pragma: no cover
    return scim_json_response(resource)


@router.delete("/Groups/{group_id}")
def delete_group_endpoint(
    idp_id: str,
    group_id: str,
    ctx: Annotated[InboundScimContext, Depends(require_inbound_scim_auth)],
):
    """SCIM 2.0 `DELETE /Groups/{id}`: remove the IdP group."""
    try:
        delete_group(ctx["tenant_id"], ctx["idp_id"], group_id)
    except ScimWriteError as exc:
        _raise_from_write_error(exc)
        return  # pragma: no cover
    return Response(status_code=204)
