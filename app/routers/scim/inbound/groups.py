"""Inbound SCIM Groups endpoints (read-only in iteration 2).

`GET /Groups` and `GET /Groups/{id}` return SCIM 2.0 Group resources
of `group_type='idp'` scoped to the authenticating IdP connection.
Writes (POST / PUT / PATCH / DELETE) ship in iteration 4.

`weftid` (manually managed) groups are NEVER visible via this
endpoint -- they are an internal organisational construct, not
directory state the IdP is allowed to enumerate.
"""

from __future__ import annotations

from typing import Annotated

from api_dependencies import InboundScimContext, require_inbound_scim_auth
from fastapi import APIRouter, Depends, Query, Request
from schemas.scim import LIST_RESPONSE_SCHEMA
from services.scim import inbound_read
from utils.scim_responses import scim_json_response
from utils.urls import tenant_base_url

from ._query import FilterParseError, parse_eq_filter, parse_pagination
from .errors import ScimErrorException

router = APIRouter()

_GROUP_FILTER_ATTRS = ["displayName"]


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
