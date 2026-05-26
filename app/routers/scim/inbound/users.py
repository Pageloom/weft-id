"""Inbound SCIM Users endpoints (read-only in iteration 2).

`GET /Users` and `GET /Users/{id}` return SCIM 2.0 User resources
scoped to the authenticating IdP connection. Writes (POST / PUT /
PATCH / DELETE) ship in iteration 3.
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
