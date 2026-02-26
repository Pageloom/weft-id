"""Public (unauthenticated) branding endpoints for serving logo images."""

import hashlib
from typing import Annotated

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from schemas.branding import LogoSlot
from services import branding as branding_service

router = APIRouter(
    prefix="/branding",
    tags=["branding"],
    include_in_schema=False,
)


@router.get("/logo/{slot}")
def serve_logo(
    request: Request,
    slot: LogoSlot,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Serve a tenant logo image. Unauthenticated, uses hostname-based tenant resolution.

    Supports ETag-based conditional requests and cache headers.
    """
    result = branding_service.get_logo_for_serving(tenant_id, slot.value)

    if result is None:
        return Response(status_code=404)

    # Build ETag from tenant_id + slot + updated_at timestamp
    updated_str = str(result["updated_at"])
    etag_source = f"{tenant_id}:{slot.value}:{updated_str}"
    etag = hashlib.md5(etag_source.encode()).hexdigest()  # noqa: S324
    etag_header = f'"{etag}"'

    # Check If-None-Match for 304
    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match == etag_header:
        return Response(status_code=304, headers={"ETag": etag_header})

    return Response(
        content=result["logo_data"],
        media_type=result["mime_type"],
        headers={
            "ETag": etag_header,
            "Cache-Control": "public, max-age=3600, must-revalidate",
        },
    )


@router.get("/group-logo/{group_id}")
def serve_group_logo(
    request: Request,
    group_id: str,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Serve a group logo image. Unauthenticated, uses hostname-based tenant resolution.

    Supports ETag-based conditional requests and cache headers.
    """
    result = branding_service.get_group_logo_for_serving(tenant_id, group_id)

    if result is None:
        return Response(status_code=404)

    updated_str = str(result["updated_at"])
    etag_source = f"{group_id}:{updated_str}"
    etag = hashlib.md5(etag_source.encode()).hexdigest()  # noqa: S324
    etag_header = f'"{etag}"'

    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match == etag_header:
        return Response(status_code=304, headers={"ETag": etag_header})

    return Response(
        content=result["logo_data"],
        media_type=result["logo_mime"],
        headers={
            "ETag": etag_header,
            "Cache-Control": "public, max-age=3600, must-revalidate",
        },
    )
