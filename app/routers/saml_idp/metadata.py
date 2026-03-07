"""Public SAML IdP metadata endpoints.

These endpoints are unauthenticated so downstream SPs can fetch
the IdP metadata XML to configure trust.
"""

import logging
from typing import Annotated

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from services import service_providers as sp_service
from services.exceptions import NotFoundError

from ._helpers import get_base_url

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/saml/idp",
    tags=["saml-idp"],
    include_in_schema=False,
)


@router.get("/metadata/{sp_id}", response_class=Response)
def sp_idp_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    sp_id: str,
):
    """Return IdP metadata XML with per-SP signing certificate.

    Public endpoint for a specific SP's metadata.
    """
    base_url = get_base_url(request)

    try:
        xml = sp_service.get_sp_idp_metadata_xml(tenant_id, sp_id, base_url)
        return Response(content=xml, media_type="application/xml")
    except NotFoundError:
        return Response(
            content="Service provider or certificate not found.",
            status_code=404,
            media_type="text/plain",
        )


@router.get("/metadata/{sp_id}/download", response_class=Response)
def sp_idp_metadata_download(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    sp_id: str,
):
    """Download per-SP IdP metadata XML as a file."""
    base_url = get_base_url(request)

    try:
        xml = sp_service.get_sp_idp_metadata_xml(tenant_id, sp_id, base_url)
        return Response(
            content=xml,
            media_type="application/xml",
            headers={
                "Content-Disposition": f'attachment; filename="idp-metadata-{sp_id[:8]}.xml"',
            },
        )
    except NotFoundError:
        return Response(
            content="Service provider or certificate not found.",
            status_code=404,
            media_type="text/plain",
        )
