"""Public OIDC discovery endpoint.

Root-path, tenant-scoped, unauthenticated: relying parties fetch this to
learn the tenant's issuer and endpoint layout before starting a flow. The
issuer and every advertised endpoint are built from the request host, so a
request on one tenant's host can never surface another tenant's issuer.
"""

import logging
from typing import Annotated

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from services import oidc as oidc_service
from utils.urls import tenant_base_url

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["oidc"],
    include_in_schema=False,
)


@router.get("/.well-known/openid-configuration")
def openid_configuration(
    request: Request,
    # Resolve (and thereby validate) the tenant host: an unknown host 404s here
    # rather than advertising an issuer for a host no tenant owns.
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
) -> dict:
    """Return the tenant's OpenID Provider metadata (discovery document).

    The `issuer` and all endpoint URLs are derived from the request's tenant
    base URL so they match the exact host the relying party used. Only
    capabilities actually implemented today are advertised.
    """
    issuer = tenant_base_url(request)
    metadata = oidc_service.build_discovery_metadata(issuer)
    return metadata.model_dump()
