"""Public OIDC JWKS endpoint.

Root-path, tenant-scoped, unauthenticated: relying parties fetch this to get
the public keys that verify WeftID-issued ID tokens. The tenant is resolved
by request host (RLS-scoped), and only public key components are exposed.
"""

import logging
from typing import Annotated

from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from services import oidc as oidc_service

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["oidc"],
    include_in_schema=False,
)


@router.get("/.well-known/jwks.json")
def jwks(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
) -> dict:
    """Return the tenant's JSON Web Key Set.

    Publishes the active signing key plus any within-grace retired key, each
    as a public RSA JWK (kty, use=sig, alg=RS256, stable kid, n, e). The key
    is provisioned lazily on first fetch. No private material is exposed.
    """
    jwks_doc = oidc_service.get_jwks(tenant_id)
    return jwks_doc.model_dump()
