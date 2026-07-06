"""OIDC provider router package.

Root-path, tenant-scoped OIDC provider surface. Iteration 1 exposes the
public JWKS endpoint; later iterations add discovery and userinfo.
"""

from fastapi import APIRouter

from .jwks import router as jwks_router

router = APIRouter()
router.include_router(jwks_router)
