"""OIDC provider router package.

Root-path, tenant-scoped OIDC provider surface: the public JWKS and discovery
endpoints (Iteration 1/3) and the Bearer-authenticated userinfo endpoint
(Iteration 3).
"""

from fastapi import APIRouter

from .discovery import router as discovery_router
from .jwks import router as jwks_router
from .userinfo import router as userinfo_router

router = APIRouter()
router.include_router(jwks_router)
router.include_router(discovery_router)
router.include_router(userinfo_router)
