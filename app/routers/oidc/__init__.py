"""OIDC provider router package.

Root-path, tenant-scoped OIDC provider surface: the public JWKS and discovery
endpoints (Iteration 1/3), the Bearer-authenticated userinfo endpoint
(Iteration 3), and the RP-initiated logout (end_session) endpoint.
"""

from fastapi import APIRouter

from .discovery import router as discovery_router
from .jwks import router as jwks_router
from .logout import router as logout_router
from .userinfo import router as userinfo_router

router = APIRouter()
router.include_router(jwks_router)
router.include_router(discovery_router)
router.include_router(userinfo_router)
router.include_router(logout_router)
