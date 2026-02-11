"""SAML IdP router package.

Routes for managing this platform as a SAML Identity Provider
(downstream SP registration, metadata exposure, SSO flow).
"""

from fastapi import APIRouter

from .admin import router as admin_router
from .metadata import router as metadata_router

router = APIRouter()
router.include_router(admin_router)
router.include_router(metadata_router)
