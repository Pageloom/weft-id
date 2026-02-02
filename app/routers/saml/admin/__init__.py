"""Admin SAML router: combines IdP management, debugging, and domain binding routes."""

from fastapi import APIRouter
from routers.saml.admin.debug import router as debug_router
from routers.saml.admin.domains import router as domains_router
from routers.saml.admin.providers import router as providers_router

router = APIRouter()

# Include admin sub-routers
# NOTE: Route order matters for FastAPI - literal paths must come before parameterized ones
# The debug router includes /debug which must match before /{idp_id} in providers
# So debug_router MUST be included BEFORE providers_router
router.include_router(debug_router)
router.include_router(providers_router)
router.include_router(domains_router)
