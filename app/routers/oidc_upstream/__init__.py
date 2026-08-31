"""OIDC upstream (relying-party) router package.

Provides HTTP routes for the consuming direction of OIDC:
- Public authentication endpoints (login, callback)
- Admin management UI (connection CRUD, detail tabs, test-connection)

The package is split into focused modules:
- authentication.py: Core auth flow (login initiation, callback)
- admin.py: Admin-only management endpoints (list, create, detail tabs)
"""

from fastapi import APIRouter
from routers.oidc_upstream.admin import router as admin_router
from routers.oidc_upstream.authentication import router as auth_router

router = APIRouter(tags=["oidc_upstream"], include_in_schema=False)

# Include the auth router first (public /auth/oidc/* routes), then the admin
# router (/admin/settings/oidc-identity-providers/*).
router.include_router(auth_router)
router.include_router(admin_router)
