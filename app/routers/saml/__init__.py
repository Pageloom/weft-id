"""SAML SSO router package.

This package provides HTTP routes for SAML SSO operations:
- Public authentication endpoints (metadata, login, ACS)
- Single Logout (SLO) handling
- IdP selection page
- Admin management UI (IdP CRUD, debugging, domain binding)

The package is split into focused modules for maintainability:
- authentication.py: Core auth flow (metadata, login initiation, ACS)
- logout.py: Single Logout handling
- selection.py: Multi-IdP selection page
- admin/: Admin-only management endpoints
  - providers.py: IdP CRUD and certificate rotation
  - debug.py: SAML debugging and connection testing
  - domains.py: Domain-to-IdP binding

This module re-exports the combined router for backwards compatibility.
Existing code using `from routers import saml` will continue to work.
"""

from fastapi import APIRouter
from routers.saml.admin import router as admin_router
from routers.saml.authentication import router as auth_router
from routers.saml.logout import router as logout_router
from routers.saml.selection import router as selection_router

# Create the main router with the same configuration as the original
router = APIRouter(tags=["saml"], include_in_schema=False)

# Include all sub-routers
router.include_router(auth_router)
router.include_router(logout_router)
router.include_router(selection_router)
router.include_router(admin_router)
