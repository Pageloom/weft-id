"""OIDC upstream (relying-party) authentication router.

The public login and callback endpoints for the consuming direction of OIDC.
Mirrors ``routers.saml.authentication``: the login endpoint initiates the
authorization-code flow with PKCE, and the callback validates the response,
exchanges the code, validates the ID token, correlates the user, and completes
login (honoring the platform-MFA gate).
"""

from fastapi import APIRouter
from routers.oidc_upstream.authentication import router as auth_router

router = APIRouter(tags=["oidc_upstream"], include_in_schema=False)
router.include_router(auth_router)
