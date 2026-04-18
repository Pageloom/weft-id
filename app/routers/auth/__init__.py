"""Authentication router package."""

from fastapi import APIRouter
from routers.auth._helpers import _get_client_ip  # noqa: F401
from routers.auth.dashboard import router as dashboard_router
from routers.auth.enhanced_enrollment import router as enhanced_enrollment_router
from routers.auth.login import router as login_router
from routers.auth.logout import router as logout_router
from routers.auth.onboarding import router as onboarding_router
from routers.auth.password_reset import router as password_reset_router
from routers.auth.reactivation import router as reactivation_router

router = APIRouter(tags=["auth"], include_in_schema=False)

router.include_router(login_router)
router.include_router(logout_router)
router.include_router(reactivation_router)
router.include_router(dashboard_router)
router.include_router(onboarding_router)
router.include_router(password_reset_router)
router.include_router(enhanced_enrollment_router)
