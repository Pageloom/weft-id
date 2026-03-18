"""User API router package."""

from fastapi import APIRouter
from routers.api.v1.users.admin import router as admin_router
from routers.api.v1.users.emails import router as emails_router
from routers.api.v1.users.groups import router as groups_router
from routers.api.v1.users.mfa import router as mfa_router
from routers.api.v1.users.password import router as password_router
from routers.api.v1.users.profile import router as profile_router

# Re-export services for backwards compatibility with test mocks
# Tests patch routers.api.v1.users.users_service, etc.
from services import emails as emails_service  # noqa: F401
from services import groups as groups_service  # noqa: F401
from services import mfa as mfa_service  # noqa: F401
from services import saml as saml_service  # noqa: F401
from services import service_providers as sp_service  # noqa: F401
from services import settings as settings_service  # noqa: F401
from services import users as users_service  # noqa: F401

# Re-export email utilities for backwards compatibility with test mocks
from utils.email import (
    send_email_verification,  # noqa: F401
    send_mfa_code_email,  # noqa: F401
    send_primary_email_changed_notification,  # noqa: F401
    send_secondary_email_added_notification,  # noqa: F401
    send_secondary_email_removed_notification,  # noqa: F401
)

router = APIRouter(prefix="/api/v1/users", tags=["Users"])

router.include_router(profile_router)
router.include_router(password_router)
router.include_router(emails_router)
router.include_router(mfa_router)
router.include_router(admin_router)
router.include_router(groups_router)
