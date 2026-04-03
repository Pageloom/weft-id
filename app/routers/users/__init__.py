"""User management router package."""

from fastapi import APIRouter
from routers.users.bulk_ops import router as bulk_ops_router
from routers.users.creation import router as creation_router
from routers.users.detail import router as detail_router
from routers.users.emails import router as emails_router
from routers.users.groups import router as groups_router
from routers.users.lifecycle import router as lifecycle_router
from routers.users.listing import router as listing_router

router = APIRouter(tags=["users"], include_in_schema=False)

router.include_router(listing_router)
router.include_router(creation_router)
router.include_router(bulk_ops_router)
router.include_router(detail_router)
router.include_router(emails_router)
router.include_router(groups_router)
router.include_router(lifecycle_router)
