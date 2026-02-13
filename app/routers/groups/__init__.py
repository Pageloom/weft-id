"""Group management router package."""

from fastapi import APIRouter
from routers.groups.creation import router as creation_router
from routers.groups.detail import router as detail_router
from routers.groups.listing import router as listing_router
from routers.groups.members import router as members_router
from routers.groups.relationships import router as relationships_router

router = APIRouter(tags=["admin-groups"], include_in_schema=False)

router.include_router(listing_router)
router.include_router(creation_router)
router.include_router(detail_router)
router.include_router(members_router)
router.include_router(relationships_router)
