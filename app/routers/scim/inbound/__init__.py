"""Inbound SCIM 2.0 endpoints (IdP → WeftID).

URL prefix: `/scim/v2/inbound/{idp_id}/`

This iteration ships:
- Bearer-token authentication against `scim_inbound_tokens`.
- Metadata: `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`.
- Read endpoints: `/Users`, `/Users/{id}`, `/Groups`, `/Groups/{id}`.

Write endpoints (POST / PUT / PATCH / DELETE) ship in iteration 3
(Users) and iteration 4 (Groups). Until then, write methods 404 by
omission.
"""

from fastapi import APIRouter

from . import groups, metadata, users
from .errors import register_scim_exception_handlers

router = APIRouter(
    prefix="/scim/v2/inbound/{idp_id}",
    tags=["Inbound SCIM"],
    include_in_schema=False,
)
router.include_router(metadata.router)
router.include_router(users.router)
router.include_router(groups.router)


__all__ = ["register_scim_exception_handlers", "router"]
