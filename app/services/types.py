"""Type definitions for service layer."""

from typing import TypedDict


class RequestingUser(TypedDict):
    """Represents the authenticated user making a request.

    This is passed to service functions that need to know who is
    performing the action (for authorization and audit).
    """

    id: str
    tenant_id: str
    role: str  # "user", "admin", "super_admin"
