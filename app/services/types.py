"""Type definitions for service layer."""

from typing import Any, NotRequired, TypedDict


class RequestingUser(TypedDict):
    """Represents the authenticated user making a request.

    This is passed to service functions that need to know who is
    performing the action (for authorization and audit).

    The request_metadata field is optional and only present for
    web requests (not background jobs or system actions).
    """

    id: str
    tenant_id: str
    role: str  # "user", "admin", "super_admin"
    request_metadata: NotRequired[dict[str, Any] | None]  # Request metadata for event logging
