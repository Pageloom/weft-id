"""Reactivation request service layer.

This module provides business logic for user reactivation requests:
- Creating reactivation requests (by inactivated users)
- Listing pending requests (for admins)
- Approving/denying requests (by admins)

All functions:
- Receive a RequestingUser for authorization (where applicable)
- Return Pydantic models from app/schemas/reactivation.py
- Raise ServiceError subclasses on failures
- Have no knowledge of HTTP concepts
"""

import database
from schemas.reactivation import ReactivationRequest
from services.event_log import log_event
from services.exceptions import (
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser

# =============================================================================
# Authorization Helpers (private)
# =============================================================================


def _require_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not admin or super_admin."""
    if user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
            required_role="admin",
        )


# =============================================================================
# Request Creation (by inactivated user)
# =============================================================================


def create_request(
    tenant_id: str,
    user_id: str,
) -> ReactivationRequest:
    """
    Create a reactivation request for an inactivated user.

    This is called after email verification succeeds.
    No authorization check - the user is verified via email.

    Args:
        tenant_id: Tenant ID
        user_id: User ID requesting reactivation

    Returns:
        ReactivationRequest object

    Raises:
        ValidationError: If user is not inactivated or was denied
        NotFoundError: If user does not exist
    """
    # Get user to verify eligibility
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
            details={"user_id": user_id},
        )

    # Must be inactivated
    if not user.get("is_inactivated"):
        raise ValidationError(
            message="User is not inactivated",
            code="not_inactivated",
        )

    # Cannot request if previously denied
    if user.get("reactivation_denied_at"):
        raise ValidationError(
            message="Reactivation was previously denied",
            code="previously_denied",
        )

    # Check for existing pending request
    existing = database.reactivation.get_pending_request(tenant_id, user_id)
    if existing:
        # Return existing request instead of creating new
        return ReactivationRequest(
            id=str(existing["id"]),
            user_id=str(existing["user_id"]),
            first_name=user.get("first_name", ""),
            last_name=user.get("last_name", ""),
            email=None,  # Not included in pending request
            requested_at=existing["requested_at"],
            decision=None,
        )

    # Create request
    result = database.reactivation.create_request(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        user_id=user_id,
    )

    if not result:
        raise ValidationError(
            message="Failed to create reactivation request",
            code="request_creation_failed",
        )

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="reactivation_request",
        artifact_id=str(result["id"]),
        event_type="reactivation_requested",
    )

    return ReactivationRequest(
        id=str(result["id"]),
        user_id=str(result["user_id"]),
        first_name=user.get("first_name", ""),
        last_name=user.get("last_name", ""),
        email=None,
        requested_at=result["requested_at"],
        decision=None,
    )


def has_pending_request(tenant_id: str, user_id: str) -> bool:
    """
    Check if a user has a pending reactivation request.

    Args:
        tenant_id: Tenant ID
        user_id: User ID to check

    Returns:
        True if pending request exists, False otherwise
    """
    existing = database.reactivation.get_pending_request(tenant_id, user_id)
    return existing is not None


def can_request_reactivation(tenant_id: str, user_id: str) -> dict:
    """
    Check if a user can submit a reactivation request.

    Args:
        tenant_id: Tenant ID
        user_id: User ID to check

    Returns:
        Dict with can_request (bool) and reason (str if cannot)
    """
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        return {"can_request": False, "reason": "user_not_found"}

    if not user.get("is_inactivated"):
        return {"can_request": False, "reason": "not_inactivated"}

    if user.get("reactivation_denied_at"):
        return {"can_request": False, "reason": "previously_denied"}

    # Check for existing pending request
    existing = database.reactivation.get_pending_request(tenant_id, user_id)
    if existing:
        return {"can_request": False, "reason": "request_pending"}

    return {"can_request": True, "reason": None}


# =============================================================================
# Admin Operations
# =============================================================================


def list_pending_requests(
    requesting_user: RequestingUser,
) -> list[ReactivationRequest]:
    """
    List all pending reactivation requests for the tenant.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated admin making the request

    Returns:
        List of ReactivationRequest objects

    Raises:
        ForbiddenError: If user lacks admin permissions
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    rows = database.reactivation.list_pending_requests(tenant_id)

    return [
        ReactivationRequest(
            id=str(row["id"]),
            user_id=str(row["user_id"]),
            first_name=row.get("first_name", ""),
            last_name=row.get("last_name", ""),
            email=row.get("email"),
            requested_at=row["requested_at"],
            decision=None,
        )
        for row in rows
    ]


def count_pending_requests(requesting_user: RequestingUser) -> int:
    """
    Count pending reactivation requests for the tenant.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated admin making the request

    Returns:
        Number of pending requests

    Raises:
        ForbiddenError: If user lacks admin permissions
    """
    _require_admin(requesting_user)
    return database.reactivation.count_pending_requests(requesting_user["tenant_id"])


def list_previous_requests(
    requesting_user: RequestingUser,
) -> list[ReactivationRequest]:
    """
    List all previously decided reactivation requests for the tenant.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated admin making the request

    Returns:
        List of ReactivationRequest objects with decision details

    Raises:
        ForbiddenError: If user lacks admin permissions
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    rows = database.reactivation.list_decided_requests(tenant_id)

    return [
        ReactivationRequest(
            id=str(row["id"]),
            user_id=str(row["user_id"]),
            first_name=row.get("first_name", ""),
            last_name=row.get("last_name", ""),
            email=row.get("email"),
            requested_at=row["requested_at"],
            decision=row.get("decision"),
            decided_at=row.get("decided_at"),
            decided_by_name=(
                f"{row.get('decided_by_first_name', '')} {row.get('decided_by_last_name', '')}".strip()
                if row.get("decided_by_first_name")
                else None
            ),
        )
        for row in rows
    ]


def approve_request(
    requesting_user: RequestingUser,
    request_id: str,
) -> ReactivationRequest:
    """
    Approve a reactivation request and reactivate the user.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated admin making the request
        request_id: UUID of the request to approve

    Returns:
        Updated ReactivationRequest object

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If request does not exist
        ValidationError: If request already decided
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Get the request
    request = database.reactivation.get_request_by_id(tenant_id, request_id)
    if not request:
        raise NotFoundError(
            message="Reactivation request not found",
            code="request_not_found",
            details={"request_id": request_id},
        )

    if request.get("decision"):
        raise ValidationError(
            message="Request has already been decided",
            code="already_decided",
        )

    user_id = str(request["user_id"])

    # Approve the request
    database.reactivation.approve_request(tenant_id, request_id, requesting_user["id"])

    # Reactivate the user
    database.users.reactivate_user(tenant_id, user_id)

    # Clear any denial flag
    database.users.clear_reactivation_denied(tenant_id, user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="reactivation_request",
        artifact_id=request_id,
        event_type="reactivation_approved",
        metadata={"user_id": user_id},
        request_metadata=requesting_user.get("request_metadata"),
    )

    # Also log user reactivation event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_reactivated",
        metadata={"via": "reactivation_request"},
        request_metadata=requesting_user.get("request_metadata"),
    )

    return ReactivationRequest(
        id=str(request["id"]),
        user_id=user_id,
        first_name=request.get("first_name", ""),
        last_name=request.get("last_name", ""),
        email=request.get("email"),
        requested_at=request["requested_at"],
        decision="approved",
    )


def deny_request(
    requesting_user: RequestingUser,
    request_id: str,
) -> ReactivationRequest:
    """
    Deny a reactivation request.

    The user will be marked as denied and cannot submit future requests.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated admin making the request
        request_id: UUID of the request to deny

    Returns:
        Updated ReactivationRequest object

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If request does not exist
        ValidationError: If request already decided
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Get the request
    request = database.reactivation.get_request_by_id(tenant_id, request_id)
    if not request:
        raise NotFoundError(
            message="Reactivation request not found",
            code="request_not_found",
            details={"request_id": request_id},
        )

    if request.get("decision"):
        raise ValidationError(
            message="Request has already been decided",
            code="already_decided",
        )

    user_id = str(request["user_id"])

    # Deny the request
    database.reactivation.deny_request(tenant_id, request_id, requesting_user["id"])

    # Mark user as denied
    database.users.set_reactivation_denied(tenant_id, user_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="reactivation_request",
        artifact_id=request_id,
        event_type="reactivation_denied",
        metadata={"user_id": user_id},
        request_metadata=requesting_user.get("request_metadata"),
    )

    return ReactivationRequest(
        id=str(request["id"]),
        user_id=user_id,
        first_name=request.get("first_name", ""),
        last_name=request.get("last_name", ""),
        email=request.get("email"),
        requested_at=request["requested_at"],
        decision="denied",
    )
