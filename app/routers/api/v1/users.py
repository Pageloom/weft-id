"""User API endpoints."""

from typing import Annotated

import database
from api_dependencies import get_current_user_api
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, HTTPException
from schemas.api import UserProfile, UserProfileUpdate

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


@router.get("/me", response_model=UserProfile)
def get_current_user_profile(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Get the current user's profile.

    Supports authentication via:
    - Bearer token (OAuth2)
    - Session cookie

    Returns:
        User profile including id, email, name, role, timezone, locale, MFA status
    """
    return UserProfile(**user)


@router.patch("/me", response_model=UserProfile)
def update_current_user_profile(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    profile_update: UserProfileUpdate,
):
    """
    Update the current user's profile.

    Supports authentication via:
    - Bearer token (OAuth2)
    - Session cookie

    Request Body:
        first_name: User's first name (optional)
        last_name: User's last name (optional)
        timezone: IANA timezone (optional, e.g., "America/New_York")
        locale: Two-letter locale code (optional, e.g., "en")

    Returns:
        Updated user profile

    Note:
        Only provided fields are updated. Omitted fields remain unchanged.
    """
    # Update profile fields if provided
    if profile_update.first_name or profile_update.last_name:
        # Update name
        first_name = profile_update.first_name or user["first_name"]
        last_name = profile_update.last_name or user["last_name"]

        database.users.update_user_profile(
            tenant_id=tenant_id,
            user_id=user["id"],
            first_name=first_name,
            last_name=last_name,
        )

    if profile_update.timezone and profile_update.locale:
        # Update both timezone and locale
        database.users.update_user_timezone_and_locale(
            tenant_id=tenant_id,
            user_id=user["id"],
            timezone=profile_update.timezone,
            locale=profile_update.locale,
        )
    elif profile_update.timezone:
        # Update timezone only
        database.users.update_timezone(
            tenant_id=tenant_id,
            user_id=user["id"],
            timezone=profile_update.timezone,
        )
    elif profile_update.locale:
        # Update locale only
        database.users.update_locale(
            tenant_id=tenant_id,
            user_id=user["id"],
            locale=profile_update.locale,
        )

    # Fetch updated user
    updated_user = database.users.get_user_by_id(tenant_id, user["id"])

    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Add primary email
    primary_email = database.user_emails.get_primary_email(tenant_id, updated_user["id"])
    if primary_email:
        updated_user["email"] = primary_email["email"]

    return UserProfile(**updated_user)
