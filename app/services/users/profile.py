"""Current user profile operations.

This module provides self-service profile management:
- get_current_user_profile
- update_current_user_profile

These are operations users can perform on their own accounts.
"""

import database
from schemas.api import UserProfile, UserProfileUpdate
from services.activity import track_activity
from services.event_log import log_event
from services.exceptions import ForbiddenError, NotFoundError
from services.settings import can_user_edit_profile
from services.types import RequestingUser
from services.users._converters import _user_row_to_profile


def get_current_user_profile(
    requesting_user: RequestingUser,
    user_data: dict,
) -> UserProfile:
    """
    Get the current user's profile.

    Authorization: Any authenticated user.

    Args:
        requesting_user: The authenticated user making the request
        user_data: The full user dict from authentication (includes email)

    Returns:
        UserProfile for the current user
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    return _user_row_to_profile(user_data)


def update_current_user_profile(
    requesting_user: RequestingUser,
    user_data: dict,
    profile_update: UserProfileUpdate,
) -> UserProfile:
    """
    Update the current user's profile.

    Authorization: Any authenticated user (for their own profile).

    Args:
        requesting_user: The authenticated user making the request
        user_data: The full user dict from authentication
        profile_update: Fields to update (first_name, last_name, timezone, locale, theme)

    Returns:
        Updated UserProfile

    Raises:
        NotFoundError: If user no longer exists
    """
    tenant_id = requesting_user["tenant_id"]
    user_id = requesting_user["id"]

    # Enforce allow_users_edit_profile policy for name changes.
    # Super admins are always allowed; other roles are blocked when disabled.
    if profile_update.first_name or profile_update.last_name:
        if requesting_user["role"] != "super_admin":
            if not can_user_edit_profile(tenant_id):
                raise ForbiddenError(
                    message="Profile editing is disabled by your organization",
                    code="profile_editing_disabled",
                )

    # Track changes for logging
    changes: dict = {}

    # Update profile fields if provided
    if profile_update.first_name or profile_update.last_name:
        first_name = profile_update.first_name or user_data["first_name"]
        last_name = profile_update.last_name or user_data["last_name"]
        if profile_update.first_name and profile_update.first_name != user_data["first_name"]:
            changes["first_name"] = {
                "old": user_data["first_name"],
                "new": profile_update.first_name,
            }
        if profile_update.last_name and profile_update.last_name != user_data["last_name"]:
            changes["last_name"] = {"old": user_data["last_name"], "new": profile_update.last_name}
        database.users.update_user_profile(
            tenant_id=tenant_id,
            user_id=user_id,
            first_name=first_name,
            last_name=last_name,
        )

    if profile_update.timezone and profile_update.locale:
        if profile_update.timezone != user_data.get("tz"):
            changes["timezone"] = {"old": user_data.get("tz"), "new": profile_update.timezone}
        if profile_update.locale != user_data.get("locale"):
            changes["locale"] = {"old": user_data.get("locale"), "new": profile_update.locale}
        database.users.update_user_timezone_and_locale(
            tenant_id=tenant_id,
            user_id=user_id,
            timezone=profile_update.timezone,
            locale=profile_update.locale,
        )
    elif profile_update.timezone:
        if profile_update.timezone != user_data.get("tz"):
            changes["timezone"] = {"old": user_data.get("tz"), "new": profile_update.timezone}
        database.users.update_user_timezone(
            tenant_id=tenant_id,
            user_id=user_id,
            timezone=profile_update.timezone,
        )
    elif profile_update.locale:
        if profile_update.locale != user_data.get("locale"):
            changes["locale"] = {"old": user_data.get("locale"), "new": profile_update.locale}
        database.users.update_user_locale(
            tenant_id=tenant_id,
            user_id=user_id,
            locale=profile_update.locale,
        )

    if profile_update.theme:
        old_theme = user_data.get("theme", "system")
        if profile_update.theme != old_theme:
            changes["theme"] = {"old": old_theme, "new": profile_update.theme}
        database.users.update_user_theme(
            tenant_id=tenant_id,
            user_id=user_id,
            theme=profile_update.theme,
        )

    # Fetch updated user
    updated_user = database.users.get_user_by_id(tenant_id, user_id)
    if not updated_user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    # Add primary email
    primary_email = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email:
        updated_user["email"] = primary_email["email"]

    # Log the event if there were actual changes
    if changes:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_profile_updated",
            metadata={"changes": changes},
        )

    return _user_row_to_profile(updated_user)
