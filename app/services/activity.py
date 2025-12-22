"""User activity tracking utilities for service layer.

This module provides activity tracking that should be called from service functions
to update the user's last_activity_at timestamp.

Usage in service functions:
    from services.activity import track_activity

    # For read operations - uses 3-hour cache to avoid constant DB writes
    def get_user_profile(requesting_user: RequestingUser, ...):
        track_activity(requesting_user["tenant_id"], requesting_user["id"])
        # ... rest of function

    # For write operations - log_event() automatically calls track_activity(force=True)
    def update_user(requesting_user: RequestingUser, ...):
        # ... business logic ...
        log_event(...)  # This also updates activity
        return result
"""

import logging

import database
import settings
from utils import cache

logger = logging.getLogger(__name__)

ACTIVITY_CACHE_KEY_PREFIX = "user_activity:"


def track_activity(tenant_id: str, user_id: str, force: bool = False) -> None:
    """
    Track user activity with 3-hour caching.

    This function updates the user's last_activity_at timestamp. To avoid
    constant database writes, read operations use a cache to only update
    the timestamp if 3+ hours have passed since the last update.

    Args:
        tenant_id: Tenant ID for the user
        user_id: User ID to track activity for
        force: If True, always update the database (bypasses cache).
               Set to True for write operations.

    Note:
        This function is synchronous and does not raise on failure to avoid
        disrupting the main business operation.
    """
    cache_key = f"{ACTIVITY_CACHE_KEY_PREFIX}{user_id}"

    try:
        if force:
            # Writes always update the database
            database.user_activity.upsert_activity(tenant_id, user_id)
            cache.set(cache_key, b"1", ttl=settings.ACTIVITY_CACHE_TTL_SECONDS)
        else:
            # Reads only update if cache miss (3+ hours since last update)
            if cache.get(cache_key) is None:
                database.user_activity.upsert_activity(tenant_id, user_id)
                cache.set(cache_key, b"1", ttl=settings.ACTIVITY_CACHE_TTL_SECONDS)
    except Exception as e:
        # Log the error but don't fail the main operation
        logger.error(
            "Failed to track activity: %s (tenant=%s, user=%s)",
            str(e),
            tenant_id,
            user_id,
        )
