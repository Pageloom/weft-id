"""Session management utilities for secure authentication."""

import time
from typing import Any

from starlette.requests import Request


def regenerate_session(
    request: Request,
    user_id: str,
    max_age: int | None,
    additional_data: dict[str, Any] | None = None,
) -> None:
    """
    Regenerate session after authentication to prevent session fixation.

    This mitigates session fixation attacks by:
    1. Clearing all pre-authentication session data
    2. Creating a fresh session with only authenticated user data

    With Starlette's signed cookie sessions, clearing and recreating the
    session effectively creates a new "session ID" since the entire
    signed payload changes.

    Args:
        request: The Starlette request object with session access
        user_id: The authenticated user's ID
        max_age: Session max_age setting (None for session cookie, int for persistent)
        additional_data: Optional additional data to include in the new session
    """
    # Step 1: Clear ALL existing session data
    # This invalidates any pre-auth data an attacker may have set
    request.session.clear()

    # Step 2: Set authenticated session data
    request.session["user_id"] = user_id
    request.session["session_start"] = int(time.time())
    request.session["_max_age"] = max_age

    # Step 3: Add any additional data if provided
    if additional_data:
        for key, value in additional_data.items():
            # Prevent overwriting core session keys
            if key not in ("user_id", "session_start", "_max_age"):
                request.session[key] = value
