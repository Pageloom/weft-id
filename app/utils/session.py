"""Session management utilities for secure authentication."""

import secrets
import time
from typing import Any

from starlette.requests import Request

# Session key for the opaque session identifier (the OIDC ``sid`` claim).
SESSION_ID_KEY = "sid"

# Keys regenerate_session() owns; additional_data can never overwrite them.
_CORE_SESSION_KEYS = ("user_id", "session_start", "_max_age", SESSION_ID_KEY)


def _new_session_id() -> str:
    return secrets.token_urlsafe(24)


def ensure_session_id(session: dict) -> str:
    """Return the session's identifier, minting one if the session predates it.

    Every login mints a fresh identifier (``regenerate_session``). Sessions
    created before the identifier existed get one the first time something
    needs it, and keep it for the rest of their life.
    """
    sid = session.get(SESSION_ID_KEY)
    if not isinstance(sid, str) or not sid:
        sid = _new_session_id()
        session[SESSION_ID_KEY] = sid
    return sid


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
    2. Creating a fresh session with only authenticated user data, including a
       new random session identifier (``sid``), so an identifier known before
       login never names the authenticated session

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
    request.session[SESSION_ID_KEY] = _new_session_id()

    # Step 3: Add any additional data if provided
    if additional_data:
        for key, value in additional_data.items():
            # Prevent overwriting core session keys
            if key not in _CORE_SESSION_KEYS:
                request.session[key] = value
