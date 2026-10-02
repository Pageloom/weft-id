"""Confirming a forced re-authentication in router tests.

A ``prompt=login`` / ``max_age`` / mismatched ``id_token_hint`` request only
renders the confirmation page; the session ends when the user posts it.
"""

from routers.oauth2 import PENDING_REAUTH_KEY


def confirm_reauth(http, session: dict, action: str = "continue"):
    """Post the confirmation form for the request stashed in ``session``."""
    return http.post(
        "/oauth2/authorize/reauthenticate",
        data={"reauth_request_id": session[PENDING_REAUTH_KEY]["id"], "action": action},
    )
