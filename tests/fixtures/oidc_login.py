"""Seed a started upstream sign-in for callback tests.

The login route keeps ``state`` in the session and the rest (nonce, PKCE
verifier, entry) in the login state store. :func:`login_session` writes the
store entry and returns the session dict to patch in.
"""

from services.oidc_upstream.login_state import LoginState, save_login_state


def login_session(
    connection: dict,
    *,
    state: str = "state-1",
    nonce: str = "n-1",
    code_verifier: str = "verifier-1",
    entry: str = "routed",
    callback_fields: dict[str, str] | None = None,
) -> dict:
    """Store a started sign-in for ``connection``; return the matching session."""
    assert save_login_state(
        state,
        LoginState(
            tenant_id=str(connection["tenant_id"]),
            connection_id=str(connection["id"]),
            nonce=nonce,
            code_verifier=code_verifier,
            entry=entry,
            callback_fields=callback_fields,
        ),
    )
    return {f"oidc_auth:{connection['id']}:state": state}
