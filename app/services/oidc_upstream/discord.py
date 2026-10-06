"""Discord sign-in adapter.

Discord is an OAuth2 provider, not OIDC: no discovery document, no ID token.
After the code exchange the adapter reads ``GET /users/@me`` (API v10):

- ``id`` (a snowflake, never reused) is the subject. ``username`` can change.
- ``email`` becomes the identity's email, with ``email_verified: true``, only
  when ``verified`` is true (Discord has confirmed the address). An
  unverified address is left out, so it can neither email-link nor be
  provisioned.
- ``global_name`` (the display name) is split into given and family names;
  without one, the username stands in for the given name.

Discord has no groups to sync: guild membership is not requested.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from services.oidc_upstream._oauth2 import (
    ProviderAPIError,
    access_token_for_code,
    api_get,
    build_authorize_url,
    split_name,
)
from services.oidc_upstream.adapters import (
    ProviderCheckError,
    ProviderLoginError,
    UpstreamIdentity,
    resolve_client_credentials,
)
from services.oidc_upstream.token_exchange import TokenExchangeError, exchange_code

AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
TOKEN_URL = "https://discord.com/api/oauth2/token"
API_BASE_URL = "https://discord.com/api/v10"
AVATAR_URL = "https://cdn.discordapp.com/avatars/{user_id}/{avatar}.png"

# A code Discord cannot have issued, for Test Connection.
_CHECK_CODE = "weftid-connection-test"


def build_identity(access_token: str) -> UpstreamIdentity:
    """Read the signed-in user from the Discord API.

    Raises:
        ProviderAPIError: the call failed or returned an unusable shape.
        ProviderLoginError: the user has no id or username.
    """
    user = api_get(f"{API_BASE_URL}/users/@me", access_token=access_token)
    if not isinstance(user, dict):
        raise ProviderAPIError("/users/@me did not return an object")
    user_id = user.get("id")
    username = user.get("username")
    if (
        not isinstance(user_id, str)
        or not (user_id.isascii() and user_id.isdigit())
        or not isinstance(username, str)
    ):
        raise ProviderLoginError("missing_sub", "Discord /users/@me has no id or username")

    email = user.get("email")
    verified = user.get("verified") is True and isinstance(email, str) and bool(email)
    display_name = user.get("global_name")
    given_name, family_name = split_name(display_name, username)

    claims: dict[str, Any] = {
        "sub": user_id,
        "preferred_username": username,
        "given_name": given_name,
        "email_verified": verified,
    }
    if isinstance(display_name, str) and display_name.strip():
        claims["name"] = display_name.strip()
    if family_name:
        claims["family_name"] = family_name
    if verified:
        claims["email"] = email
    avatar = user.get("avatar")
    # An avatar hash (``a_`` marks an animated one); anything else would
    # inject into the URL.
    if isinstance(avatar, str) and avatar.removeprefix("a_").isalnum():
        claims["picture"] = AVATAR_URL.format(user_id=user_id, avatar=avatar)

    return UpstreamIdentity(subject=user_id, claims=claims)


class DiscordAdapter:
    """Sign-in with Discord (OAuth2 authorization code flow with PKCE)."""

    def prepare(self, tenant_id: str, connection: dict) -> dict:
        # Fixed endpoints: nothing to discover.
        return connection

    def authorize_url(
        self,
        connection: dict,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
    ) -> str:
        return build_authorize_url(
            AUTHORIZE_URL,
            connection,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
        )

    def complete(
        self,
        tenant_id: str,
        connection: dict,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        nonce: str | None,
        callback_fields: Mapping[str, str] | None = None,
    ) -> UpstreamIdentity:
        access_token = access_token_for_code(
            connection,
            token_url=TOKEN_URL,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        try:
            return build_identity(access_token)
        except ProviderAPIError as exc:
            raise ProviderLoginError("discord_api", str(exc)) from exc

    def check(self, tenant_id: str, connection: dict, *, redirect_uri: str) -> dict:
        """Present the client credentials to Discord with a made-up code.

        Discord authenticates the client first: ``invalid_client`` means a
        wrong client id or secret, ``invalid_grant`` means the credentials
        were accepted and only the code was refused.
        """
        credentials = resolve_client_credentials(connection)
        if credentials is None:
            raise ProviderCheckError("Enter the Discord application's client ID and client secret.")
        try:
            exchange_code(
                token_endpoint=TOKEN_URL,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                code=_CHECK_CODE,
                redirect_uri=redirect_uri,
                code_verifier=_CHECK_CODE,
                auth_method=credentials.token_auth_method,
            )
        except TokenExchangeError as exc:
            if exc.error == "invalid_grant":
                return connection
            if exc.error == "invalid_client":
                raise ProviderCheckError(
                    "Discord rejected the client ID or client secret."
                ) from exc
            raise ProviderCheckError(f"Discord check failed: {exc}") from exc
        # Discord never accepts the made-up code.
        raise ProviderCheckError("Discord accepted an invalid code; check the app settings.")
