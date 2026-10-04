"""Facebook sign-in adapter.

Facebook Login is used as plain OAuth2 (the manual web flow): no discovery
and no ID token. After the code exchange the adapter reads the user from the
Graph API, ``GET /me?fields=id,name,first_name,last_name,email,picture``:

- ``id`` is the subject. It is an app-scoped user id: the same person has a
  different id in another Facebook app.
- ``first_name`` / ``last_name`` become the given and family names.
- ``email`` is passed on when present, but always with
  ``email_verified: false``. The Graph API says nothing about whether the
  address is verified, so the Facebook preset never email-links, and a user
  provisioned from Facebook must confirm the address with WeftID before the
  sign-in completes (see ``services.oidc_upstream.email_confirmation``).

Graph calls carry ``appsecret_proof`` (HMAC-SHA256 of the access token keyed
with the app secret), so an app with "Require App Secret" turned on works.

The Graph API version is pinned in ``GRAPH_API_VERSION``. Meta retires a
version about two years after its release; move it forward before then.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from services.oidc_upstream._oauth2 import (
    ProviderAPIError,
    access_token_for_code,
    api_get,
    build_authorize_url,
    request_status,
)
from services.oidc_upstream.adapters import (
    ProviderCheckError,
    ProviderLoginError,
    UpstreamIdentity,
    resolve_client_credentials,
)

GRAPH_API_VERSION = "v25.0"
AUTHORIZE_URL = f"https://www.facebook.com/{GRAPH_API_VERSION}/dialog/oauth"
TOKEN_URL = f"https://graph.facebook.com/{GRAPH_API_VERSION}/oauth/access_token"
API_BASE_URL = f"https://graph.facebook.com/{GRAPH_API_VERSION}"

_ME_FIELDS = "id,name,first_name,last_name,email,picture"


def appsecret_proof(access_token: str, app_secret: str) -> str:
    """Return Graph's ``appsecret_proof`` for an access token."""
    return hmac.new(app_secret.encode(), access_token.encode(), hashlib.sha256).hexdigest()


def _picture_url(picture: Any) -> str | None:
    """The profile picture URL, unless it is Facebook's placeholder silhouette."""
    data = picture.get("data") if isinstance(picture, dict) else None
    if not isinstance(data, dict) or data.get("is_silhouette") is True:
        return None
    url = data.get("url")
    return url if isinstance(url, str) and url.startswith("https://") else None


def build_identity(access_token: str, app_secret: str) -> UpstreamIdentity:
    """Read the signed-in user from the Graph API.

    Raises:
        ProviderAPIError: the call failed or returned an unusable shape.
        ProviderLoginError: the user has no id.
    """
    user = api_get(
        f"{API_BASE_URL}/me",
        access_token=access_token,
        params={
            "fields": _ME_FIELDS,
            "appsecret_proof": appsecret_proof(access_token, app_secret),
        },
    )
    if not isinstance(user, dict):
        raise ProviderAPIError("/me did not return an object")
    user_id = user.get("id")
    if not isinstance(user_id, str) or not (user_id.isascii() and user_id.isdigit()):
        raise ProviderLoginError("missing_sub", "Facebook /me has no id")

    claims: dict[str, Any] = {
        "sub": user_id,
        # Never asserted: the Graph API does not say.
        "email_verified": False,
    }
    for claim, key in (
        ("name", "name"),
        ("given_name", "first_name"),
        ("family_name", "last_name"),
    ):
        value = user.get(key)
        if isinstance(value, str) and value.strip():
            claims[claim] = value.strip()
    email = user.get("email")
    if isinstance(email, str) and email:
        claims["email"] = email
    picture = _picture_url(user.get("picture"))
    if picture:
        claims["picture"] = picture

    return UpstreamIdentity(subject=user_id, claims=claims)


class FacebookAdapter:
    """Sign-in with Facebook (OAuth2 authorization code flow with PKCE)."""

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
    ) -> UpstreamIdentity:
        # The app secret also signs the Graph call (appsecret_proof).
        credentials = resolve_client_credentials(connection)
        if credentials is None:
            raise ProviderLoginError("configuration_error", public_error="configuration_error")
        access_token = access_token_for_code(
            connection,
            token_url=TOKEN_URL,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        try:
            return build_identity(access_token, credentials.client_secret)
        except ProviderAPIError as exc:
            raise ProviderLoginError("facebook_api", str(exc)) from exc

    def check(self, tenant_id: str, connection: dict, *, redirect_uri: str) -> dict:
        """Ask Graph for an app access token with the app id and secret.

        The client credentials grant succeeds only for a matching app id and
        secret. It cannot check the redirect URI; Facebook only compares that
        during a real sign-in.
        """
        credentials = resolve_client_credentials(connection)
        if credentials is None:
            raise ProviderCheckError("Enter the Facebook app ID and app secret.")
        try:
            status = request_status(
                "POST",
                TOKEN_URL,
                data={
                    "client_id": credentials.client_id,
                    "client_secret": credentials.client_secret,
                    "grant_type": "client_credentials",
                },
            )
        except ProviderAPIError as exc:
            raise ProviderCheckError(f"Facebook check failed: {exc}") from exc
        if status == 200:
            return connection
        if status in (400, 401):
            raise ProviderCheckError("Facebook rejected the app ID or app secret.")
        raise ProviderCheckError(f"Facebook check failed: HTTP {status}")
