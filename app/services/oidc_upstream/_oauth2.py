"""Shared plumbing for the OAuth2 (non-OIDC) sign-in adapters.

GitHub, Discord and Facebook have no discovery document and no ID token:
each adapter fixes its endpoints, exchanges the code for an access token, and
reads the user from the provider's REST API. What they share lives here; the
adapters keep only what differs (endpoints, the API calls, and how the
provider's user becomes claims).

Every call goes through :func:`utils.safe_http.build_safe_client`.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode

from services.oidc_upstream._http import SAFE_CLIENT_OPTIONS, read_capped
from services.oidc_upstream.adapters import ProviderLoginError, resolve_client_credentials
from services.oidc_upstream.errors import OIDCUpstreamError
from services.oidc_upstream.presets import get_preset
from services.oidc_upstream.token_exchange import TokenExchangeError, exchange_code
from utils.safe_http import build_safe_client


class ProviderAPIError(OIDCUpstreamError):
    """A provider REST API call failed or returned an unusable shape."""


def api_get(
    url: str,
    *,
    access_token: str,
    headers: dict[str, str] | None = None,
    params: dict | None = None,
) -> Any:
    """GET a provider API URL with the user's access token; return the JSON body.

    Raises:
        ProviderAPIError: transport failure, a non-200 status, or invalid JSON.
    """
    request_headers = {**(headers or {}), "Authorization": f"Bearer {access_token}"}
    with build_safe_client(**SAFE_CLIENT_OPTIONS) as client:
        try:
            status, body = read_capped(client, "GET", url, headers=request_headers, params=params)
        except Exception as exc:  # noqa: BLE001
            raise ProviderAPIError(f"{_path(url)} failed: {exc}") from exc
    if status != 200:
        raise ProviderAPIError(f"{_path(url)} returned HTTP {status}")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise ProviderAPIError(f"{_path(url)} returned invalid JSON") from exc


def _path(url: str) -> str:
    """The URL without scheme and host, for error messages."""
    return "/" + url.split("://", 1)[-1].split("/", 1)[-1].split("?", 1)[0]


def build_authorize_url(
    endpoint: str,
    connection: dict,
    *,
    redirect_uri: str,
    state: str,
    code_challenge: str,
) -> str:
    """Build an OAuth2 authorize URL (authorization code with PKCE, no nonce).

    These providers issue no ID token, so there is nothing to bind a nonce
    to; PKCE and state protect the code.

    Raises:
        ProviderLoginError: the connection has no client id.
    """
    client_id = connection.get("client_id")
    if not client_id:
        raise ProviderLoginError("configuration_error", public_error="configuration_error")
    preset = get_preset(connection.get("provider_type") or "")
    scopes = connection.get("scopes") or (preset.scopes if preset else "")
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scopes,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{endpoint}?{urlencode(params)}"


def access_token_for_code(
    connection: dict,
    *,
    token_url: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> str:
    """Exchange an authorization code for the user's access token.

    Raises:
        ProviderLoginError: no credentials (``configuration_error``), or the
            exchange failed or returned no access token (``token_exchange``).
    """
    credentials = resolve_client_credentials(connection)
    if credentials is None:
        raise ProviderLoginError("configuration_error", public_error="configuration_error")
    try:
        token_response = exchange_code(
            token_endpoint=token_url,
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            auth_method=credentials.token_auth_method,
        )
    except TokenExchangeError as exc:
        raise ProviderLoginError("token_exchange", str(exc)) from exc

    access_token = token_response.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise ProviderLoginError("token_exchange", "The provider returned no access token")
    return access_token


def split_name(name: Any, fallback: str) -> tuple[str, str | None]:
    """Split a single display name into given and family names.

    No display name: ``fallback`` (a username) stands in for the given name.
    """
    if isinstance(name, str) and name.strip():
        parts = name.strip().split(None, 1)
        return parts[0], parts[1] if len(parts) > 1 else None
    return fallback, None


def request_status(method: str, url: str, **kwargs: Any) -> int:
    """Send one request and return only its HTTP status (Test Connection).

    Raises:
        ProviderAPIError: the request could not be made.
    """
    with build_safe_client(**SAFE_CLIENT_OPTIONS) as client:
        try:
            status, _ = read_capped(client, method, url, **kwargs)
        except Exception as exc:  # noqa: BLE001
            raise ProviderAPIError(f"{_path(url)} failed: {exc}") from exc
    return status
