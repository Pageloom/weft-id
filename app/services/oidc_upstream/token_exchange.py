"""OIDC upstream token exchange and userinfo helpers.

Both go through :func:`utils.safe_http.build_safe_client` (cross-cutting
requirement 1 -- SSRF): the token endpoint and userinfo endpoint are
admin-supplied or derived from an admin-supplied discovery document, which is
the textbook SSRF shape.

These helpers are pure HTTP plumbing with no session/Request concerns so they
stay unit-testable; the routes in Iteration 3 own all session state and call
these with the values they already hold.
"""

from __future__ import annotations

import logging

from services.oidc_upstream.errors import OIDCUpstreamError
from utils.safe_http import build_safe_client

logger = logging.getLogger(__name__)


class TokenExchangeError(OIDCUpstreamError):
    """The token endpoint rejected the authorization-code exchange."""


class UserinfoError(OIDCUpstreamError):
    """The userinfo endpoint could not be reached or returned an error."""


def exchange_code(
    *,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict:
    """Exchange an authorization code for tokens at the IdP's token endpoint.

    Uses the authorization-code grant with PKCE (S256). The client secret is
    sent via HTTP Basic auth (the standard confidential-client form).

    Args:
        token_endpoint: The IdP token endpoint URL.
        client_id: The connection's client_id.
        client_secret: The connection's decrypted client secret.
        code: The authorization code from the callback.
        redirect_uri: The callback URL (must match the authorize request).
        code_verifier: The PKCE code verifier from the login flow.

    Returns:
        The parsed token response dict (access_token, id_token, ...).

    Raises:
        TokenExchangeError: on any non-2xx response or parse failure.
    """
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }

    with build_safe_client(timeout=10.0) as client:
        try:
            response = client.post(
                token_endpoint,
                data=data,
                auth=(client_id, client_secret),
            )
        except Exception as exc:  # noqa: BLE001
            raise TokenExchangeError(f"Token exchange failed: {exc}") from exc

    if response.status_code != 200:
        raise TokenExchangeError(f"Token endpoint returned HTTP {response.status_code}")

    try:
        payload = response.json()
    except Exception as exc:  # noqa: BLE001
        raise TokenExchangeError(f"Token response is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise TokenExchangeError("Token response is not a JSON object")

    if "error" in payload:
        raise TokenExchangeError(f"Token endpoint returned an error: {payload.get('error')}")

    return payload


def fetch_userinfo(*, userinfo_endpoint: str, access_token: str) -> dict:
    """Fetch the user's claims from the IdP's userinfo endpoint.

    Args:
        userinfo_endpoint: The IdP userinfo endpoint URL.
        access_token: The access token from the token exchange.

    Returns:
        The parsed userinfo claims dict.

    Raises:
        UserinfoError: on any non-2xx response or parse failure.
    """
    headers = {"Authorization": f"Bearer {access_token}"}

    with build_safe_client(timeout=10.0) as client:
        try:
            response = client.get(userinfo_endpoint, headers=headers)
        except Exception as exc:  # noqa: BLE001
            raise UserinfoError(f"Userinfo fetch failed: {exc}") from exc

    if response.status_code != 200:
        raise UserinfoError(f"Userinfo endpoint returned HTTP {response.status_code}")

    try:
        payload = response.json()
    except Exception as exc:  # noqa: BLE001
        raise UserinfoError(f"Userinfo response is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise UserinfoError("Userinfo response is not a JSON object")

    return payload
