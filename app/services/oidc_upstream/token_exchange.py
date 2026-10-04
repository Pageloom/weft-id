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

import json
import logging

from services.oidc_upstream._http import SAFE_CLIENT_OPTIONS, read_capped
from services.oidc_upstream.errors import OIDCUpstreamError
from utils.safe_http import build_safe_client

logger = logging.getLogger(__name__)


class TokenExchangeError(OIDCUpstreamError):
    """The token endpoint rejected the authorization-code exchange."""


class UserinfoError(OIDCUpstreamError):
    """The userinfo endpoint could not be reached or returned an error."""


class UserinfoSubjectMismatchError(OIDCUpstreamError):
    """The userinfo ``sub`` differs from the ID token's (OIDC Core 5.3.2).

    Deliberately not a :class:`UserinfoError`: an unreachable userinfo
    endpoint is tolerated, a response about another subject is not.
    """


def exchange_code(
    *,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    auth_method: str = "client_secret_basic",
) -> dict:
    """Exchange an authorization code for tokens at the IdP's token endpoint.

    Uses the authorization-code grant with PKCE (S256). The client secret is
    sent via HTTP Basic auth (the standard confidential-client form), or in
    the form body for a provider that only accepts ``client_secret_post``.

    Args:
        token_endpoint: The IdP token endpoint URL.
        client_id: The connection's client_id.
        client_secret: The connection's decrypted client secret.
        code: The authorization code from the callback.
        redirect_uri: The callback URL (must match the authorize request).
        code_verifier: The PKCE code verifier from the login flow.
        auth_method: ``client_secret_basic`` or ``client_secret_post``.

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
    auth: tuple[str, str] | None = (client_id, client_secret)
    if auth_method == "client_secret_post":
        data["client_id"] = client_id
        data["client_secret"] = client_secret
        auth = None

    with build_safe_client(**SAFE_CLIENT_OPTIONS) as client:
        try:
            status, body = read_capped(
                client,
                "POST",
                token_endpoint,
                data=data,
                auth=auth,
            )
        except Exception as exc:  # noqa: BLE001
            raise TokenExchangeError(f"Token exchange failed: {exc}") from exc

    if status != 200:
        raise TokenExchangeError(f"Token endpoint returned HTTP {status}")

    try:
        payload = json.loads(body)
    except Exception as exc:  # noqa: BLE001
        raise TokenExchangeError(f"Token response is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise TokenExchangeError("Token response is not a JSON object")

    if "error" in payload:
        raise TokenExchangeError(f"Token endpoint returned an error: {payload.get('error')}")

    return payload


def fetch_userinfo(*, userinfo_endpoint: str, access_token: str, expected_sub: str) -> dict:
    """Fetch the user's claims from the IdP's userinfo endpoint.

    Args:
        userinfo_endpoint: The IdP userinfo endpoint URL.
        access_token: The access token from the token exchange.
        expected_sub: The verified ID token's ``sub``; the response must carry
            the same value (OIDC Core 5.3.2) or it must not be used.

    Returns:
        The parsed userinfo claims dict.

    Raises:
        UserinfoError: on any non-2xx response or parse failure.
        UserinfoSubjectMismatchError: if the response's ``sub`` is missing or
            differs from ``expected_sub``.
    """
    headers = {"Authorization": f"Bearer {access_token}"}

    with build_safe_client(**SAFE_CLIENT_OPTIONS) as client:
        try:
            status, body = read_capped(client, "GET", userinfo_endpoint, headers=headers)
        except Exception as exc:  # noqa: BLE001
            raise UserinfoError(f"Userinfo fetch failed: {exc}") from exc

    if status != 200:
        raise UserinfoError(f"Userinfo endpoint returned HTTP {status}")

    try:
        payload = json.loads(body)
    except Exception as exc:  # noqa: BLE001
        raise UserinfoError(f"Userinfo response is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise UserinfoError("Userinfo response is not a JSON object")

    if payload.get("sub") != expected_sub:
        raise UserinfoSubjectMismatchError("Userinfo sub does not match the ID token sub")

    return payload
