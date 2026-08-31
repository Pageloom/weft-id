"""OIDC upstream login initiation helpers.

Pure, session-free helpers for the relying-party authorization-code flow with
PKCE: generating the PKCE pair, the ``state``/``nonce``, and assembling the
authorize URL. The routes in ``routers.oidc_upstream.authentication`` own all
session state and call these with the values they already hold, so this module
stays unit-testable with no ``Request``/session concerns.

PKCE (RFC 7636) is always used with the S256 challenge method. The
``code_verifier`` is a high-entropy random value; the ``code_challenge`` is
its base64url-encoded SHA-256 digest.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import urlencode

# PKCE verifier length (RFC 7636 allows 43-128 chars of unreserved chars).
_VERIFIER_LENGTH = 64

# The only challenge method used. Hard-coded (never derived from input).
_CODE_CHALLENGE_METHOD = "S256"


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE ``(code_verifier, code_challenge)`` pair.

    The verifier is a URL-safe random string; the challenge is its S256
    (SHA-256, base64url, unpadded) digest.
    """
    verifier = secrets.token_urlsafe(_VERIFIER_LENGTH)
    challenge = _s256_challenge(verifier)
    return verifier, challenge


def _s256_challenge(verifier: str) -> str:
    """Compute the S256 code challenge for a verifier (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def generate_state() -> str:
    """Generate a high-entropy ``state`` value for CSRF protection."""
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    """Generate a high-entropy ``nonce`` value for replay protection."""
    return secrets.token_urlsafe(32)


def build_authorize_url(
    *,
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str,
    scopes: str,
    hosted_domain: str | None = None,
) -> str:
    """Assemble the IdP's authorization endpoint URL.

    Always requests the authorization-code response type with PKCE (S256) and
    carries ``state`` and ``nonce``. When ``hosted_domain`` is set (Google
    ``hd``), it is added as an extra parameter.

    Args:
        authorization_endpoint: The IdP's authorization endpoint URL.
        client_id: The connection's client_id.
        redirect_uri: The callback URL (must match the registered redirect).
        state: The CSRF ``state`` value.
        nonce: The replay-protection ``nonce`` value.
        code_challenge: The PKCE S256 challenge.
        scopes: Space-separated scopes (``openid profile email`` minimum).
        hosted_domain: Optional Google ``hd`` restriction.

    Returns:
        The fully-assembled authorize URL.
    """
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": _CODE_CHALLENGE_METHOD,
    }
    if hosted_domain:
        params["hd"] = hosted_domain

    return f"{authorization_endpoint}?{urlencode(params)}"
