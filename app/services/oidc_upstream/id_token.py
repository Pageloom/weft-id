"""OIDC upstream ID-token validation.

Validates an ID token issued by an upstream OIDC IdP against the connection's
JWKS and configured issuer/client_id. This is the relying-party mirror of
``services.oidc.tokens`` (which *mints* ID tokens for downstream RPs); here we
*verify* them.

Validation performed (each failure raises a distinct typed error):

- **Signature** against the JWKS (RS256), with a single refetch on failure to
  tolerate key rotation.
- **``iss``** matches the connection issuer.
- **``aud``** includes the connection client_id.
- **``nonce``** matches the expected nonce (when one is supplied).
- **``exp``** / **``iat``** within tolerance (leeway).

The module is free of ``Request``/session concerns so it stays unit-testable;
the routes in Iteration 3 own all session state.
"""

from __future__ import annotations

import logging

import jwt
from services.oidc_upstream import jwks as jwks_service
from services.oidc_upstream.errors import (
    IDTokenAudienceError,
    IDTokenExpiredError,
    IDTokenIssuerError,
    IDTokenMissingClaimsError,
    IDTokenNonceError,
    IDTokenNotYetValidError,
    IDTokenSignatureError,
)

logger = logging.getLogger(__name__)

# Only RS256 is accepted. The algorithm is hard-coded (never derived from the
# token header) per RFC 8725 section 2.1.
_ALLOWED_ALGORITHMS = ["RS256"]

# Clock-skew tolerance in seconds for exp/iat checks.
_LEEWAY_SECONDS = 60

# Required claims that must be present in the ID token.
_REQUIRED_CLAIMS = ("iss", "aud", "exp", "iat", "sub")


def _select_key(token: str, key_set: jwt.PyJWKSet) -> jwt.PyJWK:
    """Select the verification key by the token's ``kid`` header.

    Raises IDTokenSignatureError if the token has no ``kid`` or the key set
    has no matching key.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise IDTokenSignatureError(f"ID token header is invalid: {exc}") from exc

    kid = header.get("kid")
    if not kid:
        raise IDTokenSignatureError("ID token header is missing 'kid'")

    try:
        return key_set[kid]
    except KeyError as exc:
        raise IDTokenSignatureError(f"JWKS has no key for kid {kid!r}") from exc


def _decode_with_key(
    token: str,
    key_set: jwt.PyJWKSet,
    *,
    issuer: str,
    client_id: str,
) -> dict:
    """Decode and verify the token against a key set, mapping PyJWT errors."""
    key = _select_key(token, key_set)
    try:
        return jwt.decode(
            token,
            key=key,
            algorithms=_ALLOWED_ALGORITHMS,
            audience=client_id,
            issuer=issuer,
            leeway=_LEEWAY_SECONDS,
        )
    except jwt.ExpiredSignatureError as exc:
        raise IDTokenExpiredError("ID token is expired") from exc
    except jwt.InvalidIssuerError as exc:
        raise IDTokenIssuerError("ID token issuer does not match the connection") from exc
    except jwt.InvalidAudienceError as exc:
        raise IDTokenAudienceError("ID token audience does not include the client_id") from exc
    except jwt.ImmatureSignatureError as exc:
        raise IDTokenNotYetValidError("ID token is not yet valid") from exc
    except jwt.InvalidIssuedAtError as exc:
        raise IDTokenNotYetValidError("ID token issued-at is in the future") from exc
    except jwt.MissingRequiredClaimError as exc:
        # A missing iss/aud/exp/iat claim is a structural problem, not a
        # signature failure -- and must not trigger the key-rotation refetch.
        raise IDTokenMissingClaimsError(f"ID token missing required claim: {exc}") from exc
    except jwt.InvalidTokenError as exc:
        # Signature failures and other structural problems land here.
        raise IDTokenSignatureError(f"ID token signature verification failed: {exc}") from exc


def validate_id_token(
    *,
    token: str,
    tenant_id: str,
    connection_id: str,
    issuer: str,
    client_id: str,
    jwks_uri: str,
    nonce: str | None = None,
) -> dict:
    """Validate an upstream ID token and return its claims.

    Args:
        token: The compact JWT string.
        tenant_id: Tenant ID (JWKS cache namespace).
        connection_id: Connection ID (JWKS cache namespace).
        issuer: The expected ``iss`` (the connection's configured issuer).
        client_id: The expected ``aud`` (the connection's client_id).
        jwks_uri: The JWKS endpoint URL.
        nonce: The expected nonce, or None to skip the nonce check.

    Returns:
        The decoded claims dict.

    Raises:
        IDTokenValidationError (and subclasses) on any failure.
    """
    # Fetch the JWKS (cached), then verify. On a signature failure, refetch
    # once to tolerate key rotation, then verify again.
    key_set = jwks_service.get_jwks(tenant_id, connection_id, jwks_uri)

    try:
        claims = _decode_with_key(
            token,
            key_set,
            issuer=issuer,
            client_id=client_id,
        )
    except IDTokenSignatureError:
        key_set = jwks_service.refresh_jwks(tenant_id, connection_id, jwks_uri)
        claims = _decode_with_key(
            token,
            key_set,
            issuer=issuer,
            client_id=client_id,
        )

    # Nonce check is performed explicitly (PyJWT does not verify nonce).
    if nonce is not None:
        token_nonce = claims.get("nonce")
        if token_nonce != nonce:
            raise IDTokenNonceError("ID token nonce does not match the expected nonce")

    # Required-claim presence check (PyJWT verifies exp/iat/iss/aud when the
    # corresponding options are on, but sub is not verified by default).
    for claim in _REQUIRED_CLAIMS:
        if claim not in claims:
            raise IDTokenMissingClaimsError(f"ID token missing required claim '{claim}'")

    return claims
