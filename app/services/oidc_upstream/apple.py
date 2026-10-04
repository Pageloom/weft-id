"""Sign in with Apple adapter.

Apple is OIDC (discovery, signed ID tokens) with these differences, all
handled here:

- **Client secret**: not a stored string but a short-lived ES256 JWT signed
  with the admin's private key (the ``.p8`` file), naming the team id, key
  id and client id (the Services ID). Minted per request by
  :func:`apple_client_credentials`.
- **form_post**: requesting the ``name`` or ``email`` scope makes Apple post
  the callback (``response_mode=form_post``) from its own site. The callback
  route records the posted fields and continues on a same-site GET.
- **Name**: Apple sends the user's name once, on the first authorization, in
  the posted ``user`` field (JSON, not signed). Only the name is read from
  it; the email always comes from the signed ID token.
- **Booleans as strings**: ``email_verified`` and ``is_private_email`` may be
  ``"true"``/``"false"``; they are normalized to booleans.
- **No PKCE**: Apple does not document PKCE for web sign-in, so no challenge
  or verifier is sent. ``state``, ``nonce`` and the signed client secret
  protect the code.
- **No userinfo**: everything is in the ID token.

Private relay addresses (``...@privaterelay.appleid.com``) are verified
addresses Apple forwards to the user; they are treated like any other.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from services.oidc_upstream.adapters import (
    ClientCredentials,
    ProviderCheckError,
    ProviderLoginError,
    SpecOIDCAdapter,
    UpstreamIdentity,
)
from services.oidc_upstream.presets import TOKEN_AUTH_POST
from services.oidc_upstream.token_exchange import TokenExchangeError, exchange_code

# The audience of the client secret JWT.
APPLE_AUDIENCE = "https://appleid.apple.com"

# How long a minted client secret is valid. Apple allows up to six months; a
# fresh one is minted for every request.
_CLIENT_SECRET_LIFETIME = 300

# A code Apple cannot have issued, for Test Connection.
_CHECK_CODE = "weftid-connection-test"

# Upper bound on a name part read from the unsigned ``user`` field.
_MAX_NAME_LENGTH = 255

_FALLBACK_SCOPES = "openid name email"


class ApplePrivateKeyError(ValueError):
    """The private key is not an Apple Sign in with Apple key (EC P-256 PEM)."""


def load_apple_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    """Parse a ``.p8`` key and check it is an EC P-256 private key.

    Raises:
        ApplePrivateKeyError: anything else.
    """
    try:
        key = load_pem_private_key(pem.strip().encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise ApplePrivateKeyError("not a PEM private key") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ApplePrivateKeyError("not an EC P-256 key")
    return key


def mint_client_secret(
    *,
    team_id: str,
    key_id: str,
    client_id: str,
    private_key_pem: str,
    now: int | None = None,
) -> str:
    """Return a client secret JWT for Apple's token endpoint."""
    issued_at = int(time.time()) if now is None else now
    return jwt.encode(
        {
            "iss": team_id,
            "iat": issued_at,
            "exp": issued_at + _CLIENT_SECRET_LIFETIME,
            "aud": APPLE_AUDIENCE,
            "sub": client_id,
        },
        load_apple_private_key(private_key_pem),
        algorithm="ES256",
        headers={"kid": key_id},
    )


def apple_client_credentials(connection: dict) -> ClientCredentials | None:
    """Return the connection's client id and a freshly minted client secret.

    None when the client id, team id, key id or key is missing, or the key
    is unusable.
    """
    from services.oidc_upstream.connections import decrypt_client_secret

    client_id = connection.get("client_id")
    team_id = connection.get("apple_team_id")
    key_id = connection.get("apple_key_id")
    private_key_enc = connection.get("apple_private_key_enc")
    if not client_id or not team_id or not key_id or not private_key_enc:
        return None
    try:
        secret = mint_client_secret(
            team_id=team_id,
            key_id=key_id,
            client_id=client_id,
            private_key_pem=decrypt_client_secret(private_key_enc),
        )
    except Exception:  # noqa: BLE001 - an unusable key means "not configured"
        return None
    return ClientCredentials(
        client_id=client_id, client_secret=secret, token_auth_method=TOKEN_AUTH_POST
    )


def _as_bool(value: Any) -> bool:
    """Apple sends some booleans as ``"true"``/``"false"`` strings."""
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() == "true"


def _name_part(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()[:_MAX_NAME_LENGTH]
    return value or None


def parse_user_field(raw: str | None) -> dict[str, str]:
    """Read ``given_name``/``family_name`` from Apple's posted ``user`` field.

    The field is not signed, so nothing else (in particular the email) is
    taken from it. Anything malformed yields no names.
    """
    if not raw:
        return {}
    try:
        user = json.loads(raw)
    except ValueError:
        return {}
    name = user.get("name") if isinstance(user, dict) else None
    if not isinstance(name, dict):
        return {}
    names = {
        "given_name": _name_part(name.get("firstName")),
        "family_name": _name_part(name.get("lastName")),
    }
    return {claim: value for claim, value in names.items() if value}


class AppleAdapter(SpecOIDCAdapter):
    """Sign in with Apple: spec OIDC plus the differences listed above."""

    def authorize_url(
        self,
        connection: dict,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_challenge: str,
    ) -> str:
        authorization_endpoint = connection.get("authorization_endpoint")
        client_id = connection.get("client_id")
        if not authorization_endpoint or not client_id:
            raise ProviderLoginError("configuration_error", public_error="configuration_error")
        params = {
            "response_type": "code",
            # Required by Apple whenever name or email is requested.
            "response_mode": "form_post",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": connection.get("scopes") or _FALLBACK_SCOPES,
            "state": state,
            "nonce": nonce,
        }
        return f"{authorization_endpoint}?{urlencode(params)}"

    def complete(
        self,
        tenant_id: str,
        connection: dict,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
        nonce: str | None,
        callback_fields: Mapping[str, str] | None = None,
    ) -> UpstreamIdentity:
        identity = super().complete(
            tenant_id,
            connection,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=None,
            nonce=nonce,
        )
        claims = dict(identity.claims)
        claims["email_verified"] = _as_bool(claims.get("email_verified"))
        if "is_private_email" in claims:
            claims["is_private_email"] = _as_bool(claims["is_private_email"])
        for claim, value in parse_user_field((callback_fields or {}).get("user")).items():
            claims.setdefault(claim, value)
        return UpstreamIdentity(
            subject=identity.subject,
            claims=claims,
            upstream_sub=identity.upstream_sub,
            upstream_sid=identity.upstream_sid,
            id_token=identity.id_token,
        )

    def check(self, tenant_id: str, connection: dict, *, redirect_uri: str) -> dict:
        """Discovery and keys, then the signed client secret at Apple's token endpoint.

        Apple authenticates the client first: ``invalid_client`` means the
        Services ID, team id, key id or key is wrong; ``invalid_grant`` means
        the client secret was accepted and only the made-up code refused.
        """
        row = super().check(tenant_id, connection, redirect_uri=redirect_uri)
        credentials = apple_client_credentials(row)
        if credentials is None:
            raise ProviderCheckError(
                "Enter the Services ID, team ID, key ID and private key (.p8) from Apple."
            )
        token_endpoint = row.get("token_endpoint")
        if not token_endpoint:
            raise ProviderCheckError("Apple's discovery document has no token endpoint.")
        try:
            exchange_code(
                token_endpoint=token_endpoint,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                code=_CHECK_CODE,
                redirect_uri=redirect_uri,
                code_verifier=None,
                auth_method=credentials.token_auth_method,
            )
        except TokenExchangeError as exc:
            if exc.error == "invalid_grant":
                return row
            if exc.error == "invalid_client":
                raise ProviderCheckError(
                    "Apple rejected the client secret. Check the Services ID, team ID, "
                    "key ID and private key."
                ) from exc
            raise ProviderCheckError(f"Apple check failed: {exc}") from exc
        raise ProviderCheckError("Apple accepted an invalid code; check the app settings.")
