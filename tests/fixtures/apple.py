"""Sign in with Apple fixtures.

``tests/fixtures/oidc/apple/discovery.json`` is Apple's live discovery
document (fetched 2026-10-04). The RSA key and JWKS there are throwaway keys
standing in for Apple's ID-token signing keys; ``auth_key.p8`` is a throwaway
EC P-256 key standing in for the admin's Sign in with Apple key. ID tokens
are minted per test with the claim shapes Apple documents (``email_verified``
and ``is_private_email`` as strings).
"""

from __future__ import annotations

import json
import time

import jwt

from tests.fixtures.oidc import load_fixture, load_fixture_text

ISSUER = "https://appleid.apple.com"
CLIENT_ID = "com.example.signin"
TEAM_ID = "TEAM123456"
KEY_ID = "KEY1234567"
SUBJECT = "001234.0a1b2c3d4e5f60718293a4b5c6d7e8f9.1234"
RELAY_EMAIL = "x7k2m9q4pz@privaterelay.appleid.com"
KID = "apple-fixture-key"

# What Apple posts in the ``user`` field on the first authorization.
USER_FIELD = json.dumps(
    {
        "name": {"firstName": "Ada", "lastName": "Lovelace"},
        "email": "not-from-the-id-token@example.com",
    }
)


def discovery() -> dict:
    return load_fixture("apple/discovery")


def jwks() -> dict:
    return load_fixture("apple/jwks")


def auth_key_pem() -> str:
    """The admin's ``.p8`` key (throwaway)."""
    return load_fixture_text("apple/auth_key.p8")


def id_token(*, nonce: str = "n-1", **claims) -> str:
    """An Apple-shaped ID token signed with the fixture key."""
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": SUBJECT,
        "iat": now,
        "exp": now + 600,
        "nonce": nonce,
        "nonce_supported": True,
        "email": RELAY_EMAIL,
        "email_verified": "true",
        "is_private_email": "true",
        "auth_time": now,
    }
    payload.update(claims)
    payload = {key: value for key, value in payload.items() if value is not None}
    return jwt.encode(
        payload,
        load_fixture_text("apple/private_key.pem"),
        algorithm="RS256",
        headers={"kid": KID},
    )


def make_apple_row(tenant: dict, created_by: str, **overrides) -> dict:
    """An enabled Apple connection row with Apple's endpoints and a key set."""
    import database
    from services.oidc_upstream.connections import _encrypt_secret

    doc = discovery()
    kwargs = {
        "authorization_endpoint": doc["authorization_endpoint"],
        "token_endpoint": doc["token_endpoint"],
        "jwks_uri": doc["jwks_uri"],
        "discovery_url": f"{ISSUER}/.well-known/openid-configuration",
        "client_id": CLIENT_ID,
        "scopes": "openid name email",
        "apple_team_id": TEAM_ID,
        "apple_key_id": KEY_ID,
        "apple_private_key_enc": _encrypt_secret(auth_key_pem()),
        "is_enabled": True,
    }
    kwargs.update(overrides)
    return database.oidc_upstream.create_connection(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=kwargs.pop("name", "Apple"),
        provider_type="apple",
        issuer=ISSUER,
        created_by=str(created_by),
        **kwargs,
    )
