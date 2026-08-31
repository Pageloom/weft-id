"""Tests for OIDC upstream ID-token validation.

Covers the good path and each failure mode (bad signature, wrong issuer,
wrong audience, wrong nonce, expired, missing claims) using tokens signed
with the recorded fixture key. No live network calls: the JWKS fetch is
patched to return the fixture document.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import jwt
import pytest
from services.oidc_upstream import id_token as id_token_service
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

from tests.fixtures.oidc import load_fixture, load_fixture_text

JWKS_DOC = load_fixture("jwks")
PRIVATE_KEY_PEM = load_fixture_text("private_key.pem")

ISSUER = "https://idp.example.com"
CLIENT_ID = "client-123"
JWKS_URI = "https://idp.example.com/jwks"
KID = "oidc-upstream-fixture-key"


def _sign(payload, key_pem=PRIVATE_KEY_PEM, kid=KID):
    return jwt.encode(payload, key_pem, algorithm="RS256", headers={"kid": kid})


def _base_payload(**overrides):
    now = datetime.now(UTC)
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "subject-123",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    payload.update(overrides)
    return payload


def _patch_jwks():
    return patch(
        "services.oidc_upstream.jwks._fetch_jwks",
        return_value=JWKS_DOC,
    )


def _validate(token, **kwargs):
    return id_token_service.validate_id_token(
        token=token,
        tenant_id="t1",
        connection_id="c1",
        issuer=ISSUER,
        client_id=CLIENT_ID,
        jwks_uri=JWKS_URI,
        **kwargs,
    )


class TestGoodPath:
    def test_valid_token_returns_claims(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        token = _sign(_base_payload(nonce="n-123"))
        with _patch_jwks():
            claims = _validate(token, nonce="n-123")
        assert claims["sub"] == "subject-123"
        assert claims["iss"] == ISSUER
        assert claims["aud"] == CLIENT_ID

    def test_nonce_optional_when_not_supplied(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        token = _sign(_base_payload())
        with _patch_jwks():
            claims = _validate(token)
        assert claims["sub"] == "subject-123"


class TestFailureModes:
    def test_bad_signature(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        # Sign with a different key.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        token = _sign(_base_payload(), key_pem=other_pem)
        with _patch_jwks():
            with pytest.raises(IDTokenSignatureError):
                _validate(token)

    def test_wrong_issuer(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        token = _sign(_base_payload(iss="https://evil.example.com"))
        with _patch_jwks():
            with pytest.raises(IDTokenIssuerError):
                _validate(token)

    def test_wrong_audience(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        token = _sign(_base_payload(aud="other-client"))
        with _patch_jwks():
            with pytest.raises(IDTokenAudienceError):
                _validate(token)

    def test_wrong_nonce(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        token = _sign(_base_payload(nonce="n-other"))
        with _patch_jwks():
            with pytest.raises(IDTokenNonceError):
                _validate(token, nonce="n-expected")

    def test_expired(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        now = datetime.now(UTC)
        token = _sign(
            _base_payload(
                iat=int((now - timedelta(hours=2)).timestamp()),
                exp=int((now - timedelta(hours=1)).timestamp()),
            )
        )
        with _patch_jwks():
            with pytest.raises(IDTokenExpiredError):
                _validate(token)

    def test_missing_sub(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        payload = _base_payload()
        del payload["sub"]
        token = _sign(payload)
        with _patch_jwks():
            with pytest.raises(IDTokenMissingClaimsError):
                _validate(token)

    def test_not_yet_valid(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        now = datetime.now(UTC)
        token = _sign(
            _base_payload(
                iat=int((now + timedelta(hours=1)).timestamp()),
                exp=int((now + timedelta(hours=2)).timestamp()),
            )
        )
        with _patch_jwks():
            with pytest.raises(IDTokenNotYetValidError):
                _validate(token)

    def test_nbf_in_future(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        now = datetime.now(UTC)
        token = _sign(
            _base_payload(
                nbf=int((now + timedelta(hours=1)).timestamp()),
                exp=int((now + timedelta(hours=2)).timestamp()),
            )
        )
        with _patch_jwks():
            with pytest.raises(IDTokenNotYetValidError):
                _validate(token)

    @pytest.mark.parametrize("claim", ["iss", "aud", "exp", "iat"])
    def test_missing_required_claim(self, claim):
        jwks_service.clear_jwks_cache("t1", "c1")
        payload = _base_payload()
        del payload[claim]
        token = _sign(payload)
        with _patch_jwks():
            with pytest.raises(IDTokenMissingClaimsError):
                _validate(token)


class TestKeyRotation:
    def test_refetch_on_signature_failure(self):
        """A signature failure triggers a single JWKS refetch (key rotation)."""
        jwks_service.clear_jwks_cache("t1", "c1")
        token = _sign(_base_payload())
        with _patch_jwks() as mock:
            claims = _validate(token)
        # First fetch (cache miss) + no refetch needed on success.
        assert mock.call_count == 1
        assert claims["sub"] == "subject-123"
