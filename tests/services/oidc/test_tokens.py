"""Unit tests for OIDC ID-token minting (services/oidc/tokens.py).

Proves a real relying-party verification path: a minted token verifies against
the tenant's published JWKS (Iteration 1). Also covers the envelope claims,
scope-gated payload, nonce echo semantics, and that `sub` is the stable user
id, never the email.
"""

import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from jwt.algorithms import RSAAlgorithm
from services import oidc as oidc_service
from services.oidc import tokens as tokens_service


def _verify_against_jwks(token: str, tenant_id: str, *, audience: str, issuer: str) -> dict:
    """Select the JWKS key by the token's kid and verify the RS256 signature."""
    header = jwt.get_unverified_header(token)
    jwks = oidc_service.get_jwks(tenant_id)
    entry = next(k for k in jwks.keys if k.kid == header["kid"])
    public_key = RSAAlgorithm.from_jwk(json.dumps(entry.model_dump()))
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
    )


class TestIssueIdToken:
    def test_verifies_against_published_jwks(self, test_tenant, test_user):
        """The core RP path: token minted here verifies against the served JWKS."""
        issuer = "https://tenant.example.com"
        token = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer=issuer,
            client_uuid=str(test_user["id"]),  # any tenant uuid works as artifact
            client_id="weft-id_client_abc",
            user_id=str(test_user["id"]),
            scopes={"openid", "profile", "email"},
        )
        decoded = _verify_against_jwks(
            token, str(test_tenant["id"]), audience="weft-id_client_abc", issuer=issuer
        )
        assert decoded["iss"] == issuer
        assert decoded["aud"] == "weft-id_client_abc"
        assert decoded["sub"] == str(test_user["id"])
        assert decoded["exp"] > decoded["iat"]
        assert "auth_time" in decoded

    def test_sub_is_user_id_not_email(self, test_tenant, test_user):
        token = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer="https://t.example.com",
            client_uuid=str(test_user["id"]),
            client_id="cid",
            user_id=str(test_user["id"]),
            scopes={"openid", "email"},
        )
        decoded = jwt.decode(token, options={"verify_signature": False})
        assert decoded["sub"] == str(test_user["id"])
        assert decoded["sub"] != test_user["email"]

    def test_carries_only_envelope_claims(self, test_tenant, test_user):
        """Identity claims come from userinfo, never the ID token, whatever
        scopes were granted (OpenID Connect Core 1.0, section 5.4)."""
        token = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer="https://t.example.com",
            client_uuid=str(test_user["id"]),
            client_id="cid",
            user_id=str(test_user["id"]),
            scopes={"openid", "profile", "email", "groups"},
            nonce="n-1",
        )
        decoded = jwt.decode(token, options={"verify_signature": False})
        assert set(decoded) == {"iss", "sub", "aud", "iat", "exp", "auth_time", "nonce"}

    def test_nonce_echoed_only_when_supplied(self, test_tenant, test_user):
        with_nonce = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer="https://t.example.com",
            client_uuid=str(test_user["id"]),
            client_id="cid",
            user_id=str(test_user["id"]),
            scopes={"openid"},
            nonce="n-0S6_WzA2Mj",
        )
        decoded = jwt.decode(with_nonce, options={"verify_signature": False})
        assert decoded["nonce"] == "n-0S6_WzA2Mj"

        without_nonce = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer="https://t.example.com",
            client_uuid=str(test_user["id"]),
            client_id="cid",
            user_id=str(test_user["id"]),
            scopes={"openid"},
        )
        decoded2 = jwt.decode(without_nonce, options={"verify_signature": False})
        assert "nonce" not in decoded2

    def test_auth_time_reflects_supplied_value(self, test_tenant, test_user):
        auth_time = datetime.now(UTC) - timedelta(minutes=42)
        token = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer="https://t.example.com",
            client_uuid=str(test_user["id"]),
            client_id="cid",
            user_id=str(test_user["id"]),
            scopes={"openid"},
            auth_time=auth_time,
        )
        decoded = jwt.decode(token, options={"verify_signature": False})
        assert decoded["auth_time"] == int(auth_time.timestamp())

    def test_auth_time_falls_back_to_iat(self, test_tenant, test_user):
        token = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer="https://t.example.com",
            client_uuid=str(test_user["id"]),
            client_id="cid",
            user_id=str(test_user["id"]),
            scopes={"openid"},
            auth_time=None,
        )
        decoded = jwt.decode(token, options={"verify_signature": False})
        assert decoded["auth_time"] == decoded["iat"]

    def test_kid_header_present(self, test_tenant, test_user):
        token = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer="https://t.example.com",
            client_uuid=str(test_user["id"]),
            client_id="cid",
            user_id=str(test_user["id"]),
            scopes={"openid"},
        )
        active = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        assert jwt.get_unverified_header(token)["kid"] == active.kid

    def test_emits_event(self, test_tenant, test_user):
        from unittest.mock import patch

        with patch("services.oidc.tokens.log_event") as mock_log:
            tokens_service.issue_id_token(
                tenant_id=str(test_tenant["id"]),
                issuer="https://t.example.com",
                client_uuid=str(test_user["id"]),
                client_id="cid",
                user_id=str(test_user["id"]),
                scopes={"openid", "profile"},
                nonce="abc",
            )
        mock_log.assert_called_once()
        kwargs = mock_log.call_args.kwargs
        assert kwargs["event_type"] == "oidc_id_token_issued"
        assert kwargs["artifact_id"] == str(test_user["id"])
        assert kwargs["metadata"]["client_id"] == "cid"
        assert kwargs["metadata"]["nonce_echoed"] is True


class TestVerifyIdTokenHint:
    """``id_token_hint`` verification for the authorization endpoint."""

    ISSUER = "https://tenant.example.com"

    def _mint(self, test_tenant, test_user, *, client_id="rp-1", issuer=ISSUER) -> str:
        return tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer=issuer,
            client_uuid=str(test_user["id"]),
            client_id=client_id,
            user_id=str(test_user["id"]),
            scopes={"openid"},
        )

    def test_valid_hint_returns_claims(self, test_tenant, test_user):
        token = self._mint(test_tenant, test_user)
        claims = tokens_service.verify_id_token_hint(
            tenant_id=str(test_tenant["id"]), issuer=self.ISSUER, client_id="rp-1", id_token=token
        )
        assert claims is not None
        assert claims["sub"] == str(test_user["id"])
        assert claims["aud"] == "rp-1"

    def test_expired_hint_is_still_accepted(self, test_tenant, test_user, mocker):
        """A hint is routinely presented after the token expired."""
        mocker.patch.object(tokens_service, "ID_TOKEN_EXPIRY", timedelta(hours=-1))
        token = self._mint(test_tenant, test_user)
        # Under normal RP verification the token is expired...
        with pytest.raises(jwt.ExpiredSignatureError):
            _verify_against_jwks(token, str(test_tenant["id"]), audience="rp-1", issuer=self.ISSUER)
        # ...but the hint verifier deliberately ignores exp.
        claims = tokens_service.verify_id_token_hint(
            tenant_id=str(test_tenant["id"]), issuer=self.ISSUER, client_id="rp-1", id_token=token
        )
        assert claims is not None and claims["sub"] == str(test_user["id"])

    def test_wrong_audience_rejected(self, test_tenant, test_user):
        token = self._mint(test_tenant, test_user, client_id="rp-1")
        assert (
            tokens_service.verify_id_token_hint(
                tenant_id=str(test_tenant["id"]),
                issuer=self.ISSUER,
                client_id="rp-2",
                id_token=token,
            )
            is None
        )

    def test_wrong_issuer_rejected(self, test_tenant, test_user):
        token = self._mint(test_tenant, test_user, issuer="https://other.example.com")
        assert (
            tokens_service.verify_id_token_hint(
                tenant_id=str(test_tenant["id"]),
                issuer=self.ISSUER,
                client_id="rp-1",
                id_token=token,
            )
            is None
        )

    def test_garbage_and_tampered_rejected(self, test_tenant, test_user):
        token = self._mint(test_tenant, test_user)
        header, payload, signature = token.split(".")
        tampered = f"{header}.{payload}.{signature[:-4]}AAAA"
        for bad in ("", "not-a-jwt", "a.b.c", tampered):
            assert (
                tokens_service.verify_id_token_hint(
                    tenant_id=str(test_tenant["id"]),
                    issuer=self.ISSUER,
                    client_id="rp-1",
                    id_token=bad,
                )
                is None
            ), bad

    def test_unknown_kid_rejected(self, test_tenant, test_user):
        token = self._mint(test_tenant, test_user)
        payload = jwt.decode(token, options={"verify_signature": False})
        # Sign with a key WeftID never issued, under a foreign kid.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        forged = jwt.encode(payload, pem, algorithm="RS256", headers={"kid": "foreign"})
        assert (
            tokens_service.verify_id_token_hint(
                tenant_id=str(test_tenant["id"]),
                issuer=self.ISSUER,
                client_id="rp-1",
                id_token=forged,
            )
            is None
        )

    def test_missing_kid_rejected(self, test_tenant, test_user):
        token = self._mint(test_tenant, test_user)
        payload = jwt.decode(token, options={"verify_signature": False})
        signing_key = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        no_kid = jwt.encode(payload, signing_key.private_key_pem, algorithm="RS256")
        assert (
            tokens_service.verify_id_token_hint(
                tenant_id=str(test_tenant["id"]),
                issuer=self.ISSUER,
                client_id="rp-1",
                id_token=no_kid,
            )
            is None
        )

    def test_previous_key_after_rotation_still_verifies(
        self, test_tenant, test_user, test_admin_user
    ):
        """A hint signed before a rotation is a token we issued; honour it."""
        token = self._mint(test_tenant, test_user)
        old_kid = jwt.get_unverified_header(token)["kid"]
        oidc_service.rotate_signing_key(
            {**test_admin_user, "tenant_id": str(test_tenant["id"]), "role": "super_admin"}
        )
        keys = oidc_service.get_verification_public_keys(str(test_tenant["id"]))
        assert old_kid in keys and len(keys) == 2
        claims = tokens_service.verify_id_token_hint(
            tenant_id=str(test_tenant["id"]), issuer=self.ISSUER, client_id="rp-1", id_token=token
        )
        assert claims is not None and claims["sub"] == str(test_user["id"])
