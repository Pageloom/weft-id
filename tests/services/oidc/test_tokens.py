"""Unit tests for OIDC ID-token minting (services/oidc/tokens.py).

Proves a real relying-party verification path: a minted token verifies against
the tenant's published JWKS (Iteration 1). Also covers the envelope claims,
scope-gated payload, nonce echo semantics, and that `sub` is the stable user
id, never the email.
"""

import json
from datetime import UTC, datetime, timedelta

import jwt
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

    def test_scope_gates_claims(self, test_tenant, test_user):
        token = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer="https://t.example.com",
            client_uuid=str(test_user["id"]),
            client_id="cid",
            user_id=str(test_user["id"]),
            scopes={"openid"},
        )
        decoded = jwt.decode(token, options={"verify_signature": False})
        # openid alone releases no profile/email claims.
        for claim in ("email", "name", "given_name", "family_name"):
            assert claim not in decoded

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
