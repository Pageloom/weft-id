"""Router tests for the OIDC userinfo endpoint (`GET /userinfo`).

Covers Bearer authentication, scope-gated claim release, consistency with the
ID token (proving the shared assembler is reused), the correct OAuth2 error
responses for bad/missing credentials, and the audit event.
"""

from unittest.mock import patch
from uuid import uuid4

import database
import jwt
import pytest
import settings

# Envelope claims live only on the ID token, never in the userinfo body.
_ENVELOPE_CLAIMS = {"iss", "aud", "exp", "iat", "auth_time", "nonce"}


@pytest.fixture
def oidc_client(test_tenant, test_admin_user):
    """A normal OAuth2 client with OIDC enabled."""
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="UserInfo Test Client",
        redirect_uris=["http://localhost:3000/callback"],
        created_by=test_admin_user["id"],
    )
    database.execute(
        test_tenant["id"],
        "update oauth2_clients set oidc_enabled = true where id = :id",
        {"id": client["id"]},
    )
    return client


def _access_token(test_tenant, oidc_client, test_user, *, scope):
    """Mint an access token carrying a granted scope, as the token endpoint would."""
    return database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=oidc_client["id"],
        user_id=test_user["id"],
        scope=scope,
    )


def _userinfo(client, host, token):
    return client.get(
        "/userinfo",
        headers={"Host": host, "Authorization": f"Bearer {token}"},
    )


class TestUserInfoClaims:
    def test_returns_sub_and_scoped_claims(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        token = _access_token(test_tenant, oidc_client, test_user, scope="openid profile email")
        resp = _userinfo(client, test_tenant_host, token)
        assert resp.status_code == 200
        body = resp.json()
        assert body["sub"] == str(test_user["id"])
        assert body["name"] == "Test User"
        assert body["email"] == test_user["email"]
        assert body["email_verified"] is True

    def test_sub_present_with_only_openid_scope(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """userinfo MUST return sub even when no profile/email scope is granted."""
        token = _access_token(test_tenant, oidc_client, test_user, scope="openid")
        body = _userinfo(client, test_tenant_host, token).json()
        assert body["sub"] == str(test_user["id"])
        assert "email" not in body
        assert "name" not in body

    def test_email_scope_gates_email_claims_only(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        token = _access_token(test_tenant, oidc_client, test_user, scope="openid email")
        body = _userinfo(client, test_tenant_host, token).json()
        assert body["email"] == test_user["email"]
        assert "name" not in body
        assert "given_name" not in body

    def test_profile_scope_gates_profile_claims_only(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        token = _access_token(test_tenant, oidc_client, test_user, scope="openid profile")
        body = _userinfo(client, test_tenant_host, token).json()
        assert body["name"] == "Test User"
        assert body["given_name"] == "Test"
        assert "email" not in body

    def test_sub_is_user_id_not_email(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        token = _access_token(test_tenant, oidc_client, test_user, scope="openid email")
        body = _userinfo(client, test_tenant_host, token).json()
        assert body["sub"] == str(test_user["id"])
        assert body["sub"] != test_user["email"]

    def test_groups_scope_releases_groups_claim(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """The `groups` claim appears in userinfo only when the token carries the
        `groups` scope, and reflects effective (DAG-aware) membership."""
        parent = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=test_tenant["id"], name="Org"
        )
        child = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=test_tenant["id"], name="Team"
        )
        database.groups.add_group_relationship(
            test_tenant["id"], test_tenant["id"], parent["id"], child["id"]
        )
        database.groups.add_group_member(
            test_tenant["id"], test_tenant["id"], child["id"], test_user["id"]
        )

        token = _access_token(test_tenant, oidc_client, test_user, scope="openid groups")
        body = _userinfo(client, test_tenant_host, token).json()
        assert set(body["groups"]) == {"Org", "Team"}

    def test_groups_claim_absent_without_groups_scope(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        group = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=test_tenant["id"], name="Unseen"
        )
        database.groups.add_group_member(
            test_tenant["id"], test_tenant["id"], group["id"], test_user["id"]
        )

        token = _access_token(test_tenant, oidc_client, test_user, scope="openid profile email")
        body = _userinfo(client, test_tenant_host, token).json()
        assert "groups" not in body

    def test_userinfo_matches_id_token_for_same_scopes(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """Proves the shared assembler is reused: the identity claims in userinfo
        equal those the ID token carries for the same granted scopes."""
        scope = "openid profile email"
        code = database.oauth2.create_authorization_code(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=oidc_client["id"],
            user_id=test_user["id"],
            redirect_uri="http://localhost:3000/callback",
            scope=scope,
        )
        token_resp = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "client_id": oidc_client["client_id"],
                "client_secret": oidc_client["client_secret"],
                "code": code,
                "redirect_uri": "http://localhost:3000/callback",
            },
        )
        assert token_resp.status_code == 200
        tokens = token_resp.json()
        id_claims = jwt.decode(tokens["id_token"], options={"verify_signature": False})

        userinfo = _userinfo(client, test_tenant_host, tokens["access_token"]).json()

        # sub is consistent across both surfaces.
        assert userinfo["sub"] == id_claims["sub"]

        # Identity claims (everything except the ID-token envelope) match exactly.
        id_identity = {k: v for k, v in id_claims.items() if k not in _ENVELOPE_CLAIMS}
        assert userinfo == id_identity


class TestUserInfoAuth:
    def test_missing_bearer_challenges_without_error_code(self, client, test_tenant_host):
        resp = client.get("/userinfo", headers={"Host": test_tenant_host})
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"] == "Bearer"

    def test_invalid_token_rejected(self, client, test_tenant_host):
        resp = _userinfo(client, test_tenant_host, "weft-id_access_bogustoken")
        assert resp.status_code == 401
        assert 'error="invalid_token"' in resp.headers["WWW-Authenticate"]

    def test_empty_bearer_rejected(self, client, test_tenant_host):
        resp = client.get(
            "/userinfo",
            headers={"Host": test_tenant_host, "Authorization": "Bearer "},
        )
        assert resp.status_code == 401
        assert 'error="invalid_token"' in resp.headers["WWW-Authenticate"]

    def test_expired_token_rejected(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        token = _access_token(test_tenant, oidc_client, test_user, scope="openid email")
        database.execute(
            test_tenant["id"],
            "update oauth2_tokens set expires_at = now() - interval '1 hour' "
            "where client_id = :cid",
            {"cid": oidc_client["id"]},
        )
        resp = _userinfo(client, test_tenant_host, token)
        assert resp.status_code == 401
        assert 'error="invalid_token"' in resp.headers["WWW-Authenticate"]

    def test_revoked_token_rejected(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        token = _access_token(test_tenant, oidc_client, test_user, scope="openid email")
        database.oauth2.revoke_all_client_tokens(test_tenant["id"], oidc_client["id"])
        resp = _userinfo(client, test_tenant_host, token)
        assert resp.status_code == 401
        assert 'error="invalid_token"' in resp.headers["WWW-Authenticate"]

    def test_non_oidc_client_token_rejected(
        self, client, test_tenant, test_tenant_host, test_admin_user, test_user
    ):
        """A plain (non-oidc_enabled) client's token is not valid at /userinfo.

        userinfo is an OIDC endpoint: only tokens issued to an oidc_enabled client
        may read identity claims here, even if the token carries identity scopes.
        The token remains valid at other OAuth2-protected APIs.
        """
        plain_client = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            name="Plain OAuth2 Client",
            redirect_uris=["http://localhost:3000/callback"],
            created_by=test_admin_user["id"],
        )
        # oidc_enabled stays false (the default) -- do not enable it.
        token = database.oauth2.create_access_token(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=plain_client["id"],
            user_id=test_user["id"],
            scope="openid profile email groups",
        )
        resp = _userinfo(client, test_tenant_host, token)
        assert resp.status_code == 401
        assert 'error="invalid_token"' in resp.headers["WWW-Authenticate"]

    def test_token_from_other_tenant_rejected(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """A token valid for tenant A must not resolve on tenant B's host."""
        token = _access_token(test_tenant, oidc_client, test_user, scope="openid email")
        other_sub = f"ui-other-{uuid4().hex[:8]}"
        other = database.fetchone(
            database.UNSCOPED,
            "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id, subdomain",
            {"s": other_sub, "n": "Other UI"},
        )
        try:
            other_host = f"{other['subdomain']}.{settings.BASE_DOMAIN}"
            resp = _userinfo(client, other_host, token)
            assert resp.status_code == 401
        finally:
            database.execute(
                database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": other["id"]}
            )


class TestUserInfoEvent:
    def test_emits_userinfo_accessed_event(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        token = _access_token(test_tenant, oidc_client, test_user, scope="openid email")
        with patch("services.oidc.userinfo.log_event") as mock_log:
            resp = _userinfo(client, test_tenant_host, token)
        assert resp.status_code == 200
        assert mock_log.call_count == 1
        kwargs = mock_log.call_args.kwargs
        assert kwargs["event_type"] == "oidc_userinfo_accessed"
        assert kwargs["actor_user_id"] == str(test_user["id"])
        assert kwargs["artifact_type"] == "oauth2_client"
        assert kwargs["artifact_id"] == str(oidc_client["id"])
        assert kwargs["metadata"]["client_id"] == oidc_client["client_id"]
        assert kwargs["metadata"]["scopes"] == ["email", "openid"]
