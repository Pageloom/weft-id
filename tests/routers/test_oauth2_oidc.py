"""Integration tests for OIDC ID-token issuance through the OAuth2 flow.

These exercise the additive OIDC behaviour on the existing token endpoint:
an `id_token` is returned ONLY when the client is `oidc_enabled` and the
request carried the `openid` scope. Plain OAuth2 clients are unaffected.

The happy path is a real relying-party verification: the token endpoint's
`id_token` is verified against the JWKS served at `/.well-known/jwks.json`
(Iteration 1), selecting the key by the token's `kid`.
"""

import json
from datetime import UTC, datetime

import database
import jwt
import pytest
from jwt.algorithms import RSAAlgorithm


@pytest.fixture
def oidc_client(test_tenant, test_admin_user):
    """A normal OAuth2 client with OIDC enabled (opted into ID tokens)."""
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="OIDC Test Client",
        redirect_uris=["http://localhost:3000/callback"],
        created_by=test_admin_user["id"],
    )
    database.execute(
        test_tenant["id"],
        "update oauth2_clients set oidc_enabled = true where id = :id",
        {"id": client["id"]},
    )
    return client


def _make_code(test_tenant, client, test_user, *, scope, nonce=None, auth_time=None):
    return database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=client["id"],
        user_id=test_user["id"],
        redirect_uri="http://localhost:3000/callback",
        scope=scope,
        nonce=nonce,
        auth_time=auth_time,
    )


def _exchange(client_http, host, oauth_client, code):
    return client_http.post(
        "/oauth2/token",
        headers={"Host": host},
        data={
            "grant_type": "authorization_code",
            "client_id": oauth_client["client_id"],
            "client_secret": oauth_client["client_secret"],
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
        },
    )


def _verify_via_jwks(client_http, host, id_token, *, audience, issuer):
    """True RP path: fetch the published JWKS and verify the token signature."""
    jwks = client_http.get("/.well-known/jwks.json", headers={"Host": host}).json()
    header = jwt.get_unverified_header(id_token)
    entry = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    public_key = RSAAlgorithm.from_jwk(json.dumps(entry))
    return jwt.decode(id_token, public_key, algorithms=["RS256"], audience=audience, issuer=issuer)


class TestIdTokenIssuance:
    def test_id_token_issued_and_verifies_against_jwks(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        code = _make_code(
            test_tenant, oidc_client, test_user, scope="openid profile email", nonce="xyz789"
        )
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        assert resp.status_code == 200
        body = resp.json()
        assert body["id_token"], "expected an id_token for an oidc_enabled client"

        decoded = _verify_via_jwks(
            client,
            test_tenant_host,
            body["id_token"],
            audience=oidc_client["client_id"],
            issuer=f"https://{test_tenant_host}",
        )
        assert decoded["sub"] == str(test_user["id"])
        assert decoded["aud"] == oidc_client["client_id"]
        assert decoded["iss"] == f"https://{test_tenant_host}"
        assert decoded["nonce"] == "xyz789"
        # scope-gated claims present
        assert decoded["email"] == test_user["email"]
        assert decoded["name"] == "Test User"

    def test_sub_is_user_id_not_email(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        code = _make_code(test_tenant, oidc_client, test_user, scope="openid email")
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        decoded = jwt.decode(resp.json()["id_token"], options={"verify_signature": False})
        assert decoded["sub"] == str(test_user["id"])
        assert decoded["sub"] != test_user["email"]

    def test_groups_claim_gated_on_groups_scope_in_id_token(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """The `groups` claim rides the ID token only when the `groups` scope is
        granted, and carries effective (DAG-aware) membership."""
        parent = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=test_tenant["id"], name="Division"
        )
        child = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=test_tenant["id"], name="Squad"
        )
        database.groups.add_group_relationship(
            test_tenant["id"], test_tenant["id"], parent["id"], child["id"]
        )
        database.groups.add_group_member(
            test_tenant["id"], test_tenant["id"], child["id"], test_user["id"]
        )

        # With the groups scope: claim present, effective membership included.
        code = _make_code(test_tenant, oidc_client, test_user, scope="openid groups")
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        decoded = jwt.decode(resp.json()["id_token"], options={"verify_signature": False})
        assert set(decoded["groups"]) == {"Division", "Squad"}

        # Without the groups scope: claim absent.
        code2 = _make_code(test_tenant, oidc_client, test_user, scope="openid profile")
        resp2 = _exchange(client, test_tenant_host, oidc_client, code2)
        decoded2 = jwt.decode(resp2.json()["id_token"], options={"verify_signature": False})
        assert "groups" not in decoded2

    def test_no_id_token_for_non_oidc_client(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """A plain OAuth2 client gets no id_token even with the openid scope."""
        code = _make_code(test_tenant, normal_oauth2_client, test_user, scope="openid profile")
        resp = _exchange(client, test_tenant_host, normal_oauth2_client, code)
        assert resp.status_code == 200
        assert resp.json()["id_token"] is None
        # existing opaque tokens unaffected
        assert resp.json()["access_token"]
        assert resp.json()["refresh_token"]

    def test_no_id_token_when_openid_scope_absent(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """An oidc_enabled client without the openid scope gets no id_token."""
        code = _make_code(test_tenant, oidc_client, test_user, scope="profile email")
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        assert resp.status_code == 200
        assert resp.json()["id_token"] is None

    def test_no_id_token_when_scope_null(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """No scope at all (legacy code) yields no id_token."""
        code = _make_code(test_tenant, oidc_client, test_user, scope=None)
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        assert resp.status_code == 200
        assert resp.json()["id_token"] is None

    def test_nonce_echoed_only_when_supplied(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        code = _make_code(test_tenant, oidc_client, test_user, scope="openid", nonce=None)
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        decoded = jwt.decode(resp.json()["id_token"], options={"verify_signature": False})
        assert "nonce" not in decoded

    def test_auth_time_persisted_and_echoed(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        auth_time = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
        code = _make_code(test_tenant, oidc_client, test_user, scope="openid", auth_time=auth_time)
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        decoded = jwt.decode(resp.json()["id_token"], options={"verify_signature": False})
        assert decoded["auth_time"] == int(auth_time.timestamp())

    def test_consumed_code_replay_rejected(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """An authorization code is single-use: replay is rejected."""
        code = _make_code(test_tenant, oidc_client, test_user, scope="openid email")

        first = _exchange(client, test_tenant_host, oidc_client, code)
        assert first.status_code == 200
        assert first.json()["id_token"]

        replay = _exchange(client, test_tenant_host, oidc_client, code)
        assert replay.status_code == 400
        assert replay.json()["detail"]["error"] == "invalid_grant"

    def test_granted_scope_persisted_on_access_token(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """The granted scope is persisted on the access-token row.

        This locks the acceptance criterion that `oauth2_tokens.scope` carries
        the granted scopes so a later userinfo iteration can gate released
        claims. Without persistence, downstream claim gating silently breaks.
        """
        code = _make_code(test_tenant, oidc_client, test_user, scope="openid profile email")
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        assert resp.status_code == 200

        row = database.fetchone(
            test_tenant["id"],
            """
            select scope from oauth2_tokens
            where token_type = 'access' and client_id = :cid
            order by created_at desc
            limit 1
            """,
            {"cid": oidc_client["id"]},
        )
        assert row is not None
        assert row["scope"] == "openid profile email"

    def test_email_verified_false_surfaced_in_id_token(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """email_verified must reflect an unverified primary email end-to-end.

        The claims layer computes this; this guards the full token-endpoint
        path so a false value cannot silently become true (or be dropped) for
        a relying party making an authentication decision.
        """
        database.execute(
            test_tenant["id"],
            "update user_emails set verified_at = null where user_id = :uid and is_primary",
            {"uid": test_user["id"]},
        )
        code = _make_code(test_tenant, oidc_client, test_user, scope="openid email")
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        assert resp.status_code == 200
        decoded = jwt.decode(resp.json()["id_token"], options={"verify_signature": False})
        assert decoded["email"] == test_user["email"]
        assert decoded["email_verified"] is False


class TestRefreshTokenCarriesScope:
    """The refresh_token grant must carry the originally-granted scope forward.

    Regression: previously the refresh token stored `scope = NULL` and the
    refreshed access token was minted without a scope, so `GET /userinfo`
    returned only `sub` after a refresh, dropping every profile/email claim.
    """

    def test_userinfo_consistent_after_refresh(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        # 1. authorization_code grant for an oidc_enabled client with full scope.
        code = _make_code(test_tenant, oidc_client, test_user, scope="openid profile email")
        first = _exchange(client, test_tenant_host, oidc_client, code)
        assert first.status_code == 200
        refresh_token = first.json()["refresh_token"]
        assert refresh_token

        # 2. Use the refresh token to mint a new access token.
        refresh_resp = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "refresh_token",
                "client_id": oidc_client["client_id"],
                "client_secret": oidc_client["client_secret"],
                "refresh_token": refresh_token,
            },
        )
        assert refresh_resp.status_code == 200
        refreshed_access = refresh_resp.json()["access_token"]
        # This grant does not rotate the refresh token.
        assert refresh_resp.json().get("refresh_token") is None

        # 3. userinfo with the REFRESHED access token returns the full claim set.
        userinfo = client.get(
            "/userinfo",
            headers={"Host": test_tenant_host, "Authorization": f"Bearer {refreshed_access}"},
        )
        assert userinfo.status_code == 200
        body = userinfo.json()
        assert body["sub"] == str(test_user["id"])
        assert body["name"] == "Test User"
        assert body["email"] == test_user["email"]
        assert body["email_verified"] is True

        # 4. The refreshed access token persists the original granted scope.
        row = database.fetchone(
            test_tenant["id"],
            """
            select scope from oauth2_tokens
            where token_type = 'access' and client_id = :cid
            order by created_at desc
            limit 1
            """,
            {"cid": oidc_client["id"]},
        )
        assert row is not None
        assert row["scope"] == "openid profile email"

    def test_groups_claim_survives_refresh(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """SEAM: the DAG-aware `groups` claim (Iteration 4) must survive the
        refresh-token scope carry-forward (Iteration 2) and reappear at userinfo.

        A refresh with the `groups` scope carried forward must yield an access
        token whose userinfo still releases effective (ancestor-inclusive) group
        names, not just profile/email. This locks the interaction the per-scope
        refresh test (profile/email only) does not cover.
        """
        parent = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=test_tenant["id"], name="RefreshDivision"
        )
        child = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=test_tenant["id"], name="RefreshSquad"
        )
        database.groups.add_group_relationship(
            test_tenant["id"], test_tenant["id"], parent["id"], child["id"]
        )
        database.groups.add_group_member(
            test_tenant["id"], test_tenant["id"], child["id"], test_user["id"]
        )

        code = _make_code(test_tenant, oidc_client, test_user, scope="openid groups")
        first = _exchange(client, test_tenant_host, oidc_client, code)
        assert first.status_code == 200
        refresh_token = first.json()["refresh_token"]

        refresh_resp = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "refresh_token",
                "client_id": oidc_client["client_id"],
                "client_secret": oidc_client["client_secret"],
                "refresh_token": refresh_token,
            },
        )
        assert refresh_resp.status_code == 200
        refreshed_access = refresh_resp.json()["access_token"]

        userinfo = client.get(
            "/userinfo",
            headers={"Host": test_tenant_host, "Authorization": f"Bearer {refreshed_access}"},
        )
        assert userinfo.status_code == 200
        body = userinfo.json()
        assert body["sub"] == str(test_user["id"])
        # Effective, DAG-aware membership survives the refresh carry-forward.
        assert set(body["groups"]) == {"RefreshDivision", "RefreshSquad"}

    def test_refresh_token_row_records_scope(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """The refresh token row itself persists the granted scope at issuance."""
        code = _make_code(test_tenant, oidc_client, test_user, scope="openid profile email")
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        assert resp.status_code == 200

        row = database.fetchone(
            test_tenant["id"],
            """
            select scope from oauth2_tokens
            where token_type = 'refresh' and client_id = :cid
            order by created_at desc
            limit 1
            """,
            {"cid": oidc_client["id"]},
        )
        assert row is not None
        assert row["scope"] == "openid profile email"

    def test_non_oidc_refresh_scope_stays_null(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """Plain OAuth2 (no scope) is unaffected: refreshed token scope stays NULL."""
        code = database.oauth2.create_authorization_code(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
            redirect_uri="http://localhost:3000/callback",
            scope=None,
        )
        first = _exchange(client, test_tenant_host, normal_oauth2_client, code)
        assert first.status_code == 200
        refresh_token = first.json()["refresh_token"]

        refresh_resp = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "refresh_token",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "refresh_token": refresh_token,
            },
        )
        assert refresh_resp.status_code == 200

        row = database.fetchone(
            test_tenant["id"],
            """
            select scope from oauth2_tokens
            where token_type = 'access' and client_id = :cid
            order by created_at desc
            limit 1
            """,
            {"cid": normal_oauth2_client["id"]},
        )
        assert row is not None
        assert row["scope"] is None


class TestAuthorizeStoresScopeAndNonce:
    """The authorize flow captures scope + nonce and persists them onto the code."""

    def test_authorize_persists_scope_and_nonce(
        self, client, test_tenant, test_tenant_host, test_user, oidc_client, override_auth
    ):
        import re

        override_auth(test_user)

        # OIDC-enabled clients are access-gated at authorize; grant the user.
        group = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=test_tenant["id"], name="Authz Scope Group"
        )
        database.execute(
            test_tenant["id"],
            """
            insert into sp_group_assignments (tenant_id, oauth2_client_id, group_id, assigned_by)
            values (:tid, :cid, :gid, :by)
            """,
            {
                "tid": test_tenant["id"],
                "cid": oidc_client["id"],
                "gid": group["id"],
                "by": test_user["id"],
            },
        )
        database.groups.add_group_member(
            test_tenant["id"], test_tenant["id"], group["id"], test_user["id"]
        )

        get_resp = client.get(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            params={
                "client_id": oidc_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
                "scope": "openid profile",
                "nonce": "capture-me",
            },
            follow_redirects=False,
        )
        assert get_resp.status_code == 200
        match = re.search(r'name="auth_request_id"[^>]*value="([^"]+)"', get_resp.text)
        assert match, "auth_request_id not found in authorize page"
        auth_request_id = match.group(1)

        post_resp = client.post(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            data={"auth_request_id": auth_request_id, "action": "allow"},
            follow_redirects=False,
        )
        assert post_resp.status_code == 303
        location = post_resp.headers["location"]
        code = re.search(r"[?&]code=([^&]+)", location).group(1)

        # Exchange it and confirm the captured scope/nonce made it into the token.
        resp = _exchange(client, test_tenant_host, oidc_client, code)
        assert resp.status_code == 200
        decoded = jwt.decode(resp.json()["id_token"], options={"verify_signature": False})
        assert decoded["nonce"] == "capture-me"
        assert decoded["name"] == "Test User"  # profile scope was captured

    def test_authorize_rejects_oversized_scope_and_nonce(
        self, client, test_tenant_host, test_user, oidc_client, override_auth
    ):
        # scope/nonce are length-bounded on the GET handler (max 500/512) so an
        # oversized value is rejected up front rather than stored in the session
        # and only caught by the DB CHECK at POST time.
        override_auth(test_user)
        base = {
            "client_id": oidc_client["client_id"],
            "redirect_uri": "http://localhost:3000/callback",
        }
        oversized_scope = client.get(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            params={**base, "scope": "openid " + "x" * 600},
            follow_redirects=False,
        )
        assert oversized_scope.status_code == 422

        oversized_nonce = client.get(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            params={**base, "nonce": "n" * 600},
            follow_redirects=False,
        )
        assert oversized_nonce.status_code == 422
