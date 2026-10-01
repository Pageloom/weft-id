"""Pairwise subject identifiers through the assembled app (OpenID Connect Core 8.1).

A pairwise app gets the same opaque ``sub`` everywhere it meets the user: the
ID token, userinfo, and token introspection. A public app keeps the user id.
"""

import base64

import database
import jwt
import pytest
from services.oidc import subject as subject_service

REDIRECT_URI = "http://localhost:3000/callback"


def _make_client(test_tenant, test_admin_user, *, name, redirect_uri, pairwise):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name=name,
        redirect_uris=[redirect_uri],
        created_by=test_admin_user["id"],
    )
    database.execute(
        test_tenant["id"],
        "update oauth2_clients set oidc_enabled = true, available_to_all = true,"
        " subject_type = :subject_type where id = :id",
        {"id": client["id"], "subject_type": "pairwise" if pairwise else "public"},
    )
    return client


@pytest.fixture
def pairwise_client(test_tenant, test_admin_user):
    return _make_client(
        test_tenant, test_admin_user, name="Pairwise", redirect_uri=REDIRECT_URI, pairwise=True
    )


def _code_flow(http, host, test_tenant, oauth_client, user, redirect_uri=REDIRECT_URI):
    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=oauth_client["id"],
        user_id=user["id"],
        redirect_uri=redirect_uri,
        scope="openid email",
    )
    response = http.post(
        "/oauth2/token",
        headers={"Host": host},
        data={
            "grant_type": "authorization_code",
            "client_id": oauth_client["client_id"],
            "client_secret": oauth_client["client_secret"],
            "code": code,
            "redirect_uri": redirect_uri,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _sub(id_token: str) -> str:
    return jwt.decode(id_token, options={"verify_signature": False})["sub"]


def _basic(oauth_client) -> dict[str, str]:
    raw = f"{oauth_client['client_id']}:{oauth_client['client_secret']}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}


class TestPairwiseSubject:
    def test_id_token_userinfo_and_introspection_agree(
        self, client, test_tenant, test_tenant_host, pairwise_client, test_user
    ):
        tokens = _code_flow(client, test_tenant_host, test_tenant, pairwise_client, test_user)
        sub = _sub(tokens["id_token"])

        assert sub != str(test_user["id"])
        assert sub == subject_service.pairwise_subject("localhost", str(test_user["id"]))

        userinfo = client.get(
            "/userinfo",
            headers={"Host": test_tenant_host, "Authorization": f"Bearer {tokens['access_token']}"},
        ).json()
        assert userinfo["sub"] == sub
        assert userinfo["email"] == test_user["email"]

        introspection = client.post(
            "/oauth2/introspect",
            headers={"Host": test_tenant_host, **_basic(pairwise_client)},
            data={"token": tokens["access_token"]},
        ).json()
        assert introspection["active"] is True
        assert introspection["sub"] == sub

    def test_sector_separates_apps_and_public_app_keeps_user_id(
        self, client, test_tenant, test_tenant_host, test_admin_user, pairwise_client, test_user
    ):
        other_uri = "https://other.example/callback"
        other_sector = _make_client(
            test_tenant, test_admin_user, name="Other", redirect_uri=other_uri, pairwise=True
        )
        public = _make_client(
            test_tenant, test_admin_user, name="Public", redirect_uri=REDIRECT_URI, pairwise=False
        )

        here = _sub(
            _code_flow(client, test_tenant_host, test_tenant, pairwise_client, test_user)[
                "id_token"
            ]
        )
        there = _sub(
            _code_flow(client, test_tenant_host, test_tenant, other_sector, test_user, other_uri)[
                "id_token"
            ]
        )
        plain = _sub(
            _code_flow(client, test_tenant_host, test_tenant, public, test_user)["id_token"]
        )

        assert here != there
        assert plain == str(test_user["id"])

    def test_signed_userinfo_carries_pairwise_sub(
        self, client, test_tenant, test_tenant_host, pairwise_client, test_user
    ):
        database.execute(
            test_tenant["id"],
            "update oauth2_clients set registration_metadata ="
            " jsonb_build_object('userinfo_signed_response_alg', 'RS256') where id = :id",
            {"id": pairwise_client["id"]},
        )
        tokens = _code_flow(client, test_tenant_host, test_tenant, pairwise_client, test_user)
        response = client.get(
            "/userinfo",
            headers={"Host": test_tenant_host, "Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert response.headers["content-type"].startswith("application/jwt")
        assert _sub(response.text) == _sub(tokens["id_token"])
