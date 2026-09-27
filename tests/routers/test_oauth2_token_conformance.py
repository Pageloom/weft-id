"""Token-endpoint and userinfo conformance (RFC 6749, RFC 6750, OIDC Core).

Covers what the OpenID Foundation conformance suite's Basic OP plan checks at
``/oauth2/token`` and ``/userinfo``: RFC 6749 section 5.2 error objects (no
FastAPI ``detail`` envelope), the no-store cache headers, absent fields
omitted rather than ``null``, authorization-code reuse revoking the grant,
refresh-token rotation and client binding, and userinfo over POST.
"""

import base64

import database
import pytest

REDIRECT_URI = "http://localhost:3000/callback"


@pytest.fixture
def oidc_client(test_tenant, test_admin_user):
    """An OIDC-enabled normal client, available to every user."""
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Token Conformance Client",
        redirect_uris=[REDIRECT_URI],
        created_by=test_admin_user["id"],
    )
    database.execute(
        test_tenant["id"],
        "update oauth2_clients set oidc_enabled = true, available_to_all = true where id = :id",
        {"id": client["id"]},
    )
    return client


@pytest.fixture
def second_oidc_client(test_tenant, test_admin_user):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Second Token Conformance Client",
        redirect_uris=[REDIRECT_URI],
        created_by=test_admin_user["id"],
    )
    database.execute(
        test_tenant["id"],
        "update oauth2_clients set oidc_enabled = true, available_to_all = true where id = :id",
        {"id": client["id"]},
    )
    return client


def _code(test_tenant, oauth_client, user, scope="openid profile email"):
    return database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=oauth_client["id"],
        user_id=user["id"],
        redirect_uri=REDIRECT_URI,
        scope=scope,
    )


def _token(http, host, oauth_client, **data):
    body = {
        "client_id": oauth_client["client_id"],
        "client_secret": oauth_client["client_secret"],
        **data,
    }
    return http.post("/oauth2/token", headers={"Host": host}, data=body)


def _exchange(http, host, oauth_client, code):
    return _token(
        http,
        host,
        oauth_client,
        grant_type="authorization_code",
        code=code,
        redirect_uri=REDIRECT_URI,
    )


def _refresh(http, host, oauth_client, refresh_token):
    return _token(http, host, oauth_client, grant_type="refresh_token", refresh_token=refresh_token)


def _userinfo(http, host, access_token):
    return http.get("/userinfo", headers={"Host": host, "Authorization": f"Bearer {access_token}"})


def _assert_no_store(response):
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def _assert_rfc6749_error(response, error, status=400):
    assert response.status_code == status
    body = response.json()
    assert body["error"] == error
    assert isinstance(body["error_description"], str)
    assert "detail" not in body
    _assert_no_store(response)


# ============================================================================
# Error shape (RFC 6749 section 5.2)
# ============================================================================


class TestTokenErrorShape:
    def test_invalid_grant_is_top_level(self, client, test_tenant_host, oidc_client):
        response = _exchange(client, test_tenant_host, oidc_client, "not-a-code")
        _assert_rfc6749_error(response, "invalid_grant")

    def test_invalid_client_is_401_with_basic_challenge(self, client, test_tenant_host):
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={"grant_type": "client_credentials", "client_id": "x", "client_secret": "y"},
        )
        _assert_rfc6749_error(response, "invalid_client", status=401)
        assert response.headers["www-authenticate"] == 'Basic realm="oauth2"'

    def test_invalid_client_via_basic_header_is_401(self, client, test_tenant_host, oidc_client):
        basic = base64.b64encode(f"{oidc_client['client_id']}:wrong".encode()).decode()
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host, "Authorization": f"Basic {basic}"},
            data={"grant_type": "authorization_code", "code": "x", "redirect_uri": REDIRECT_URI},
        )
        _assert_rfc6749_error(response, "invalid_client", status=401)
        assert response.headers["www-authenticate"].startswith("Basic")

    def test_missing_grant_type_is_invalid_request(self, client, test_tenant_host, oidc_client):
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "client_id": oidc_client["client_id"],
                "client_secret": oidc_client["client_secret"],
            },
        )
        _assert_rfc6749_error(response, "invalid_request")

    def test_over_long_parameter_is_invalid_request(self, client, test_tenant_host, oidc_client):
        response = _exchange(client, test_tenant_host, oidc_client, "c" * 300)
        _assert_rfc6749_error(response, "invalid_request")

    def test_other_paths_keep_default_validation_errors(self, client, test_tenant_host):
        """The invalid_request mapping is scoped to the token endpoint."""
        response = client.get(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            params={"client_id": "c" * 300},
        )
        assert response.status_code == 422
        assert "detail" in response.json()

    def test_unsupported_grant_type(self, client, test_tenant_host, oidc_client):
        response = _token(client, test_tenant_host, oidc_client, grant_type="password")
        _assert_rfc6749_error(response, "unsupported_grant_type")

    def test_unauthorized_client(self, client, test_tenant_host, b2b_oauth2_client):
        response = _token(
            client,
            test_tenant_host,
            b2b_oauth2_client,
            grant_type="authorization_code",
            code="x",
            redirect_uri=REDIRECT_URI,
        )
        _assert_rfc6749_error(response, "unauthorized_client")

    def test_b2b_without_service_user_is_server_error(
        self, client, test_tenant_host, b2b_oauth2_client, mocker
    ):
        broken = dict(
            database.oauth2.get_client_by_client_id(
                b2b_oauth2_client["tenant_id"], b2b_oauth2_client["client_id"]
            )
        )
        broken["service_user_id"] = None
        mocker.patch("services.oauth2.get_client_by_client_id", return_value=broken)
        response = _token(
            client, test_tenant_host, b2b_oauth2_client, grant_type="client_credentials"
        )
        _assert_rfc6749_error(response, "server_error", status=500)


# ============================================================================
# Successful responses: cache headers and omitted fields
# ============================================================================


class TestTokenSuccessShape:
    def test_code_exchange_has_no_store_headers(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        response = _exchange(
            client, test_tenant_host, oidc_client, _code(test_tenant, oidc_client, test_user)
        )
        assert response.status_code == 200
        _assert_no_store(response)
        assert {"access_token", "refresh_token", "id_token"} <= response.json().keys()

    def test_absent_fields_are_omitted_not_null(self, client, test_tenant_host, b2b_oauth2_client):
        response = _token(
            client, test_tenant_host, b2b_oauth2_client, grant_type="client_credentials"
        )
        assert response.status_code == 200
        _assert_no_store(response)
        body = response.json()
        assert "refresh_token" not in body
        assert "id_token" not in body
        assert None not in body.values()

    def test_plain_oauth2_client_gets_no_id_token_key(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        response = _exchange(
            client,
            test_tenant_host,
            normal_oauth2_client,
            _code(test_tenant, normal_oauth2_client, test_user),
        )
        assert response.status_code == 200
        assert "id_token" not in response.json()


# ============================================================================
# Authorization-code reuse revokes the grant
# ============================================================================


class TestAuthorizationCodeReuse:
    def test_reuse_is_invalid_grant_and_revokes_tokens(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        code = _code(test_tenant, oidc_client, test_user)
        first = _exchange(client, test_tenant_host, oidc_client, code)
        assert first.status_code == 200
        tokens = first.json()
        assert _userinfo(client, test_tenant_host, tokens["access_token"]).status_code == 200

        replay = _exchange(client, test_tenant_host, oidc_client, code)
        _assert_rfc6749_error(replay, "invalid_grant")

        # Both tokens issued from the code are gone.
        assert _userinfo(client, test_tenant_host, tokens["access_token"]).status_code == 401
        _assert_rfc6749_error(
            _refresh(client, test_tenant_host, oidc_client, tokens["refresh_token"]),
            "invalid_grant",
        )

    def test_reuse_revokes_tokens_minted_by_refresh(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """The grant id is carried through rotation, so a reuse after a refresh
        still reaches the rotated refresh token and its access token."""
        code = _code(test_tenant, oidc_client, test_user)
        first = _exchange(client, test_tenant_host, oidc_client, code).json()
        refreshed = _refresh(client, test_tenant_host, oidc_client, first["refresh_token"]).json()

        _exchange(client, test_tenant_host, oidc_client, code)

        assert _userinfo(client, test_tenant_host, refreshed["access_token"]).status_code == 401
        _assert_rfc6749_error(
            _refresh(client, test_tenant_host, oidc_client, refreshed["refresh_token"]),
            "invalid_grant",
        )

    def test_reuse_leaves_other_grants_alone(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        other = _exchange(
            client, test_tenant_host, oidc_client, _code(test_tenant, oidc_client, test_user)
        ).json()
        code = _code(test_tenant, oidc_client, test_user)
        _exchange(client, test_tenant_host, oidc_client, code)
        _exchange(client, test_tenant_host, oidc_client, code)

        assert _userinfo(client, test_tenant_host, other["access_token"]).status_code == 200

    def test_reuse_is_audited(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user, mocker
    ):
        code = _code(test_tenant, oidc_client, test_user)
        _exchange(client, test_tenant_host, oidc_client, code)
        log = mocker.patch("services.oauth2.log_event")
        _exchange(client, test_tenant_host, oidc_client, code)

        log.assert_called_once()
        kwargs = log.call_args.kwargs
        assert kwargs["event_type"] == "oauth2_authorization_code_reused"
        assert kwargs["actor_user_id"] == str(test_user["id"])
        assert kwargs["artifact_type"] == "oauth2_client"
        assert kwargs["artifact_id"] == str(oidc_client["id"])
        assert kwargs["metadata"]["tokens_revoked"] == 2


# ============================================================================
# Refresh tokens: rotation and client binding
# ============================================================================


class TestRefreshTokenRotation:
    def test_refresh_rotates_and_old_token_stops_working(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        first = _exchange(
            client, test_tenant_host, oidc_client, _code(test_tenant, oidc_client, test_user)
        ).json()

        refreshed = _refresh(client, test_tenant_host, oidc_client, first["refresh_token"])
        assert refreshed.status_code == 200
        _assert_no_store(refreshed)
        body = refreshed.json()
        assert body["refresh_token"] != first["refresh_token"]
        assert "id_token" not in body
        assert None not in body.values()

        _assert_rfc6749_error(
            _refresh(client, test_tenant_host, oidc_client, first["refresh_token"]),
            "invalid_grant",
        )
        assert (
            _refresh(client, test_tenant_host, oidc_client, body["refresh_token"]).status_code
            == 200
        )

    def test_access_tokens_survive_rotation(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user
    ):
        """Rotation re-parents the old access token instead of cascading it away."""
        first = _exchange(
            client, test_tenant_host, oidc_client, _code(test_tenant, oidc_client, test_user)
        ).json()
        refreshed = _refresh(client, test_tenant_host, oidc_client, first["refresh_token"]).json()

        assert _userinfo(client, test_tenant_host, first["access_token"]).status_code == 200
        userinfo = _userinfo(client, test_tenant_host, refreshed["access_token"])
        assert userinfo.status_code == 200
        assert userinfo.json()["email"] == test_user["email"]

    def test_refresh_token_of_another_client_is_invalid_grant(
        self, client, test_tenant, test_tenant_host, oidc_client, second_oidc_client, test_user
    ):
        issued_to_second = _exchange(
            client,
            test_tenant_host,
            second_oidc_client,
            _code(test_tenant, second_oidc_client, test_user),
        ).json()

        response = _refresh(
            client, test_tenant_host, oidc_client, issued_to_second["refresh_token"]
        )
        _assert_rfc6749_error(response, "invalid_grant")
        # The rightful client can still use it.
        assert (
            _refresh(
                client, test_tenant_host, second_oidc_client, issued_to_second["refresh_token"]
            ).status_code
            == 200
        )

    def test_lost_rotation_race_is_invalid_grant(
        self, client, test_tenant, test_tenant_host, oidc_client, test_user, mocker
    ):
        first = _exchange(
            client, test_tenant_host, oidc_client, _code(test_tenant, oidc_client, test_user)
        ).json()
        mocker.patch("services.oauth2.rotate_refresh_token", return_value=None)
        response = _refresh(client, test_tenant_host, oidc_client, first["refresh_token"])
        _assert_rfc6749_error(response, "invalid_grant")


# ============================================================================
# Userinfo over POST (OpenID Connect Core 1.0, section 5.3.1; RFC 6750)
# ============================================================================


@pytest.fixture
def access_token(client, test_tenant, test_tenant_host, oidc_client, test_user):
    return _exchange(
        client, test_tenant_host, oidc_client, _code(test_tenant, oidc_client, test_user)
    ).json()["access_token"]


class TestUserinfoPost:
    def test_post_with_bearer_header(self, client, test_tenant_host, test_user, access_token):
        response = client.post(
            "/userinfo",
            headers={"Host": test_tenant_host, "Authorization": f"Bearer {access_token}"},
        )
        assert response.status_code == 200
        assert response.json()["sub"] == str(test_user["id"])
        assert response.json()["email"] == test_user["email"]

    def test_post_with_token_in_form_body(self, client, test_tenant_host, test_user, access_token):
        response = client.post(
            "/userinfo",
            headers={"Host": test_tenant_host},
            data={"access_token": access_token},
        )
        assert response.status_code == 200
        assert response.json()["sub"] == str(test_user["id"])

    def test_post_with_both_methods_is_invalid_request(
        self, client, test_tenant_host, access_token
    ):
        response = client.post(
            "/userinfo",
            headers={"Host": test_tenant_host, "Authorization": f"Bearer {access_token}"},
            data={"access_token": access_token},
        )
        assert response.status_code == 400
        assert 'error="invalid_request"' in response.headers["www-authenticate"]

    def test_post_without_token_is_bare_challenge(self, client, test_tenant_host):
        response = client.post("/userinfo", headers={"Host": test_tenant_host})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_post_with_invalid_body_token(self, client, test_tenant_host):
        response = client.post(
            "/userinfo", headers={"Host": test_tenant_host}, data={"access_token": "nope"}
        )
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'

    def test_post_with_over_long_body_token(self, client, test_tenant_host):
        response = client.post(
            "/userinfo", headers={"Host": test_tenant_host}, data={"access_token": "a" * 600}
        )
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'

    def test_body_token_ignored_on_get(self, client, test_tenant_host, access_token):
        """RFC 6750 section 2.2 is POST-only; a GET needs the header."""
        response = client.request(
            "GET",
            "/userinfo",
            headers={
                "Host": test_tenant_host,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            content=f"access_token={access_token}",
        )
        assert response.status_code == 401

    def test_json_body_is_not_a_token_source(self, client, test_tenant_host, access_token):
        response = client.post(
            "/userinfo",
            headers={"Host": test_tenant_host},
            json={"access_token": access_token},
        )
        assert response.status_code == 401

    def test_post_needs_no_csrf_token_even_with_a_session(
        self, client, test_tenant_host, access_token, test_user, override_auth
    ):
        """Bearer-only endpoint: exempt from CSRF even when a browser session
        cookie rides along."""
        override_auth(test_user)
        response = client.post(
            "/userinfo",
            headers={"Host": test_tenant_host, "Authorization": f"Bearer {access_token}"},
        )
        assert response.status_code == 200
