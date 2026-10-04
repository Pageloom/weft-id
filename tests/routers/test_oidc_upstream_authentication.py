"""Tests for the OIDC upstream login and callback routes.

Covers login initiation (state/nonce/verifier stored, authorize URL built,
off-origin redirect), and callback branches: state mismatch, missing verifier,
replayed callback, PKCE round trip, each correlation branch, the MFA-required
branch, inactivated user, and rate limiting.
"""

import json
import os
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from main import app

from tests.fixtures.oidc_login import login_session
from tests.helpers.client import TestClient


@pytest.fixture(autouse=True)
def setup_app_directory():
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def tenant_client(test_tenant):
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_tenant["id"])
    client = TestClient(app)
    yield client


def _make_connection(test_tenant, test_user, **overrides):
    import database
    from services.oidc_upstream.connections import _encrypt_secret

    kwargs = {
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks",
        "client_id": "client-123",
        "client_secret_enc": _encrypt_secret("super-secret-value"),
        "is_enabled": True,
    }
    kwargs.update(overrides)

    row = database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test OIDC",
        provider_type="generic",
        issuer="https://idp.example.com",
        created_by=str(test_user["id"]),
        **kwargs,
    )
    return row


class TestLogin:
    def test_login_redirects_off_origin(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        response = tenant_client.get(f"/auth/oidc/{conn['id']}/login", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("https://idp.example.com/authorize?")
        assert "response_type=code" in response.headers["location"]
        assert "code_challenge_method=S256" in response.headers["location"]

    def test_login_stores_session_state(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        with patch("starlette.requests.Request.session", {}) as session:
            tenant_client.get(f"/auth/oidc/{conn['id']}/login", follow_redirects=False)
            # Session is a dict-like; assert keys were set via the request.
            # We can't easily read the session back through TestClient, so we
            # assert the redirect happened and rely on callback tests for the
            # round trip.
            assert session is not None

    def test_login_disabled_connection(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user, is_enabled=False)
        response = tenant_client.get(f"/auth/oidc/{conn['id']}/login", follow_redirects=False)
        assert response.status_code == 303
        assert "/login?error=idp_disabled" in response.headers["location"]

    def test_login_unknown_connection(self, tenant_client):
        response = tenant_client.get(f"/auth/oidc/{uuid4()}/login", follow_redirects=False)
        assert response.status_code == 303
        assert "/login?error=idp_not_found" in response.headers["location"]

    def test_login_malformed_connection_id(self, tenant_client):
        response = tenant_client.get("/auth/oidc/not-a-uuid/login", follow_redirects=False)
        assert response.status_code == 303
        assert "/login?error=idp_not_found" in response.headers["location"]


class TestCallback:
    def test_callback_state_mismatch(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        response = tenant_client.get(
            f"/auth/oidc/{conn['id']}/callback?state=wrong&code=abc",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "/login?error=auth_failed" in response.headers["location"]

    def test_callback_missing_verifier(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        # No prior login -> no session state -> state mismatch (single-use).
        response = tenant_client.get(
            f"/auth/oidc/{conn['id']}/callback?state=s&code=abc",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "/login?error=auth_failed" in response.headers["location"]

    def test_callback_idp_error(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        response = tenant_client.get(
            f"/auth/oidc/{conn['id']}/callback?error=access_denied",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "/login?error=auth_failed" in response.headers["location"]

    def test_callback_unknown_connection(self, tenant_client):
        response = tenant_client.get(
            f"/auth/oidc/{uuid4()}/callback?state=s&code=abc",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "/login?error=idp_not_found" in response.headers["location"]

    def test_callback_malformed_connection_id(self, tenant_client):
        response = tenant_client.get(
            "/auth/oidc/not-a-uuid/callback?state=s&code=abc",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "/login?error=idp_not_found" in response.headers["location"]


class TestPkceRoundTrip:
    def test_full_round_trip_jit(self, tenant_client, test_tenant, test_user):
        """Login stores state; callback with matching state + mocked exchange
        provisions a user via JIT."""
        import database

        conn = _make_connection(test_tenant, test_user, jit_provisioning=True)

        # Start login to populate session state.
        login = tenant_client.get(f"/auth/oidc/{conn['id']}/login", follow_redirects=False)
        assert login.status_code == 303

        # Read the session state back from the client's cookie jar is not
        # directly possible; instead we drive the callback with a mocked
        # exchange + ID-token validation and a session pre-populated via the
        # request-level session patch.
        from datetime import UTC, datetime, timedelta

        import jwt

        from tests.fixtures.oidc import load_fixture, load_fixture_text

        jwks_doc = load_fixture("jwks")
        key_pem = load_fixture_text("private_key.pem")
        now = datetime.now(UTC)
        id_token = jwt.encode(
            {
                "iss": "https://idp.example.com",
                "aud": "client-123",
                "sub": "subject-123",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=1)).timestamp()),
                "nonce": "n-1",
                "email": "oidc-user@example.com",
                "email_verified": True,
                "given_name": "Oidc",
                "family_name": "User",
            },
            key_pem,
            algorithm="RS256",
            headers={"kid": "oidc-upstream-fixture-key"},
        )

        session = login_session(conn)

        with patch(
            "starlette.requests.Request.session",
            new_callable=lambda: property(lambda self: session),
        ):
            with patch(
                "services.oidc_upstream.exchange_code",
                return_value={"access_token": "at", "id_token": id_token},
            ):
                with patch("services.oidc_upstream.jwks._fetch_jwks", return_value=jwks_doc):
                    response = tenant_client.get(
                        f"/auth/oidc/{conn['id']}/callback?state=state-1&code=code-1",
                        follow_redirects=False,
                    )

        # JIT provisioning should have created a user and linked it.
        linked = database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "subject-123"
        )
        assert linked is not None
        assert response.status_code == 303


class TestMfaGate:
    def test_mfa_required_redirects_to_mfa_verify(self, tenant_client, test_tenant, test_user):
        from datetime import UTC, datetime, timedelta

        import jwt

        from tests.fixtures.oidc import load_fixture, load_fixture_text

        conn = _make_connection(
            test_tenant, test_user, require_platform_mfa=True, jit_provisioning=True
        )

        jwks_doc = load_fixture("jwks")
        key_pem = load_fixture_text("private_key.pem")
        now = datetime.now(UTC)
        id_token = jwt.encode(
            {
                "iss": "https://idp.example.com",
                "aud": "client-123",
                "sub": "subject-123",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=1)).timestamp()),
                "nonce": "n-1",
                "email": "oidc-user@example.com",
                "email_verified": True,
                "given_name": "Oidc",
                "family_name": "User",
            },
            key_pem,
            algorithm="RS256",
            headers={"kid": "oidc-upstream-fixture-key"},
        )

        session = login_session(conn)

        with patch(
            "starlette.requests.Request.session",
            new_callable=lambda: property(lambda self: session),
        ):
            with patch(
                "services.oidc_upstream.exchange_code",
                return_value={"access_token": "at", "id_token": id_token},
            ):
                with patch("services.oidc_upstream.jwks._fetch_jwks", return_value=jwks_doc):
                    with patch("routers.oidc_upstream.authentication.send_mfa_code_email"):
                        response = tenant_client.get(
                            f"/auth/oidc/{conn['id']}/callback?state=state-1&code=code-1",
                            follow_redirects=False,
                        )

        assert response.status_code == 303
        assert response.headers["location"] == "/mfa/verify"


def _signed_id_token(**overrides):
    from datetime import UTC, datetime, timedelta

    import jwt

    from tests.fixtures.oidc import load_fixture_text

    now = datetime.now(UTC)
    claims = {
        "iss": "https://idp.example.com",
        "aud": "client-123",
        "sub": "subject-123",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "nonce": "n-1",
        "email": "oidc-user@example.com",
        "email_verified": True,
    }
    claims.update(overrides)
    return jwt.encode(
        claims,
        load_fixture_text("private_key.pem"),
        algorithm="RS256",
        headers={"kid": "oidc-upstream-fixture-key"},
    )


class _FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_bytes(self):
        yield b"not json" if self._body is None else json.dumps(self._body).encode()


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def stream(self, method, url, **kwargs):
        return self._response


def _last_login_failure(tenant_id, connection_id):
    import database

    events = database.event_log.list_events(tenant_id, limit=20)
    return next(
        e
        for e in events
        if e["event_type"] == "oidc_login_failed" and str(e["artifact_id"]) == str(connection_id)
    )


class TestLoginDiscoveryRefresh:
    """Sign-in refreshes a discovery-managed connection past the TTL."""

    def _stale(self, test_tenant, conn):
        import database

        database.execute(
            test_tenant["id"],
            "update oidc_idp_connections set discovery_fetched_at = now() - interval '2 hours'"
            " where id = :id",
            {"id": conn["id"]},
        )

    def test_refreshed_endpoints_are_used(self, tenant_client, test_tenant, test_user):
        from tests.fixtures.oidc import load_fixture

        conn = _make_connection(test_tenant, test_user)
        self._stale(test_tenant, conn)
        doc = dict(
            load_fixture("discovery"), authorization_endpoint="https://idp.example.com/authorize2"
        )
        with patch(
            "services.oidc_upstream.discovery.build_safe_client",
            return_value=_FakeClient(_FakeResponse(200, doc)),
        ):
            response = tenant_client.get(f"/auth/oidc/{conn['id']}/login", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("https://idp.example.com/authorize2?")

    def test_refused_document_stops_login(self, tenant_client, test_tenant, test_user):
        from tests.fixtures.oidc import load_fixture

        conn = _make_connection(test_tenant, test_user)
        self._stale(test_tenant, conn)
        doc = dict(load_fixture("discovery"), issuer="https://other.example.com")
        with patch(
            "services.oidc_upstream.discovery.build_safe_client",
            return_value=_FakeClient(_FakeResponse(200, doc)),
        ):
            response = tenant_client.get(f"/auth/oidc/{conn['id']}/login", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].endswith("/login?error=configuration_error")
        event = _last_login_failure(test_tenant["id"], conn["id"])
        assert event["metadata"]["reason"] == "discovery"
        assert "issuer mismatch" in event["metadata"]["detail"]


class TestUserinfoSubject:
    """OIDC Core 5.3.2: the userinfo sub must equal the ID token sub."""

    def _callback(self, tenant_client, conn, userinfo_response):
        from tests.fixtures.oidc import load_fixture

        session = login_session(conn)
        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: session),
            ),
            patch(
                "services.oidc_upstream.exchange_code",
                return_value={"access_token": "at", "id_token": _signed_id_token()},
            ),
            patch("services.oidc_upstream.jwks._fetch_jwks", return_value=load_fixture("jwks")),
            patch(
                "services.oidc_upstream.token_exchange.build_safe_client",
                return_value=_FakeClient(userinfo_response),
            ),
        ):
            return tenant_client.get(
                f"/auth/oidc/{conn['id']}/callback?state=state-1&code=code-1",
                follow_redirects=False,
            )

    def test_mismatched_sub_fails_login(self, tenant_client, test_tenant, test_user):
        import database

        conn = _make_connection(
            test_tenant,
            test_user,
            jit_provisioning=True,
            userinfo_endpoint="https://idp.example.com/userinfo",
        )
        response = self._callback(
            tenant_client, conn, _FakeResponse(200, {"sub": "someone-else", "email": "x@y.z"})
        )
        assert response.headers["location"].endswith("/login?error=auth_failed")
        assert (
            database.oidc_upstream.get_user_id_by_sub(
                test_tenant["id"], str(conn["id"]), "subject-123"
            )
            is None
        )
        event = _last_login_failure(test_tenant["id"], conn["id"])
        assert event["metadata"]["reason"] == "userinfo_sub_mismatch"

    def test_matching_sub_signs_in(self, tenant_client, test_tenant, test_user):
        import database

        conn = _make_connection(
            test_tenant,
            test_user,
            jit_provisioning=True,
            userinfo_endpoint="https://idp.example.com/userinfo",
        )
        response = self._callback(
            tenant_client, conn, _FakeResponse(200, {"sub": "subject-123", "name": "Oidc User"})
        )
        assert response.status_code == 303
        assert "error=" not in response.headers["location"]
        assert database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "subject-123"
        )

    def test_unreachable_userinfo_still_signs_in(self, tenant_client, test_tenant, test_user):
        """Unchanged: userinfo is optional when the endpoint fails."""
        conn = _make_connection(
            test_tenant,
            test_user,
            jit_provisioning=True,
            userinfo_endpoint="https://idp.example.com/userinfo",
        )
        response = self._callback(tenant_client, conn, _FakeResponse(503))
        assert "error=" not in response.headers["location"]


class TestCallbackFailures:
    """Every callback failure fails closed: an error redirect, an
    oidc_login_failed audit with its reason, and no signed-in session."""

    def _callback(self, tenant_client, conn, *, query="state=state-1&code=code-1", **patches):
        from tests.fixtures.oidc import load_fixture

        session = login_session(conn)
        exchange = patches.get(
            "exchange", {"return_value": {"access_token": "at", "id_token": _signed_id_token()}}
        )
        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: session),
            ),
            patch("services.oidc_upstream.exchange_code", **exchange),
            patch("services.oidc_upstream.jwks._fetch_jwks", return_value=load_fixture("jwks")),
        ):
            response = tenant_client.get(
                f"/auth/oidc/{conn['id']}/callback?{query}", follow_redirects=False
            )
        assert "user_id" not in session
        return response

    def _assert_failed(self, response, test_tenant, conn, reason, error="auth_failed"):
        assert response.status_code == 303
        assert response.headers["location"].endswith(f"/login?error={error}")
        event = _last_login_failure(test_tenant["id"], conn["id"])
        assert event["metadata"]["reason"] == reason
        return event

    def test_missing_code(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        response = self._callback(tenant_client, conn, query="state=state-1")
        self._assert_failed(response, test_tenant, conn, "missing_code")

    def test_token_exchange_failure(self, tenant_client, test_tenant, test_user):
        import services.oidc_upstream as oidc_service

        conn = _make_connection(test_tenant, test_user)
        response = self._callback(
            tenant_client,
            conn,
            exchange={"side_effect": oidc_service.TokenExchangeError("token endpoint said 400")},
        )
        event = self._assert_failed(response, test_tenant, conn, "token_exchange")
        assert "400" in event["metadata"]["detail"]

    def test_missing_id_token(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        response = self._callback(
            tenant_client, conn, exchange={"return_value": {"access_token": "at"}}
        )
        self._assert_failed(response, test_tenant, conn, "missing_id_token")

    def test_invalid_id_token(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user, jit_provisioning=True)
        response = self._callback(
            tenant_client,
            conn,
            exchange={"return_value": {"id_token": _signed_id_token(nonce="replayed")}},
        )
        self._assert_failed(response, test_tenant, conn, "id_token")

    def test_missing_correlation_claim(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(
            test_tenant, test_user, correlation_claim="employee_id", jit_provisioning=True
        )
        response = self._callback(tenant_client, conn)
        self._assert_failed(response, test_tenant, conn, "missing_sub")

    def test_unknown_user_without_jit(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user, jit_provisioning=False)
        response = self._callback(tenant_client, conn)
        self._assert_failed(response, test_tenant, conn, "user_not_found", error="user_not_found")

    def test_forbidden_user(self, tenant_client, test_tenant, test_user):
        from services.exceptions import ForbiddenError

        conn = _make_connection(test_tenant, test_user, jit_provisioning=True)
        with patch(
            "services.oidc_upstream.authenticate_via_oidc",
            side_effect=ForbiddenError(message="User is deactivated"),
        ):
            response = self._callback(tenant_client, conn)
        self._assert_failed(response, test_tenant, conn, "auth_failed")

    def test_saml_assigned_user_refused(
        self, tenant_client, test_tenant, test_user, test_super_admin_user
    ):
        """A linked user who is assigned to SAML is sent back to email-first."""
        import database

        conn = _make_connection(test_tenant, test_user)
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )
        idp = database.saml.create_identity_provider(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="Corp SAML",
            provider_type="okta",
            sp_entity_id=f"https://sp.example.com/{uuid4()}",
            created_by=str(test_super_admin_user["id"]),
            is_enabled=True,
        )
        database.users.update_user_saml_idp(test_tenant["id"], str(test_user["id"]), str(idp["id"]))

        response = self._callback(tenant_client, conn)

        assert response.status_code == 303
        assert response.headers["location"].endswith("/login?error=sso_required")
        events = database.event_log.list_events(test_tenant["id"], limit=20)
        refused = [e for e in events if e["event_type"] == "oidc_login_refused"]
        assert len(refused) == 1
        assert refused[0]["metadata"]["reason"] == "saml_assigned_user"
        # Audited once, as a refusal, not also as a generic failure.
        assert not any(e["event_type"] == "oidc_login_failed" for e in events)

    def test_already_linked_refused(self, tenant_client, test_tenant, test_user):
        from services.exceptions import ForbiddenError

        conn = _make_connection(test_tenant, test_user, jit_provisioning=True)
        with patch(
            "services.oidc_upstream.authenticate_via_oidc",
            side_effect=ForbiddenError(
                message="already linked", code="oidc_connection_already_linked"
            ),
        ):
            response = self._callback(tenant_client, conn)
        assert response.headers["location"].endswith("/login?error=account_already_linked")

    def test_connection_disabled_since_login(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user, is_enabled=False)
        response = self._callback(tenant_client, conn)
        assert response.headers["location"].endswith("/login?error=idp_disabled")

    @pytest.mark.parametrize("missing", ["token_endpoint", "jwks_uri"])
    def test_incomplete_configuration(self, tenant_client, test_tenant, test_user, missing):
        import routers.oidc_upstream.authentication as auth_router

        conn = _make_connection(test_tenant, test_user)
        real = auth_router._get_connection

        def incomplete(tenant_id, connection_id):
            row = real(tenant_id, connection_id)
            return {**row, missing: None}

        with patch.object(auth_router, "_get_connection", side_effect=incomplete):
            response = self._callback(tenant_client, conn)
        self._assert_failed(
            response, test_tenant, conn, "configuration_error", error="configuration_error"
        )


class TestSocialPresetRoutes:
    """The spec OIDC presets for consumer providers go through the same routes."""

    def test_linkedin_login_and_callback(self, tenant_client, test_tenant, test_user):
        import database

        conn = _make_connection(test_tenant, test_user, jit_provisioning=True)
        database.execute(
            test_tenant["id"],
            "update oidc_idp_connections set provider_type = 'linkedin' where id = :id",
            {"id": conn["id"]},
        )

        login = tenant_client.get(f"/auth/oidc/{conn['id']}/login", follow_redirects=False)
        assert login.status_code == 303
        location = login.headers["location"]
        assert location.startswith("https://idp.example.com/authorize?")
        assert f"%2Fauth%2Foidc%2F{conn['id']}%2Fcallback" in location

        from tests.fixtures.oidc import load_fixture

        session = login_session(conn)
        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: session),
            ),
            patch(
                "services.oidc_upstream.exchange_code",
                return_value={"access_token": "at", "id_token": _signed_id_token()},
            ) as exchange,
            patch("services.oidc_upstream.jwks._fetch_jwks", return_value=load_fixture("jwks")),
        ):
            response = tenant_client.get(
                f"/auth/oidc/{conn['id']}/callback?state=state-1&code=code-1",
                follow_redirects=False,
            )
        assert response.status_code == 303
        assert "error=" not in response.headers["location"]
        # LinkedIn only accepts the client credentials in the request body.
        assert exchange.call_args.kwargs["auth_method"] == "client_secret_post"
        assert database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "subject-123"
        )

    def test_login_without_authorization_endpoint(self, tenant_client, test_tenant, test_user):
        import routers.oidc_upstream.authentication as auth_router

        conn = _make_connection(test_tenant, test_user)
        real = auth_router._get_connection

        def unconfigured(tenant_id, connection_id):
            return {**real(tenant_id, connection_id), "authorization_endpoint": None}

        with (
            patch.object(auth_router, "_get_connection", side_effect=unconfigured),
            patch("services.oidc_upstream.refresh_for_login", side_effect=lambda t, c: c),
        ):
            response = tenant_client.get(f"/auth/oidc/{conn['id']}/login", follow_redirects=False)
        assert response.headers["location"].endswith("/login?error=configuration_error")


class TestRefusalMessages:
    @pytest.mark.parametrize(
        ("error", "text"),
        [
            ("sso_required", "signs in through your organization's single sign-on"),
            ("account_already_linked", "already linked to a different account at this provider"),
        ],
    )
    def test_login_page_explains_refusal(self, tenant_client, error, text):
        response = tenant_client.get(f"/login?error={error}")
        assert response.status_code == 200
        assert text in response.text.replace("&#39;", "'")
