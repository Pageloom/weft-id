"""OIDC back-channel logout (OpenID Connect Back-Channel Logout 1.0), OP side.

Ending a WeftID session queues a logout-token delivery for every client that
received an ID token in it and registered a ``backchannel_logout_uri``; the
worker sends them (``tests/services/oidc/test_backchannel.py``). Covers each
path that ends a session (end_session with a verified hint, the confirmation
form, the logout button, forced re-authentication), that no path waits on the
RP (no intermediate page for back-channel-only clients), the queued row, and
audit.
"""

import time

import database
import pytest
from services.oidc import tokens as tokens_service
from utils.session import SESSION_ID_KEY

SID = "sess-under-test"
REDIRECT_URI = "https://rp.example/cb"
BYE = "https://rp.example/post_logout_redirect"
BC_URI = "https://rp.example/backchannel_logout"


@pytest.fixture
def session_data(mocker) -> dict:
    data: dict = {}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: data),
    )
    return data


@pytest.fixture
def http(client, test_tenant_host, session_data):
    """Tenant-scoped client that never follows redirects."""

    class _Client:
        def get(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            return client.get(url, headers={"Host": test_tenant_host}, **kw)

        def post(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            return client.post(url, headers={"Host": test_tenant_host}, **kw)

    return _Client()


@pytest.fixture
def signed_in(http, test_user, override_auth, session_data):
    override_auth(test_user)
    session_data.update(
        {
            "user_id": str(test_user["id"]),
            "session_start": int(time.time()),
            SESSION_ID_KEY: SID,
        }
    )
    return http


@pytest.fixture
def make_client(test_tenant, test_admin_user):
    """Factory: an OIDC-enabled client with back-channel logout."""

    def _make(name, *, bc_uri=BC_URI):
        client = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            name=name,
            redirect_uris=[REDIRECT_URI],
            created_by=test_admin_user["id"],
            post_logout_redirect_uris=[BYE],
            backchannel_logout_uri=bc_uri,
        )
        database.oauth2.update_client_oidc_settings(
            test_tenant["id"], client["client_id"], oidc_enabled=True, available_to_all=True
        )
        return client

    return _make


@pytest.fixture
def issue(test_tenant, test_tenant_host):
    """Factory: an ID token for ``user`` issued to ``client`` in session ``sid``."""

    def _issue(client, user, *, sid=SID) -> str:
        return tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer=f"https://{test_tenant_host}",
            client_uuid=str(client["id"]),
            client_id=client["client_id"],
            user_id=str(user["id"]),
            scopes={"openid"},
            sid=sid,
        )

    return _issue


def _deliveries(test_tenant) -> list[dict]:
    return database.fetchall(
        str(test_tenant["id"]),
        "select * from oidc_backchannel_logout_deliveries order by created_at",
    )


def _last_signed_out(test_tenant) -> dict:
    return next(
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=20)
        if e["event_type"] == "user_signed_out"
    )


class TestEndSession:
    def test_verified_hint_queues_delivery_and_redirects_at_once(
        self, signed_in, make_client, issue, test_user, test_tenant, test_tenant_host
    ):
        rp = make_client("RP")
        hint = issue(rp, test_user)

        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": hint, "post_logout_redirect_uri": BYE, "state": "st"},
        )

        assert response.status_code == 303
        assert response.headers["location"] == f"{BYE}?state=st"
        (row,) = _deliveries(test_tenant)
        assert str(row["client_id"]) == str(rp["id"])
        assert row["sub"] == str(test_user["id"])
        assert row["sid"] == SID
        assert row["issuer"] == f"https://{test_tenant_host}"
        assert row["status"] == "pending"

    def test_audit_counts_backchannel_deliveries(
        self, signed_in, make_client, issue, test_user, test_tenant
    ):
        rp = make_client("RP")
        signed_in.get("/oauth2/logout", params={"id_token_hint": issue(rp, test_user)})
        event = _last_signed_out(test_tenant)
        assert event["metadata"]["backchannel_logout_count"] == 1
        assert event["metadata"]["frontchannel_logout_count"] == 0

    def test_other_sessions_are_not_queued(
        self, signed_in, make_client, issue, test_user, test_tenant
    ):
        rp = make_client("RP", bc_uri=None)
        other = make_client("Other")
        issue(other, test_user, sid="another-session")
        signed_in.get("/oauth2/logout", params={"id_token_hint": issue(rp, test_user)})
        assert _deliveries(test_tenant) == []

    def test_failure_never_blocks_logout(
        self, signed_in, make_client, issue, test_user, session_data, mocker
    ):
        rp = make_client("RP")
        hint = issue(rp, test_user)
        mocker.patch(
            "database.oauth2.consume_session_clients",
            side_effect=RuntimeError("database unavailable"),
        )
        response = signed_in.get(
            "/oauth2/logout", params={"id_token_hint": hint, "post_logout_redirect_uri": BYE}
        )
        assert response.status_code == 303
        assert response.headers["location"] == BYE
        assert session_data == {}


class TestConfirm:
    def test_confirm_queues_delivery(
        self, signed_in, make_client, issue, test_user, test_tenant, session_data
    ):
        rp = make_client("RP")
        issue(rp, test_user)
        response = signed_in.post("/oauth2/logout/confirm")
        assert response.status_code == 303
        assert response.headers["location"] == "/oauth2/logout/done"
        assert len(_deliveries(test_tenant)) == 1
        assert session_data == {}


class TestLocalLogout:
    def test_logout_button_queues_delivery(
        self, signed_in, make_client, issue, test_user, test_tenant
    ):
        rp = make_client("RP")
        issue(rp, test_user)
        response = signed_in.post("/logout")
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert len(_deliveries(test_tenant)) == 1
        assert _last_signed_out(test_tenant)["metadata"]["backchannel_logout_count"] == 1

    def test_without_backchannel_clients_counts_zero(self, signed_in, test_tenant):
        signed_in.post("/logout")
        assert _last_signed_out(test_tenant)["metadata"]["backchannel_logout_count"] == 0


class TestReauthentication:
    def test_other_clients_queued_asking_client_not(
        self, signed_in, make_client, issue, test_user, test_tenant
    ):
        asking = make_client("Asking")
        other = make_client("Other")
        issue(asking, test_user)
        issue(other, test_user)

        response = signed_in.get(
            "/oauth2/authorize",
            params={
                "client_id": asking["client_id"],
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
                "prompt": "login",
            },
        )

        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")
        (row,) = _deliveries(test_tenant)
        assert str(row["client_id"]) == str(other["id"])
        event = _last_signed_out(test_tenant)
        assert event["metadata"]["reason"] == "reauthentication"
        assert event["metadata"]["backchannel_logout_count"] == 1


class TestRefreshTokenRevocation:
    """Ending a session revokes the refresh tokens issued in it (BCL 2.7)."""

    @staticmethod
    def _refresh(test_tenant, client, user, sid=SID) -> str:
        tid = str(test_tenant["id"])
        token, _ = database.oauth2.create_refresh_token(
            tid, tid, str(client["id"]), str(user["id"]), scope="openid", sid=sid
        )
        return token

    @staticmethod
    def _valid(test_tenant, client, token) -> bool:
        return (
            database.oauth2.validate_refresh_token(str(test_tenant["id"]), token, str(client["id"]))
            is not None
        )

    def test_logout_button_revokes_session_tokens(
        self, signed_in, make_client, issue, test_user, test_tenant
    ):
        rp = make_client("RP")
        issue(rp, test_user)
        mine = self._refresh(test_tenant, rp, test_user)
        elsewhere = self._refresh(test_tenant, rp, test_user, sid="another-session")

        signed_in.post("/logout")

        assert not self._valid(test_tenant, rp, mine)
        assert self._valid(test_tenant, rp, elsewhere)
        assert _last_signed_out(test_tenant)["metadata"]["refresh_tokens_revoked"] == 1

    def test_end_session_revokes_session_tokens(
        self, signed_in, make_client, issue, test_user, test_tenant
    ):
        rp = make_client("RP", bc_uri=None)
        hint = issue(rp, test_user)
        token = self._refresh(test_tenant, rp, test_user)

        signed_in.get("/oauth2/logout", params={"id_token_hint": hint})

        assert not self._valid(test_tenant, rp, token)

    def test_reauthentication_revokes_and_audits(
        self, signed_in, make_client, issue, test_user, test_tenant
    ):
        asking = make_client("Asking")
        issue(asking, test_user)
        token = self._refresh(test_tenant, asking, test_user)

        signed_in.get(
            "/oauth2/authorize",
            params={
                "client_id": asking["client_id"],
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
                "prompt": "login",
            },
        )

        assert not self._valid(test_tenant, asking, token)
        event = _last_signed_out(test_tenant)
        assert event["metadata"]["reason"] == "reauthentication"
        assert event["metadata"]["refresh_tokens_revoked"] == 1


class TestServerSideRevocation:
    """Every path that ends a session revokes its sid (a copied cookie dies too)."""

    @staticmethod
    def _revoked(test_tenant) -> bool:
        return database.revoked_sessions.is_session_revoked(str(test_tenant["id"]), SID)

    def test_logout_button(self, signed_in, test_tenant):
        signed_in.post("/logout")
        assert self._revoked(test_tenant)

    def test_end_session_with_verified_hint(
        self, signed_in, make_client, issue, test_user, test_tenant
    ):
        rp = make_client("RP", bc_uri=None)
        signed_in.get("/oauth2/logout", params={"id_token_hint": issue(rp, test_user)})
        assert self._revoked(test_tenant)

    def test_confirm(self, signed_in, test_tenant):
        signed_in.post("/oauth2/logout/confirm")
        assert self._revoked(test_tenant)

    def test_reauthentication(self, signed_in, make_client, test_tenant):
        asking = make_client("Asking")
        signed_in.get(
            "/oauth2/authorize",
            params={
                "client_id": asking["client_id"],
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
                "prompt": "login",
            },
        )
        assert self._revoked(test_tenant)
