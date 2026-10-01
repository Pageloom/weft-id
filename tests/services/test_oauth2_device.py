"""Service tests for the device authorization grant (services.oauth2_device).
Real database."""

from datetime import UTC, datetime

import database
import oauth2
import pytest
from services import oauth2_device as svc
from services.event_log import SYSTEM_ACTOR_ID
from services.exceptions import ForbiddenError


def _client(test_tenant, test_admin_user, *, enabled=True, **kwargs):
    created = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Device CLI",
        redirect_uris=["http://localhost:3000/callback"],
        created_by=str(test_admin_user["id"]),
        device_grant_enabled=enabled,
        **kwargs,
    )
    # The client as the routers pass it (a fresh lookup).
    return database.oauth2.get_client_by_client_id(test_tenant["id"], created["client_id"])


def _events(test_tenant, event_type):
    return [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=30)
        if e["event_type"] == event_type
    ]


@pytest.fixture
def device_client(test_tenant, test_admin_user):
    return _client(test_tenant, test_admin_user)


def _start(test_tenant, client, scope="openid profile"):
    return svc.start_device_authorization(test_tenant["id"], client, scope)


def _approve(test_tenant, started, user):
    pending = svc.find_pending_request(test_tenant["id"], started.user_code)
    assert svc.decide_request(
        test_tenant["id"], pending, str(user["id"]), approved=True, auth_time=datetime.now(UTC)
    )
    return pending


class TestClientEligibility:
    def test_matrix(self):
        base = {"client_type": "normal", "is_active": True, "device_grant_enabled": True}
        assert svc.client_can_use_device_grant(base)
        assert not svc.client_can_use_device_grant({**base, "device_grant_enabled": False})
        assert not svc.client_can_use_device_grant({**base, "is_active": False})
        assert not svc.client_can_use_device_grant({**base, "client_type": "b2b"})


class TestStart:
    def test_returns_codes_and_logs_with_system_actor(self, test_tenant, device_client):
        started = _start(test_tenant, device_client)

        assert started.device_code.startswith("device_")
        assert len(started.user_code) == 9 and started.user_code[4] == "-"
        assert started.expires_in == 600
        assert started.interval == 5

        events = _events(test_tenant, "oauth2_device_authorization_requested")
        assert len(events) == 1
        assert str(events[0]["actor_user_id"]) == SYSTEM_ACTOR_ID
        assert str(events[0]["artifact_id"]) == str(device_client["id"])
        assert events[0]["metadata"]["client_id"] == device_client["client_id"]
        assert events[0]["metadata"]["scope"] == "openid profile"

    @pytest.mark.parametrize(
        "change",
        [
            {"device_grant_enabled": False},
            {"is_active": False},
            {"client_type": "b2b"},
        ],
    )
    def test_refuses_ineligible_clients(self, test_tenant, device_client, change):
        with pytest.raises(ForbiddenError) as exc:
            _start(test_tenant, {**device_client, **change})
        assert exc.value.code == "unauthorized_client"
        assert _events(test_tenant, "oauth2_device_authorization_requested") == []

    def test_sweeps_long_expired_requests(self, test_tenant, device_client):
        old = _start(test_tenant, device_client)
        database.execute(
            test_tenant["id"],
            "update oauth2_device_codes set expires_at = now() - interval '2 hours'",
            {},
        )
        _start(test_tenant, device_client)
        assert (
            database.oauth2.find_device_code(
                test_tenant["id"], old.device_code, str(device_client["id"])
            )
            is None
        )


class TestFindPendingRequest:
    def test_accepts_lowercase_and_no_separator(self, test_tenant, device_client):
        started = _start(test_tenant, device_client)
        typed = started.user_code.replace("-", " ").lower()
        pending = svc.find_pending_request(test_tenant["id"], typed)
        assert pending is not None
        assert pending.user_code == started.user_code
        assert pending.scope == "openid profile"
        assert pending.client["client_id"] == device_client["client_id"]

    @pytest.mark.parametrize("typed", ["", "ABC", "AAAA-AAAA", "BCDF-GHJK-L", "<script>"])
    def test_malformed_never_queries(self, test_tenant, typed, mocker):
        spy = mocker.patch("database.oauth2.get_pending_by_user_code")
        assert svc.find_pending_request(test_tenant["id"], typed) is None
        spy.assert_not_called()

    def test_unknown_code(self, test_tenant, device_client):
        _start(test_tenant, device_client)
        assert svc.find_pending_request(test_tenant["id"], "ZZZZ-ZZZZ") is None

    def test_client_switched_off_or_deactivated_since(self, test_tenant, device_client):
        started = _start(test_tenant, device_client)
        tid = test_tenant["id"]
        database.oauth2.update_client(tid, device_client["client_id"], device_grant_enabled=False)
        assert svc.find_pending_request(tid, started.user_code) is None

        database.oauth2.update_client(tid, device_client["client_id"], device_grant_enabled=True)
        database.oauth2.deactivate_client(tid, device_client["client_id"])
        assert svc.find_pending_request(tid, started.user_code) is None


class TestDecide:
    def test_approve_records_consent_and_logs(self, test_tenant, device_client, test_user):
        started = _start(test_tenant, device_client)
        _approve(test_tenant, started, test_user)

        grant = database.oauth2.get_consent_grant(
            test_tenant["id"], str(device_client["id"]), str(test_user["id"])
        )
        assert set(grant["scopes"]) == {"openid", "profile"}
        events = _events(test_tenant, "oauth2_device_authorization_approved")
        assert len(events) == 1
        assert str(events[0]["actor_user_id"]) == str(test_user["id"])
        assert events[0]["metadata"]["client_id"] == device_client["client_id"]

    def test_deny_logs_without_consent(self, test_tenant, device_client, test_user):
        started = _start(test_tenant, device_client)
        pending = svc.find_pending_request(test_tenant["id"], started.user_code)
        assert svc.decide_request(
            test_tenant["id"], pending, str(test_user["id"]), approved=False, auth_time=None
        )
        assert (
            database.oauth2.get_consent_grant(
                test_tenant["id"], str(device_client["id"]), str(test_user["id"])
            )
            is None
        )
        assert len(_events(test_tenant, "oauth2_device_authorization_denied")) == 1

    def test_second_decision_writes_nothing(self, test_tenant, device_client, test_user):
        started = _start(test_tenant, device_client)
        pending = _approve(test_tenant, started, test_user)
        assert not svc.decide_request(
            test_tenant["id"], pending, str(test_user["id"]), approved=False, auth_time=None
        )
        assert _events(test_tenant, "oauth2_device_authorization_denied") == []
        assert len(_events(test_tenant, "oauth2_device_authorization_approved")) == 1


class TestPollAndRedeem:
    def _poll(self, test_tenant, client, started):
        return svc.poll(test_tenant["id"], client, started.device_code)

    def test_pending_then_slow_down(self, test_tenant, device_client):
        started = _start(test_tenant, device_client)
        assert self._poll(test_tenant, device_client, started).outcome == svc.AUTHORIZATION_PENDING
        assert self._poll(test_tenant, device_client, started).outcome == svc.SLOW_DOWN

    def test_unknown_or_other_clients_code(self, test_tenant, device_client, test_admin_user):
        started = _start(test_tenant, device_client)
        other = _client(test_tenant, test_admin_user)
        assert svc.poll(test_tenant["id"], device_client, "device_x").outcome == svc.INVALID_GRANT
        assert self._poll(test_tenant, other, started).outcome == svc.INVALID_GRANT

    def test_denied(self, test_tenant, device_client, test_user):
        started = _start(test_tenant, device_client)
        pending = svc.find_pending_request(test_tenant["id"], started.user_code)
        svc.decide_request(
            test_tenant["id"], pending, str(test_user["id"]), approved=False, auth_time=None
        )
        assert self._poll(test_tenant, device_client, started).outcome == svc.ACCESS_DENIED

    def test_expired(self, test_tenant, device_client):
        started = _start(test_tenant, device_client)
        database.execute(
            test_tenant["id"],
            "update oauth2_device_codes set expires_at = now() - interval '1 second'",
            {},
        )
        assert self._poll(test_tenant, device_client, started).outcome == svc.EXPIRED_TOKEN

    def test_approved_redeems_once_and_logs(self, test_tenant, device_client, test_user):
        started = _start(test_tenant, device_client)
        _approve(test_tenant, started, test_user)

        result = self._poll(test_tenant, device_client, started)
        assert result.outcome == svc.APPROVED
        redeemed = svc.redeem(test_tenant["id"], device_client, result.row)
        assert isinstance(redeemed["id"], str)
        assert str(redeemed["user_id"]) == str(test_user["id"])
        assert redeemed["scope"] == "openid profile"

        events = _events(test_tenant, "oauth2_device_code_redeemed")
        assert len(events) == 1
        assert str(events[0]["actor_user_id"]) == str(test_user["id"])

        # Redeemed: later polls are invalid_grant, a second redeem is None.
        assert self._poll(test_tenant, device_client, started).outcome == svc.INVALID_GRANT
        assert svc.redeem(test_tenant["id"], device_client, result.row) is None
        assert len(_events(test_tenant, "oauth2_device_code_redeemed")) == 1


class TestUserCodeHelpers:
    def test_generate_uses_alphabet(self):
        for _ in range(50):
            code = oauth2.generate_user_code()
            assert len(code) == 8 and set(code) <= set(oauth2.USER_CODE_ALPHABET)

    def test_normalize_and_format(self):
        assert oauth2.normalize_user_code(" bcdf-ghjk ") == "BCDFGHJK"
        assert oauth2.normalize_user_code("BCDF\tGHJK") == "BCDFGHJK"
        assert oauth2.normalize_user_code("BCDFGHJ") is None
        assert oauth2.normalize_user_code("BCDFGHJA") is None  # vowel
        assert oauth2.format_user_code("BCDFGHJK") == "BCDF-GHJK"
