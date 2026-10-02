"""Database tests: device authorization grant (RFC 8628) rows and the
device_grant_enabled client column.

Covers creation (hashed codes, defaults), user-code lookup and one-time
decisions, device-code lookup bound to the client, poll recording with
slow_down, exactly-once redemption, the expiry sweep, the cleanup on user
token revocation, and RLS tenant isolation.
"""

from datetime import UTC, datetime
from uuid import uuid4

import database
import oauth2
import pytest
from psycopg.errors import CheckViolation


def _client(test_tenant, test_admin_user, **kwargs):
    kwargs.setdefault("redirect_uris", ["http://localhost:3000/callback"])
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Device App",
        created_by=str(test_admin_user["id"]),
        **kwargs,
    )


def _create(test_tenant, client, scope="openid profile"):
    return database.oauth2.create_device_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        client_id=str(client["id"]),
        scope=scope,
    )


def _set(test_tenant, row_id, assignments):
    database.execute(
        test_tenant["id"],
        f"update oauth2_device_codes set {assignments} where id = :id",
        {"id": row_id},
    )


def _approve(test_tenant, created, user):
    return database.oauth2.decide_device_code(
        test_tenant["id"],
        created["id"],
        approved=True,
        user_id=str(user["id"]),
        auth_time=datetime.now(UTC),
    )


@pytest.fixture
def client_row(test_tenant, test_admin_user):
    return _client(test_tenant, test_admin_user, device_grant_enabled=True)


class TestDeviceGrantColumn:
    def test_defaults_to_false(self, test_tenant, normal_oauth2_client):
        row = database.oauth2.get_client_by_client_id(
            test_tenant["id"], normal_oauth2_client["client_id"]
        )
        assert row["device_grant_enabled"] is False

    def test_create_read_update(self, test_tenant, test_admin_user):
        tid = test_tenant["id"]
        created = _client(test_tenant, test_admin_user, device_grant_enabled=True)
        assert created["device_grant_enabled"] is True
        assert database.oauth2.get_client_by_id(tid, str(created["id"]))["device_grant_enabled"]
        listed = [
            c
            for c in database.oauth2.get_all_clients(tid)
            if c["client_id"] == created["client_id"]
        ]
        assert listed[0]["device_grant_enabled"] is True

        off = database.oauth2.update_client(tid, created["client_id"], device_grant_enabled=False)
        assert off["device_grant_enabled"] is False
        # Omitted leaves it alone.
        kept = database.oauth2.update_client(tid, created["client_id"], name="Renamed")
        assert kept["device_grant_enabled"] is False


class TestPublicClientColumn:
    def _public(self, test_tenant, test_admin_user):
        return _client(
            test_tenant,
            test_admin_user,
            redirect_uris=[],
            device_grant_enabled=True,
            is_public=True,
        )

    def test_defaults_to_false_everywhere(self, test_tenant, normal_oauth2_client):
        tid = test_tenant["id"]
        assert normal_oauth2_client["is_public"] is False
        assert (
            database.oauth2.get_client_by_client_id(tid, normal_oauth2_client["client_id"])[
                "is_public"
            ]
            is False
        )
        assert (
            database.oauth2.get_client_by_id(tid, str(normal_oauth2_client["id"]))["is_public"]
            is False
        )

    def test_public_client_gets_no_secret(self, test_tenant, test_admin_user):
        tid = test_tenant["id"]
        created = self._public(test_tenant, test_admin_user)
        assert created["is_public"] is True
        assert "client_secret" not in created

        row = database.oauth2.get_client_by_client_id(tid, created["client_id"])
        assert row["is_public"] is True
        # The stored hash is of a secret nobody has: it is still a valid hash.
        assert row["client_secret_hash"].startswith("$argon2")
        listed = [c for c in database.oauth2.get_all_clients(tid, client_type="normal")]
        assert [c["is_public"] for c in listed if c["client_id"] == created["client_id"]] == [True]
        # Every update path returns the flag.
        assert database.oauth2.update_client(tid, created["client_id"], name="TV")["is_public"]

    def test_public_client_must_keep_the_device_grant(self, test_tenant, test_admin_user):
        created = self._public(test_tenant, test_admin_user)
        with pytest.raises(CheckViolation, match="chk_oauth2_clients_public_device_only"):
            database.oauth2.update_client(
                test_tenant["id"], created["client_id"], device_grant_enabled=False
            )

    def test_public_client_needs_the_device_grant_at_creation(self, test_tenant, test_admin_user):
        with pytest.raises(CheckViolation, match="chk_oauth2_clients_public_device_only"):
            _client(test_tenant, test_admin_user, redirect_uris=[], is_public=True)

    def test_secret_cannot_be_regenerated(self, test_tenant, test_admin_user):
        tid = test_tenant["id"]
        created = self._public(test_tenant, test_admin_user)
        before = database.oauth2.get_client_by_client_id(tid, created["client_id"])

        assert database.oauth2.regenerate_client_secret(tid, created["client_id"]) is None
        after = database.oauth2.get_client_by_client_id(tid, created["client_id"])
        assert after["client_secret_hash"] == before["client_secret_hash"]

    def test_regenerate_unknown_client(self, test_tenant):
        assert database.oauth2.regenerate_client_secret(test_tenant["id"], "nope") is None

    def test_registered_public_client(self, test_tenant):
        created = database.oauth2.create_registered_client(
            test_tenant["id"],
            str(test_tenant["id"]),
            name="TV",
            redirect_uris=[],
            post_logout_redirect_uris=[],
            frontchannel_logout_uri=None,
            frontchannel_logout_session_required=True,
            backchannel_logout_uri=None,
            backchannel_logout_session_required=True,
            logo_uri=None,
            client_uri=None,
            policy_uri=None,
            tos_uri=None,
            initiate_login_uri=None,
            registration_metadata={},
            registration_access_token_hash="x",
            registered_with_token_id=None,
            available_to_all=False,
            device_grant_enabled=True,
            is_public=True,
        )
        assert created["is_public"] is True
        assert created["device_grant_enabled"] is True
        assert "client_secret" not in created


class TestCreate:
    def test_returns_plain_codes_and_stores_only_digests(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        assert created["device_code"].startswith("device_")
        assert len(created["user_code"]) == oauth2.USER_CODE_LENGTH
        assert set(created["user_code"]) <= set(oauth2.USER_CODE_ALPHABET)
        assert created["poll_interval"] == oauth2.DEVICE_POLL_INTERVAL_SECONDS

        row = database.fetchone(
            test_tenant["id"],
            "select * from oauth2_device_codes where id = :id",
            {"id": created["id"]},
        )
        assert row["status"] == "pending"
        assert row["scope"] == "openid profile"
        assert row["device_code_lookup"] == oauth2.token_lookup(created["device_code"])
        assert row["user_code_lookup"] == oauth2.token_lookup(created["user_code"])
        assert created["device_code"] not in row["device_code_hash"]
        # A fast digest (no Argon2 on a public endpoint polled every 5s).
        assert row["device_code_hash"] == oauth2.token_lookup(created["device_code"])
        assert row["user_id"] is None

    def test_retries_on_user_code_collision(self, test_tenant, client_row, mocker):
        first = _create(test_tenant, client_row)
        mocker.patch("oauth2.generate_user_code", side_effect=[first["user_code"], "BCDFGHJK"])
        second = _create(test_tenant, client_row)
        assert second["user_code"] == "BCDFGHJK"

    def test_gives_up_after_repeated_collisions(self, test_tenant, client_row, mocker):
        first = _create(test_tenant, client_row)
        mocker.patch("oauth2.generate_user_code", return_value=first["user_code"])
        with pytest.raises(RuntimeError):
            _create(test_tenant, client_row)


class TestUserCodeLookupAndDecision:
    def test_finds_pending_request(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        row = database.oauth2.get_pending_by_user_code(test_tenant["id"], created["user_code"])
        assert str(row["id"]) == created["id"]
        assert str(row["client_id"]) == str(client_row["id"])
        assert row["scope"] == "openid profile"

    def test_unknown_code_is_none(self, test_tenant, client_row):
        _create(test_tenant, client_row)
        assert database.oauth2.get_pending_by_user_code(test_tenant["id"], "ZZZZZZZZ") is None

    def test_expired_is_none(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        _set(test_tenant, created["id"], "expires_at = now() - interval '1 second'")
        assert (
            database.oauth2.get_pending_by_user_code(test_tenant["id"], created["user_code"])
            is None
        )

    def test_approve_records_user_and_auth_time_once(self, test_tenant, client_row, test_user):
        created = _create(test_tenant, client_row)
        decided = _approve(test_tenant, created, test_user)
        assert str(decided["id"]) == created["id"]

        row = database.fetchone(
            test_tenant["id"],
            "select status, user_id, auth_time, decided_at from oauth2_device_codes where id = :id",
            {"id": created["id"]},
        )
        assert row["status"] == "approved"
        assert str(row["user_id"]) == str(test_user["id"])
        assert row["auth_time"] is not None and row["decided_at"] is not None

        # A decided request is no longer found by its user code, and cannot be
        # decided again.
        assert (
            database.oauth2.get_pending_by_user_code(test_tenant["id"], created["user_code"])
            is None
        )
        assert _approve(test_tenant, created, test_user) is None

    def test_deny_stores_no_auth_time(self, test_tenant, client_row, test_user):
        created = _create(test_tenant, client_row)
        decided = database.oauth2.decide_device_code(
            test_tenant["id"],
            created["id"],
            approved=False,
            user_id=str(test_user["id"]),
            auth_time=datetime.now(UTC),
        )
        assert decided is not None
        row = database.fetchone(
            test_tenant["id"],
            "select status, auth_time from oauth2_device_codes where id = :id",
            {"id": created["id"]},
        )
        assert row["status"] == "denied"
        assert row["auth_time"] is None

    def test_expired_cannot_be_decided(self, test_tenant, client_row, test_user):
        created = _create(test_tenant, client_row)
        _set(test_tenant, created["id"], "expires_at = now() - interval '1 second'")
        assert _approve(test_tenant, created, test_user) is None


class TestDeviceCodeLookup:
    def test_finds_by_device_code_for_its_client(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        row = database.oauth2.find_device_code(
            test_tenant["id"], created["device_code"], str(client_row["id"])
        )
        assert str(row["id"]) == created["id"]
        assert row["status"] == "pending"
        assert row["expired"] is False
        assert "device_code_hash" not in row

    def test_other_client_or_wrong_code_is_none(self, test_tenant, client_row, test_admin_user):
        created = _create(test_tenant, client_row)
        other = _client(test_tenant, test_admin_user, device_grant_enabled=True)
        tid = test_tenant["id"]
        assert (
            database.oauth2.find_device_code(tid, created["device_code"], str(other["id"])) is None
        )
        assert database.oauth2.find_device_code(tid, "device_nope", str(client_row["id"])) is None

    def test_expired_row_is_returned_flagged(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        _set(test_tenant, created["id"], "expires_at = now() - interval '1 second'")
        row = database.oauth2.find_device_code(
            test_tenant["id"], created["device_code"], str(client_row["id"])
        )
        assert row["expired"] is True


class TestRecordPoll:
    def test_first_poll_is_not_slow_down(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        polled = database.oauth2.record_poll(test_tenant["id"], created["id"])
        assert polled == {"slow_down": False, "poll_interval": 5}

    def test_immediate_second_poll_slows_down_and_grows_interval(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        database.oauth2.record_poll(test_tenant["id"], created["id"])
        polled = database.oauth2.record_poll(test_tenant["id"], created["id"])
        assert polled == {"slow_down": True, "poll_interval": 10}
        # The grown interval sticks for later polls.
        _set(test_tenant, created["id"], "last_polled_at = now() - interval '6 seconds'")
        again = database.oauth2.record_poll(test_tenant["id"], created["id"])
        assert again == {"slow_down": True, "poll_interval": 15}

    def test_poll_after_interval_is_fine(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        _set(test_tenant, created["id"], "last_polled_at = now() - interval '5 seconds'")
        polled = database.oauth2.record_poll(test_tenant["id"], created["id"])
        assert polled == {"slow_down": False, "poll_interval": 5}

    def test_one_second_of_jitter_is_tolerated(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        _set(test_tenant, created["id"], "last_polled_at = now() - interval '4.2 seconds'")
        assert database.oauth2.record_poll(test_tenant["id"], created["id"])["slow_down"] is False

    def test_interval_is_capped(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        _set(test_tenant, created["id"], "poll_interval = 298, last_polled_at = now()")
        polled = database.oauth2.record_poll(test_tenant["id"], created["id"])
        assert polled == {"slow_down": True, "poll_interval": 300}

    def test_missing_row_is_none(self, test_tenant):
        assert database.oauth2.record_poll(test_tenant["id"], str(uuid4())) is None


class TestRedeem:
    def test_redeems_approved_exactly_once(self, test_tenant, client_row, test_user):
        created = _create(test_tenant, client_row)
        _approve(test_tenant, created, test_user)
        redeemed = database.oauth2.redeem_device_code(test_tenant["id"], created["id"])
        assert str(redeemed["id"]) == created["id"]
        assert str(redeemed["user_id"]) == str(test_user["id"])
        assert redeemed["scope"] == "openid profile"
        assert redeemed["auth_time"] is not None
        assert database.oauth2.redeem_device_code(test_tenant["id"], created["id"]) is None

    def test_pending_or_denied_cannot_be_redeemed(self, test_tenant, client_row, test_user):
        pending = _create(test_tenant, client_row)
        assert database.oauth2.redeem_device_code(test_tenant["id"], pending["id"]) is None
        denied = _create(test_tenant, client_row)
        database.oauth2.decide_device_code(
            test_tenant["id"],
            denied["id"],
            approved=False,
            user_id=str(test_user["id"]),
            auth_time=None,
        )
        assert database.oauth2.redeem_device_code(test_tenant["id"], denied["id"]) is None

    def test_expired_approval_cannot_be_redeemed(self, test_tenant, client_row, test_user):
        created = _create(test_tenant, client_row)
        _approve(test_tenant, created, test_user)
        _set(test_tenant, created["id"], "expires_at = now() - interval '1 second'")
        assert database.oauth2.redeem_device_code(test_tenant["id"], created["id"]) is None


class TestCleanup:
    def test_sweeps_only_rows_expired_over_an_hour_ago(self, test_tenant, client_row):
        live = _create(test_tenant, client_row)
        recent = _create(test_tenant, client_row)
        old = _create(test_tenant, client_row)
        _set(test_tenant, recent["id"], "expires_at = now() - interval '10 minutes'")
        _set(test_tenant, old["id"], "expires_at = now() - interval '61 minutes'")

        assert database.oauth2.cleanup_expired_device_codes(test_tenant["id"]) == 1
        remaining = {
            str(r["id"])
            for r in database.fetchall(test_tenant["id"], "select id from oauth2_device_codes", {})
        }
        assert {live["id"], recent["id"]} <= remaining
        assert old["id"] not in remaining

    def test_revoking_user_tokens_drops_unredeemed_approvals(
        self, test_tenant, client_row, test_user
    ):
        approved = _create(test_tenant, client_row)
        _approve(test_tenant, approved, test_user)
        pending = _create(test_tenant, client_row)

        database.oauth2.revoke_all_user_tokens(test_tenant["id"], str(test_user["id"]))

        assert database.oauth2.redeem_device_code(test_tenant["id"], approved["id"]) is None
        assert (
            database.oauth2.get_pending_by_user_code(test_tenant["id"], pending["user_code"])
            is not None
        )


class TestTenantIsolation:
    def test_not_visible_under_other_tenant(self, test_tenant, client_row):
        created = _create(test_tenant, client_row)
        other = database.fetchone(
            database.UNSCOPED,
            "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
            {"s": f"other-{uuid4().hex[:8]}", "n": "Other Tenant"},
        )
        try:
            oid = other["id"]
            assert database.oauth2.get_pending_by_user_code(oid, created["user_code"]) is None
            assert (
                database.oauth2.find_device_code(oid, created["device_code"], str(client_row["id"]))
                is None
            )
            assert database.oauth2.redeem_device_code(oid, created["id"]) is None
        finally:
            database.execute(
                database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": other["id"]}
            )
        assert database.oauth2.get_pending_by_user_code(test_tenant["id"], created["user_code"])

    def test_unscoped_write_fails_closed(self, test_tenant, client_row):
        with pytest.raises(Exception, match="row-level security|violates"):
            database.oauth2.create_device_code(
                tenant_id=database.UNSCOPED,
                tenant_id_value=str(test_tenant["id"]),
                client_id=str(client_row["id"]),
                scope=None,
            )
