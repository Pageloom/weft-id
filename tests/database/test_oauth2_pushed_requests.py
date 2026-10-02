"""Database tests: pushed authorization requests (RFC 9126).

Covers the ``require_pushed_authorization_requests`` client column (default,
CHECK, every read returns it, update, registered clients) and the pushed
request store (single use, bound to the client, expiry, sweep, cascade, RLS).
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import database
import pytest
from psycopg.errors import CheckViolation


def _client(test_tenant, test_admin_user, **kwargs):
    kwargs.setdefault("redirect_uris", ["https://app.example.com/callback"])
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="PAR App",
        created_by=str(test_admin_user["id"]),
        **kwargs,
    )


def _push(test_tenant, client, reference_hash="h1", *, expires_at=None, parameters=None):
    return database.oauth2.create_pushed_request(
        test_tenant["id"],
        str(test_tenant["id"]),
        client_id=str(client["id"]),
        reference_hash=reference_hash,
        parameters=parameters or {"response_type": "code", "state": "s"},
        expires_at=expires_at or datetime.now(UTC) + timedelta(seconds=60),
    )


def _count(test_tenant) -> int:
    return database.fetchone(
        test_tenant["id"], "select count(*) as n from oauth2_pushed_authorization_requests", {}
    )["n"]


class TestRequirePushedColumn:
    def test_default_false_on_every_read(self, test_tenant, test_admin_user):
        created = _client(test_tenant, test_admin_user)
        assert created["require_pushed_authorization_requests"] is False
        tid = test_tenant["id"]
        by_client_id = database.oauth2.get_client_by_client_id(tid, created["client_id"])
        by_id = database.oauth2.get_client_by_id(tid, str(created["id"]))
        listed = database.oauth2.get_all_clients(tid)
        listed_normal = database.oauth2.get_all_clients(tid, client_type="normal")
        for row in (by_client_id, by_id, listed[0], listed_normal[0]):
            assert row["require_pushed_authorization_requests"] is False

    def test_update_client_sets_it(self, test_tenant, test_admin_user):
        created = _client(test_tenant, test_admin_user)
        updated = database.oauth2.update_client(
            test_tenant["id"], created["client_id"], require_pushed_authorization_requests=True
        )
        assert updated["require_pushed_authorization_requests"] is True
        # Every other writer returns the column too.
        tid, cid = test_tenant["id"], created["client_id"]
        assert database.oauth2.deactivate_client(tid, cid)["require_pushed_authorization_requests"]
        assert database.oauth2.reactivate_client(tid, cid)["require_pushed_authorization_requests"]
        assert database.oauth2.update_client_oidc_settings(tid, cid, oidc_enabled=True)[
            "require_pushed_authorization_requests"
        ]
        assert database.oauth2.set_client_tenant_introspection(tid, cid, True)[
            "require_pushed_authorization_requests"
        ]

    def test_check_refuses_public_client(self, test_tenant, test_admin_user):
        public = _client(
            test_tenant,
            test_admin_user,
            redirect_uris=[],
            is_public=True,
            device_grant_enabled=True,
        )
        with pytest.raises(CheckViolation, match="chk_oauth2_clients_require_par"):
            database.oauth2.update_client(
                test_tenant["id"], public["client_id"], require_pushed_authorization_requests=True
            )

    def test_check_refuses_b2b_client(self, test_tenant, b2b_oauth2_client):
        with pytest.raises(CheckViolation, match="chk_oauth2_clients_require_par"):
            database.oauth2.update_client(
                test_tenant["id"],
                b2b_oauth2_client["client_id"],
                require_pushed_authorization_requests=True,
            )

    def test_registered_client_create_and_replace(self, test_tenant):
        common = {
            "name": "Registered",
            "redirect_uris": ["https://rp.example/cb"],
            "post_logout_redirect_uris": [],
            "frontchannel_logout_uri": None,
            "frontchannel_logout_session_required": True,
            "backchannel_logout_uri": None,
            "backchannel_logout_session_required": True,
            "logo_uri": None,
            "client_uri": None,
            "policy_uri": None,
            "tos_uri": None,
            "initiate_login_uri": None,
            "registration_metadata": {},
        }
        created = database.oauth2.create_registered_client(
            test_tenant["id"],
            str(test_tenant["id"]),
            registration_access_token_hash="x",
            registered_with_token_id=None,
            available_to_all=False,
            require_pushed_authorization_requests=True,
            **common,
        )
        assert created["require_pushed_authorization_requests"] is True
        replaced = database.oauth2.replace_registered_client(
            test_tenant["id"],
            created["client_id"],
            previous_token_hash="x",
            registration_access_token_hash="y",
            **common,
        )
        assert replaced["require_pushed_authorization_requests"] is False


class TestPushedRequestStore:
    def test_consume_returns_parameters_once(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        row = _push(test_tenant, client, parameters={"state": "abc", "scope": "openid"})
        assert row["id"]
        consumed = database.oauth2.consume_pushed_request(
            test_tenant["id"], str(client["id"]), "h1"
        )
        assert consumed == {"state": "abc", "scope": "openid"}
        assert (
            database.oauth2.consume_pushed_request(test_tenant["id"], str(client["id"]), "h1")
            is None
        )

    def test_bound_to_the_client(self, test_tenant, test_admin_user):
        owner = _client(test_tenant, test_admin_user)
        other = _client(test_tenant, test_admin_user)
        _push(test_tenant, owner)
        assert (
            database.oauth2.consume_pushed_request(test_tenant["id"], str(other["id"]), "h1")
            is None
        )
        # Left in place for its owner.
        assert database.oauth2.consume_pushed_request(test_tenant["id"], str(owner["id"]), "h1")

    def test_expired_is_not_returned(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        _push(test_tenant, client, expires_at=datetime.now(UTC) - timedelta(seconds=1))
        assert (
            database.oauth2.consume_pushed_request(test_tenant["id"], str(client["id"]), "h1")
            is None
        )

    def test_unknown_hash_is_not_returned(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        _push(test_tenant, client)
        assert (
            database.oauth2.consume_pushed_request(test_tenant["id"], str(client["id"]), "h2")
            is None
        )

    def test_create_sweeps_expired_rows(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        _push(test_tenant, client, "old", expires_at=datetime.now(UTC) - timedelta(seconds=1))
        _push(test_tenant, client, "new")
        hashes = database.fetchall(
            test_tenant["id"], "select reference_hash from oauth2_pushed_authorization_requests", {}
        )
        assert [r["reference_hash"] for r in hashes] == ["new"]

    def test_reference_hash_unique_per_tenant(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        _push(test_tenant, client)
        with pytest.raises(Exception, match="uq_oauth2_pushed_authorization_requests_reference"):
            _push(test_tenant, client)

    def test_parameters_must_be_an_object(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        with pytest.raises(CheckViolation):
            database.execute(
                test_tenant["id"],
                "insert into oauth2_pushed_authorization_requests "
                "(tenant_id, client_id, reference_hash, parameters, expires_at) "
                "values (:t, :c, 'h', cast('[]' as jsonb), now())",
                {"t": str(test_tenant["id"]), "c": str(client["id"])},
            )

    def test_cascade_on_client_delete(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        _push(test_tenant, client)
        database.oauth2.delete_client(test_tenant["id"], client["client_id"])
        assert _count(test_tenant) == 0

    def test_rls_isolates_tenants(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        _push(test_tenant, client)
        other_tenant_id = str(uuid4())
        rows = database.fetchall(
            other_tenant_id, "select id from oauth2_pushed_authorization_requests", {}
        )
        assert rows == []
        assert (
            database.oauth2.consume_pushed_request(other_tenant_id, str(client["id"]), "h1") is None
        )
        with pytest.raises(Exception, match="row-level security|violates"):
            database.execute(
                other_tenant_id,
                "insert into oauth2_pushed_authorization_requests "
                "(tenant_id, client_id, reference_hash, parameters, expires_at) "
                "values (:t, :c, 'x', cast('{}' as jsonb), now() + interval '1 minute')",
                {"t": str(test_tenant["id"]), "c": str(client["id"])},
            )
        assert _count(test_tenant) == 1

    def test_unscoped_sees_nothing(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        _push(test_tenant, client)
        rows = database.fetchall(
            database.UNSCOPED, "select id from oauth2_pushed_authorization_requests", {}
        )
        assert rows == []
