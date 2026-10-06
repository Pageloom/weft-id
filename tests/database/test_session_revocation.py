"""Integration tests for server-side session revocation and upstream sessions.

Covers ``database.revoked_sessions`` and ``database.oidc_upstream.sessions``
(upstream session links and the logout-token replay store) against the real
schema: writes, lookups, cascades, retention sweeps, and strict RLS.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import database
import psycopg.errors
import pytest


@pytest.fixture
def other_tenant():
    suffix = str(uuid4())[:8]
    tenant = database.fetchone(
        database.UNSCOPED,
        "insert into tenants (subdomain, name) values (:s, :n) returning id, subdomain",
        {"s": f"other-{suffix}", "n": f"Other {suffix}"},
    )
    yield tenant
    database.execute(database.UNSCOPED, "delete from tenants where id = :id", {"id": tenant["id"]})


@pytest.fixture
def connection(test_tenant, test_user):
    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=f"IdP {uuid4().hex[:6]}",
        provider_type="generic",
        issuer="https://idp.example.com",
        created_by=str(test_user["id"]),
    )


def _tid(tenant) -> str:
    return str(tenant["id"])


def _link(tenant, connection, user, *, sid, sub="up-sub", upstream_sid="up-sid"):
    database.oidc_upstream.record_idp_session(
        _tid(tenant),
        _tid(tenant),
        sid=sid,
        idp_id=str(connection["id"]),
        user_id=str(user["id"]),
        upstream_sub=sub,
        upstream_sid=upstream_sid,
    )


class TestRevokedSessions:
    def test_revoke_then_revoked(self, test_tenant):
        assert not database.revoked_sessions.is_session_revoked(_tid(test_tenant), "s1")
        assert database.revoked_sessions.revoke_session(_tid(test_tenant), _tid(test_tenant), "s1")
        assert database.revoked_sessions.is_session_revoked(_tid(test_tenant), "s1")
        assert not database.revoked_sessions.is_session_revoked(_tid(test_tenant), "s2")

    def test_revoke_is_idempotent(self, test_tenant):
        tid = _tid(test_tenant)
        assert database.revoked_sessions.revoke_session(tid, tid, "s1") == 1
        assert database.revoked_sessions.revoke_session(tid, tid, "s1") == 0

    def test_tenant_isolation(self, test_tenant, other_tenant):
        database.revoked_sessions.revoke_session(_tid(test_tenant), _tid(test_tenant), "s1")
        assert not database.revoked_sessions.is_session_revoked(_tid(other_tenant), "s1")
        assert not database.revoked_sessions.is_session_revoked(database.UNSCOPED, "s1")

    def test_unscoped_write_rejected(self, test_tenant):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            database.revoked_sessions.revoke_session(database.UNSCOPED, _tid(test_tenant), "s1")

    def test_purge_removes_only_old_rows(self, test_tenant):
        tid = _tid(test_tenant)
        database.revoked_sessions.revoke_session(tid, tid, "old")
        database.revoked_sessions.revoke_session(tid, tid, "new")
        database.execute(
            tid,
            "update revoked_sessions set revoked_at = now() - interval '16 days' where sid = 'old'",
        )
        assert database.revoked_sessions.purge_revoked_sessions(older_than_days=15) >= 1
        assert not database.revoked_sessions.is_session_revoked(tid, "old")
        assert database.revoked_sessions.is_session_revoked(tid, "new")

    def test_tenant_delete_cascades(self, other_tenant):
        tid = _tid(other_tenant)
        database.revoked_sessions.revoke_session(tid, tid, "s1")
        database.execute(database.UNSCOPED, "delete from tenants where id = :id", {"id": tid})
        assert database.fetchall(tid, "select * from revoked_sessions") == []


class TestUpstreamSessions:
    def test_record_and_get(self, test_tenant, connection, test_user):
        _link(test_tenant, connection, test_user, sid="w1")
        row = database.oidc_upstream.get_idp_session(_tid(test_tenant), "w1")
        assert str(row["idp_id"]) == str(connection["id"])
        assert str(row["user_id"]) == str(test_user["id"])
        assert row["upstream_sub"] == "up-sub"
        assert row["upstream_sid"] == "up-sid"

    def test_id_token_stored_and_replaced(self, test_tenant, connection, test_user):
        tid = _tid(test_tenant)
        database.oidc_upstream.record_idp_session(
            tid,
            tid,
            sid="w-id",
            idp_id=str(connection["id"]),
            user_id=str(test_user["id"]),
            upstream_sub="up-sub",
            upstream_sid=None,
            id_token="header.payload.signature",
        )
        assert database.oidc_upstream.get_idp_session(tid, "w-id")["id_token"] == (
            "header.payload.signature"
        )
        _link(test_tenant, connection, test_user, sid="w-id")
        assert database.oidc_upstream.get_idp_session(tid, "w-id")["id_token"] is None

    def test_id_token_length_bound(self, test_tenant, connection, test_user):
        tid = _tid(test_tenant)
        with pytest.raises(psycopg.errors.CheckViolation):
            database.oidc_upstream.record_idp_session(
                tid,
                tid,
                sid="w-big",
                idp_id=str(connection["id"]),
                user_id=str(test_user["id"]),
                upstream_sub="up-sub",
                upstream_sid=None,
                id_token="x" * 16385,
            )

    def test_connection_sign_out_defaults(self, test_tenant, connection):
        assert connection["sign_out_at_idp"] is False
        assert connection["end_session_endpoint"] is None
        row = database.oidc_upstream.update_connection(
            _tid(test_tenant),
            str(connection["id"]),
            sign_out_at_idp=True,
            end_session_endpoint="https://idp.example.com/logout",
        )
        assert row["sign_out_at_idp"] is True
        assert row["end_session_endpoint"] == "https://idp.example.com/logout"
        # Discovery clears an endpoint the provider stopped publishing.
        row = database.oidc_upstream.update_connection(
            _tid(test_tenant), str(connection["id"]), end_session_endpoint=None
        )
        assert row["end_session_endpoint"] is None

    def test_end_session_endpoint_length_bound(self, test_tenant, connection):
        with pytest.raises(psycopg.errors.CheckViolation):
            database.oidc_upstream.update_connection(
                _tid(test_tenant),
                str(connection["id"]),
                end_session_endpoint="https://x.example/" + "x" * 2048,
            )

    def test_record_replaces_same_sid(self, test_tenant, connection, test_user):
        _link(test_tenant, connection, test_user, sid="w1", upstream_sid="a")
        _link(test_tenant, connection, test_user, sid="w1", upstream_sid=None)
        row = database.oidc_upstream.get_idp_session(_tid(test_tenant), "w1")
        assert row["upstream_sid"] is None

    def test_find_by_upstream_sid(self, test_tenant, connection, test_user):
        _link(test_tenant, connection, test_user, sid="w1", upstream_sid="a")
        _link(test_tenant, connection, test_user, sid="w2", upstream_sid="a")
        _link(test_tenant, connection, test_user, sid="w3", upstream_sid="b")
        rows = database.oidc_upstream.find_idp_sessions(
            _tid(test_tenant), str(connection["id"]), upstream_sid="a", upstream_sub=None
        )
        assert [r["sid"] for r in rows] == ["w1", "w2"]

    def test_find_by_sid_narrowed_by_sub(self, test_tenant, connection, test_user):
        _link(test_tenant, connection, test_user, sid="w1", sub="alice", upstream_sid="a")
        _link(test_tenant, connection, test_user, sid="w2", sub="bob", upstream_sid="a")
        rows = database.oidc_upstream.find_idp_sessions(
            _tid(test_tenant), str(connection["id"]), upstream_sid="a", upstream_sub="bob"
        )
        assert [r["sid"] for r in rows] == ["w2"]

    def test_find_by_sub_only(self, test_tenant, connection, test_user):
        _link(test_tenant, connection, test_user, sid="w1", sub="alice", upstream_sid="a")
        _link(test_tenant, connection, test_user, sid="w2", sub="alice", upstream_sid=None)
        _link(test_tenant, connection, test_user, sid="w3", sub="bob", upstream_sid="b")
        rows = database.oidc_upstream.find_idp_sessions(
            _tid(test_tenant), str(connection["id"]), upstream_sid=None, upstream_sub="alice"
        )
        assert sorted(r["sid"] for r in rows) == ["w1", "w2"]

    def test_find_with_neither_returns_nothing(self, test_tenant, connection, test_user):
        _link(test_tenant, connection, test_user, sid="w1")
        assert (
            database.oidc_upstream.find_idp_sessions(
                _tid(test_tenant), str(connection["id"]), upstream_sid=None, upstream_sub=None
            )
            == []
        )

    def test_find_is_per_connection(self, test_tenant, connection, test_user):
        other = database.oidc_upstream.create_connection(
            tenant_id=test_tenant["id"],
            tenant_id_value=_tid(test_tenant),
            name="Other IdP",
            provider_type="generic",
            issuer="https://other.example.com",
            created_by=str(test_user["id"]),
        )
        _link(test_tenant, connection, test_user, sid="w1", upstream_sid="a")
        assert (
            database.oidc_upstream.find_idp_sessions(
                _tid(test_tenant), str(other["id"]), upstream_sid="a", upstream_sub=None
            )
            == []
        )

    def test_find_user_sessions_at_connection(
        self, test_tenant, connection, test_user, test_admin_user
    ):
        other = database.oidc_upstream.create_connection(
            tenant_id=test_tenant["id"],
            tenant_id_value=_tid(test_tenant),
            name="Other IdP",
            provider_type="generic",
            issuer="https://other.example.com",
            created_by=str(test_user["id"]),
        )
        _link(test_tenant, connection, test_user, sid="w1", sub="s-1")
        _link(test_tenant, connection, test_user, sid="w2", sub="s-2", upstream_sid=None)
        _link(test_tenant, other, test_user, sid="w3")
        _link(test_tenant, connection, test_admin_user, sid="w4")

        rows = database.oidc_upstream.find_user_idp_sessions(
            _tid(test_tenant), str(connection["id"]), str(test_user["id"])
        )

        assert [row["sid"] for row in rows] == ["w1", "w2"]

    def test_find_user_sessions_tenant_isolation(
        self, test_tenant, other_tenant, connection, test_user
    ):
        _link(test_tenant, connection, test_user, sid="w1")
        assert (
            database.oidc_upstream.find_user_idp_sessions(
                _tid(other_tenant), str(connection["id"]), str(test_user["id"])
            )
            == []
        )

    def test_delete(self, test_tenant, connection, test_user):
        _link(test_tenant, connection, test_user, sid="w1")
        assert database.oidc_upstream.delete_idp_session(_tid(test_tenant), "w1") == 1
        assert database.oidc_upstream.get_idp_session(_tid(test_tenant), "w1") is None

    def test_connection_delete_cascades(self, test_tenant, connection, test_user):
        _link(test_tenant, connection, test_user, sid="w1")
        database.oidc_upstream.delete_connection(test_tenant["id"], str(connection["id"]))
        assert database.oidc_upstream.get_idp_session(_tid(test_tenant), "w1") is None

    def test_user_delete_cascades(self, test_tenant, connection):
        # Not the connection's creator: that user's FK on the connection is
        # its own (SET NULL on a NOT NULL tenant_id) and out of scope here.
        user = database.fetchone(
            _tid(test_tenant),
            "insert into users (tenant_id, password_hash, first_name, last_name, role) "
            "values (:t, :p, 'Linked', 'User', 'member') returning id",
            {"t": _tid(test_tenant), "p": "x" * 60},
        )
        _link(test_tenant, connection, user, sid="w1")
        database.execute(_tid(test_tenant), "delete from users where id = :id", {"id": user["id"]})
        assert database.oidc_upstream.get_idp_session(_tid(test_tenant), "w1") is None

    def test_sweep_removes_only_old_rows(self, test_tenant, connection, test_user):
        _link(test_tenant, connection, test_user, sid="old")
        _link(test_tenant, connection, test_user, sid="new")
        database.execute(
            _tid(test_tenant),
            "update oidc_idp_sessions set created_at = now() - interval '91 days' "
            "where sid = 'old'",
        )
        assert database.oidc_upstream.sweep_stale_idp_sessions(older_than_days=90) >= 1
        assert database.oidc_upstream.get_idp_session(_tid(test_tenant), "old") is None
        assert database.oidc_upstream.get_idp_session(_tid(test_tenant), "new") is not None

    def test_tenant_isolation(self, test_tenant, other_tenant, connection, test_user):
        _link(test_tenant, connection, test_user, sid="w1")
        assert database.oidc_upstream.get_idp_session(_tid(other_tenant), "w1") is None
        assert database.oidc_upstream.get_idp_session(database.UNSCOPED, "w1") is None

    def test_upstream_sub_length_bounded(self, test_tenant, connection, test_user):
        with pytest.raises(psycopg.errors.CheckViolation):
            _link(test_tenant, connection, test_user, sid="w1", sub="x" * 256)


class TestLogoutTokenJtis:
    def _consume(self, tenant, connection, jti, *, expires_in=timedelta(minutes=5)):
        return database.oidc_upstream.consume_logout_token_jti(
            _tid(tenant),
            _tid(tenant),
            idp_id=str(connection["id"]),
            jti=jti,
            expires_at=datetime.now(UTC) + expires_in,
        )

    def test_first_use_accepted_replay_refused(self, test_tenant, connection):
        assert self._consume(test_tenant, connection, "j1") is True
        assert self._consume(test_tenant, connection, "j1") is False
        assert self._consume(test_tenant, connection, "j2") is True

    def test_same_jti_other_connection_accepted(self, test_tenant, connection, test_user):
        other = database.oidc_upstream.create_connection(
            tenant_id=test_tenant["id"],
            tenant_id_value=_tid(test_tenant),
            name="Other IdP",
            provider_type="generic",
            issuer="https://other.example.com",
            created_by=str(test_user["id"]),
        )
        assert self._consume(test_tenant, connection, "j1") is True
        assert self._consume(test_tenant, other, "j1") is True

    def test_purge_removes_expired_only(self, test_tenant, connection):
        self._consume(test_tenant, connection, "expired", expires_in=timedelta(seconds=-1))
        self._consume(test_tenant, connection, "live")
        assert database.oidc_upstream.purge_expired_logout_token_jtis() >= 1
        remaining = database.fetchall(
            _tid(test_tenant), "select jti from oidc_idp_logout_token_jtis order by jti"
        )
        assert [r["jti"] for r in remaining] == ["live"]

    def test_unscoped_write_rejected(self, test_tenant, connection):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            database.oidc_upstream.consume_logout_token_jti(
                database.UNSCOPED,
                _tid(test_tenant),
                idp_id=str(connection["id"]),
                jti="j1",
                expires_at=datetime.now(UTC),
            )
