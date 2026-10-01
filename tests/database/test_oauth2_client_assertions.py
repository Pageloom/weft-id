"""Database tests: private_key_jwt client columns and the client assertion
replay store.

Covers the client columns' defaults and CHECKs, the authentication setter
(secret rotation, public clients untouched), secret regeneration refused for
private_key_jwt clients, registered clients with keys, and the jti store
(once per client, per-client scope, expiry sweep, RLS tenant isolation).
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import database
import oauth2
import pytest
from psycopg.errors import CheckViolation

from tests.helpers.client_keys import JWKS


def _client(test_tenant, test_admin_user, **kwargs):
    kwargs.setdefault("redirect_uris", ["https://app.example.com/callback"])
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Signed App",
        created_by=str(test_admin_user["id"]),
        **kwargs,
    )


def _set_auth(test_tenant, client_id, **overrides):
    fields = {
        "client_auth_method": "private_key_jwt",
        "jwks": JWKS,
        "jwks_uri": None,
        "token_endpoint_auth_signing_alg": None,
        "rotate_secret": True,
    }
    fields.update(overrides)
    return database.oauth2.set_client_authentication(test_tenant["id"], client_id, **fields)


def _secret_hash(test_tenant, client_id):
    return database.fetchone(
        test_tenant["id"],
        "select client_secret_hash from oauth2_clients where client_id = :c",
        {"c": client_id},
    )["client_secret_hash"]


def _future(minutes=5):
    return datetime.now(UTC) + timedelta(minutes=minutes)


class TestClientColumns:
    def test_defaults(self, test_tenant, test_admin_user):
        created = _client(test_tenant, test_admin_user)
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], created["client_id"])
        assert row["client_auth_method"] == "client_secret"
        assert row["jwks"] is None
        assert row["jwks_uri"] is None
        assert row["token_endpoint_auth_signing_alg"] is None

    def test_every_client_read_returns_the_columns(self, test_tenant, test_admin_user):
        created = _client(test_tenant, test_admin_user)
        _set_auth(test_tenant, created["client_id"])
        by_id = database.oauth2.get_client_by_id(test_tenant["id"], str(created["id"]))
        listed = [
            c
            for c in database.oauth2.get_all_clients(test_tenant["id"], client_type="normal")
            if c["client_id"] == created["client_id"]
        ][0]
        for row in (by_id, listed):
            assert row["client_auth_method"] == "private_key_jwt"
            assert row["jwks"] == JWKS

    @pytest.mark.parametrize(
        ("assignments", "constraint"),
        [
            ("client_auth_method = 'tls_client_auth'", "chk_oauth2_clients_auth_method"),
            ("client_auth_method = 'private_key_jwt'", "chk_oauth2_clients_private_key_jwt"),
            (
                "jwks = cast('{}' as jsonb), jwks_uri = 'https://k.example/jwks'",
                "chk_oauth2_clients_jwks_one_source",
            ),
            ("token_endpoint_auth_signing_alg = 'HS256'", "chk_oauth2_clients_auth_signing_alg"),
            (
                "jwks_uri = 'https://k.example/' || repeat('a', 2048)",
                "chk_oauth2_clients_jwks_uri_length",
            ),
        ],
    )
    def test_checks(self, test_tenant, test_admin_user, assignments, constraint):
        created = _client(test_tenant, test_admin_user)
        with pytest.raises(CheckViolation, match=constraint):
            database.execute(
                test_tenant["id"],
                f"update oauth2_clients set {assignments} where id = :id",
                {"id": created["id"]},
            )

    def test_public_client_cannot_use_private_key_jwt(self, test_tenant, test_admin_user):
        created = _client(
            test_tenant,
            test_admin_user,
            redirect_uris=[],
            device_grant_enabled=True,
            is_public=True,
        )
        with pytest.raises(CheckViolation, match="chk_oauth2_clients_private_key_jwt"):
            database.execute(
                test_tenant["id"],
                "update oauth2_clients set client_auth_method = 'private_key_jwt', "
                "jwks_uri = 'https://k.example/jwks' where id = :id",
                {"id": created["id"]},
            )


class TestSetClientAuthentication:
    def test_switch_to_private_key_jwt_rotates_secret_to_unknown(
        self, test_tenant, test_admin_user
    ):
        created = _client(test_tenant, test_admin_user)
        updated = _set_auth(
            test_tenant, created["client_id"], token_endpoint_auth_signing_alg="PS256"
        )
        assert updated["client_auth_method"] == "private_key_jwt"
        assert updated["jwks"] == JWKS
        assert updated["token_endpoint_auth_signing_alg"] == "PS256"
        assert "client_secret" not in updated
        assert not oauth2.verify_token_hash(
            created["client_secret"], _secret_hash(test_tenant, created["client_id"])
        )

    def test_without_rotation_keeps_secret(self, test_tenant, test_admin_user):
        created = _client(test_tenant, test_admin_user)
        _set_auth(test_tenant, created["client_id"], rotate_secret=False)
        assert oauth2.verify_token_hash(
            created["client_secret"], _secret_hash(test_tenant, created["client_id"])
        )

    def test_switch_back_returns_a_working_secret(self, test_tenant, test_admin_user):
        created = _client(test_tenant, test_admin_user)
        _set_auth(test_tenant, created["client_id"])
        updated = _set_auth(
            test_tenant, created["client_id"], client_auth_method="client_secret", jwks=None
        )
        assert updated["client_auth_method"] == "client_secret"
        assert updated["jwks"] is None
        assert oauth2.verify_token_hash(
            updated["client_secret"], _secret_hash(test_tenant, created["client_id"])
        )

    def test_jwks_uri(self, test_tenant, test_admin_user):
        created = _client(test_tenant, test_admin_user)
        updated = _set_auth(
            test_tenant, created["client_id"], jwks=None, jwks_uri="https://k.example/jwks"
        )
        assert updated["jwks_uri"] == "https://k.example/jwks"
        assert updated["jwks"] is None

    def test_public_client_is_untouched(self, test_tenant, test_admin_user):
        created = _client(
            test_tenant,
            test_admin_user,
            redirect_uris=[],
            device_grant_enabled=True,
            is_public=True,
        )
        assert _set_auth(test_tenant, created["client_id"]) is None

    def test_unknown_client(self, test_tenant):
        assert _set_auth(test_tenant, "weft-id_client_nope") is None

    def test_regenerate_refused_for_private_key_jwt(self, test_tenant, test_admin_user):
        created = _client(test_tenant, test_admin_user)
        _set_auth(test_tenant, created["client_id"])
        before = _secret_hash(test_tenant, created["client_id"])
        assert (
            database.oauth2.regenerate_client_secret(test_tenant["id"], created["client_id"])
            is None
        )
        assert _secret_hash(test_tenant, created["client_id"]) == before


class TestRegisteredClientKeys:
    def _register(self, test_tenant, **overrides):
        fields = {
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
            "registration_access_token_hash": oauth2.hash_token("rat"),
            "registered_with_token_id": None,
            "available_to_all": False,
        }
        fields.update(overrides)
        return database.oauth2.create_registered_client(
            test_tenant["id"], test_tenant["id"], **fields
        )

    def test_private_key_jwt_client_gets_no_secret(self, test_tenant):
        client = self._register(
            test_tenant,
            client_auth_method="private_key_jwt",
            jwks=JWKS,
            token_endpoint_auth_signing_alg="RS256",
        )
        assert "client_secret" not in client
        assert client["client_auth_method"] == "private_key_jwt"
        assert client["jwks"] == JWKS
        assert client["token_endpoint_auth_signing_alg"] == "RS256"

    def test_secret_client_with_keys(self, test_tenant):
        client = self._register(test_tenant, jwks_uri="https://rp.example/jwks")
        assert client["client_secret"]
        assert client["jwks_uri"] == "https://rp.example/jwks"

    def test_replace_sets_keys(self, test_tenant):
        client = self._register(test_tenant, client_auth_method="private_key_jwt", jwks=JWKS)
        replaced = database.oauth2.replace_registered_client(
            test_tenant["id"],
            client["client_id"],
            name="Registered",
            redirect_uris=["https://rp.example/cb"],
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
            jwks=None,
            jwks_uri="https://rp.example/rotated",
            token_endpoint_auth_signing_alg="ES256",
        )
        assert replaced["jwks"] is None
        assert replaced["jwks_uri"] == "https://rp.example/rotated"
        assert replaced["token_endpoint_auth_signing_alg"] == "ES256"
        assert replaced["client_auth_method"] == "private_key_jwt"


class TestAssertionJtis:
    def _record(self, test_tenant, client, jti="jti-1", expires_at=None):
        return database.oauth2.record_client_assertion_jti(
            test_tenant["id"],
            str(test_tenant["id"]),
            str(client["id"]),
            jti,
            expires_at or _future(),
        )

    def test_once_per_client(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        assert self._record(test_tenant, client) is True
        assert self._record(test_tenant, client) is False

    def test_scoped_to_the_client(self, test_tenant, test_admin_user):
        first = _client(test_tenant, test_admin_user)
        second = _client(test_tenant, test_admin_user)
        assert self._record(test_tenant, first) is True
        assert self._record(test_tenant, second) is True

    def test_expired_rows_are_swept(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        past = datetime.now(UTC) - timedelta(minutes=1)
        assert self._record(test_tenant, client, jti="old", expires_at=past) is True
        self._record(test_tenant, client, jti="new")
        rows = database.fetchall(
            test_tenant["id"],
            "select jti from oauth2_client_assertion_jtis where client_id = :c",
            {"c": client["id"]},
        )
        assert [r["jti"] for r in rows] == ["new"]
        # Once swept, an expired jti could be recorded again; its exp check
        # (in the service) is what refuses the old assertion.
        assert self._record(test_tenant, client, jti="old") is True

    def test_deleted_with_the_client(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        self._record(test_tenant, client)
        database.oauth2.delete_client(test_tenant["id"], client["client_id"])
        assert (
            database.fetchone(
                test_tenant["id"],
                "select count(*) as n from oauth2_client_assertion_jtis where client_id = :c",
                {"c": client["id"]},
            )["n"]
            == 0
        )

    def test_rls_isolates_tenants(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        self._record(test_tenant, client)
        other_tenant_id = str(uuid4())
        rows = database.fetchall(other_tenant_id, "select id from oauth2_client_assertion_jtis", {})
        assert rows == []
        with pytest.raises(Exception, match="row-level security|violates"):
            database.execute(
                other_tenant_id,
                "insert into oauth2_client_assertion_jtis (tenant_id, client_id, jti, expires_at) "
                "values (:t, :c, 'x', now() + interval '1 minute')",
                {"t": str(test_tenant["id"]), "c": str(client["id"])},
            )
