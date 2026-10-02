"""Database tests for dynamic client registration: the tenant settings row,
initial access tokens, dynamically registered clients, and the relaxed
``oauth2_clients.created_by`` (migration 0070)."""

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import database
import pytest


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _iat(test_tenant, creator, name="Partner", token="tok", expires_at=None):
    return database.oauth2.create_initial_access_token(
        test_tenant["id"],
        test_tenant["id"],
        name=name,
        token_hash=_digest(f"{token}-{uuid4().hex}"),
        created_by=str(creator["id"]),
        expires_at=expires_at,
    )


def _registered(test_tenant, **overrides):
    fields = {
        "name": "Registered app",
        "redirect_uris": ["https://rp.example/cb"],
        "post_logout_redirect_uris": [],
        "frontchannel_logout_uri": None,
        "frontchannel_logout_session_required": True,
        "backchannel_logout_uri": None,
        "backchannel_logout_session_required": True,
        "logo_uri": "https://rp.example/logo.png",
        "client_uri": None,
        "policy_uri": "https://rp.example/privacy",
        "tos_uri": None,
        "initiate_login_uri": "https://rp.example/start",
        "registration_metadata": {"grant_types": ["authorization_code"], "contacts": ["a@b.c"]},
        "registration_access_token_hash": "argon-hash",
        "registered_with_token_id": None,
        "available_to_all": False,
    }
    fields.update(overrides)
    return database.oauth2.create_registered_client(test_tenant["id"], test_tenant["id"], **fields)


@pytest.fixture
def other_tenant():
    row = database.fetchone(
        database.UNSCOPED,
        "insert into tenants (subdomain, name) values (:s, :n) returning id",
        {"s": f"dcr-other-{uuid4().hex[:8]}", "n": "Other"},
    )
    yield {"id": str(row["id"])}
    database.execute(
        database.UNSCOPED, "delete from tenants where id = :id", {"id": str(row["id"])}
    )


class TestRegistrationSettings:
    def test_missing_row_is_none(self, test_tenant):
        assert database.oauth2.get_registration_settings(test_tenant["id"]) is None

    def test_upsert_creates_then_updates(self, test_tenant, test_admin_user):
        created = database.oauth2.upsert_registration_settings(
            test_tenant["id"],
            test_tenant["id"],
            policy="token_required",
            default_access="none",
            updated_by=str(test_admin_user["id"]),
        )
        assert created["policy"] == "token_required"

        database.oauth2.upsert_registration_settings(
            test_tenant["id"],
            test_tenant["id"],
            policy="open",
            default_access="all",
            updated_by=str(test_admin_user["id"]),
        )

        row = database.oauth2.get_registration_settings(test_tenant["id"])
        assert row["policy"] == "open"
        assert row["default_access"] == "all"
        assert str(row["updated_by"]) == str(test_admin_user["id"])

    def test_check_constraint_rejects_unknown_policy(self, test_tenant, test_admin_user):
        with pytest.raises(Exception, match="chk_oauth2_registration_settings_policy"):
            database.oauth2.upsert_registration_settings(
                test_tenant["id"],
                test_tenant["id"],
                policy="sometimes",
                default_access="none",
                updated_by=str(test_admin_user["id"]),
            )

    def test_other_tenant_cannot_see(self, test_tenant, test_admin_user, other_tenant):
        database.oauth2.upsert_registration_settings(
            test_tenant["id"],
            test_tenant["id"],
            policy="open",
            default_access="all",
            updated_by=str(test_admin_user["id"]),
        )
        assert database.oauth2.get_registration_settings(other_tenant["id"]) is None


class TestInitialAccessTokens:
    def test_create_returns_metadata_not_hash(self, test_tenant, test_admin_user):
        row = _iat(test_tenant, test_admin_user, name="Partner A")

        assert row["name"] == "Partner A"
        assert str(row["created_by"]) == str(test_admin_user["id"])
        assert row["revoked_at"] is None
        assert "token_hash" not in row

    def test_find_by_hash(self, test_tenant, test_admin_user):
        token_hash = _digest("find-me")
        database.oauth2.create_initial_access_token(
            test_tenant["id"],
            test_tenant["id"],
            name="Findable",
            token_hash=token_hash,
            created_by=str(test_admin_user["id"]),
        )

        found = database.oauth2.get_initial_access_token_by_hash(test_tenant["id"], token_hash)

        assert found["name"] == "Findable"
        assert "token_hash" not in found
        assert (
            database.oauth2.get_initial_access_token_by_hash(test_tenant["id"], _digest("other"))
            is None
        )

    def test_hash_lookup_is_tenant_scoped(self, test_tenant, test_admin_user, other_tenant):
        token_hash = _digest(f"scoped-{uuid4().hex}")
        database.oauth2.create_initial_access_token(
            test_tenant["id"],
            test_tenant["id"],
            name="Scoped",
            token_hash=token_hash,
            created_by=str(test_admin_user["id"]),
        )
        assert (
            database.oauth2.get_initial_access_token_by_hash(other_tenant["id"], token_hash) is None
        )

    def test_list_newest_first_with_creator_and_count(self, test_tenant, test_admin_user):
        first = _iat(test_tenant, test_admin_user, name="First")
        second = _iat(test_tenant, test_admin_user, name="Second")
        _registered(test_tenant, registered_with_token_id=str(first["id"]))
        _registered(test_tenant, registered_with_token_id=str(first["id"]))

        rows = database.oauth2.list_initial_access_tokens(test_tenant["id"])

        by_id = {str(r["id"]): r for r in rows}
        assert [str(r["id"]) for r in rows][:2] == [str(second["id"]), str(first["id"])]
        assert by_id[str(first["id"])]["registered_client_count"] == 2
        assert by_id[str(second["id"])]["registered_client_count"] == 0
        assert by_id[str(first["id"])]["created_by_first_name"] == test_admin_user["first_name"]
        assert all("token_hash" not in r for r in rows)

    def test_get_by_id(self, test_tenant, test_admin_user):
        row = _iat(test_tenant, test_admin_user)
        assert database.oauth2.get_initial_access_token(test_tenant["id"], str(row["id"]))
        assert database.oauth2.get_initial_access_token(test_tenant["id"], str(uuid4())) is None

    def test_revoke_once(self, test_tenant, test_admin_user):
        row = _iat(test_tenant, test_admin_user)

        revoked = database.oauth2.revoke_initial_access_token(test_tenant["id"], str(row["id"]))
        again = database.oauth2.revoke_initial_access_token(test_tenant["id"], str(row["id"]))

        assert revoked["revoked_at"] is not None
        assert again is None

    def test_touch_sets_last_used(self, test_tenant, test_admin_user):
        row = _iat(test_tenant, test_admin_user)

        database.oauth2.touch_initial_access_token(test_tenant["id"], str(row["id"]))

        fresh = database.oauth2.get_initial_access_token(test_tenant["id"], str(row["id"]))
        assert fresh["last_used_at"] is not None

    def test_expiry_is_stored(self, test_tenant, test_admin_user):
        expires = datetime.now(UTC) + timedelta(days=3)
        row = _iat(test_tenant, test_admin_user, expires_at=expires)
        assert abs((row["expires_at"] - expires).total_seconds()) < 1

    def test_deleting_token_keeps_registered_client(self, test_tenant, test_admin_user):
        row = _iat(test_tenant, test_admin_user)
        client = _registered(test_tenant, registered_with_token_id=str(row["id"]))

        database.execute(
            test_tenant["id"],
            "delete from oauth2_initial_access_tokens where id = :id",
            {"id": str(row["id"])},
        )

        fresh = database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"])
        assert fresh is not None
        assert fresh["registered_with_token_id"] is None


class TestRegisteredClients:
    def test_create_sets_registration_fields(self, test_tenant):
        client = _registered(test_tenant)

        assert client["client_secret"]
        assert client["client_type"] == "normal"
        assert client["oidc_enabled"] is True
        assert client["dynamically_registered"] is True
        assert client["available_to_all"] is False
        assert client["logo_uri"] == "https://rp.example/logo.png"
        assert client["initiate_login_uri"] == "https://rp.example/start"
        assert client["registration_metadata"]["contacts"] == ["a@b.c"]
        assert "registration_access_token_hash" not in client

        full = database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"])
        assert full["registration_access_token_hash"] == "argon-hash"
        created_by = database.fetchone(
            test_tenant["id"],
            "select created_by from oauth2_clients where client_id = :c",
            {"c": client["client_id"]},
        )
        assert created_by["created_by"] is None

    def test_available_to_all_flag(self, test_tenant):
        client = _registered(test_tenant, available_to_all=True)
        assert client["available_to_all"] is True

    def test_list_carries_registration_fields(self, test_tenant):
        client = _registered(test_tenant)

        rows = database.oauth2.get_all_clients(test_tenant["id"], client_type="normal")

        row = next(r for r in rows if r["client_id"] == client["client_id"])
        assert row["dynamically_registered"] is True
        assert row["policy_uri"] == "https://rp.example/privacy"

    def test_replace_overwrites_metadata(self, test_tenant):
        client = _registered(test_tenant)

        replaced = database.oauth2.replace_registered_client(
            test_tenant["id"],
            client["client_id"],
            name="Renamed",
            redirect_uris=["https://rp.example/new"],
            post_logout_redirect_uris=[],
            frontchannel_logout_uri=None,
            frontchannel_logout_session_required=True,
            backchannel_logout_uri=None,
            backchannel_logout_session_required=True,
            logo_uri=None,
            client_uri="https://rp.example",
            policy_uri=None,
            tos_uri=None,
            initiate_login_uri="https://rp.example/login",
            registration_metadata={},
            previous_token_hash="argon-hash",
            registration_access_token_hash="rotated-hash",
        )

        assert replaced["initiate_login_uri"] == "https://rp.example/login"
        assert replaced["name"] == "Renamed"
        assert replaced["redirect_uris"] == ["https://rp.example/new"]
        assert replaced["logo_uri"] is None
        assert replaced["client_uri"] == "https://rp.example"
        assert replaced["registration_metadata"] == {}
        full = database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"])
        assert full["registration_access_token_hash"] == "rotated-hash"

    def test_replace_with_a_stale_token_hash_changes_nothing(self, test_tenant):
        client = _registered(test_tenant)
        fields = {
            "name": "Renamed",
            "redirect_uris": ["https://rp.example/new"],
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

        result = database.oauth2.replace_registered_client(
            test_tenant["id"],
            client["client_id"],
            previous_token_hash="not-current",
            registration_access_token_hash="rotated-hash",
            **fields,
        )

        assert result is None
        full = database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"])
        assert full["name"] != "Renamed"
        assert full["registration_access_token_hash"] == "argon-hash"

    def test_set_registration_access_token(self, test_tenant, normal_oauth2_client):
        client = _registered(test_tenant)

        row = database.oauth2.set_registration_access_token(
            test_tenant["id"], client["client_id"], registration_access_token_hash="reset-hash"
        )

        assert row["client_id"] == client["client_id"]
        full = database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"])
        assert full["registration_access_token_hash"] == "reset-hash"
        # An admin-created client has no registration to reset.
        assert (
            database.oauth2.set_registration_access_token(
                test_tenant["id"],
                normal_oauth2_client["client_id"],
                registration_access_token_hash="reset-hash",
            )
            is None
        )

    def test_replace_ignores_admin_created_client(self, test_tenant, normal_oauth2_client):
        result = database.oauth2.replace_registered_client(
            test_tenant["id"],
            normal_oauth2_client["client_id"],
            name="Hijacked",
            redirect_uris=["https://evil.example/cb"],
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
            previous_token_hash="argon-hash",
            registration_access_token_hash="rotated-hash",
        )

        assert result is None
        fresh = database.oauth2.get_client_by_client_id(
            test_tenant["id"], normal_oauth2_client["client_id"]
        )
        assert fresh["name"] != "Hijacked"
        assert fresh["dynamically_registered"] is False


class TestCreatedByForeignKey:
    def test_deleting_creator_nulls_created_by(self, test_tenant):
        """The creator FK nulls only created_by (it used to try tenant_id too)."""
        user = database.fetchone(
            test_tenant["id"],
            """
            insert into users (tenant_id, first_name, last_name, role)
            values (:t, 'Gone', 'Creator', 'admin') returning id
            """,
            {"t": test_tenant["id"]},
        )
        client = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            name="Orphan",
            redirect_uris=["https://rp.example/cb"],
            created_by=str(user["id"]),
        )

        database.execute(
            test_tenant["id"], "delete from users where id = :id", {"id": str(user["id"])}
        )

        row = database.fetchone(
            test_tenant["id"],
            "select created_by, tenant_id from oauth2_clients where client_id = :c",
            {"c": client["client_id"]},
        )
        assert row["created_by"] is None
        assert str(row["tenant_id"]) == str(test_tenant["id"])

    def test_admin_can_delete_a_client_creator(self, test_tenant, test_super_admin_user):
        """The user service's delete used to fail on the creator FK (regression)."""
        from services import users as users_service

        creator = database.fetchone(
            test_tenant["id"],
            """
            insert into users (tenant_id, first_name, last_name, role)
            values (:t, 'Former', 'Admin', 'admin') returning id
            """,
            {"t": test_tenant["id"]},
        )
        client = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            name="Kept",
            redirect_uris=["https://rp.example/cb"],
            created_by=str(creator["id"]),
        )

        users_service.delete_user(
            {
                "id": str(test_super_admin_user["id"]),
                "tenant_id": str(test_tenant["id"]),
                "role": "super_admin",
            },
            str(creator["id"]),
        )

        assert database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"])
