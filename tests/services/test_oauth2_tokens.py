"""Service tests for token introspection, revocation, and the per-client
tenant-introspection permission (services.oauth2_tokens). Real database."""

import logging

import database
import pytest
from services import oauth2_tokens as svc
from services.exceptions import ForbiddenError, NotFoundError, ValidationError

ISSUER = "https://tenant.example.test"


def _tokens(test_tenant, oauth_client, user, scope="openid email"):
    refresh, refresh_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=oauth_client["id"],
        user_id=user["id"],
        scope=scope,
    )
    access = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=oauth_client["id"],
        user_id=user["id"],
        parent_token_id=refresh_id,
        scope=scope,
    )
    return refresh, access


def _client(test_tenant, created):
    """The client as the router passes it (a fresh lookup)."""
    return database.oauth2.get_client_by_client_id(test_tenant["id"], created["client_id"])


def _events(test_tenant, event_type):
    return [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=30)
        if e["event_type"] == event_type
    ]


def _user(test_tenant, user, role):
    return {"id": str(user["id"]), "tenant_id": str(test_tenant["id"]), "role": role}


class TestIntrospect:
    def test_own_access_token(self, test_tenant, normal_oauth2_client, test_user):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        body = svc.introspect_token(
            test_tenant["id"], _client(test_tenant, normal_oauth2_client), access, ISSUER
        )

        row = database.oauth2.find_token(test_tenant["id"], access)
        assert body == {
            "active": True,
            "scope": "openid email",
            "client_id": normal_oauth2_client["client_id"],
            "sub": str(test_user["id"]),
            "token_type": "Bearer",
            "exp": int(row["expires_at"].timestamp()),
            "iat": int(row["created_at"].timestamp()),
            "iss": ISSUER,
        }

    def test_own_refresh_token_has_no_token_type(
        self, test_tenant, normal_oauth2_client, test_user
    ):
        refresh, _ = _tokens(test_tenant, normal_oauth2_client, test_user)

        body = svc.introspect_token(
            test_tenant["id"], _client(test_tenant, normal_oauth2_client), refresh, ISSUER
        )

        assert body["active"] is True
        assert "token_type" not in body

    def test_token_without_scope_omits_scope(self, test_tenant, b2b_oauth2_client):
        access = database.oauth2.create_access_token(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=b2b_oauth2_client["id"],
            user_id=b2b_oauth2_client["service_user_id"],
            is_client_credentials=True,
        )

        body = svc.introspect_token(
            test_tenant["id"], _client(test_tenant, b2b_oauth2_client), access, ISSUER
        )

        assert body["active"] is True
        assert "scope" not in body
        assert body["sub"] == str(b2b_oauth2_client["service_user_id"])

    def test_unknown_token(self, test_tenant, normal_oauth2_client):
        body = svc.introspect_token(
            test_tenant["id"], _client(test_tenant, normal_oauth2_client), "nope", ISSUER
        )
        assert body == {"active": False}

    def test_other_clients_token_is_inactive(
        self, test_tenant, normal_oauth2_client, b2b_oauth2_client, test_user
    ):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        body = svc.introspect_token(
            test_tenant["id"], _client(test_tenant, b2b_oauth2_client), access, ISSUER
        )

        assert body == {"active": False}

    def test_resource_server_sees_other_clients_token(
        self, test_tenant, normal_oauth2_client, b2b_oauth2_client, test_user
    ):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        database.oauth2.set_client_tenant_introspection(
            test_tenant["id"], b2b_oauth2_client["client_id"], True
        )

        body = svc.introspect_token(
            test_tenant["id"], _client(test_tenant, b2b_oauth2_client), access, ISSUER
        )

        assert body["active"] is True
        assert body["client_id"] == normal_oauth2_client["client_id"]
        assert body["sub"] == str(test_user["id"])

    def test_logs_info_without_the_token(
        self, test_tenant, normal_oauth2_client, test_user, caplog
    ):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        with caplog.at_level(logging.INFO, logger="services.oauth2_tokens"):
            svc.introspect_token(
                test_tenant["id"], _client(test_tenant, normal_oauth2_client), access, ISSUER
            )
            svc.introspect_token(
                test_tenant["id"], _client(test_tenant, normal_oauth2_client), "nope", ISSUER
            )

        messages = [r.getMessage() for r in caplog.records if r.name == "services.oauth2_tokens"]
        assert len(messages) == 2
        assert "active=true" in messages[0]
        assert "token_type=access" in messages[0]
        assert "active=false" in messages[1]
        assert all(access not in m for m in messages)

    def test_writes_no_audit_event(self, test_tenant, normal_oauth2_client, test_user):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        before = len(database.event_log.list_events(test_tenant["id"], limit=100))

        svc.introspect_token(
            test_tenant["id"], _client(test_tenant, normal_oauth2_client), access, ISSUER
        )

        assert len(database.event_log.list_events(test_tenant["id"], limit=100)) == before


class TestRevoke:
    def test_revoking_access_token_keeps_refresh_token(
        self, test_tenant, normal_oauth2_client, test_user
    ):
        refresh, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        client = _client(test_tenant, normal_oauth2_client)

        assert svc.revoke_token(test_tenant["id"], client, access) is True

        assert database.oauth2.find_token(test_tenant["id"], access) is None
        assert database.oauth2.find_token(test_tenant["id"], refresh) is not None

    def test_revoking_refresh_token_revokes_its_access_tokens(
        self, test_tenant, normal_oauth2_client, test_user
    ):
        refresh, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        assert svc.revoke_token(
            test_tenant["id"], _client(test_tenant, normal_oauth2_client), refresh
        )

        assert database.oauth2.find_token(test_tenant["id"], refresh) is None
        assert database.oauth2.find_token(test_tenant["id"], access) is None

    def test_logs_event(self, test_tenant, normal_oauth2_client, test_user):
        refresh, _ = _tokens(test_tenant, normal_oauth2_client, test_user)

        svc.revoke_token(test_tenant["id"], _client(test_tenant, normal_oauth2_client), refresh)

        events = _events(test_tenant, "oauth2_token_revoked")
        assert len(events) == 1
        event = events[0]
        assert str(event["actor_user_id"]) == str(test_user["id"])
        assert event["artifact_type"] == "oauth2_client"
        assert str(event["artifact_id"]) == str(normal_oauth2_client["id"])
        assert event["metadata"]["client_id"] == normal_oauth2_client["client_id"]
        assert event["metadata"]["token_type"] == "refresh"

    def test_unknown_token_is_a_quiet_no_op(self, test_tenant, normal_oauth2_client):
        assert (
            svc.revoke_token(test_tenant["id"], _client(test_tenant, normal_oauth2_client), "x")
            is False
        )
        assert _events(test_tenant, "oauth2_token_revoked") == []

    def test_other_clients_token_is_left_alone(
        self, test_tenant, normal_oauth2_client, b2b_oauth2_client, test_user
    ):
        """Even a resource server (tenant introspection) cannot revoke others' tokens."""
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        database.oauth2.set_client_tenant_introspection(
            test_tenant["id"], b2b_oauth2_client["client_id"], True
        )

        assert (
            svc.revoke_token(test_tenant["id"], _client(test_tenant, b2b_oauth2_client), access)
            is False
        )

        assert database.oauth2.find_token(test_tenant["id"], access) is not None
        assert _events(test_tenant, "oauth2_token_revoked") == []

    def test_revoking_twice(self, test_tenant, normal_oauth2_client, test_user):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        client = _client(test_tenant, normal_oauth2_client)

        assert svc.revoke_token(test_tenant["id"], client, access) is True
        assert svc.revoke_token(test_tenant["id"], client, access) is False
        assert len(_events(test_tenant, "oauth2_token_revoked")) == 1


class TestSetTenantIntrospection:
    def test_admin_enables_on_app(self, test_tenant, test_admin_user, normal_oauth2_client):
        updated = svc.set_tenant_introspection(
            _user(test_tenant, test_admin_user, "admin"), normal_oauth2_client["client_id"], True
        )

        assert updated["can_introspect_tenant_tokens"] is True
        events = _events(test_tenant, "oauth2_client_introspection_changed")
        assert len(events) == 1
        assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])
        assert str(events[0]["artifact_id"]) == str(normal_oauth2_client["id"])
        assert events[0]["metadata"]["can_introspect_tenant_tokens"] is True

    def test_unchanged_value_logs_nothing(self, test_tenant, test_admin_user, normal_oauth2_client):
        svc.set_tenant_introspection(
            _user(test_tenant, test_admin_user, "admin"), normal_oauth2_client["client_id"], False
        )
        assert _events(test_tenant, "oauth2_client_introspection_changed") == []

    def test_disable(self, test_tenant, test_admin_user, normal_oauth2_client):
        admin = _user(test_tenant, test_admin_user, "admin")
        svc.set_tenant_introspection(admin, normal_oauth2_client["client_id"], True)

        updated = svc.set_tenant_introspection(admin, normal_oauth2_client["client_id"], False)

        assert updated["can_introspect_tenant_tokens"] is False
        events = _events(test_tenant, "oauth2_client_introspection_changed")
        assert [e["metadata"]["can_introspect_tenant_tokens"] for e in events] == [False, True]

    def test_member_forbidden(self, test_tenant, test_user, normal_oauth2_client):
        with pytest.raises(ForbiddenError):
            svc.set_tenant_introspection(
                _user(test_tenant, test_user, "member"), normal_oauth2_client["client_id"], True
            )

    def test_admin_forbidden_on_b2b(self, test_tenant, test_admin_user, b2b_oauth2_client):
        with pytest.raises(ForbiddenError):
            svc.set_tenant_introspection(
                _user(test_tenant, test_admin_user, "admin"), b2b_oauth2_client["client_id"], True
            )
        row = _client(test_tenant, b2b_oauth2_client)
        assert row["can_introspect_tenant_tokens"] is False

    def test_super_admin_on_b2b(self, test_tenant, test_super_admin_user, b2b_oauth2_client):
        updated = svc.set_tenant_introspection(
            _user(test_tenant, test_super_admin_user, "super_admin"),
            b2b_oauth2_client["client_id"],
            True,
        )
        assert updated["can_introspect_tenant_tokens"] is True

    def test_unknown_client(self, test_tenant, test_admin_user):
        with pytest.raises(NotFoundError):
            svc.set_tenant_introspection(_user(test_tenant, test_admin_user, "admin"), "nope", True)

    def test_public_client_refused(self, test_tenant, test_admin_user):
        public = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="TV App",
            redirect_uris=[],
            created_by=str(test_admin_user["id"]),
            device_grant_enabled=True,
            is_public=True,
        )
        admin = _user(test_tenant, test_admin_user, "admin")
        with pytest.raises(ValidationError) as exc:
            svc.set_tenant_introspection(admin, public["client_id"], True)
        assert exc.value.code == "public_client_no_introspection"
        assert _events(test_tenant, "oauth2_client_introspection_changed") == []
        # Switching it off stays a harmless no-op.
        assert svc.set_tenant_introspection(admin, public["client_id"], False)
