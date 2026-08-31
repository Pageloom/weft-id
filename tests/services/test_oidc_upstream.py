"""Tests for the OIDC upstream connection service layer.

Covers CRUD, encryption-at-rest (secret never stored or returned in
plaintext), delete-guard, and event logging.
"""

from uuid import uuid4

import pytest
from schemas.oidc_upstream import OIDCConnectionCreate, OIDCConnectionUpdate
from services.exceptions import ConflictError, ForbiddenError, NotFoundError
from services.types import RequestingUser

BASE_URL = "https://test.example.com"


def _make_requesting_user(user, tenant_id, role=None):
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role or user.get("role", "member"),
    )


def _create_data(**overrides):
    data = {
        "name": "Test OIDC",
        "provider_type": "generic",
        "issuer": "https://idp.example.com",
        "client_id": "client-123",
        "client_secret": "super-secret-value",
    }
    data.update(overrides)
    return OIDCConnectionCreate(**data)


def _verify_event_logged(tenant_id, event_type, artifact_id):
    import database

    events = database.event_log.list_events(tenant_id, limit=20)
    matching = [
        e
        for e in events
        if e["event_type"] == event_type and str(e["artifact_id"]) == str(artifact_id)
    ]
    assert len(matching) > 0, f"No events logged for {event_type} with artifact_id {artifact_id}"


class TestCreate:
    def test_create_as_super_admin(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(ru, _create_data(), BASE_URL)

        assert conn.id is not None
        assert conn.name == "Test OIDC"
        assert conn.provider_type == "generic"
        assert conn.issuer == "https://idp.example.com"
        assert conn.client_id == "client-123"
        assert conn.client_secret_set is True
        assert conn.callback_url == f"{BASE_URL}/auth/oidc/{conn.id}/callback"
        assert conn.is_enabled is False
        assert conn.is_default is False
        assert conn.allow_email_linking is False

        _verify_event_logged(test_tenant["id"], "oidc_idp_connection_created", conn.id)

    def test_create_as_admin_forbidden(self, test_tenant, test_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        with pytest.raises(ForbiddenError) as exc_info:
            svc.create_connection(ru, _create_data(), BASE_URL)
        assert exc_info.value.code == "super_admin_required"

    def test_secret_encrypted_at_rest(self, test_tenant, test_super_admin_user):
        import database
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(ru, _create_data(), BASE_URL)

        row = database.oidc_upstream.get_connection(test_tenant["id"], conn.id)
        assert row["client_secret_enc"] is not None
        assert row["client_secret_enc"] != "super-secret-value"
        assert "super-secret-value" not in row["client_secret_enc"]

    def test_secret_max_length_fits_encrypted_column(self, test_tenant, test_super_admin_user):
        """A 3000-char secret encrypts to ~4088 chars, under the 4096 column CHECK."""
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        long_secret = "s" * 3000
        conn = svc.create_connection(ru, _create_data(client_secret=long_secret), BASE_URL)
        assert conn.client_secret_set is True

    def test_decrypt_client_secret_round_trip(self, test_tenant, test_super_admin_user):
        """decrypt_client_secret is the reversible inverse of the at-rest encryption."""
        import database
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(ru, _create_data(client_secret="round-trip-secret"), BASE_URL)

        row = database.oidc_upstream.get_connection(test_tenant["id"], conn.id)
        assert svc.decrypt_client_secret(row["client_secret_enc"]) == "round-trip-secret"

    def test_secret_over_max_length_rejected_at_schema(self):
        """A >3000-char secret is rejected by the schema before reaching the DB."""
        from pydantic import ValidationError as PydanticValidationError

        with pytest.raises(PydanticValidationError):
            _create_data(client_secret="s" * 3001)


class TestGetAndList:
    def test_get_returns_config_without_secret(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)

        got = svc.get_connection(ru, created.id, BASE_URL)
        assert got.id == created.id
        assert got.client_secret_set is True
        # The secret is never exposed on the response schema.
        assert not hasattr(got, "client_secret")

    def test_get_not_found(self, test_tenant, test_super_admin_user):
        from uuid import uuid4

        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        with pytest.raises(NotFoundError) as exc_info:
            svc.get_connection(ru, str(uuid4()), BASE_URL)
        assert exc_info.value.code == "oidc_connection_not_found"

    def test_list(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        svc.create_connection(ru, _create_data(), BASE_URL)
        result = svc.list_connections(ru)
        assert result.total >= 1
        assert any(item.name == "Test OIDC" for item in result.items)


class TestUpdate:
    def test_update_name(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)

        updated = svc.update_connection(
            ru, created.id, OIDCConnectionUpdate(name="Renamed"), BASE_URL
        )
        assert updated.name == "Renamed"
        assert updated.issuer == created.issuer
        _verify_event_logged(test_tenant["id"], "oidc_idp_connection_updated", created.id)

    def test_update_secret_reencrypts(self, test_tenant, test_super_admin_user):
        import database
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)
        before = database.oidc_upstream.get_connection(test_tenant["id"], created.id)[
            "client_secret_enc"
        ]

        svc.update_connection(
            ru, created.id, OIDCConnectionUpdate(client_secret="new-secret"), BASE_URL
        )
        after = database.oidc_upstream.get_connection(test_tenant["id"], created.id)[
            "client_secret_enc"
        ]
        assert after != before
        assert "new-secret" not in after


class TestDelete:
    def test_delete_disabled_connection(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)

        svc.delete_connection(ru, created.id)

        with pytest.raises(NotFoundError):
            svc.get_connection(ru, created.id, BASE_URL)
        _verify_event_logged(test_tenant["id"], "oidc_idp_connection_deleted", created.id)

    def test_delete_enabled_connection_conflict(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(is_enabled=True), BASE_URL)

        with pytest.raises(ConflictError) as exc_info:
            svc.delete_connection(ru, created.id)
        assert exc_info.value.code == "oidc_connection_is_enabled"

    def test_delete_with_linked_users_conflict(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=created.id,
            sub="subject-123",
            user_id=str(test_user["id"]),
        )

        with pytest.raises(ConflictError) as exc_info:
            svc.delete_connection(ru, created.id)
        assert exc_info.value.code == "oidc_connection_has_linked_users"


class TestEnableDisableDefault:
    def test_enable_and_disable(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)

        enabled = svc.set_connection_enabled(ru, created.id, True, BASE_URL)
        assert enabled.is_enabled is True
        _verify_event_logged(test_tenant["id"], "oidc_idp_connection_enabled", created.id)

        disabled = svc.set_connection_enabled(ru, created.id, False, BASE_URL)
        assert disabled.is_enabled is False
        _verify_event_logged(test_tenant["id"], "oidc_idp_connection_disabled", created.id)

    def test_set_default(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)

        default = svc.set_connection_default(ru, created.id, BASE_URL)
        assert default.is_default is True
        _verify_event_logged(test_tenant["id"], "oidc_idp_connection_set_default", created.id)

    def test_requires_platform_mfa(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(require_platform_mfa=True), BASE_URL)

        assert svc.oidc_connection_requires_platform_mfa(test_tenant["id"], created.id) is True
        assert svc.oidc_connection_requires_platform_mfa(test_tenant["id"], str(uuid4())) is False
