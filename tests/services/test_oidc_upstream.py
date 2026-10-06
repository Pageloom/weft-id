"""Tests for the OIDC upstream connection service layer.

Covers CRUD, encryption-at-rest (secret never stored or returned in
plaintext), delete-guard, and event logging.
"""

import json
from unittest.mock import patch
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


class TestPresetDefaults:
    """Preset defaults are applied server-side (not just in browser JS)."""

    def test_entra_defaults_correlation_claim_and_authority(
        self, test_tenant, test_super_admin_user
    ):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(
            ru,
            OIDCConnectionCreate(
                name="Entra",
                provider_type="entra",
                entra_tenant_id="contoso.onmicrosoft.com",
            ),
            BASE_URL,
        )
        assert conn.correlation_claim == "oid"
        assert conn.issuer == "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
        assert conn.discovery_url == (
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
            "/.well-known/openid-configuration"
        )
        assert conn.scopes == "openid profile email User.Read"

    def test_google_defaults_issuer_and_scopes(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(
            ru,
            OIDCConnectionCreate(name="Google", provider_type="google"),
            BASE_URL,
        )
        assert conn.issuer == "https://accounts.google.com"
        assert conn.discovery_url == (
            "https://accounts.google.com/.well-known/openid-configuration"
        )
        assert conn.correlation_claim == "sub"
        assert conn.scopes == "openid profile email"

    def test_generic_requires_explicit_issuer(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc
        from services.exceptions import ValidationError

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        with pytest.raises(ValidationError) as exc_info:
            svc.create_connection(
                ru,
                OIDCConnectionCreate(name="Generic", provider_type="generic"),
                BASE_URL,
            )
        assert exc_info.value.code == "oidc_connection_issuer_required"

    def test_explicit_correlation_claim_not_overridden(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(
            ru,
            OIDCConnectionCreate(
                name="Entra custom",
                provider_type="entra",
                entra_tenant_id="contoso.onmicrosoft.com",
                correlation_claim="sub",
            ),
            BASE_URL,
        )
        assert conn.correlation_claim == "sub"


class TestMultiTenantEntraRefused:
    """common / organizations / consumers accept any directory: refused on save."""

    @pytest.mark.parametrize("tenant_value", ["common", "organizations", "consumers", " Common "])
    def test_create_entra_with_multi_tenant_id(
        self, tenant_value, test_tenant, test_super_admin_user
    ):
        from services import oidc_upstream as svc
        from services.exceptions import ValidationError

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        with pytest.raises(ValidationError) as exc_info:
            svc.create_connection(
                ru,
                OIDCConnectionCreate(
                    name="Entra", provider_type="entra", entra_tenant_id=tenant_value
                ),
                BASE_URL,
            )
        assert exc_info.value.code == "oidc_entra_multi_tenant_not_supported"

    @pytest.mark.parametrize("provider_type", ["entra", "generic"])
    def test_create_with_hand_entered_multi_tenant_issuer(
        self, provider_type, test_tenant, test_super_admin_user
    ):
        from services import oidc_upstream as svc
        from services.exceptions import ValidationError

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        with pytest.raises(ValidationError) as exc_info:
            svc.create_connection(
                ru,
                _create_data(
                    provider_type=provider_type,
                    issuer="https://login.microsoftonline.com/organizations/v2.0",
                    entra_tenant_id="contoso.onmicrosoft.com" if provider_type == "entra" else None,
                ),
                BASE_URL,
            )
        assert exc_info.value.code == "oidc_entra_multi_tenant_not_supported"

    def test_single_tenant_guid_accepted(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        tenant_guid = "72f988bf-86f1-41af-91ab-2d7cd011db47"
        conn = svc.create_connection(
            ru,
            OIDCConnectionCreate(name="Entra", provider_type="entra", entra_tenant_id=tenant_guid),
            BASE_URL,
        )
        assert conn.issuer == f"https://login.microsoftonline.com/{tenant_guid}/v2.0"

    def test_microsoft_personal_preset_unaffected(self, test_tenant, test_super_admin_user):
        """Personal accounts have their own type, with the fixed consumers issuer."""
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(
            ru, OIDCConnectionCreate(name="MSA", provider_type="microsoft"), BASE_URL
        )
        assert "9188040d-6c67-4c5b-b112-36a304b66dad" in conn.issuer

    def test_update_to_multi_tenant_refused(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc
        from services.exceptions import ValidationError

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(
            ru,
            OIDCConnectionCreate(
                name="Entra", provider_type="entra", entra_tenant_id="contoso.onmicrosoft.com"
            ),
            BASE_URL,
        )
        for update in (
            OIDCConnectionUpdate(entra_tenant_id="organizations"),
            OIDCConnectionUpdate(issuer="https://login.microsoftonline.com/common/v2.0"),
        ):
            with pytest.raises(ValidationError) as exc_info:
                svc.update_connection(ru, created.id, update, BASE_URL)
            assert exc_info.value.code == "oidc_entra_multi_tenant_not_supported"


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


class TestManualEndpoints:
    """Manually supplied endpoints must be https (http only in IS_DEV)."""

    ENDPOINTS = {
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "userinfo_endpoint": "https://idp.example.com/userinfo",
        "jwks_uri": "https://idp.example.com/keys",
        "end_session_endpoint": "https://idp.example.com/logout",
    }

    def test_create_persists_manual_endpoints(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(ru, _create_data(**self.ENDPOINTS), BASE_URL)

        for field, value in self.ENDPOINTS.items():
            assert getattr(conn, field) == value

    @pytest.mark.parametrize("field", sorted(ENDPOINTS))
    def test_create_rejects_non_https_endpoint(self, test_tenant, test_super_admin_user, field):
        from services import oidc_upstream as svc
        from services.exceptions import ValidationError

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        data = _create_data(**{field: "http://idp.example.com/insecure"})

        with (
            patch("services.oidc_upstream.connections.settings.IS_DEV", False),
            pytest.raises(ValidationError) as exc_info,
        ):
            svc.create_connection(ru, data, BASE_URL)
        assert exc_info.value.code == "oidc_endpoint_not_https"
        assert field in exc_info.value.message

    def test_create_rejects_schemeless_endpoint(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc
        from services.exceptions import ValidationError

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        data = _create_data(jwks_uri="idp.example.com/keys")

        # Rejected even in IS_DEV: only http/https are ever acceptable.
        with pytest.raises(ValidationError) as exc_info:
            svc.create_connection(ru, data, BASE_URL)
        assert exc_info.value.code == "oidc_endpoint_not_https"

    def test_create_allows_http_in_dev(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(
            ru, _create_data(token_endpoint="http://localhost:9000/token"), BASE_URL
        )
        assert conn.token_endpoint == "http://localhost:9000/token"

    def test_update_sets_manual_endpoints(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)
        assert created.authorization_endpoint is None

        updated = svc.update_connection(
            ru, created.id, OIDCConnectionUpdate(**self.ENDPOINTS), BASE_URL
        )
        for field, value in self.ENDPOINTS.items():
            assert getattr(updated, field) == value

    def test_update_rejects_non_https_endpoint(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc
        from services.exceptions import ValidationError

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(**self.ENDPOINTS), BASE_URL)

        with (
            patch("services.oidc_upstream.connections.settings.IS_DEV", False),
            pytest.raises(ValidationError) as exc_info,
        ):
            svc.update_connection(
                ru,
                created.id,
                OIDCConnectionUpdate(token_endpoint="http://idp.example.com/token"),
                BASE_URL,
            )
        assert exc_info.value.code == "oidc_endpoint_not_https"

        # Nothing was written.
        current = svc.get_connection(ru, created.id, BASE_URL)
        assert current.token_endpoint == self.ENDPOINTS["token_endpoint"]

    def test_update_unset_endpoint_leaves_value(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(**self.ENDPOINTS), BASE_URL)

        updated = svc.update_connection(
            ru,
            created.id,
            OIDCConnectionUpdate(jwks_uri="https://idp.example.com/keys-v2"),
            BASE_URL,
        )
        assert updated.jwks_uri == "https://idp.example.com/keys-v2"
        assert updated.token_endpoint == self.ENDPOINTS["token_endpoint"]

    def _mark_discovered(self, tenant_id, connection_id):
        import database

        database.execute(
            tenant_id,
            "update oidc_idp_connections set discovery_fetched_at = now() where id = :id",
            {"id": connection_id},
        )

    def test_manual_endpoint_edit_leaves_discovery_management(
        self, test_tenant, test_super_admin_user
    ):
        """Hand-set endpoints must not be overwritten by the sign-in refresh,
        which only refetches connections with a discovery timestamp."""
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(**self.ENDPOINTS), BASE_URL)
        self._mark_discovered(test_tenant["id"], created.id)

        updated = svc.update_connection(
            ru,
            created.id,
            OIDCConnectionUpdate(jwks_uri="https://idp.example.com/keys-v2"),
            BASE_URL,
        )
        assert updated.discovery_fetched_at is None

    def test_other_edit_keeps_discovery_management(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)
        self._mark_discovered(test_tenant["id"], created.id)

        updated = svc.update_connection(
            ru, created.id, OIDCConnectionUpdate(name="Renamed"), BASE_URL
        )
        assert updated.discovery_fetched_at is not None


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
        self.urls: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def stream(self, method, url, **kwargs):
        self.urls.append(url)
        return self._response


class TestTestConnection:
    """Test Connection: discovery now, then the advertised key set."""

    def _run(self, ru, connection_id, discovery_status=200, jwks_status=200):
        from services import oidc_upstream as svc
        from services.oidc_upstream import jwks as jwks_service

        from tests.fixtures.oidc import load_fixture

        jwks_service.clear_jwks_cache(ru["tenant_id"], connection_id)
        jwks_client = _FakeClient(
            _FakeResponse(jwks_status, load_fixture("jwks") if jwks_status == 200 else None)
        )
        with (
            patch(
                "services.oidc_upstream.discovery.build_safe_client",
                return_value=_FakeClient(
                    _FakeResponse(
                        discovery_status,
                        load_fixture("discovery") if discovery_status == 200 else None,
                    )
                ),
            ),
            patch("services.oidc_upstream.jwks.build_safe_client", return_value=jwks_client),
        ):
            try:
                return svc.test_connection(ru, connection_id, BASE_URL), jwks_client
            except Exception as exc:  # noqa: BLE001 - returned for the assertions
                return exc, jwks_client

    def _last_event(self, tenant_id, connection_id):
        import database

        events = database.event_log.list_events(tenant_id, limit=20)
        return next(
            e
            for e in events
            if e["event_type"] == "oidc_idp_connection_tested"
            and str(e["artifact_id"]) == str(connection_id)
        )

    def test_success_stores_endpoints_fetches_keys_and_logs(
        self, test_tenant, test_super_admin_user
    ):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)

        result, jwks_client = self._run(ru, created.id)

        assert result.token_endpoint == "https://idp.example.com/token"
        assert result.discovery_fetched_at is not None
        assert jwks_client.urls == ["https://idp.example.com/jwks"]
        event = self._last_event(test_tenant["id"], created.id)
        assert event["metadata"]["result"] == "success"

    def test_jwks_failure_is_reported(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc
        from services.exceptions import ValidationError

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)

        result, _ = self._run(ru, created.id, jwks_status=500)

        assert isinstance(result, ValidationError)
        assert result.code == "oidc_connection_test_failed"
        assert result.message.startswith("Key set (JWKS) failed:")
        event = self._last_event(test_tenant["id"], created.id)
        assert event["metadata"]["result"] == "failed"
        assert event["metadata"]["detail"] == result.message

    def test_discovery_failure_skips_keys(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc
        from services.exceptions import ValidationError

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)

        result, jwks_client = self._run(ru, created.id, discovery_status=404)

        assert isinstance(result, ValidationError)
        assert result.message.startswith("Discovery failed:")
        assert jwks_client.urls == []

    def test_member_forbidden(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)

        with pytest.raises(ForbiddenError):
            svc.test_connection(
                _make_requesting_user(test_user, test_tenant["id"]), created.id, BASE_URL
            )

    def test_unknown_connection(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        with pytest.raises(NotFoundError):
            svc.test_connection(ru, str(uuid4()), BASE_URL)


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

    def test_clear_default(self, test_tenant, test_super_admin_user):
        import database
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)
        svc.set_connection_default(ru, created.id, BASE_URL)

        cleared = svc.clear_connection_default(ru, created.id, BASE_URL)

        assert cleared.is_default is False
        row = database.oidc_upstream.get_connection(test_tenant["id"], created.id)
        assert row["is_default"] is False
        _verify_event_logged(test_tenant["id"], "oidc_idp_connection_default_cleared", created.id)

    def test_clear_default_when_not_default_changes_nothing(
        self, test_tenant, test_super_admin_user
    ):
        import database
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)

        with patch("services.oidc_upstream.connections.log_event") as log_event:
            result = svc.clear_connection_default(ru, created.id, BASE_URL)

        assert result.is_default is False
        log_event.assert_not_called()
        row = database.oidc_upstream.get_connection(test_tenant["id"], created.id)
        assert row["is_default"] is False

    def test_clear_default_unknown_connection(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        with pytest.raises(NotFoundError):
            svc.clear_connection_default(ru, str(uuid4()), BASE_URL)

    def test_clear_default_admin_forbidden(
        self, test_tenant, test_super_admin_user, test_admin_user
    ):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(), BASE_URL)
        svc.set_connection_default(ru, created.id, BASE_URL)

        with pytest.raises(ForbiddenError):
            svc.clear_connection_default(
                _make_requesting_user(test_admin_user, test_tenant["id"], "admin"),
                created.id,
                BASE_URL,
            )

    def test_requires_platform_mfa(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(require_platform_mfa=True), BASE_URL)

        assert svc.oidc_connection_requires_platform_mfa(test_tenant["id"], created.id) is True
        assert svc.oidc_connection_requires_platform_mfa(test_tenant["id"], str(uuid4())) is False


class TestGroupLifecycle:
    """Base group lifecycle and group-claim settings on the connection."""

    def test_create_makes_base_group(self, test_tenant, test_super_admin_user):
        import database
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(ru, _create_data(name="Acme OIDC"), BASE_URL)

        base_id = database.groups.get_idp_base_group_id(test_tenant["id"], conn.id, "oidc")
        assert base_id is not None
        base = database.groups.get_group_by_id(test_tenant["id"], base_id)
        assert base is not None
        assert base["name"] == "Acme OIDC"
        assert base["group_type"] == "idp"
        assert str(base["oidc_connection_id"]) == conn.id
        assert base["idp_name"] == "Acme OIDC"
        _verify_event_logged(test_tenant["id"], "idp_group_created", base_id)

    def test_create_survives_base_group_conflict(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        with patch(
            "services.oidc_upstream.connections.groups_service.create_idp_base_group",
            side_effect=ConflictError(message="dup", code="group_name_exists"),
        ):
            conn = svc.create_connection(ru, _create_data(), BASE_URL)
        assert conn.id is not None

    def test_rename_follows_to_base_group(self, test_tenant, test_super_admin_user):
        import database
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(ru, _create_data(name="Old Name"), BASE_URL)
        base_id = database.groups.get_idp_base_group_id(test_tenant["id"], conn.id, "oidc")

        svc.update_connection(ru, conn.id, OIDCConnectionUpdate(name="New Name"), BASE_URL)

        base = database.groups.get_group_by_id(test_tenant["id"], base_id)
        assert base is not None and base["name"] == "New Name"
        assert database.groups.get_idp_base_group_id(test_tenant["id"], conn.id, "oidc") == base_id
        _verify_event_logged(test_tenant["id"], "idp_group_renamed", base_id)

    def test_delete_removes_groups(self, test_tenant, test_super_admin_user):
        import database
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(ru, _create_data(), BASE_URL)
        base_id = database.groups.get_idp_base_group_id(test_tenant["id"], conn.id, "oidc")
        claim_group = database.groups.create_idp_group(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=conn.id,
            name="engineering",
            source="oidc",
        )

        svc.delete_connection(ru, conn.id)

        assert database.groups.get_group_by_id(test_tenant["id"], base_id) is None
        assert database.groups.get_group_by_id(test_tenant["id"], str(claim_group["id"])) is None
        _verify_event_logged(test_tenant["id"], "idp_group_invalidated", base_id)
        events = database.event_log.list_events(test_tenant["id"], limit=20)
        deleted = [e for e in events if e["event_type"] == "oidc_idp_connection_deleted"]
        assert deleted[0]["metadata"]["groups_removed"] == 2

    def test_group_claim_settings_persist(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(
            ru,
            _create_data(group_claim_source=" groups ", group_claim_name_key="displayName"),
            BASE_URL,
        )
        assert conn.group_claim_source == "groups"
        assert conn.group_claim_name_key == "displayName"

    def test_blank_group_claim_on_create_stored_as_null(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(
            ru, _create_data(group_claim_source="  ", group_claim_name_key=""), BASE_URL
        )
        assert conn.group_claim_source is None
        assert conn.group_claim_name_key is None

    def test_update_blank_clears_and_none_leaves(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        conn = svc.create_connection(
            ru, _create_data(group_claim_source="groups", group_claim_name_key="name"), BASE_URL
        )

        # None leaves unchanged.
        updated = svc.update_connection(ru, conn.id, OIDCConnectionUpdate(name="X"), BASE_URL)
        assert updated.group_claim_source == "groups"
        assert updated.group_claim_name_key == "name"

        # Empty string clears.
        cleared = svc.update_connection(
            ru,
            conn.id,
            OIDCConnectionUpdate(group_claim_source="", group_claim_name_key="  "),
            BASE_URL,
        )
        assert cleared.group_claim_source is None
        assert cleared.group_claim_name_key is None


class TestCredentialUpdate:
    """Editing the settings fixed at creation (issue #177)."""

    ENDPOINTS = TestManualEndpoints.ENDPOINTS

    def _mark_discovered(self, tenant_id, connection_id):
        import database

        database.execute(
            tenant_id,
            "update oidc_idp_connections set discovery_fetched_at = now() where id = :id",
            {"id": connection_id},
        )

    def test_issuer_change_drops_discovered_endpoints(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(**self.ENDPOINTS), BASE_URL)
        self._mark_discovered(test_tenant["id"], created.id)

        updated = svc.update_connection(
            ru, created.id, OIDCConnectionUpdate(issuer="https://new-idp.example.com"), BASE_URL
        )
        assert updated.issuer == "https://new-idp.example.com"
        assert updated.discovery_fetched_at is None
        for field in self.ENDPOINTS:
            assert getattr(updated, field) is None

    def test_same_issuer_keeps_discovered_endpoints(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(**self.ENDPOINTS), BASE_URL)
        self._mark_discovered(test_tenant["id"], created.id)

        updated = svc.update_connection(
            ru,
            created.id,
            OIDCConnectionUpdate(issuer="https://idp.example.com/", client_id="other"),
            BASE_URL,
        )
        assert updated.discovery_fetched_at is not None
        assert updated.token_endpoint == self.ENDPOINTS["token_endpoint"]

    def test_issuer_change_keeps_hand_set_endpoints(self, test_tenant, test_super_admin_user):
        """A never-discovered connection's endpoints were set by hand: keep them."""
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(ru, _create_data(**self.ENDPOINTS), BASE_URL)

        updated = svc.update_connection(
            ru, created.id, OIDCConnectionUpdate(issuer="https://new-idp.example.com"), BASE_URL
        )
        assert updated.token_endpoint == self.ENDPOINTS["token_endpoint"]

    def test_entra_tenant_change_recomposes_authority(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(
            ru,
            _create_data(provider_type="entra", issuer=None, entra_tenant_id="old.example.com"),
            BASE_URL,
        )
        assert created.issuer == "https://login.microsoftonline.com/old.example.com/v2.0"

        updated = svc.update_connection(
            ru, created.id, OIDCConnectionUpdate(entra_tenant_id="new.example.com"), BASE_URL
        )
        assert updated.entra_tenant_id == "new.example.com"
        assert updated.issuer == "https://login.microsoftonline.com/new.example.com/v2.0"
        assert updated.discovery_url == (
            "https://login.microsoftonline.com/new.example.com/v2.0/.well-known/openid-configuration"
        )

    def test_entra_multi_tenant_refused_on_update(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc
        from services.exceptions import ValidationError

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(
            ru,
            _create_data(provider_type="entra", issuer=None, entra_tenant_id="old.example.com"),
            BASE_URL,
        )
        with pytest.raises(ValidationError):
            svc.update_connection(
                ru, created.id, OIDCConnectionUpdate(entra_tenant_id="common"), BASE_URL
            )

    def test_gitlab_issuer_override_follows_discovery(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(
            ru, _create_data(provider_type="gitlab", issuer=None), BASE_URL
        )
        assert created.discovery_url == "https://gitlab.com/.well-known/openid-configuration"

        moved = svc.update_connection(
            ru, created.id, OIDCConnectionUpdate(issuer="https://git.example.com"), BASE_URL
        )
        assert moved.issuer == "https://git.example.com"
        assert moved.discovery_url is None

        back = svc.update_connection(
            ru, created.id, OIDCConnectionUpdate(issuer="https://gitlab.com"), BASE_URL
        )
        assert back.discovery_url == "https://gitlab.com/.well-known/openid-configuration"

    def test_hosted_domain_blank_clears(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        ru = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        created = svc.create_connection(
            ru,
            _create_data(provider_type="google", issuer=None, hosted_domain="example.com"),
            BASE_URL,
        )
        assert created.hosted_domain == "example.com"

        updated = svc.update_connection(
            ru, created.id, OIDCConnectionUpdate(hosted_domain=""), BASE_URL
        )
        assert updated.hosted_domain is None
