"""Service tests for dynamic client registration (services.oauth2_registration):
metadata validation, the admin settings and initial access tokens, and the
RFC 7591 / RFC 7592 protocol functions. Real database."""

from datetime import UTC, datetime, timedelta

import database
import oauth2
import pytest
from schemas.oauth2 import InitialAccessTokenCreate, RegistrationSettingsUpdate
from services import oauth2_registration as svc
from services.event_log import SYSTEM_ACTOR_ID
from services.exceptions import (
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)

BASE = "https://tenant.example.test"


def _user(test_tenant, user, role="admin"):
    return {"id": str(user["id"]), "tenant_id": str(test_tenant["id"]), "role": role}


def _events(test_tenant, event_type):
    return [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=50)
        if e["event_type"] == event_type
    ]


def _set_policy(test_tenant, admin, policy, default_access="none"):
    svc.update_registration_settings(
        _user(test_tenant, admin),
        RegistrationSettingsUpdate(policy=policy, default_access=default_access),
        BASE,
    )


def _register(test_tenant, metadata=None, token=None):
    return svc.register_client(
        test_tenant["id"],
        metadata or {"redirect_uris": ["https://rp.example/cb"]},
        initial_access_token=token,
        base_url=BASE,
    )


def _error_code(metadata):
    with pytest.raises(ValidationError) as exc:
        svc.validate_client_metadata(metadata)
    return exc.value.code


# =============================================================================
# Metadata validation (pure)
# =============================================================================


class TestValidateClientMetadata:
    def test_minimal_request_gets_defaults(self):
        accepted = svc.validate_client_metadata({"redirect_uris": ["https://rp.example/cb"]})

        assert accepted["client_name"] == "Registered client (rp.example)"
        assert accepted["redirect_uris"] == ["https://rp.example/cb"]
        assert accepted["extra"] == {
            "application_type": "web",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "client_secret_basic",
        }
        assert accepted["logo_uri"] is None

    def test_full_request(self):
        accepted = svc.validate_client_metadata(
            {
                "redirect_uris": ["https://rp.example/cb", "https://rp.example/cb"],
                "client_name": " Acme ",
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "client_secret_post",
                "id_token_signed_response_alg": "RS256",
                "subject_type": "public",
                "logo_uri": "https://rp.example/logo.png",
                "client_uri": "https://rp.example",
                "policy_uri": "https://rp.example/privacy",
                "tos_uri": "https://rp.example/tos",
                "contacts": ["ops@rp.example"],
                "jwks_uri": "https://rp.example/jwks",
                "post_logout_redirect_uris": ["https://rp.example/bye"],
                "frontchannel_logout_uri": "https://rp.example/fc",
                "frontchannel_logout_session_required": False,
                "backchannel_logout_uri": "https://rp.example/bc",
                "unknown_field": "ignored",
            }
        )

        assert accepted["client_name"] == "Acme"
        assert accepted["redirect_uris"] == ["https://rp.example/cb"]
        assert accepted["extra"]["grant_types"] == ["authorization_code", "refresh_token"]
        assert accepted["extra"]["token_endpoint_auth_method"] == "client_secret_post"
        assert accepted["extra"]["contacts"] == ["ops@rp.example"]
        assert accepted["extra"]["jwks_uri"] == "https://rp.example/jwks"
        assert "unknown_field" not in accepted["extra"]
        assert accepted["frontchannel_logout_session_required"] is False
        assert accepted["backchannel_logout_uri"] == "https://rp.example/bc"
        assert accepted["post_logout_redirect_uris"] == ["https://rp.example/bye"]

    def test_inline_jwks_stored(self):
        jwks = {"keys": [{"kty": "RSA", "e": "AQAB", "n": "abc"}]}
        accepted = svc.validate_client_metadata(
            {"redirect_uris": ["https://rp.example/cb"], "jwks": jwks}
        )
        assert accepted["extra"]["jwks"] == jwks

    @pytest.mark.parametrize(
        "uris",
        [
            None,
            [],
            "https://rp.example/cb",
            ["https://rp.example/cb#frag"],
            ["http://rp.example/cb"],
            ["http://127.0.0.1/cb"],  # loopback http is for native clients only
            ["myapp:/cb"],
            ["/relative"],
            [123],
            ["https://rp.example/" + "a" * 2050],
            [f"https://rp.example/{i}" for i in range(51)],
        ],
    )
    def test_bad_redirect_uris(self, uris):
        metadata = {} if uris is None else {"redirect_uris": uris}
        assert _error_code(metadata) == "invalid_redirect_uri"

    @pytest.mark.parametrize(
        "uri", ["http://127.0.0.1:8080/cb", "http://localhost/cb", "http://[::1]/cb"]
    )
    def test_native_client_may_use_loopback_http(self, uri):
        accepted = svc.validate_client_metadata(
            {"redirect_uris": [uri], "application_type": "native"}
        )
        assert accepted["redirect_uris"] == [uri]
        assert accepted["extra"]["application_type"] == "native"

    def test_native_client_still_needs_loopback_for_http(self):
        assert (
            _error_code({"redirect_uris": ["http://rp.example/cb"], "application_type": "native"})
            == "invalid_redirect_uri"
        )

    @pytest.mark.parametrize(
        "extra",
        [
            {"response_types": ["code id_token"]},
            {"response_types": ["token"]},
            {"grant_types": ["implicit"]},
            {"grant_types": ["refresh_token"]},
            {"grant_types": ["client_credentials"]},
            {"grant_types": "authorization_code"},
            {"token_endpoint_auth_method": "private_key_jwt"},
            {"token_endpoint_auth_method": "none"},
            {"application_type": "desktop"},
            {"id_token_signed_response_alg": "none"},
            {"id_token_signed_response_alg": "HS256"},
            {"subject_type": "pairwise"},
            {"userinfo_signed_response_alg": "RS256"},
            {"id_token_encrypted_response_alg": "RSA-OAEP"},
            {"request_object_signing_alg": "RS256"},
            {"token_endpoint_auth_signing_alg": "RS256"},
            {"client_name": 42},
            {"client_name": "x" * 256},
            {"logo_uri": "http://rp.example/logo.png"},
            {"policy_uri": "not a uri"},
            {"tos_uri": "https://rp.example/tos#x"},
            {"client_uri": ["https://rp.example"]},
            {"contacts": "ops@rp.example"},
            {"contacts": [f"c{i}@rp.example" for i in range(11)]},
            {"jwks": {"keys": "nope"}},
            {"jwks": [1]},
            {"jwks": {"keys": [{"kty": "RSA"}] * 21}},
            {"jwks": {"keys": [{"kty": "RSA", "n": "x" * 40000}]}},
            {"jwks": {"keys": []}, "jwks_uri": "https://rp.example/jwks"},
            {"jwks_uri": "http://rp.example/jwks"},
            {"frontchannel_logout_session_required": "yes"},
            {"post_logout_redirect_uris": ["ftp://rp.example/bye"]},
            {"frontchannel_logout_uri": "https://other.example/fc"},
            {"backchannel_logout_uri": "https://rp.example/bc#x"},
        ],
    )
    def test_invalid_client_metadata(self, extra):
        metadata = {"redirect_uris": ["https://rp.example/cb"], **extra}
        assert _error_code(metadata) == "invalid_client_metadata"

    def test_body_must_be_object(self):
        assert _error_code(["redirect_uris"]) == "invalid_client_metadata"

    def test_null_optional_values_are_absent(self):
        accepted = svc.validate_client_metadata(
            {"redirect_uris": ["https://rp.example/cb"], "logo_uri": None, "grant_types": []}
        )
        assert accepted["logo_uri"] is None
        assert accepted["extra"]["grant_types"] == ["authorization_code"]


# =============================================================================
# Admin: settings
# =============================================================================


class TestRegistrationSettings:
    def test_defaults(self, test_tenant, test_admin_user):
        settings = svc.get_registration_settings(_user(test_tenant, test_admin_user), BASE)

        assert settings.policy == "off"
        assert settings.default_access == "none"
        assert settings.registration_endpoint is None
        assert svc.is_registration_enabled(test_tenant["id"]) is False

    def test_update_logs_changes(self, test_tenant, test_admin_user):
        result = svc.update_registration_settings(
            _user(test_tenant, test_admin_user),
            RegistrationSettingsUpdate(policy="token_required"),
            BASE,
        )

        assert result.policy == "token_required"
        assert result.default_access == "none"
        assert result.registration_endpoint == f"{BASE}/oauth2/register"
        assert svc.is_registration_enabled(test_tenant["id"]) is True
        events = _events(test_tenant, "oauth2_registration_settings_updated")
        assert len(events) == 1
        assert events[0]["metadata"]["changes"] == {
            "policy": {"old": "off", "new": "token_required"}
        }
        assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])

    def test_unchanged_update_writes_nothing(self, test_tenant, test_admin_user):
        svc.update_registration_settings(
            _user(test_tenant, test_admin_user),
            RegistrationSettingsUpdate(policy="off", default_access="none"),
            BASE,
        )

        assert database.oauth2.get_registration_settings(test_tenant["id"]) is None
        assert _events(test_tenant, "oauth2_registration_settings_updated") == []

    def test_member_forbidden(self, test_tenant, test_user):
        with pytest.raises(ForbiddenError):
            svc.get_registration_settings(_user(test_tenant, test_user, "member"), BASE)
        with pytest.raises(ForbiddenError):
            svc.update_registration_settings(
                _user(test_tenant, test_user, "member"),
                RegistrationSettingsUpdate(policy="open"),
                BASE,
            )


# =============================================================================
# Admin: initial access tokens
# =============================================================================


class TestInitialAccessTokens:
    def test_create_returns_value_once_and_logs(self, test_tenant, test_admin_user):
        created = svc.create_initial_access_token(
            _user(test_tenant, test_admin_user),
            InitialAccessTokenCreate(name=" Partner ", expires_in_days=7),
        )

        assert created.token.startswith("weft-id_iat_")
        assert created.name == "Partner"
        assert created.status == "active"
        assert created.expires_at > datetime.now(UTC) + timedelta(days=6)
        listed = svc.list_initial_access_tokens(_user(test_tenant, test_admin_user))
        assert [t.id for t in listed] == [created.id]
        assert not hasattr(listed[0], "token")
        assert listed[0].created_by_name == (
            f"{test_admin_user['first_name']} {test_admin_user['last_name']}"
        )
        events = _events(test_tenant, "oauth2_initial_access_token_created")
        assert events[0]["metadata"]["name"] == "Partner"
        assert created.token not in str(events[0]["metadata"])

    def test_blank_name_rejected(self, test_tenant, test_admin_user):
        with pytest.raises(ValidationError):
            svc.create_initial_access_token(
                _user(test_tenant, test_admin_user), InitialAccessTokenCreate(name="   ")
            )

    def test_revoke(self, test_tenant, test_admin_user):
        admin = _user(test_tenant, test_admin_user)
        created = svc.create_initial_access_token(admin, InitialAccessTokenCreate(name="T"))

        revoked = svc.revoke_initial_access_token(admin, created.id)

        assert revoked.status == "revoked"
        event = _events(test_tenant, "oauth2_initial_access_token_revoked")[0]
        assert event["metadata"]["name"] == "T"
        assert str(event["artifact_id"]) == created.id
        with pytest.raises(NotFoundError):
            svc.revoke_initial_access_token(admin, created.id)

    @pytest.mark.parametrize("token_id", ["not-a-uuid", "00000000-0000-0000-0000-000000000001"])
    def test_revoke_unknown(self, test_tenant, test_admin_user, token_id):
        with pytest.raises(NotFoundError):
            svc.revoke_initial_access_token(_user(test_tenant, test_admin_user), token_id)

    def test_expired_status(self, test_tenant, test_admin_user):
        admin = _user(test_tenant, test_admin_user)
        created = svc.create_initial_access_token(
            admin, InitialAccessTokenCreate(name="Old", expires_in_days=1)
        )
        database.execute(
            test_tenant["id"],
            "update oauth2_initial_access_tokens set expires_at = now() - interval '1 minute'",
            {},
        )

        assert svc.list_initial_access_tokens(admin)[0].status == "expired"
        assert created.status == "active"

    def test_member_forbidden(self, test_tenant, test_user):
        member = _user(test_tenant, test_user, "member")
        with pytest.raises(ForbiddenError):
            svc.list_initial_access_tokens(member)
        with pytest.raises(ForbiddenError):
            svc.create_initial_access_token(member, InitialAccessTokenCreate(name="x"))
        with pytest.raises(ForbiddenError):
            svc.revoke_initial_access_token(member, "00000000-0000-0000-0000-000000000001")


# =============================================================================
# Protocol: registration
# =============================================================================


class TestRegisterClient:
    def test_off_is_not_found(self, test_tenant):
        with pytest.raises(NotFoundError):
            _register(test_tenant)

    def test_open_registration(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")

        body = _register(
            test_tenant,
            {
                "redirect_uris": ["https://rp.example/cb"],
                "client_name": "Acme",
                "logo_uri": "https://rp.example/logo.png",
                "contacts": ["ops@rp.example"],
            },
        )

        assert body["client_name"] == "Acme"
        assert body["client_secret_expires_at"] == 0
        assert body["registration_access_token"].startswith("weft-id_rat_")
        assert body["registration_client_uri"] == f"{BASE}/oauth2/register/{body['client_id']}"
        assert body["logo_uri"] == "https://rp.example/logo.png"
        assert body["contacts"] == ["ops@rp.example"]
        assert body["id_token_signed_response_alg"] == "RS256"
        client = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert client["dynamically_registered"] is True
        assert client["oidc_enabled"] is True
        assert client["available_to_all"] is False
        assert oauth2.verify_token_hash(body["client_secret"], client["client_secret_hash"])
        assert oauth2.verify_token_hash(
            body["registration_access_token"], client["registration_access_token_hash"]
        )
        event = _events(test_tenant, "oauth2_client_registered")[0]
        assert str(event["actor_user_id"]) == SYSTEM_ACTOR_ID
        assert event["metadata"]["initial_access_token_id"] is None
        assert body["client_secret"] not in str(event["metadata"])

    def test_default_access_all(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open", default_access="all")

        body = _register(test_tenant)

        client = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert client["available_to_all"] is True

    def test_token_required_without_token(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "token_required")
        with pytest.raises(UnauthorizedError):
            _register(test_tenant)

    def test_token_required_with_valid_token(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "token_required")
        token = svc.create_initial_access_token(
            _user(test_tenant, test_admin_user), InitialAccessTokenCreate(name="Partner")
        )

        body = _register(test_tenant, token=token.token)

        client = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert str(client["registered_with_token_id"]) == token.id
        listed = svc.list_initial_access_tokens(_user(test_tenant, test_admin_user))[0]
        assert listed.last_used_at is not None
        assert listed.registered_client_count == 1
        event = _events(test_tenant, "oauth2_client_registered")[0]
        assert event["metadata"]["initial_access_token_id"] == token.id
        assert event["metadata"]["initial_access_token_name"] == "Partner"

    @pytest.mark.parametrize("state", ["revoked", "expired", "unknown"])
    def test_unusable_token(self, test_tenant, test_admin_user, state):
        _set_policy(test_tenant, test_admin_user, "token_required")
        admin = _user(test_tenant, test_admin_user)
        token = svc.create_initial_access_token(admin, InitialAccessTokenCreate(name="T"))
        value = token.token
        if state == "revoked":
            svc.revoke_initial_access_token(admin, token.id)
        elif state == "expired":
            database.execute(
                test_tenant["id"],
                "update oauth2_initial_access_tokens set expires_at = now() - interval '1 second'",
                {},
            )
        else:
            value = "weft-id_iat_unknown"

        with pytest.raises(UnauthorizedError):
            _register(test_tenant, token=value)

    def test_open_policy_still_rejects_bad_token(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        with pytest.raises(UnauthorizedError):
            _register(test_tenant, token="weft-id_iat_bogus")

    def test_other_tenants_token_is_unknown(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "token_required")
        other = database.fetchone(
            database.UNSCOPED,
            "insert into tenants (subdomain, name) values (:s, 'Other') returning id",
            {"s": f"dcr-svc-{datetime.now(UTC).timestamp():.0f}"},
        )
        try:
            database.oauth2.create_initial_access_token(
                str(other["id"]),
                str(other["id"]),
                name="Theirs",
                token_hash=svc._hash_initial_access_token("weft-id_iat_theirs"),
                created_by=None,
            )
            with pytest.raises(UnauthorizedError):
                _register(test_tenant, token="weft-id_iat_theirs")
        finally:
            database.execute(
                database.UNSCOPED, "delete from tenants where id = :id", {"id": str(other["id"])}
            )

    def test_invalid_metadata_creates_nothing(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        before = len(database.oauth2.get_all_clients(test_tenant["id"]))

        with pytest.raises(ValidationError):
            _register(test_tenant, {"redirect_uris": ["http://rp.example/cb"]})

        assert len(database.oauth2.get_all_clients(test_tenant["id"])) == before


# =============================================================================
# Protocol: client configuration
# =============================================================================


@pytest.fixture
def registered(test_tenant, test_admin_user):
    _set_policy(test_tenant, test_admin_user, "open")
    return _register(
        test_tenant,
        {
            "redirect_uris": ["https://rp.example/cb"],
            "client_name": "Acme",
            "grant_types": ["authorization_code", "refresh_token"],
            "logo_uri": "https://rp.example/logo.png",
        },
    )


class TestAuthenticateRegistration:
    def test_valid_token(self, test_tenant, registered):
        client = svc.authenticate_registration(
            test_tenant["id"], registered["client_id"], registered["registration_access_token"]
        )
        assert client["client_id"] == registered["client_id"]

    @pytest.mark.parametrize("token", [None, "", "weft-id_rat_wrong"])
    def test_bad_token(self, test_tenant, registered, token):
        with pytest.raises(UnauthorizedError):
            svc.authenticate_registration(test_tenant["id"], registered["client_id"], token)

    def test_unknown_client(self, test_tenant, registered):
        with pytest.raises(UnauthorizedError):
            svc.authenticate_registration(
                test_tenant["id"], "weft-id_client_nope", registered["registration_access_token"]
            )

    def test_token_of_another_client(self, test_tenant, registered):
        other = _register(test_tenant)
        with pytest.raises(UnauthorizedError):
            svc.authenticate_registration(
                test_tenant["id"], other["client_id"], registered["registration_access_token"]
            )

    def test_admin_created_client(self, test_tenant, normal_oauth2_client):
        with pytest.raises(UnauthorizedError):
            svc.authenticate_registration(
                test_tenant["id"], normal_oauth2_client["client_id"], "anything"
            )

    def test_deactivated_client(self, test_tenant, test_admin_user, registered):
        database.oauth2.deactivate_client(test_tenant["id"], registered["client_id"])
        with pytest.raises(UnauthorizedError):
            svc.authenticate_registration(
                test_tenant["id"], registered["client_id"], registered["registration_access_token"]
            )


class TestClientConfiguration:
    def _client(self, test_tenant, registered):
        return svc.authenticate_registration(
            test_tenant["id"], registered["client_id"], registered["registration_access_token"]
        )

    def test_read_matches_registration_without_secrets(self, test_tenant, registered):
        body = svc.read_client_configuration(self._client(test_tenant, registered), BASE)

        expected = {
            k: v
            for k, v in registered.items()
            if k not in ("client_secret", "client_secret_expires_at", "registration_access_token")
        }
        assert body == expected

    def test_update_replaces_and_logs(self, test_tenant, registered):
        body = svc.update_client_configuration(
            test_tenant["id"],
            self._client(test_tenant, registered),
            {
                "client_id": registered["client_id"],
                "client_secret": registered["client_secret"],
                "redirect_uris": ["https://rp.example/new"],
                "registration_access_token": "ignored",
                "client_id_issued_at": 1,
            },
            BASE,
        )

        assert body["redirect_uris"] == ["https://rp.example/new"]
        assert body["grant_types"] == ["authorization_code"]
        assert "logo_uri" not in body
        assert body["client_name"] == "Registered client (rp.example)"
        assert body["client_id_issued_at"] == registered["client_id_issued_at"]
        event = _events(test_tenant, "oauth2_client_registration_updated")[0]
        assert str(event["actor_user_id"]) == SYSTEM_ACTOR_ID
        # Credentials survive the replacement.
        svc.authenticate_registration(
            test_tenant["id"], registered["client_id"], registered["registration_access_token"]
        )

    @pytest.mark.parametrize(
        "patch",
        [
            {"client_id": None},
            {"client_id": "weft-id_client_other"},
            {"client_secret": "wrong"},
            {"client_secret": 5},
            {"redirect_uris": ["http://rp.example/cb"]},
        ],
    )
    def test_update_rejected(self, test_tenant, registered, patch):
        metadata = {"client_id": registered["client_id"], "redirect_uris": ["https://rp.example/x"]}
        metadata.update(patch)
        if metadata["client_id"] is None:
            del metadata["client_id"]

        with pytest.raises(ValidationError):
            svc.update_client_configuration(
                test_tenant["id"], self._client(test_tenant, registered), metadata, BASE
            )

        fresh = database.oauth2.get_client_by_client_id(test_tenant["id"], registered["client_id"])
        assert fresh["redirect_uris"] == ["https://rp.example/cb"]

    def test_update_body_must_be_object(self, test_tenant, registered):
        with pytest.raises(ValidationError):
            svc.update_client_configuration(
                test_tenant["id"], self._client(test_tenant, registered), ["x"], BASE
            )

    def test_update_after_concurrent_delete(self, test_tenant, registered):
        client = self._client(test_tenant, registered)
        database.oauth2.delete_client(test_tenant["id"], registered["client_id"])

        with pytest.raises(UnauthorizedError):
            svc.update_client_configuration(
                test_tenant["id"],
                client,
                {"client_id": registered["client_id"], "redirect_uris": ["https://rp.example/x"]},
                BASE,
            )

    def test_delete(self, test_tenant, registered):
        svc.delete_client_configuration(test_tenant["id"], self._client(test_tenant, registered))

        assert (
            database.oauth2.get_client_by_client_id(test_tenant["id"], registered["client_id"])
            is None
        )
        event = _events(test_tenant, "oauth2_client_registration_deleted")[0]
        assert event["metadata"]["client_id"] == registered["client_id"]

    def test_delete_twice_logs_once(self, test_tenant, registered):
        client = self._client(test_tenant, registered)
        svc.delete_client_configuration(test_tenant["id"], client)
        svc.delete_client_configuration(test_tenant["id"], client)

        assert len(_events(test_tenant, "oauth2_client_registration_deleted")) == 1
