"""Service tests for dynamic client registration (services.oauth2_registration):
metadata validation, the admin settings and initial access tokens, and the
RFC 7591 / RFC 7592 protocol functions. Real database."""

from datetime import UTC, datetime, timedelta

import database
import httpx
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

from tests.helpers.client_keys import JWKS

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
        assert accepted["initiate_login_uri"] is None

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
                "initiate_login_uri": "https://rp.example/login",
                "unknown_field": "ignored",
            }
        )

        assert accepted["client_name"] == "Acme"
        assert accepted["redirect_uris"] == ["https://rp.example/cb"]
        assert accepted["extra"]["grant_types"] == ["authorization_code", "refresh_token"]
        assert accepted["extra"]["token_endpoint_auth_method"] == "client_secret_post"
        assert accepted["extra"]["contacts"] == ["ops@rp.example"]
        # A column (it authenticates the client), not registration_metadata.
        assert accepted["jwks_uri"] == "https://rp.example/jwks"
        assert "jwks_uri" not in accepted["extra"]
        assert accepted["client_auth_method"] == "client_secret"
        assert "unknown_field" not in accepted["extra"]
        assert accepted["frontchannel_logout_session_required"] is False
        assert accepted["backchannel_logout_uri"] == "https://rp.example/bc"
        assert accepted["post_logout_redirect_uris"] == ["https://rp.example/bye"]
        # A column (admins set it too), not registration_metadata.
        assert accepted["initiate_login_uri"] == "https://rp.example/login"
        assert "initiate_login_uri" not in accepted["extra"]

    def test_inline_jwks_stored(self):
        accepted = svc.validate_client_metadata(
            {"redirect_uris": ["https://rp.example/cb"], "jwks": JWKS}
        )
        assert accepted["jwks"] == JWKS
        assert "jwks" not in accepted["extra"]

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
            {"subject_type": "pseudonymous"},
            {"subject_type": ["pairwise"]},
            {"sector_identifier_uri": "https://rp.example/s.json"},
            {"subject_type": "pairwise", "sector_identifier_uri": "http://rp.example/s.json"},
            {"subject_type": "pairwise", "sector_identifier_uri": 7},
            {"userinfo_signed_response_alg": "HS256"},
            {"userinfo_signed_response_alg": "none"},
            {"userinfo_encrypted_response_alg": "RSA-OAEP"},
            {"id_token_encrypted_response_alg": "RSA-OAEP"},
            {"request_object_signing_alg": "RS256"},
            {"request_object_signing_alg": "none", "jwks": JWKS},
            {"request_object_encryption_alg": "RSA-OAEP"},
            {"request_uris": "https://rp.example/req"},
            {"request_uris": ["http://rp.example/req"]},
            {"request_uris": ["/req"]},
            {"request_uris": [7]},
            {"request_uris": [f"https://rp.example/r{i}" for i in range(21)]},
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
            {"initiate_login_uri": "http://rp.example/login"},
            {"initiate_login_uri": "https://rp.example/login#x"},
            {"initiate_login_uri": "/login"},
            {"initiate_login_uri": ["https://rp.example/login"]},
            {"initiate_login_uri": "https://rp.example/" + "x" * 2048},
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
            "initiate_login_uri": "https://rp.example/login",
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
        assert body["initiate_login_uri"] == "https://rp.example/login"

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
        assert "initiate_login_uri" not in body
        assert body["client_name"] == "Registered client (rp.example)"
        assert body["client_id_issued_at"] == registered["client_id_issued_at"]
        event = _events(test_tenant, "oauth2_client_registration_updated")[0]
        assert str(event["actor_user_id"]) == SYSTEM_ACTOR_ID
        changed = event["metadata"]["changed"]
        assert set(changed) == {
            "client_name",
            "grant_types",
            "initiate_login_uri",
            "logo_uri",
            "redirect_uris",
        }
        assert changed["redirect_uris"] == {
            "from": ["https://rp.example/cb"],
            "to": ["https://rp.example/new"],
        }
        assert changed["logo_uri"] == {"from": "https://rp.example/logo.png", "to": None}
        # The registration access token rotates; the client secret survives.
        new_token = body["registration_access_token"]
        assert new_token != registered["registration_access_token"]
        with pytest.raises(UnauthorizedError):
            svc.authenticate_registration(
                test_tenant["id"], registered["client_id"], registered["registration_access_token"]
            )
        client = svc.authenticate_registration(
            test_tenant["id"], registered["client_id"], new_token
        )
        assert oauth2.verify_token_hash(registered["client_secret"], client["client_secret_hash"])

    def test_update_with_a_stale_token_is_refused(self, test_tenant, registered):
        """Two updates racing on one token: the second finds it already rotated."""
        client = self._client(test_tenant, registered)
        metadata = {"client_id": registered["client_id"], "redirect_uris": ["https://rp.example/a"]}
        svc.update_client_configuration(test_tenant["id"], client, metadata, BASE)
        with pytest.raises(UnauthorizedError):
            svc.update_client_configuration(test_tenant["id"], client, metadata, BASE)

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


# =============================================================================
# Device clients: the device grant, and public clients ("none")
# =============================================================================

DEVICE = oauth2.DEVICE_CODE_GRANT_TYPE


class TestDeviceClientMetadata:
    def test_public_device_client(self):
        accepted = svc.validate_client_metadata(
            {
                "grant_types": [DEVICE, "refresh_token"],
                "token_endpoint_auth_method": "none",
                "application_type": "native",
            }
        )
        assert accepted["is_public"] is True
        assert accepted["device_grant_enabled"] is True
        assert accepted["redirect_uris"] == []
        assert accepted["client_name"] == "Registered device client"
        assert accepted["extra"]["response_types"] == []
        assert accepted["extra"]["grant_types"] == [DEVICE, "refresh_token"]
        assert accepted["extra"]["token_endpoint_auth_method"] == "none"

    def test_confidential_device_only_client(self):
        accepted = svc.validate_client_metadata({"grant_types": [DEVICE]})
        assert accepted["is_public"] is False
        assert accepted["device_grant_enabled"] is True
        assert accepted["extra"]["token_endpoint_auth_method"] == "client_secret_basic"

    def test_code_and_device_client_needs_redirect_uris(self):
        assert (
            _error_code({"grant_types": ["authorization_code", DEVICE]}) == "invalid_redirect_uri"
        )
        accepted = svc.validate_client_metadata(
            {"grant_types": ["authorization_code", DEVICE], "redirect_uris": ["https://rp/cb"]}
        )
        assert accepted["device_grant_enabled"] is True
        assert accepted["is_public"] is False

    def test_code_client_has_no_device_grant(self):
        accepted = svc.validate_client_metadata({"redirect_uris": ["https://rp.example/cb"]})
        assert accepted["device_grant_enabled"] is False
        assert accepted["is_public"] is False

    def test_device_only_client_with_redirect_uris(self):
        metadata = {"grant_types": [DEVICE], "redirect_uris": ["https://rp.example/cb"]}
        assert _error_code(metadata) == "invalid_redirect_uri"

    @pytest.mark.parametrize(
        "extra",
        [
            # "none" needs a device-only client.
            {"grant_types": ["authorization_code", DEVICE], "token_endpoint_auth_method": "none"},
            {"grant_types": ["refresh_token"], "token_endpoint_auth_method": "none"},
            {"grant_types": [DEVICE], "response_types": ["code"]},
            {"grant_types": [DEVICE], "post_logout_redirect_uris": ["https://rp.example/bye"]},
            {"grant_types": [DEVICE], "initiate_login_uri": "https://rp.example/login"},
            {"grant_types": [DEVICE], "frontchannel_logout_uri": "https://rp.example/fc"},
        ],
    )
    def test_invalid_device_client_metadata(self, extra):
        assert _error_code(extra) == "invalid_client_metadata"

    def test_device_only_client_may_have_backchannel_logout(self):
        accepted = svc.validate_client_metadata(
            {"grant_types": [DEVICE], "backchannel_logout_uri": "https://rp.example/bc"}
        )
        assert accepted["backchannel_logout_uri"] == "https://rp.example/bc"


PUBLIC_DEVICE = {
    "grant_types": [DEVICE, "refresh_token"],
    "token_endpoint_auth_method": "none",
    "client_name": "TV App",
}


class TestRegisterDeviceClient:
    def test_public_client_gets_no_secret(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(test_tenant, PUBLIC_DEVICE)

        assert "client_secret" not in body
        assert "client_secret_expires_at" not in body
        assert body["registration_access_token"]
        assert body["token_endpoint_auth_method"] == "none"
        assert body["grant_types"] == [DEVICE, "refresh_token"]
        assert body["response_types"] == []
        assert body["redirect_uris"] == []

        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["is_public"] is True
        assert row["device_grant_enabled"] is True
        event = _events(test_tenant, "oauth2_client_registered")[0]
        assert event["metadata"]["is_public"] is True
        assert event["metadata"]["device_grant_enabled"] is True

    def test_confidential_device_client_gets_a_secret(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(test_tenant, {"grant_types": [DEVICE]})

        assert body["client_secret"]
        assert body["client_secret_expires_at"] == 0
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["is_public"] is False
        assert row["device_grant_enabled"] is True

    def test_token_required_policy_applies(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "token_required")
        with pytest.raises(UnauthorizedError):
            _register(test_tenant, PUBLIC_DEVICE)


class TestDeviceClientConfiguration:
    def _registered(self, test_tenant, admin, metadata):
        _set_policy(test_tenant, admin, "open")
        body = _register(test_tenant, metadata)
        client = svc.authenticate_registration(
            test_tenant["id"], body["client_id"], body["registration_access_token"]
        )
        return body, client

    def test_public_client_stays_public(self, test_tenant, test_admin_user):
        body, client = self._registered(test_tenant, test_admin_user, PUBLIC_DEVICE)

        updated = svc.update_client_configuration(
            test_tenant["id"],
            client,
            {**PUBLIC_DEVICE, "client_id": body["client_id"], "client_name": "Kitchen TV"},
            BASE,
        )
        assert updated["client_name"] == "Kitchen TV"
        assert "client_secret" not in updated
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["is_public"] is True
        assert row["device_grant_enabled"] is True

    def test_public_client_cannot_become_confidential(self, test_tenant, test_admin_user):
        body, client = self._registered(test_tenant, test_admin_user, PUBLIC_DEVICE)

        with pytest.raises(ValidationError) as exc:
            svc.update_client_configuration(
                test_tenant["id"],
                client,
                {
                    **PUBLIC_DEVICE,
                    "client_id": body["client_id"],
                    "token_endpoint_auth_method": "client_secret_basic",
                },
                BASE,
            )
        assert exc.value.code == "invalid_client_metadata"

    def test_public_client_presenting_a_secret(self, test_tenant, test_admin_user):
        body, client = self._registered(test_tenant, test_admin_user, PUBLIC_DEVICE)

        with pytest.raises(ValidationError):
            svc.update_client_configuration(
                test_tenant["id"],
                client,
                {**PUBLIC_DEVICE, "client_id": body["client_id"], "client_secret": "guess"},
                BASE,
            )

    def test_confidential_client_cannot_become_public(self, test_tenant, test_admin_user):
        body, client = self._registered(test_tenant, test_admin_user, {"grant_types": [DEVICE]})

        with pytest.raises(ValidationError) as exc:
            svc.update_client_configuration(
                test_tenant["id"],
                client,
                {
                    "client_id": body["client_id"],
                    "grant_types": [DEVICE],
                    "token_endpoint_auth_method": "none",
                },
                BASE,
            )
        assert exc.value.code == "invalid_client_metadata"

    def test_confidential_client_can_drop_the_device_grant(self, test_tenant, test_admin_user):
        body, client = self._registered(
            test_tenant,
            test_admin_user,
            {"grant_types": ["authorization_code", DEVICE], "redirect_uris": ["https://rp/cb"]},
        )
        assert client["device_grant_enabled"] is True

        svc.update_client_configuration(
            test_tenant["id"],
            client,
            {"client_id": body["client_id"], "redirect_uris": ["https://rp/cb"]},
            BASE,
        )
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["device_grant_enabled"] is False


# =============================================================================
# private_key_jwt clients
# =============================================================================

PKJWT = {
    "redirect_uris": ["https://rp.example/cb"],
    "token_endpoint_auth_method": "private_key_jwt",
    "jwks": JWKS,
}


class TestPrivateKeyJwtMetadata:
    def test_inline_keys(self):
        accepted = svc.validate_client_metadata(PKJWT)
        assert accepted["client_auth_method"] == "private_key_jwt"
        assert accepted["jwks"] == JWKS
        assert accepted["token_endpoint_auth_signing_alg"] is None
        assert accepted["extra"]["token_endpoint_auth_method"] == "private_key_jwt"

    def test_jwks_uri_and_signing_alg(self):
        accepted = svc.validate_client_metadata(
            {
                "redirect_uris": ["https://rp.example/cb"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": "https://rp.example/jwks",
                "token_endpoint_auth_signing_alg": "PS256",
            }
        )
        assert accepted["jwks_uri"] == "https://rp.example/jwks"
        assert accepted["token_endpoint_auth_signing_alg"] == "PS256"

    def test_device_only_private_key_jwt(self):
        accepted = svc.validate_client_metadata(
            {"grant_types": [DEVICE], "token_endpoint_auth_method": "private_key_jwt", "jwks": JWKS}
        )
        assert accepted["client_auth_method"] == "private_key_jwt"
        assert accepted["is_public"] is False

    @pytest.mark.parametrize(
        "metadata",
        [
            {**PKJWT, "jwks": None},
            {**PKJWT, "token_endpoint_auth_signing_alg": "HS256"},
            {**PKJWT, "token_endpoint_auth_signing_alg": "none"},
            {
                "redirect_uris": ["https://rp.example/cb"],
                "token_endpoint_auth_signing_alg": "RS256",
            },
            {**PKJWT, "jwks": {"keys": [{**JWKS["keys"][0], "d": "secret"}]}},
            {**PKJWT, "jwks": {"keys": []}},
        ],
    )
    def test_invalid(self, metadata):
        assert _error_code({k: v for k, v in metadata.items() if v is not None}) == (
            "invalid_client_metadata"
        )


class TestRegisterPrivateKeyJwtClient:
    def test_gets_no_secret_and_keys_are_stored(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(test_tenant, {**PKJWT, "token_endpoint_auth_signing_alg": "RS256"})

        assert "client_secret" not in body
        assert "client_secret_expires_at" not in body
        assert body["token_endpoint_auth_method"] == "private_key_jwt"
        assert body["token_endpoint_auth_signing_alg"] == "RS256"
        assert body["jwks"] == JWKS
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["client_auth_method"] == "private_key_jwt"
        assert row["jwks"] == JWKS
        assert "jwks" not in row["registration_metadata"]
        event = _events(test_tenant, "oauth2_client_registered")[0]
        assert event["metadata"]["client_auth_method"] == "private_key_jwt"

    def test_secret_client_with_jwks_uri_keeps_secret(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(
            test_tenant,
            {"redirect_uris": ["https://rp.example/cb"], "jwks_uri": "https://rp.example/jwks"},
        )
        assert body["client_secret"]
        assert body["jwks_uri"] == "https://rp.example/jwks"


class TestPrivateKeyJwtConfiguration:
    def _registered(self, test_tenant, admin, metadata):
        _set_policy(test_tenant, admin, "open")
        body = _register(test_tenant, metadata)
        client = svc.authenticate_registration(
            test_tenant["id"], body["client_id"], body["registration_access_token"]
        )
        return body, client

    def test_keys_are_replaced_and_cache_cleared(self, test_tenant, test_admin_user, monkeypatch):
        body, client = self._registered(test_tenant, test_admin_user, PKJWT)
        cleared = []
        monkeypatch.setattr(
            svc.oauth2_client_auth, "clear_jwks_cache", lambda t, c: cleared.append(c)
        )

        updated = svc.update_client_configuration(
            test_tenant["id"],
            client,
            {
                "client_id": body["client_id"],
                "redirect_uris": ["https://rp.example/cb"],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": "https://rp.example/rotated",
            },
            BASE,
        )
        assert updated["jwks_uri"] == "https://rp.example/rotated"
        assert "jwks" not in updated
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["jwks"] is None
        assert row["client_auth_method"] == "private_key_jwt"
        assert cleared == [str(row["id"])]

    @pytest.mark.parametrize("method", ["client_secret_basic", "none"])
    def test_cannot_leave_private_key_jwt(self, test_tenant, test_admin_user, method):
        body, client = self._registered(test_tenant, test_admin_user, PKJWT)
        with pytest.raises(ValidationError) as exc:
            svc.update_client_configuration(
                test_tenant["id"],
                client,
                {
                    "client_id": body["client_id"],
                    "redirect_uris": ["https://rp.example/cb"],
                    "token_endpoint_auth_method": method,
                },
                BASE,
            )
        assert exc.value.code == "invalid_client_metadata"

    def test_secret_client_cannot_become_private_key_jwt(self, test_tenant, test_admin_user):
        body, client = self._registered(
            test_tenant, test_admin_user, {"redirect_uris": ["https://rp.example/cb"]}
        )
        with pytest.raises(ValidationError):
            svc.update_client_configuration(
                test_tenant["id"], client, {**PKJWT, "client_id": body["client_id"]}, BASE
            )

    def test_basic_and_post_are_interchangeable(self, test_tenant, test_admin_user):
        body, client = self._registered(
            test_tenant, test_admin_user, {"redirect_uris": ["https://rp.example/cb"]}
        )
        updated = svc.update_client_configuration(
            test_tenant["id"],
            client,
            {
                "client_id": body["client_id"],
                "redirect_uris": ["https://rp.example/cb"],
                "token_endpoint_auth_method": "client_secret_post",
            },
            BASE,
        )
        assert updated["token_endpoint_auth_method"] == "client_secret_post"


class TestRequestObjectAndUserinfoMetadata:
    FULL = {
        "redirect_uris": ["https://rp.example/cb"],
        "jwks": JWKS,
        "request_uris": ["https://rp.example/req.jwt#abc"],
        "request_object_signing_alg": "PS256",
        "userinfo_signed_response_alg": "RS256",
    }

    def test_accepted_into_registration_metadata(self):
        accepted = svc.validate_client_metadata(self.FULL)
        assert accepted["extra"]["request_uris"] == ["https://rp.example/req.jwt#abc"]
        assert accepted["extra"]["request_object_signing_alg"] == "PS256"
        assert accepted["extra"]["userinfo_signed_response_alg"] == "RS256"

    def test_absent_values_are_not_stored(self):
        accepted = svc.validate_client_metadata({"redirect_uris": ["https://rp.example/cb"]})
        for name in ("request_uris", "request_object_signing_alg", "userinfo_signed_response_alg"):
            assert name not in accepted["extra"]

    def test_empty_request_uris_are_not_stored(self):
        accepted = svc.validate_client_metadata(
            {"redirect_uris": ["https://rp.example/cb"], "request_uris": []}
        )
        assert "request_uris" not in accepted["extra"]

    def test_userinfo_signing_for_device_client(self):
        accepted = svc.validate_client_metadata(
            {"grant_types": [DEVICE], "userinfo_signed_response_alg": "RS256"}
        )
        assert accepted["extra"]["userinfo_signed_response_alg"] == "RS256"

    @pytest.mark.parametrize(
        "metadata",
        [
            {"grant_types": [DEVICE], "request_uris": ["https://rp.example/req"]},
            {"grant_types": [DEVICE], "jwks": JWKS, "request_object_signing_alg": "RS256"},
        ],
    )
    def test_request_objects_need_the_code_grant(self, metadata):
        assert _error_code(metadata) == "invalid_client_metadata"

    def test_registered_and_echoed(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(test_tenant, self.FULL)
        assert body["request_uris"] == ["https://rp.example/req.jwt#abc"]
        assert body["request_object_signing_alg"] == "PS256"
        assert body["userinfo_signed_response_alg"] == "RS256"
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["registration_metadata"]["request_uris"] == ["https://rp.example/req.jwt#abc"]

    def test_update_replaces_and_clears(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(test_tenant, self.FULL)
        client = svc.authenticate_registration(
            test_tenant["id"], body["client_id"], body["registration_access_token"]
        )
        updated = svc.update_client_configuration(
            test_tenant["id"],
            client,
            {
                "client_id": body["client_id"],
                "redirect_uris": ["https://rp.example/cb"],
                "jwks": JWKS,
                "request_uris": ["https://rp.example/v2.jwt"],
            },
            BASE,
        )
        assert updated["request_uris"] == ["https://rp.example/v2.jwt"]
        assert "request_object_signing_alg" not in updated
        assert "userinfo_signed_response_alg" not in updated


class TestRequirePushedAuthorizationRequestsMetadata:
    def test_defaults_off_and_not_echoed(self, test_tenant, test_admin_user):
        accepted = svc.validate_client_metadata({"redirect_uris": ["https://rp.example/cb"]})
        assert accepted["require_pushed_authorization_requests"] is False
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(test_tenant)
        assert "require_pushed_authorization_requests" not in body

    def test_registered_stored_and_echoed(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(
            test_tenant,
            {
                "redirect_uris": ["https://rp.example/cb"],
                "require_pushed_authorization_requests": True,
            },
        )
        assert body["require_pushed_authorization_requests"] is True
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["require_pushed_authorization_requests"] is True

    def test_update_can_switch_it_off(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(
            test_tenant,
            {
                "redirect_uris": ["https://rp.example/cb"],
                "require_pushed_authorization_requests": True,
            },
        )
        client = svc.authenticate_registration(
            test_tenant["id"], body["client_id"], body["registration_access_token"]
        )
        updated = svc.update_client_configuration(
            test_tenant["id"],
            client,
            {"client_id": body["client_id"], "redirect_uris": ["https://rp.example/cb"]},
            BASE,
        )
        assert "require_pushed_authorization_requests" not in updated
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["require_pushed_authorization_requests"] is False

    def test_update_keeps_par_an_admin_required(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(test_tenant, {"redirect_uris": ["https://rp.example/cb"]})
        database.execute(
            test_tenant["id"],
            "update oauth2_clients set require_pushed_authorization_requests = true "
            "where client_id = :c",
            {"c": body["client_id"]},
        )
        client = svc.authenticate_registration(
            test_tenant["id"], body["client_id"], body["registration_access_token"]
        )
        updated = svc.update_client_configuration(
            test_tenant["id"],
            client,
            {"client_id": body["client_id"], "redirect_uris": ["https://rp.example/cb"]},
            BASE,
        )
        assert updated["require_pushed_authorization_requests"] is True
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["require_pushed_authorization_requests"] is True

    def test_update_cannot_add_the_device_grant(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(test_tenant, {"redirect_uris": ["https://rp.example/cb"]})
        client = svc.authenticate_registration(
            test_tenant["id"], body["client_id"], body["registration_access_token"]
        )
        with pytest.raises(ValidationError) as exc:
            svc.update_client_configuration(
                test_tenant["id"],
                client,
                {
                    "client_id": body["client_id"],
                    "redirect_uris": ["https://rp.example/cb"],
                    "grant_types": [
                        "authorization_code",
                        "urn:ietf:params:oauth:grant-type:device_code",
                    ],
                },
                BASE,
            )
        assert exc.value.code == "invalid_client_metadata"
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["device_grant_enabled"] is False

    def test_update_keeps_a_device_grant_the_client_has(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        grants = ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"]
        body = _register(
            test_tenant, {"redirect_uris": ["https://rp.example/cb"], "grant_types": grants}
        )
        client = svc.authenticate_registration(
            test_tenant["id"], body["client_id"], body["registration_access_token"]
        )
        updated = svc.update_client_configuration(
            test_tenant["id"],
            client,
            {
                "client_id": body["client_id"],
                "redirect_uris": ["https://rp.example/cb"],
                "grant_types": grants,
            },
            BASE,
        )
        assert updated["grant_types"] == grants

    @pytest.mark.parametrize(
        "metadata",
        [
            {
                "redirect_uris": ["https://rp.example/cb"],
                "require_pushed_authorization_requests": "yes",
            },
            {"grant_types": [DEVICE], "require_pushed_authorization_requests": True},
            {
                "grant_types": [DEVICE],
                "token_endpoint_auth_method": "none",
                "require_pushed_authorization_requests": True,
            },
        ],
    )
    def test_invalid(self, metadata):
        assert _error_code(metadata) == "invalid_client_metadata"


class TestPairwiseSubjectMetadata:
    SECTOR = "https://sector.example/redirect_uris.json"

    def _serve(self, monkeypatch, document):
        from services.oidc import subject as subject_service

        monkeypatch.setattr(
            subject_service,
            "build_safe_client",
            lambda **_: httpx.Client(
                transport=httpx.MockTransport(lambda request: httpx.Response(200, json=document))
            ),
        )

    def test_public_by_default(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(test_tenant)
        assert body["subject_type"] == "public"
        assert "sector_identifier_uri" not in body

    def test_pairwise_from_redirect_host(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(
            test_tenant, {"redirect_uris": ["https://rp.example/cb"], "subject_type": "pairwise"}
        )
        assert body["subject_type"] == "pairwise"
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["subject_type"] == "pairwise"
        assert row["sector_identifier_uri"] is None
        (event,) = _events(test_tenant, "oauth2_client_registered")
        assert event["metadata"]["subject_type"] == "pairwise"

    def test_pairwise_with_sector_identifier_uri(self, monkeypatch, test_tenant, test_admin_user):
        """oidcc-registration-sector-uri: the document lists the redirect URI."""
        _set_policy(test_tenant, test_admin_user, "open")
        uris = ["https://a.example/cb", "https://b.example/cb"]
        self._serve(monkeypatch, uris)
        body = _register(
            test_tenant,
            {
                "redirect_uris": uris,
                "subject_type": "pairwise",
                "sector_identifier_uri": self.SECTOR,
            },
        )
        assert body["subject_type"] == "pairwise"
        assert body["sector_identifier_uri"] == self.SECTOR
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert row["sector_identifier_uri"] == self.SECTOR

    def test_sector_document_without_redirect_uri_rejected(self, monkeypatch):
        """oidcc-registration-sector-bad: 400 invalid_client_metadata."""
        self._serve(monkeypatch, ["https://example.com/op"])
        metadata = {
            "redirect_uris": ["https://rp.example/cb"],
            "subject_type": "pairwise",
            "sector_identifier_uri": self.SECTOR,
        }
        assert _error_code(metadata) == "invalid_client_metadata"

    def test_pairwise_device_client_needs_sector(self):
        """Otherwise a registrant names another app's redirect host and
        collects its pairwise subjects through device polling."""
        metadata = {
            "redirect_uris": ["https://victim.example/cb"],
            "grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"],
            "subject_type": "pairwise",
        }
        with pytest.raises(ValidationError) as exc:
            svc.validate_client_metadata(metadata)
        assert exc.value.code == "invalid_client_metadata"
        assert "sector_identifier_uri" in exc.value.message

    def test_pairwise_device_client_with_sector(self, monkeypatch, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        uris = ["https://rp.example/cb"]
        self._serve(monkeypatch, uris)
        body = _register(
            test_tenant,
            {
                "redirect_uris": uris,
                "grant_types": [
                    "authorization_code",
                    "urn:ietf:params:oauth:grant-type:device_code",
                ],
                "subject_type": "pairwise",
                "sector_identifier_uri": self.SECTOR,
            },
        )
        assert body["subject_type"] == "pairwise"

    def test_pairwise_across_hosts_needs_sector(self):
        metadata = {
            "redirect_uris": ["https://a.example/cb", "https://b.example/cb"],
            "subject_type": "pairwise",
        }
        assert _error_code(metadata) == "invalid_client_metadata"

    def test_update_can_switch_back_to_public(self, test_tenant, test_admin_user):
        _set_policy(test_tenant, test_admin_user, "open")
        body = _register(
            test_tenant, {"redirect_uris": ["https://rp.example/cb"], "subject_type": "pairwise"}
        )
        client = svc.authenticate_registration(
            test_tenant["id"], body["client_id"], body["registration_access_token"]
        )
        updated = svc.update_client_configuration(
            test_tenant["id"],
            client,
            {"client_id": body["client_id"], "redirect_uris": ["https://rp.example/cb"]},
            BASE,
        )
        assert updated["subject_type"] == "public"
        (event,) = _events(test_tenant, "oauth2_client_registration_updated")
        assert event["metadata"]["changed"]["subject_type"] == {"from": "pairwise", "to": "public"}


class TestResetRegistrationAccessToken:
    def test_reset_rotates_and_logs(self, test_tenant, test_admin_user, registered):
        token = svc.reset_registration_access_token(
            _user(test_tenant, test_admin_user), registered["client_id"]
        )
        assert token.startswith("weft-id_rat")
        with pytest.raises(UnauthorizedError):
            svc.authenticate_registration(
                test_tenant["id"], registered["client_id"], registered["registration_access_token"]
            )
        svc.authenticate_registration(test_tenant["id"], registered["client_id"], token)
        event = _events(test_tenant, "oauth2_client_registration_token_reset")[0]
        assert str(event["actor_user_id"]) == str(test_admin_user["id"])
        assert event["metadata"]["client_id"] == registered["client_id"]

    def test_reset_requires_admin(self, test_tenant, test_user, registered):
        with pytest.raises(ForbiddenError):
            svc.reset_registration_access_token(
                _user(test_tenant, test_user, role="user"), registered["client_id"]
            )

    def test_reset_of_admin_created_client_is_not_found(
        self, test_tenant, test_admin_user, normal_oauth2_client
    ):
        with pytest.raises(NotFoundError):
            svc.reset_registration_access_token(
                _user(test_tenant, test_admin_user), normal_oauth2_client["client_id"]
            )


class TestReadsTrackActivity:
    @pytest.mark.parametrize(
        "call",
        [
            lambda user: svc.get_registration_settings(user, BASE),
            lambda user: svc.list_initial_access_tokens(user),
        ],
        ids=["get_registration_settings", "list_initial_access_tokens"],
    )
    def test_tracks_activity(self, monkeypatch, test_tenant, test_admin_user, call):
        calls = []
        monkeypatch.setattr(svc, "track_activity", lambda *args: calls.append(args))
        user = _user(test_tenant, test_admin_user)

        call(user)

        assert calls == [(user["tenant_id"], user["id"])]
