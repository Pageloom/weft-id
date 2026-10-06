"""Sign in with Apple adapter, preset, client secret and connection settings.

The adapter runs against Apple's recorded discovery document and fixture
keys (``tests/fixtures/apple.py``); the token endpoint is patched, so no
call leaves the test.
"""

import json
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from schemas.oidc_upstream import PROVIDER_TYPES, OIDCConnectionCreate, OIDCConnectionUpdate
from services.exceptions import ValidationError
from services.oidc_upstream import adapters, apple, presets
from services.oidc_upstream.adapters import ProviderCheckError, ProviderLoginError
from services.oidc_upstream.connections import _encrypt_secret, decrypt_client_secret
from services.oidc_upstream.errors import DiscoveryError
from services.oidc_upstream.token_exchange import TokenExchangeError
from services.types import RequestingUser

from tests.fixtures import apple as fx

REDIRECT_URI = "https://test.example.com/auth/oidc/c-apple/callback"


def _connection(**overrides) -> dict:
    doc = fx.discovery()
    row = {
        "id": "c-apple",
        "name": "Apple",
        "provider_type": "apple",
        "issuer": fx.ISSUER,
        "authorization_endpoint": doc["authorization_endpoint"],
        "token_endpoint": doc["token_endpoint"],
        "jwks_uri": doc["jwks_uri"],
        "userinfo_endpoint": None,
        "client_id": fx.CLIENT_ID,
        "scopes": "openid name email",
        "correlation_claim": "sub",
        "apple_team_id": fx.TEAM_ID,
        "apple_key_id": fx.KEY_ID,
        "apple_private_key_enc": _encrypt_secret(fx.auth_key_pem()),
    }
    row.update(overrides)
    return row


def _complete(connection=None, *, token=None, callback_fields=None, connection_id=None):
    from services.oidc_upstream import jwks as jwks_service

    connection = connection or _connection()
    if connection_id:
        connection = {**connection, "id": connection_id}
    jwks_service.clear_jwks_cache("tenant-1", str(connection["id"]))
    with (
        patch(
            "services.oidc_upstream.exchange_code",
            return_value={"access_token": "at", "id_token": token or fx.id_token()},
        ) as exchange,
        patch("services.oidc_upstream.jwks._fetch_jwks", return_value=fx.jwks()),
    ):
        identity = apple.AppleAdapter().complete(
            "tenant-1",
            connection,
            code="code-1",
            redirect_uri=REDIRECT_URI,
            code_verifier="verifier-1",
            nonce="n-1",
            callback_fields=callback_fields,
        )
    return identity, exchange


def _public_key():
    return serialization.load_pem_private_key(fx.auth_key_pem().encode(), None).public_key()


def _super_admin(user, tenant_id):
    return RequestingUser(id=str(user["id"]), tenant_id=tenant_id, role="super_admin")


class TestPreset:
    def test_apple_preset(self):
        preset = presets.get_preset("apple")
        assert preset.display_name == "Apple"
        assert preset.issuer == "https://appleid.apple.com"
        assert preset.discovery_url == "https://appleid.apple.com/.well-known/openid-configuration"
        assert preset.scopes == "openid name email"
        assert preset.correlation_claim == "sub"
        assert preset.token_auth_method == presets.TOKEN_AUTH_POST
        assert preset.email_linking_trusted is True
        assert preset.uses_discovery is True
        assert presets.login_button_style("apple") == ("Apple", "apple")

    def test_creatable_and_registered(self):
        assert "apple" in PROVIDER_TYPES
        assert isinstance(adapters.get_adapter("apple"), apple.AppleAdapter)

    def test_recorded_discovery_matches_preset(self):
        doc = fx.discovery()
        assert doc["issuer"] == presets.get_preset("apple").issuer
        assert "form_post" in doc["response_modes_supported"]
        assert doc["token_endpoint_auth_methods_supported"] == ["client_secret_post"]
        assert "userinfo_endpoint" not in doc


class TestClientSecret:
    def test_minted_secret_is_signed_with_the_key(self):
        secret = apple.mint_client_secret(
            team_id=fx.TEAM_ID,
            key_id=fx.KEY_ID,
            client_id=fx.CLIENT_ID,
            private_key_pem=fx.auth_key_pem(),
            now=1_900_000_000,
        )
        assert jwt.get_unverified_header(secret) == {"alg": "ES256", "kid": fx.KEY_ID, "typ": "JWT"}
        claims = jwt.decode(
            secret,
            _public_key(),
            algorithms=["ES256"],
            audience="https://appleid.apple.com",
            options={"verify_exp": False, "verify_iat": False},
        )
        assert claims == {
            "iss": fx.TEAM_ID,
            "iat": 1_900_000_000,
            "exp": 1_900_000_300,
            "aud": "https://appleid.apple.com",
            "sub": fx.CLIENT_ID,
        }

    def test_credentials_mint_a_fresh_secret(self):
        credentials = adapters.resolve_client_credentials(_connection())
        assert credentials.client_id == fx.CLIENT_ID
        assert credentials.token_auth_method == "client_secret_post"
        claims = jwt.decode(
            credentials.client_secret,
            _public_key(),
            algorithms=["ES256"],
            audience="https://appleid.apple.com",
        )
        assert claims["sub"] == fx.CLIENT_ID
        assert claims["iss"] == fx.TEAM_ID

    @pytest.mark.parametrize(
        "missing", ["client_id", "apple_team_id", "apple_key_id", "apple_private_key_enc"]
    )
    def test_missing_setting_means_no_credentials(self, missing):
        assert adapters.resolve_client_credentials(_connection(**{missing: None})) is None

    def test_unusable_key_means_no_credentials(self):
        row = _connection(apple_private_key_enc=_encrypt_secret("not a key"))
        assert adapters.resolve_client_credentials(row) is None

    def test_client_secret_column_is_ignored(self):
        row = _connection(client_secret_enc=_encrypt_secret("stored-secret"))
        credentials = adapters.resolve_client_credentials(row)
        assert credentials.client_secret != "stored-secret"

    def test_load_key_accepts_p8(self):
        key = apple.load_apple_private_key(fx.auth_key_pem())
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_load_key_rejects_garbage(self):
        with pytest.raises(apple.ApplePrivateKeyError):
            apple.load_apple_private_key(
                "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"
            )

    def test_load_key_rejects_rsa(self):
        pem = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
        with pytest.raises(apple.ApplePrivateKeyError):
            apple.load_apple_private_key(pem)

    def test_load_key_rejects_other_curve(self):
        pem = (
            ec.generate_private_key(ec.SECP384R1())
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
        with pytest.raises(apple.ApplePrivateKeyError):
            apple.load_apple_private_key(pem)


class TestAuthorizeUrl:
    def _params(self, connection):
        url = apple.AppleAdapter().authorize_url(
            connection,
            redirect_uri=REDIRECT_URI,
            state="state-1",
            nonce="n-1",
            code_challenge="challenge",
        )
        assert url.startswith("https://appleid.apple.com/auth/authorize?")
        return parse_qs(urlparse(url).query)

    def test_form_post_with_nonce_and_no_pkce(self):
        params = self._params(_connection())
        assert params == {
            "response_type": ["code"],
            "response_mode": ["form_post"],
            "client_id": [fx.CLIENT_ID],
            "redirect_uri": [REDIRECT_URI],
            "scope": ["openid name email"],
            "state": ["state-1"],
            "nonce": ["n-1"],
        }

    def test_scope_fallback(self):
        assert self._params(_connection(scopes=None))["scope"] == ["openid name email"]

    @pytest.mark.parametrize("missing", ["authorization_endpoint", "client_id"])
    def test_unconfigured(self, missing):
        with pytest.raises(ProviderLoginError) as exc:
            self._params(_connection(**{missing: None}))
        assert exc.value.public_error == "configuration_error"


class TestComplete:
    def test_identity_from_id_token(self):
        identity, _ = _complete()
        assert identity.subject == fx.SUBJECT
        assert identity.upstream_sub == fx.SUBJECT
        assert identity.claims["email"] == fx.RELAY_EMAIL
        # Apple's string booleans become real ones.
        assert identity.claims["email_verified"] is True
        assert identity.claims["is_private_email"] is True
        assert identity.id_token

    def test_token_request(self):
        _, exchange = _complete()
        kwargs = exchange.call_args.kwargs
        assert kwargs["token_endpoint"] == "https://appleid.apple.com/auth/token"
        assert kwargs["client_id"] == fx.CLIENT_ID
        assert kwargs["auth_method"] == "client_secret_post"
        # No PKCE for Apple.
        assert kwargs["code_verifier"] is None
        # The client secret is a JWT signed with the admin's key.
        claims = jwt.decode(
            kwargs["client_secret"],
            _public_key(),
            algorithms=["ES256"],
            audience="https://appleid.apple.com",
        )
        assert claims["sub"] == fx.CLIENT_ID

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("true", True),
            ("TRUE", True),
            (True, True),
            ("false", False),
            (False, False),
            ("yes", False),
            (None, False),
        ],
    )
    def test_email_verified_normalised(self, value, expected):
        identity, _ = _complete(token=fx.id_token(email_verified=value))
        assert identity.claims["email_verified"] is expected

    def test_is_private_email_normalised(self):
        identity, _ = _complete(token=fx.id_token(is_private_email="false"))
        assert identity.claims["is_private_email"] is False

    def test_no_is_private_email_claim(self):
        identity, _ = _complete(token=fx.id_token(is_private_email=None))
        assert "is_private_email" not in identity.claims

    def test_name_from_first_authorization(self):
        identity, _ = _complete(callback_fields={"user": fx.USER_FIELD})
        assert identity.claims["given_name"] == "Ada"
        assert identity.claims["family_name"] == "Lovelace"
        # The unsigned user field never supplies the email.
        assert identity.claims["email"] == fx.RELAY_EMAIL

    def test_no_user_field_no_names(self):
        identity, _ = _complete(callback_fields={"code": "code-1"})
        assert "given_name" not in identity.claims
        assert "family_name" not in identity.claims

    @pytest.mark.parametrize(
        "raw",
        [
            "not json",
            "[]",
            json.dumps({"name": "Ada"}),
            json.dumps({"name": {"firstName": 7, "lastName": ["x"]}}),
            json.dumps({"name": {"firstName": "   "}}),
        ],
    )
    def test_malformed_user_field(self, raw):
        identity, _ = _complete(callback_fields={"user": raw})
        assert "given_name" not in identity.claims
        assert "family_name" not in identity.claims

    def test_name_is_trimmed_and_capped(self):
        raw = json.dumps({"name": {"firstName": "  Ada  ", "lastName": "L" * 400}})
        identity, _ = _complete(callback_fields={"user": raw})
        assert identity.claims["given_name"] == "Ada"
        assert identity.claims["family_name"] == "L" * 255

    def test_signed_claims_win_over_user_field(self):
        identity, _ = _complete(
            token=fx.id_token(given_name="Signed"), callback_fields={"user": fx.USER_FIELD}
        )
        assert identity.claims["given_name"] == "Signed"
        assert identity.claims["family_name"] == "Lovelace"

    def test_wrong_nonce_fails(self):
        with pytest.raises(ProviderLoginError) as exc:
            _complete(token=fx.id_token(nonce="other"))
        assert exc.value.reason == "id_token"

    def test_wrong_audience_fails(self):
        with pytest.raises(ProviderLoginError) as exc:
            _complete(token=fx.id_token(aud="com.other.app"))
        assert exc.value.reason == "id_token"

    def test_without_key_is_a_configuration_error(self):
        with pytest.raises(ProviderLoginError) as exc:
            _complete(_connection(apple_private_key_enc=None))
        assert exc.value.public_error == "configuration_error"


class TestCheck:
    def _check(self, exchange_side_effect=None, connection=None):
        row = connection or _connection()
        with (
            patch("services.oidc_upstream.discovery.run_discovery", return_value=row),
            patch("services.oidc_upstream.jwks.refresh_jwks"),
            patch(
                "services.oidc_upstream.apple.exchange_code", side_effect=exchange_side_effect
            ) as exchange,
        ):
            result = apple.AppleAdapter().check("tenant-1", row, redirect_uri=REDIRECT_URI)
        return result, exchange

    def test_invalid_grant_means_accepted(self):
        result, exchange = self._check(TokenExchangeError("x", error="invalid_grant"))
        assert result["id"] == "c-apple"
        kwargs = exchange.call_args.kwargs
        assert kwargs["code_verifier"] is None
        assert kwargs["auth_method"] == "client_secret_post"
        assert kwargs["redirect_uri"] == REDIRECT_URI

    def test_invalid_client_is_reported(self):
        with pytest.raises(ProviderCheckError, match="rejected the client secret"):
            self._check(TokenExchangeError("x", error="invalid_client"))

    def test_other_error_is_reported(self):
        with pytest.raises(ProviderCheckError, match="Apple check failed"):
            self._check(TokenExchangeError("HTTP 500"))

    def test_accepting_a_made_up_code_is_reported(self):
        with pytest.raises(ProviderCheckError, match="accepted an invalid code"):
            self._check(None)

    def test_missing_key_is_reported(self):
        with pytest.raises(ProviderCheckError, match="private key"):
            self._check(connection=_connection(apple_key_id=None))

    def test_no_token_endpoint(self):
        with pytest.raises(ProviderCheckError, match="no token endpoint"):
            self._check(connection=_connection(token_endpoint=None))

    def test_discovery_failure_is_reported(self):
        with (
            patch(
                "services.oidc_upstream.discovery.run_discovery",
                side_effect=DiscoveryError("boom"),
            ),
            pytest.raises(ProviderCheckError, match="Discovery failed"),
        ):
            apple.AppleAdapter().check("tenant-1", _connection(), redirect_uri=REDIRECT_URI)


class TestConnectionSettings:
    def _create(self, test_tenant, test_super_admin_user, **fields):
        from services.oidc_upstream.connections import create_connection

        data = {
            "name": "Apple",
            "provider_type": "apple",
            "client_id": fx.CLIENT_ID,
            "apple_team_id": fx.TEAM_ID,
            "apple_key_id": fx.KEY_ID,
            "apple_private_key": fx.auth_key_pem(),
        }
        data.update(fields)
        return create_connection(
            _super_admin(test_super_admin_user, str(test_tenant["id"])),
            OIDCConnectionCreate(**data),
            "https://test.example.com",
        )

    def _row(self, test_tenant, connection_id):
        import database

        return database.oidc_upstream.get_connection(test_tenant["id"], connection_id)

    def test_create_stores_settings_and_encrypted_key(self, test_tenant, test_super_admin_user):
        conn = self._create(test_tenant, test_super_admin_user)
        assert conn.issuer == fx.ISSUER
        assert conn.discovery_url == f"{fx.ISSUER}/.well-known/openid-configuration"
        assert conn.scopes == "openid name email"
        assert conn.apple_team_id == fx.TEAM_ID
        assert conn.apple_key_id == fx.KEY_ID
        assert conn.apple_private_key_set is True
        assert conn.client_secret_set is False
        assert conn.provider_label == "Apple"
        row = self._row(test_tenant, conn.id)
        assert fx.auth_key_pem().strip() not in row["apple_private_key_enc"]
        assert decrypt_client_secret(row["apple_private_key_enc"]) == fx.auth_key_pem().strip()

    def test_config_hides_the_key(self, test_tenant, test_super_admin_user):
        conn = self._create(test_tenant, test_super_admin_user)
        dumped = conn.model_dump()
        assert "apple_private_key" not in dumped
        assert "apple_private_key_enc" not in dumped

    def test_create_without_key_settings(self, test_tenant, test_super_admin_user):
        conn = self._create(
            test_tenant,
            test_super_admin_user,
            apple_team_id=None,
            apple_key_id=None,
            apple_private_key=None,
        )
        assert conn.apple_team_id is None
        assert conn.apple_private_key_set is False

    def test_invalid_key_rejected(self, test_tenant, test_super_admin_user):
        with pytest.raises(ValidationError) as exc:
            self._create(test_tenant, test_super_admin_user, apple_private_key="not a key")
        assert exc.value.code == "oidc_apple_private_key_invalid"

    def test_client_secret_rejected(self, test_tenant, test_super_admin_user):
        with pytest.raises(ValidationError) as exc:
            self._create(test_tenant, test_super_admin_user, client_secret="a-secret")
        assert exc.value.code == "oidc_setting_not_supported"

    @pytest.mark.parametrize("field", ["apple_team_id", "apple_key_id", "apple_private_key"])
    def test_apple_settings_rejected_on_other_providers(
        self, test_tenant, test_super_admin_user, field
    ):
        fields = {"apple_team_id": None, "apple_key_id": None, "apple_private_key": None}
        fields[field] = fx.auth_key_pem() if field == "apple_private_key" else fx.TEAM_ID
        with pytest.raises(ValidationError) as exc:
            self._create(test_tenant, test_super_admin_user, provider_type="google", **fields)
        assert exc.value.code == "oidc_setting_not_supported"

    @pytest.mark.parametrize("value", ["short", "lowercase1", "ABCDE-1234", "ABCDE123456"])
    def test_id_pattern(self, value):
        from pydantic import ValidationError as PydanticValidationError

        with pytest.raises(PydanticValidationError):
            OIDCConnectionUpdate(apple_team_id=value)
        with pytest.raises(PydanticValidationError):
            OIDCConnectionUpdate(apple_key_id=value)

    def test_update_replaces_settings_and_logs(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import update_connection

        conn = self._create(test_tenant, test_super_admin_user)
        new_key = (
            ec.generate_private_key(ec.SECP256R1())
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
        updated = update_connection(
            _super_admin(test_super_admin_user, str(test_tenant["id"])),
            conn.id,
            OIDCConnectionUpdate(apple_key_id="NEWKEY0001", apple_private_key=new_key),
            "https://test.example.com",
        )
        assert updated.apple_key_id == "NEWKEY0001"
        assert updated.apple_team_id == fx.TEAM_ID
        row = self._row(test_tenant, conn.id)
        assert decrypt_client_secret(row["apple_private_key_enc"]) == new_key.strip()

        import database

        event = next(
            e
            for e in database.event_log.list_events(test_tenant["id"], limit=50)
            if e["event_type"] == "oidc_idp_connection_updated"
        )
        assert sorted(event["metadata"]["updated_fields"]) == [
            "apple_key_id",
            "apple_private_key_enc",
        ]

    def test_update_without_key_keeps_it(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import update_connection

        conn = self._create(test_tenant, test_super_admin_user)
        before = self._row(test_tenant, conn.id)["apple_private_key_enc"]
        update_connection(
            _super_admin(test_super_admin_user, str(test_tenant["id"])),
            conn.id,
            OIDCConnectionUpdate(apple_team_id="TEAM000002"),
            "https://test.example.com",
        )
        row = self._row(test_tenant, conn.id)
        assert row["apple_team_id"] == "TEAM000002"
        assert row["apple_private_key_enc"] == before

    def test_update_rejects_invalid_key(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import update_connection

        conn = self._create(test_tenant, test_super_admin_user)
        with pytest.raises(ValidationError) as exc:
            update_connection(
                _super_admin(test_super_admin_user, str(test_tenant["id"])),
                conn.id,
                OIDCConnectionUpdate(apple_private_key="junk"),
                "https://test.example.com",
            )
        assert exc.value.code == "oidc_apple_private_key_invalid"

    def test_update_rejects_client_secret(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import update_connection

        conn = self._create(test_tenant, test_super_admin_user)
        with pytest.raises(ValidationError) as exc:
            update_connection(
                _super_admin(test_super_admin_user, str(test_tenant["id"])),
                conn.id,
                OIDCConnectionUpdate(client_secret="a-secret"),
                "https://test.example.com",
            )
        assert exc.value.code == "oidc_setting_not_supported"

    def test_email_linking_allowed(self, test_tenant, test_super_admin_user):
        conn = self._create(test_tenant, test_super_admin_user, allow_email_linking=True)
        assert conn.allow_email_linking is True
        assert conn.email_linking_trusted is True


class TestSignIn:
    def test_jit_with_relay_email_is_verified_and_named(self, test_tenant, test_super_admin_user):
        import database
        from services.oidc_upstream.email_confirmation import pending_email_confirmation
        from services.oidc_upstream.provisioning import authenticate_via_oidc

        row = fx.make_apple_row(test_tenant, test_super_admin_user["id"], jit_provisioning=True)
        identity, _ = _complete(
            row, callback_fields={"user": fx.USER_FIELD}, connection_id=str(row["id"])
        )
        user = authenticate_via_oidc(
            tenant_id=str(test_tenant["id"]),
            connection=row,
            sub=identity.subject,
            claims=identity.claims,
        )

        assert user["first_name"] == "Ada"
        assert user["last_name"] == "Lovelace"
        primary = database.user_emails.get_primary_email_for_resend(
            test_tenant["id"], str(user["id"])
        )
        assert primary["email"] == fx.RELAY_EMAIL
        assert primary["verified_at"] is not None
        # Apple is trusted: no emailed code before sign-in completes.
        assert pending_email_confirmation(str(test_tenant["id"]), row, str(user["id"])) is None

    def test_email_link_on_verified_string_flag(
        self, test_tenant, test_super_admin_user, test_user
    ):
        from services.oidc_upstream.provisioning import authenticate_via_oidc

        row = fx.make_apple_row(test_tenant, test_super_admin_user["id"], allow_email_linking=True)
        identity, _ = _complete(
            row,
            token=fx.id_token(email=test_user["email"], is_private_email="false"),
            connection_id=str(row["id"]),
        )
        user = authenticate_via_oidc(
            tenant_id=str(test_tenant["id"]),
            connection=row,
            sub=identity.subject,
            claims=identity.claims,
        )
        assert str(user["id"]) == str(test_user["id"])

    def test_no_email_link_when_unverified(self, test_tenant, test_super_admin_user, test_user):
        from services.exceptions import NotFoundError
        from services.oidc_upstream.provisioning import authenticate_via_oidc

        row = fx.make_apple_row(test_tenant, test_super_admin_user["id"], allow_email_linking=True)
        identity, _ = _complete(
            row,
            token=fx.id_token(email=test_user["email"], email_verified="false"),
            connection_id=str(row["id"]),
        )
        with pytest.raises(NotFoundError):
            authenticate_via_oidc(
                tenant_id=str(test_tenant["id"]),
                connection=row,
                sub=identity.subject,
                claims=identity.claims,
            )
