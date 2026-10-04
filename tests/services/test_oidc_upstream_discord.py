"""Tests for the Discord sign-in adapter and Discord connections.

The adapter runs against the Discord API fixtures in
``tests/fixtures/discord`` served through a mock transport, so the real
request code runs without a network.
"""

import base64
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from schemas.oidc_upstream import PROVIDER_TYPES, OIDCConnectionCreate
from services.exceptions import ValidationError
from services.oidc_upstream import adapters, discord, presets
from services.oidc_upstream.adapters import ProviderCheckError, ProviderLoginError
from services.oidc_upstream.connections import _encrypt_secret
from services.types import RequestingUser

from tests.fixtures.discord import TOKEN_PATH, USERS_ME_PATH, discord_api, load

BASE_URL = "https://test.example.com"
REDIRECT_URI = "https://test.example.com/auth/oidc/c-1/callback"


def _connection(**overrides) -> dict:
    row = {
        "id": "c-1",
        "name": "Discord",
        "provider_type": "discord",
        "client_id": "1234567890",
        "client_secret_enc": _encrypt_secret("discord-secret"),
        "scopes": "identify email",
    }
    row.update(overrides)
    return row


def _complete(connection: dict):
    return discord.DiscordAdapter().complete(
        "tenant-1",
        connection,
        code="code-1",
        redirect_uri=REDIRECT_URI,
        code_verifier="verifier-1",
        nonce="ignored",
    )


def _user(**overrides) -> dict:
    user = load("users_me")
    user.update(overrides)
    return user


def _super_admin(user, tenant_id):
    return RequestingUser(id=str(user["id"]), tenant_id=tenant_id, role="super_admin")


class TestPreset:
    def test_discord_preset(self):
        preset = presets.get_preset("discord")
        assert preset.display_name == "Discord"
        assert preset.issuer == "https://discord.com"
        assert preset.discovery_url is None
        assert preset.scopes == "identify email"
        assert preset.token_auth_method == presets.TOKEN_AUTH_BASIC
        assert preset.email_linking_trusted is True
        assert preset.uses_discovery is False
        assert presets.login_button_style("discord") == ("Discord", "discord")

    def test_creatable_and_registered(self):
        assert "discord" in PROVIDER_TYPES
        assert isinstance(adapters.get_adapter("discord"), discord.DiscordAdapter)


class TestAuthorize:
    def test_authorize_url(self):
        url = discord.DiscordAdapter().authorize_url(
            _connection(),
            redirect_uri=REDIRECT_URI,
            state="state-1",
            nonce="nonce-1",
            code_challenge="challenge-1",
        )
        parsed = urlparse(url)
        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == discord.AUTHORIZE_URL
        assert parse_qs(parsed.query) == {
            "client_id": ["1234567890"],
            "redirect_uri": [REDIRECT_URI],
            "response_type": ["code"],
            "scope": ["identify email"],
            "state": ["state-1"],
            "code_challenge": ["challenge-1"],
            "code_challenge_method": ["S256"],
        }

    def test_scope_falls_back_to_preset(self):
        url = discord.DiscordAdapter().authorize_url(
            _connection(scopes=None),
            redirect_uri=REDIRECT_URI,
            state="s",
            nonce="n",
            code_challenge="c",
        )
        assert parse_qs(urlparse(url).query)["scope"] == ["identify email"]

    def test_unconfigured(self):
        with pytest.raises(ProviderLoginError) as exc:
            discord.DiscordAdapter().authorize_url(
                _connection(client_id=None),
                redirect_uri=REDIRECT_URI,
                state="s",
                nonce="n",
                code_challenge="c",
            )
        assert exc.value.public_error == "configuration_error"

    def test_prepare_does_not_discover(self):
        row = _connection()
        assert discord.DiscordAdapter().prepare("tenant-1", row) is row


class TestComplete:
    def test_identity(self):
        with discord_api() as requests:
            identity = _complete(_connection())

        assert identity.subject == "80351110224678912"
        assert identity.upstream_sub is None
        assert identity.id_token is None
        assert identity.claims == {
            "sub": "80351110224678912",
            "preferred_username": "nelly",
            "name": "Nelly Banks",
            "given_name": "Nelly",
            "family_name": "Banks",
            "email": "nelly@example.com",
            "email_verified": True,
            "picture": (
                "https://cdn.discordapp.com/avatars/80351110224678912/"
                "8342729096ea3675442027381ff50dfe.png"
            ),
        }
        assert [r.url.path for r in requests] == [TOKEN_PATH, USERS_ME_PATH]

    def test_token_exchange_on_the_wire(self):
        with discord_api() as requests:
            _complete(_connection())
        token_request = requests[0]
        assert str(token_request.url) == discord.TOKEN_URL
        expected = base64.b64encode(b"1234567890:discord-secret").decode()
        assert token_request.headers["authorization"] == f"Basic {expected}"
        assert parse_qs(token_request.content.decode()) == {
            "grant_type": ["authorization_code"],
            "code": ["code-1"],
            "redirect_uri": [REDIRECT_URI],
            "code_verifier": ["verifier-1"],
        }

    def test_api_request_carries_token(self):
        with discord_api() as requests:
            _complete(_connection())
        assert str(requests[1].url) == "https://discord.com/api/v10/users/@me"
        assert requests[1].headers["authorization"] == "Bearer 6qrZcUqja7812RVdnEKjpzOL4CvHBFG"

    @pytest.mark.parametrize(
        "overrides",
        [
            {"verified": False},
            {"verified": None},
            {"verified": "true"},
            {"email": None},
            {"email": ""},
        ],
    )
    def test_unverified_or_missing_email_is_dropped(self, overrides):
        with discord_api({USERS_ME_PATH: _user(**overrides)}):
            identity = _complete(_connection())
        assert "email" not in identity.claims
        assert identity.claims["email_verified"] is False

    def test_no_display_name_uses_username(self):
        with discord_api({USERS_ME_PATH: _user(global_name=None)}):
            claims = _complete(_connection()).claims
        assert claims["given_name"] == "nelly"
        assert "family_name" not in claims
        assert "name" not in claims

    def test_animated_avatar(self):
        with discord_api({USERS_ME_PATH: _user(avatar="a_1269e74af4df7417b13759eae50c83dc")}):
            claims = _complete(_connection()).claims
        assert claims["picture"].endswith("/a_1269e74af4df7417b13759eae50c83dc.png")

    @pytest.mark.parametrize("avatar", [None, "", "../../evil", "abc?x=1", 123])
    def test_no_or_unsafe_avatar(self, avatar):
        with discord_api({USERS_ME_PATH: _user(avatar=avatar)}):
            claims = _complete(_connection()).claims
        assert "picture" not in claims

    @pytest.mark.parametrize(
        "overrides",
        [
            {"id": None},
            {"id": 80351110224678912},
            {"id": "not-a-snowflake"},
            {"id": "٨٠٣"},
            {"username": None},
        ],
    )
    def test_missing_id_or_username(self, overrides):
        with discord_api({USERS_ME_PATH: _user(**overrides)}):
            with pytest.raises(ProviderLoginError) as exc:
                _complete(_connection())
        assert exc.value.reason == "missing_sub"

    def test_user_not_an_object(self):
        with discord_api({USERS_ME_PATH: ["nope"]}):
            with pytest.raises(ProviderLoginError) as exc:
                _complete(_connection())
        assert exc.value.reason == "discord_api"

    @pytest.mark.parametrize(
        "response", [httpx.Response(401), httpx.Response(200, content=b"not json")]
    )
    def test_api_failure(self, response):
        with discord_api({USERS_ME_PATH: response}):
            with pytest.raises(ProviderLoginError) as exc:
                _complete(_connection())
        assert exc.value.reason == "discord_api"
        assert exc.value.public_error == "auth_failed"

    def test_token_exchange_error(self):
        response = httpx.Response(400, json={"error": "invalid_grant"})
        with discord_api({TOKEN_PATH: response}):
            with pytest.raises(ProviderLoginError) as exc:
                _complete(_connection())
        assert exc.value.reason == "token_exchange"

    def test_no_access_token(self):
        with discord_api({TOKEN_PATH: {"token_type": "Bearer"}}):
            with pytest.raises(ProviderLoginError) as exc:
                _complete(_connection())
        assert exc.value.reason == "token_exchange"

    def test_missing_credentials(self):
        with pytest.raises(ProviderLoginError) as exc:
            _complete(_connection(client_secret_enc=None))
        assert exc.value.reason == "configuration_error"
        assert exc.value.public_error == "configuration_error"


class TestCheck:
    def _check(self, response):
        with discord_api({TOKEN_PATH: response}) as requests:
            result = discord.DiscordAdapter().check(
                "tenant-1", _connection(), redirect_uri=REDIRECT_URI
            )
        return result, requests

    def test_credentials_accepted(self):
        result, requests = self._check(httpx.Response(400, json={"error": "invalid_grant"}))
        assert result["id"] == "c-1"
        assert parse_qs(requests[0].content.decode())["redirect_uri"] == [REDIRECT_URI]

    def test_credentials_rejected(self):
        with pytest.raises(ProviderCheckError, match="rejected the client ID or client secret"):
            self._check(httpx.Response(401, json={"error": "invalid_client"}))

    def test_other_error(self):
        with pytest.raises(ProviderCheckError, match="Discord check failed: .*HTTP 400"):
            self._check(httpx.Response(400, json={"error": "unsupported_grant_type"}))

    def test_server_error(self):
        with pytest.raises(ProviderCheckError, match="HTTP 502"):
            self._check(httpx.Response(502))

    def test_code_accepted_is_a_failure(self):
        with pytest.raises(ProviderCheckError, match="accepted an invalid code"):
            self._check(load("token"))

    def test_missing_credentials(self):
        with pytest.raises(ProviderCheckError, match="client ID and client secret"):
            discord.DiscordAdapter().check(
                "tenant-1", _connection(client_id=None), redirect_uri=REDIRECT_URI
            )


class TestConnectionService:
    def test_create_with_defaults(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection

        config = create_connection(
            _super_admin(test_super_admin_user, test_tenant["id"]),
            OIDCConnectionCreate(
                name="Discord",
                provider_type="discord",
                client_id="1234567890",
                client_secret="secret",
                allow_email_linking=True,
            ),
            BASE_URL,
        )
        assert config.issuer == "https://discord.com"
        assert config.discovery_url is None
        assert config.scopes == "identify email"
        assert config.correlation_claim == "sub"
        assert config.uses_discovery is False
        assert config.provider_label == "Discord"
        assert config.email_linking_trusted is True
        assert config.allow_email_linking is True

    def test_create_rejects_discovery_settings(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection

        with pytest.raises(ValidationError) as exc:
            create_connection(
                _super_admin(test_super_admin_user, test_tenant["id"]),
                OIDCConnectionCreate(
                    name="Discord",
                    provider_type="discord",
                    discovery_url="https://discord.com/.well-known/openid-configuration",
                ),
                BASE_URL,
            )
        assert exc.value.code == "oidc_setting_not_supported"

    def test_allowed_orgs_rejected(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection

        with pytest.raises(ValidationError) as exc:
            create_connection(
                _super_admin(test_super_admin_user, test_tenant["id"]),
                OIDCConnectionCreate(
                    name="Discord", provider_type="discord", github_allowed_orgs=["acme"]
                ),
                BASE_URL,
            )
        assert exc.value.code == "oidc_setting_not_supported"


class TestSignIn:
    def _row(self, test_tenant, test_super_admin_user, **flags):
        import database

        return database.oidc_upstream.create_connection(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="Discord",
            provider_type="discord",
            issuer="https://discord.com",
            created_by=str(test_super_admin_user["id"]),
            client_id="1234567890",
            client_secret_enc=_encrypt_secret("discord-secret"),
            is_enabled=True,
            **flags,
        )

    def test_jit_gets_a_verified_email(self, test_tenant, test_super_admin_user):
        import database
        from services.oidc_upstream.provisioning import authenticate_via_oidc

        row = self._row(test_tenant, test_super_admin_user, jit_provisioning=True)
        with discord_api():
            identity = _complete(row)
        user = authenticate_via_oidc(
            tenant_id=str(test_tenant["id"]),
            connection=row,
            sub=identity.subject,
            claims=identity.claims,
        )

        assert user["first_name"] == "Nelly"
        assert user["last_name"] == "Banks"
        primary = database.user_emails.get_primary_email_for_resend(
            test_tenant["id"], str(user["id"])
        )
        assert primary["email"] == "nelly@example.com"
        assert primary["verified_at"] is not None

    def test_email_link_needs_verified_flag(self, test_tenant, test_super_admin_user, test_user):
        from services.exceptions import NotFoundError
        from services.oidc_upstream.provisioning import authenticate_via_oidc

        row = self._row(test_tenant, test_super_admin_user, allow_email_linking=True)

        with discord_api({USERS_ME_PATH: _user(email=test_user["email"], verified=False)}):
            identity = _complete(row)
        with pytest.raises(NotFoundError):
            authenticate_via_oidc(
                tenant_id=str(test_tenant["id"]),
                connection=row,
                sub=identity.subject,
                claims=identity.claims,
            )

        with discord_api({USERS_ME_PATH: _user(email=test_user["email"], verified=True)}):
            identity = _complete(row)
        user = authenticate_via_oidc(
            tenant_id=str(test_tenant["id"]),
            connection=row,
            sub=identity.subject,
            claims=identity.claims,
        )
        assert str(user["id"]) == str(test_user["id"])
