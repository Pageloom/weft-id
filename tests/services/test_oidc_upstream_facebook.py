"""Tests for the Facebook sign-in adapter and Facebook connections.

The adapter runs against the Graph API fixtures in ``tests/fixtures/facebook``
served through a mock transport, so the real request code runs without a
network.
"""

import hashlib
import hmac
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from schemas.oidc_upstream import PROVIDER_TYPES, OIDCConnectionCreate, OIDCConnectionUpdate
from services.exceptions import ValidationError
from services.oidc_upstream import adapters, facebook, presets
from services.oidc_upstream.adapters import ProviderCheckError, ProviderLoginError
from services.oidc_upstream.connections import _encrypt_secret
from services.types import RequestingUser

from tests.fixtures.facebook import ME_PATH, TOKEN_PATH, facebook_api, load

BASE_URL = "https://test.example.com"
REDIRECT_URI = "https://test.example.com/auth/oidc/c-1/callback"
ACCESS_TOKEN = "EAAGm0PX4ZCpsBAOZBzZAeZCZA4ZD"


def _connection(**overrides) -> dict:
    row = {
        "id": "c-1",
        "name": "Facebook",
        "provider_type": "facebook",
        "client_id": "1122334455",
        "client_secret_enc": _encrypt_secret("fb-secret"),
        "scopes": "public_profile email",
    }
    row.update(overrides)
    return row


def _complete(connection: dict):
    return facebook.FacebookAdapter().complete(
        "tenant-1",
        connection,
        code="code-1",
        redirect_uri=REDIRECT_URI,
        code_verifier="verifier-1",
        nonce="ignored",
    )


def _me(**overrides) -> dict:
    me = load("me")
    me.update(overrides)
    return me


def _super_admin(user, tenant_id):
    return RequestingUser(id=str(user["id"]), tenant_id=tenant_id, role="super_admin")


class TestPreset:
    def test_facebook_preset(self):
        preset = presets.get_preset("facebook")
        assert preset.display_name == "Facebook"
        assert preset.issuer == "https://www.facebook.com"
        assert preset.discovery_url is None
        assert preset.scopes == "public_profile email"
        assert preset.token_auth_method == presets.TOKEN_AUTH_POST
        assert preset.email_linking_trusted is False
        assert preset.uses_discovery is False
        assert presets.login_button_style("facebook") == ("Facebook", "facebook")

    def test_creatable_and_registered(self):
        assert "facebook" in PROVIDER_TYPES
        assert isinstance(adapters.get_adapter("facebook"), facebook.FacebookAdapter)

    def test_endpoints_pin_the_graph_version(self):
        version = facebook.GRAPH_API_VERSION
        assert facebook.AUTHORIZE_URL == f"https://www.facebook.com/{version}/dialog/oauth"
        assert facebook.TOKEN_URL == f"https://graph.facebook.com/{version}/oauth/access_token"


class TestAuthorize:
    def test_authorize_url(self):
        url = facebook.FacebookAdapter().authorize_url(
            _connection(),
            redirect_uri=REDIRECT_URI,
            state="state-1",
            nonce="nonce-1",
            code_challenge="challenge-1",
        )
        parsed = urlparse(url)
        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == facebook.AUTHORIZE_URL
        assert parse_qs(parsed.query) == {
            "client_id": ["1122334455"],
            "redirect_uri": [REDIRECT_URI],
            "response_type": ["code"],
            "scope": ["public_profile email"],
            "state": ["state-1"],
            "code_challenge": ["challenge-1"],
            "code_challenge_method": ["S256"],
        }

    def test_unconfigured(self):
        with pytest.raises(ProviderLoginError) as exc:
            facebook.FacebookAdapter().authorize_url(
                _connection(client_id=None),
                redirect_uri=REDIRECT_URI,
                state="s",
                nonce="n",
                code_challenge="c",
            )
        assert exc.value.public_error == "configuration_error"

    def test_prepare_does_not_discover(self):
        row = _connection()
        assert facebook.FacebookAdapter().prepare("tenant-1", row) is row


class TestComplete:
    def test_identity(self):
        with facebook_api() as requests:
            identity = _complete(_connection())

        assert identity.subject == "10158000000000001"
        assert identity.upstream_sub is None
        assert identity.id_token is None
        assert identity.claims == {
            "sub": "10158000000000001",
            "name": "Ada Lovelace",
            "given_name": "Ada",
            "family_name": "Lovelace",
            "email": "ada@example.com",
            # Facebook never vouches for the address.
            "email_verified": False,
            "picture": load("me")["picture"]["data"]["url"],
        }
        assert [r.url.path for r in requests] == [TOKEN_PATH, ME_PATH]

    def test_token_exchange_on_the_wire(self):
        with facebook_api() as requests:
            _complete(_connection())
        token_request = requests[0]
        assert str(token_request.url) == facebook.TOKEN_URL
        assert "authorization" not in token_request.headers
        assert parse_qs(token_request.content.decode()) == {
            "grant_type": ["authorization_code"],
            "code": ["code-1"],
            "redirect_uri": [REDIRECT_URI],
            "code_verifier": ["verifier-1"],
            "client_id": ["1122334455"],
            "client_secret": ["fb-secret"],
        }

    def test_graph_request_fields_and_appsecret_proof(self):
        with facebook_api() as requests:
            _complete(_connection())
        me_request = requests[1]
        assert me_request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
        params = parse_qs(me_request.url.query.decode())
        assert params["fields"] == ["id,name,first_name,last_name,email,picture"]
        expected = hmac.new(b"fb-secret", ACCESS_TOKEN.encode(), hashlib.sha256).hexdigest()
        assert params["appsecret_proof"] == [expected]

    def test_appsecret_proof(self):
        assert facebook.appsecret_proof("token", "secret") == (
            hmac.new(b"secret", b"token", hashlib.sha256).hexdigest()
        )

    def test_no_email(self):
        me = _me()
        del me["email"]
        with facebook_api({ME_PATH: me}):
            claims = _complete(_connection()).claims
        assert "email" not in claims
        assert claims["email_verified"] is False

    def test_missing_names(self):
        with facebook_api({ME_PATH: {"id": "10158000000000001"}}):
            claims = _complete(_connection()).claims
        assert claims == {"sub": "10158000000000001", "email_verified": False}

    @pytest.mark.parametrize(
        "picture",
        [
            {"data": {"is_silhouette": True, "url": "https://example.com/p.png"}},
            {"data": {"url": "http://example.com/p.png"}},
            {"data": "nope"},
            "nope",
        ],
    )
    def test_placeholder_or_bad_picture_dropped(self, picture):
        with facebook_api({ME_PATH: _me(picture=picture)}):
            claims = _complete(_connection()).claims
        assert "picture" not in claims

    @pytest.mark.parametrize("user_id", [None, 10158000000000001, "abc", ""])
    def test_missing_id(self, user_id):
        with facebook_api({ME_PATH: _me(id=user_id)}):
            with pytest.raises(ProviderLoginError) as exc:
                _complete(_connection())
        assert exc.value.reason == "missing_sub"

    def test_me_not_an_object(self):
        with facebook_api({ME_PATH: []}):
            with pytest.raises(ProviderLoginError) as exc:
                _complete(_connection())
        assert exc.value.reason == "facebook_api"

    def test_graph_error(self):
        response = httpx.Response(400, json={"error": {"type": "OAuthException", "code": 190}})
        with facebook_api({ME_PATH: response}):
            with pytest.raises(ProviderLoginError) as exc:
                _complete(_connection())
        assert exc.value.reason == "facebook_api"

    def test_token_exchange_error(self):
        response = httpx.Response(400, json={"error": {"type": "OAuthException", "code": 100}})
        with facebook_api({TOKEN_PATH: response}):
            with pytest.raises(ProviderLoginError) as exc:
                _complete(_connection())
        assert exc.value.reason == "token_exchange"

    def test_missing_credentials(self):
        with pytest.raises(ProviderLoginError) as exc:
            _complete(_connection(client_secret_enc=None))
        assert exc.value.public_error == "configuration_error"


class TestCheck:
    def _check(self, response):
        with facebook_api({TOKEN_PATH: response}) as requests:
            result = facebook.FacebookAdapter().check(
                "tenant-1", _connection(), redirect_uri=REDIRECT_URI
            )
        return result, requests

    def test_credentials_accepted(self):
        result, requests = self._check({"access_token": "1122334455|x", "token_type": "bearer"})
        assert result["id"] == "c-1"
        assert parse_qs(requests[0].content.decode()) == {
            "client_id": ["1122334455"],
            "client_secret": ["fb-secret"],
            "grant_type": ["client_credentials"],
        }

    @pytest.mark.parametrize("status", [400, 401])
    def test_credentials_rejected(self, status):
        with pytest.raises(ProviderCheckError, match="rejected the app ID or app secret"):
            self._check(httpx.Response(status, json={"error": {"code": 101}}))

    def test_server_error(self):
        with pytest.raises(ProviderCheckError, match="HTTP 500"):
            self._check(httpx.Response(500))

    def test_transport_failure(self):
        def boom(request):
            raise httpx.ConnectError("down")

        with pytest.raises(ProviderCheckError, match="Facebook check failed"):
            self._check(boom)

    def test_missing_credentials(self):
        with pytest.raises(ProviderCheckError, match="app ID and app secret"):
            facebook.FacebookAdapter().check(
                "tenant-1", _connection(client_secret_enc=None), redirect_uri=REDIRECT_URI
            )


class TestConnectionService:
    def test_create_with_defaults(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection

        config = create_connection(
            _super_admin(test_super_admin_user, test_tenant["id"]),
            OIDCConnectionCreate(
                name="Facebook",
                provider_type="facebook",
                client_id="1122334455",
                client_secret="secret",
                jit_provisioning=True,
            ),
            BASE_URL,
        )
        assert config.issuer == "https://www.facebook.com"
        assert config.scopes == "public_profile email"
        assert config.uses_discovery is False
        assert config.provider_label == "Facebook"
        assert config.email_linking_trusted is False

    def test_email_linking_rejected(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection, update_connection

        admin = _super_admin(test_super_admin_user, test_tenant["id"])
        with pytest.raises(ValidationError) as exc:
            create_connection(
                admin,
                OIDCConnectionCreate(
                    name="Facebook", provider_type="facebook", allow_email_linking=True
                ),
                BASE_URL,
            )
        assert exc.value.code == "oidc_email_linking_not_supported"

        config = create_connection(
            admin, OIDCConnectionCreate(name="Facebook", provider_type="facebook"), BASE_URL
        )
        with pytest.raises(ValidationError) as exc:
            update_connection(
                admin, config.id, OIDCConnectionUpdate(allow_email_linking=True), BASE_URL
            )
        assert exc.value.code == "oidc_email_linking_not_supported"

    def test_create_rejects_discovery_settings(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection

        with pytest.raises(ValidationError) as exc:
            create_connection(
                _super_admin(test_super_admin_user, test_tenant["id"]),
                OIDCConnectionCreate(
                    name="Facebook", provider_type="facebook", issuer="https://facebook.com/x"
                ),
                BASE_URL,
            )
        assert exc.value.code == "oidc_setting_not_supported"

    def test_test_connection_logs_event(self, test_tenant, test_super_admin_user):
        import database
        from services.oidc_upstream.connections import create_connection, test_connection

        admin = _super_admin(test_super_admin_user, test_tenant["id"])
        config = create_connection(
            admin,
            OIDCConnectionCreate(
                name="Facebook",
                provider_type="facebook",
                client_id="1122334455",
                client_secret="secret",
            ),
            BASE_URL,
        )
        with facebook_api({TOKEN_PATH: {"access_token": "x", "token_type": "bearer"}}):
            test_connection(admin, config.id, BASE_URL)

        events = database.event_log.list_events(test_tenant["id"], limit=10)
        assert any(
            e["event_type"] == "oidc_idp_connection_tested" and str(e["artifact_id"]) == config.id
            for e in events
        )
