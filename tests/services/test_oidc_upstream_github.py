"""Tests for the GitHub sign-in adapter and GitHub connection settings.

The adapter runs against the GitHub API fixtures in ``tests/fixtures/github``
served through a mock transport, so the real request code (headers, token
exchange body, pagination) is exercised without a network.
"""

from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import httpx
import pytest
from schemas.oidc_upstream import PROVIDER_TYPES, OIDCConnectionCreate, OIDCConnectionUpdate
from services.exceptions import ValidationError
from services.oidc_upstream import adapters, github, presets
from services.oidc_upstream.adapters import ProviderCheckError, ProviderLoginError
from services.oidc_upstream.connections import _encrypt_secret
from services.types import RequestingUser

from tests.fixtures.github import github_api, load

BASE_URL = "https://test.example.com"
REDIRECT_URI = "https://test.example.com/auth/oidc/c-1/callback"


def _connection(**overrides) -> dict:
    row = {
        "id": "c-1",
        "name": "GitHub",
        "provider_type": "github",
        "client_id": "Iv1.client",
        "client_secret_enc": _encrypt_secret("gh-secret"),
        "scopes": "read:user user:email read:org",
        "github_allowed_orgs": None,
        "group_claim_source": None,
    }
    row.update(overrides)
    return row


def _complete(connection: dict):
    return github.GitHubAdapter().complete(
        "tenant-1",
        connection,
        code="code-1",
        redirect_uri=REDIRECT_URI,
        code_verifier="verifier-1",
        nonce="ignored",
    )


def _super_admin(user, tenant_id):
    return RequestingUser(id=str(user["id"]), tenant_id=tenant_id, role="super_admin")


# =============================================================================
# Preset and registry
# =============================================================================


class TestPreset:
    def test_github_preset(self):
        preset = presets.get_preset("github")
        assert preset.display_name == "GitHub"
        assert preset.issuer == "https://github.com"
        assert preset.discovery_url is None
        assert preset.scopes == "read:user user:email read:org"
        assert preset.token_auth_method == presets.TOKEN_AUTH_POST
        assert preset.email_linking_trusted is True
        assert preset.uses_discovery is False
        assert presets.login_button_style("github") == ("GitHub", "github")

    def test_creatable(self):
        assert "github" in PROVIDER_TYPES

    def test_uses_discovery(self):
        assert presets.uses_discovery("github") is False
        assert presets.uses_discovery("google") is True
        # Unknown types are treated as spec OIDC.
        assert presets.uses_discovery("unknown") is True
        assert presets.get_preset_defaults("github")["uses_discovery"] is False

    def test_registered_adapter(self):
        assert isinstance(adapters.get_adapter("github"), github.GitHubAdapter)
        assert isinstance(adapters.get_adapter("gitlab"), adapters.SpecOIDCAdapter)

    def test_credentials_sent_in_body(self):
        credentials = adapters.resolve_client_credentials(_connection())
        assert credentials.token_auth_method == "client_secret_post"
        assert credentials.client_secret == "gh-secret"


# =============================================================================
# Authorize URL and prepare
# =============================================================================


class TestAuthorize:
    def test_authorize_url(self):
        url = github.GitHubAdapter().authorize_url(
            _connection(),
            redirect_uri=REDIRECT_URI,
            state="state-1",
            nonce="nonce-1",
            code_challenge="challenge-1",
        )
        parsed = urlparse(url)
        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == github.AUTHORIZE_URL
        params = parse_qs(parsed.query)
        assert params == {
            "client_id": ["Iv1.client"],
            "redirect_uri": [REDIRECT_URI],
            "scope": ["read:user user:email read:org"],
            "state": ["state-1"],
            "code_challenge": ["challenge-1"],
            "code_challenge_method": ["S256"],
        }

    def test_scope_falls_back_to_preset(self):
        url = github.GitHubAdapter().authorize_url(
            _connection(scopes=None),
            redirect_uri=REDIRECT_URI,
            state="s",
            nonce="n",
            code_challenge="c",
        )
        assert parse_qs(urlparse(url).query)["scope"] == ["read:user user:email read:org"]

    def test_unconfigured(self):
        with pytest.raises(ProviderLoginError) as exc:
            github.GitHubAdapter().authorize_url(
                _connection(client_id=None),
                redirect_uri=REDIRECT_URI,
                state="s",
                nonce="n",
                code_challenge="c",
            )
        assert exc.value.public_error == "configuration_error"

    def test_prepare_does_not_discover(self):
        connection = _connection()
        assert github.GitHubAdapter().prepare("tenant-1", connection) is connection


# =============================================================================
# complete(): code exchange and identity
# =============================================================================


class TestComplete:
    def test_identity(self):
        with github_api() as requests:
            identity = _complete(_connection())

        assert identity.subject == "583231"
        assert identity.upstream_sub is None
        assert identity.upstream_sid is None
        assert identity.id_token is None
        assert identity.claims == {
            "sub": "583231",
            "preferred_username": "octocat",
            "name": "The Octocat",
            "given_name": "The",
            "family_name": "Octocat",
            # The primary address, not the verified non-primary one.
            "email": "octocat@example.com",
            "email_verified": True,
            "picture": "https://avatars.githubusercontent.com/u/583231?v=4",
            "profile": "https://github.com/octocat",
        }
        # Neither allowed orgs nor group sync: no org or team calls.
        assert [r.url.path for r in requests] == [
            "/login/oauth/access_token",
            "/user",
            "/user/emails",
        ]

    def test_token_exchange_on_the_wire(self):
        with github_api() as requests:
            _complete(_connection())
        token_request = requests[0]
        assert str(token_request.url) == github.TOKEN_URL
        assert token_request.headers["accept"] == "application/json"
        assert "authorization" not in token_request.headers
        body = parse_qs(token_request.content.decode())
        assert body == {
            "grant_type": ["authorization_code"],
            "code": ["code-1"],
            "redirect_uri": [REDIRECT_URI],
            "code_verifier": ["verifier-1"],
            "client_id": ["Iv1.client"],
            "client_secret": ["gh-secret"],
        }

    def test_api_requests_carry_token_and_version(self):
        with github_api() as requests:
            _complete(_connection())
        user_request = requests[1]
        assert str(user_request.url) == "https://api.github.com/user"
        assert user_request.headers["authorization"] == (
            "Bearer gho_16C7e42F292c6912E7710c838347Ae178B4a"
        )
        assert user_request.headers["accept"] == "application/vnd.github+json"
        assert user_request.headers["x-github-api-version"] == "2022-11-28"

    def test_unverified_primary_email_is_dropped(self):
        emails = [
            {"email": "octocat@example.com", "primary": True, "verified": False},
            {"email": "other@example.com", "primary": False, "verified": True},
        ]
        with github_api({"/user/emails": emails}):
            identity = _complete(_connection())
        assert "email" not in identity.claims
        assert identity.claims["email_verified"] is False

    @pytest.mark.parametrize(
        "emails",
        [
            [],
            {"message": "not a list"},
            [{"email": None, "primary": True, "verified": True}],
            ["octocat@example.com"],
            [{"email": "octocat@example.com", "primary": "true", "verified": "true"}],
        ],
    )
    def test_malformed_emails_mean_no_email(self, emails):
        with github_api({"/user/emails": emails}):
            identity = _complete(_connection())
        assert "email" not in identity.claims
        assert identity.claims["email_verified"] is False

    def test_no_display_name_uses_login(self):
        user = {**load("user"), "name": None}
        with github_api({"/user": user}):
            identity = _complete(_connection())
        assert identity.claims["given_name"] == "octocat"
        assert "family_name" not in identity.claims
        assert "name" not in identity.claims

    def test_single_word_name(self):
        user = {**load("user"), "name": "Mona"}
        with github_api({"/user": user}):
            identity = _complete(_connection())
        assert identity.claims["given_name"] == "Mona"
        assert "family_name" not in identity.claims

    def test_missing_optional_profile_fields(self):
        user = {"id": 7, "login": "minimal"}
        with github_api({"/user": user}):
            identity = _complete(_connection())
        assert identity.subject == "7"
        assert "picture" not in identity.claims
        assert "profile" not in identity.claims

    @pytest.mark.parametrize(
        "user",
        [
            {"login": "octocat"},
            {"id": "583231", "login": "octocat"},
            {"id": True, "login": "octocat"},
            {"id": 583231},
        ],
    )
    def test_missing_id_or_login(self, user):
        with github_api({"/user": user}), pytest.raises(ProviderLoginError) as exc:
            _complete(_connection())
        assert exc.value.reason == "missing_sub"

    def test_user_not_an_object(self):
        with github_api({"/user": ["nope"]}), pytest.raises(ProviderLoginError) as exc:
            _complete(_connection())
        assert exc.value.reason == "github_api"

    def test_token_exchange_error(self):
        error = {"error": "bad_verification_code", "error_description": "expired"}
        with (
            github_api({"/login/oauth/access_token": error}),
            pytest.raises(ProviderLoginError) as exc,
        ):
            _complete(_connection())
        assert exc.value.reason == "token_exchange"
        assert "bad_verification_code" in exc.value.detail
        assert exc.value.public_error == "auth_failed"

    def test_no_access_token(self):
        with (
            github_api({"/login/oauth/access_token": {"token_type": "bearer"}}),
            pytest.raises(ProviderLoginError) as exc,
        ):
            _complete(_connection())
        assert exc.value.reason == "token_exchange"

    def test_missing_credentials(self):
        with pytest.raises(ProviderLoginError) as exc:
            _complete(_connection(client_secret_enc=None))
        assert exc.value.reason == "configuration_error"
        assert exc.value.public_error == "configuration_error"

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(401, json={"message": "Bad credentials"}),
            httpx.Response(200, content=b"not json"),
        ],
    )
    def test_api_failure(self, response):
        with github_api({"/user/emails": response}), pytest.raises(ProviderLoginError) as exc:
            _complete(_connection())
        assert exc.value.reason == "github_api"
        assert "/user/emails" in exc.value.detail

    def test_transport_failure(self):
        def boom(request):
            raise httpx.ConnectError("unreachable")

        with github_api({"/user": boom}), pytest.raises(ProviderLoginError) as exc:
            _complete(_connection())
        assert exc.value.reason == "github_api"


# =============================================================================
# Allowed organizations and groups
# =============================================================================


class TestOrganizations:
    def test_member_of_allowed_org(self):
        with github_api() as requests:
            identity = _complete(_connection(github_allowed_orgs=["acme"]))
        assert identity.subject == "583231"
        # Org list fetched, teams not (no group sync).
        paths = [r.url.path for r in requests]
        assert "/user/orgs" in paths
        assert "/user/teams" not in paths
        assert "groups" not in identity.claims

    def test_allowed_org_match_is_case_insensitive(self):
        # The fixture org is "Acme"; stored names are lower-cased.
        with github_api():
            _complete(_connection(github_allowed_orgs=["ACME"]))

    def test_not_a_member(self):
        with github_api(), pytest.raises(ProviderLoginError) as exc:
            _complete(_connection(github_allowed_orgs=["globex", "initech"]))
        assert exc.value.reason == "github_org_not_allowed"
        assert exc.value.public_error == "github_org_not_allowed"
        assert "octocat" in exc.value.detail

    def test_no_orgs_at_all(self):
        with github_api({"/user/orgs": []}), pytest.raises(ProviderLoginError) as exc:
            _complete(_connection(github_allowed_orgs=["acme"]))
        assert exc.value.reason == "github_org_not_allowed"

    def test_orgs_failure(self):
        with (
            github_api({"/user/orgs": httpx.Response(403, json={})}),
            pytest.raises(ProviderLoginError) as exc,
        ):
            _complete(_connection(github_allowed_orgs=["acme"]))
        assert exc.value.reason == "github_api"

    def test_orgs_not_a_list(self):
        with (
            github_api({"/user/orgs": {"message": "x"}}),
            pytest.raises(ProviderLoginError) as exc,
        ):
            _complete(_connection(github_allowed_orgs=["acme"]))
        assert exc.value.reason == "github_api"

    def test_groups_claim_with_group_sync(self):
        with github_api():
            identity = _complete(_connection(group_claim_source="groups"))
        assert identity.claims["groups"] == [
            "Acme",
            "octo-hobby",
            "Acme/platform",
            "octo-hobby/hobby-core",
        ]

    def test_groups_limited_to_allowed_orgs(self):
        with github_api():
            identity = _complete(
                _connection(group_claim_source="groups", github_allowed_orgs=["acme"])
            )
        assert identity.claims["groups"] == ["Acme", "Acme/platform"]

    def test_other_group_claim_does_not_fetch(self):
        with github_api() as requests:
            identity = _complete(_connection(group_claim_source="roles"))
        assert "/user/orgs" not in [r.url.path for r in requests]
        assert "groups" not in identity.claims

    def test_malformed_entries_skipped(self):
        orgs = [{"login": "acme"}, {"id": 5}, "junk"]
        teams = [
            {"slug": "core", "organization": {"login": "acme"}},
            {"slug": "no-org"},
            {"slug": "bad-org", "organization": "acme"},
            "junk",
        ]
        with github_api({"/user/orgs": orgs, "/user/teams": teams}):
            identity = _complete(_connection(group_claim_source="groups"))
        assert identity.claims["groups"] == ["acme", "acme/core"]

    def test_pagination(self):
        def orgs(request):
            page = int(request.url.params["page"])
            assert request.url.params["per_page"] == "100"
            if page == 1:
                return httpx.Response(200, json=[{"login": f"org-{i}"} for i in range(100)])
            return httpx.Response(200, json=[{"login": "acme"}])

        with github_api({"/user/orgs": orgs}) as requests:
            _complete(_connection(github_allowed_orgs=["acme"]))
        assert [r.url.params["page"] for r in requests if r.url.path == "/user/orgs"] == [
            "1",
            "2",
        ]

    def test_pagination_is_bounded(self):
        def orgs(request):
            return httpx.Response(200, json=[{"login": "x"}] * 100)

        with github_api({"/user/orgs": orgs}) as requests, pytest.raises(ProviderLoginError):
            _complete(_connection(github_allowed_orgs=["acme"]))
        assert len([r for r in requests if r.url.path == "/user/orgs"]) == github._MAX_PAGES


# =============================================================================
# check(): Test Connection
# =============================================================================


class TestCheck:
    def _check(self, token_body):
        with github_api({"/login/oauth/access_token": token_body}) as requests:
            result = github.GitHubAdapter().check(
                "tenant-1", _connection(), redirect_uri=REDIRECT_URI
            )
        return result, requests

    def test_credentials_accepted(self):
        result, requests = self._check({"error": "bad_verification_code"})
        assert result["id"] == "c-1"
        body = parse_qs(requests[0].content.decode())
        assert body["client_id"] == ["Iv1.client"]
        assert body["redirect_uri"] == [REDIRECT_URI]

    @pytest.mark.parametrize(
        ("error", "message"),
        [
            ("incorrect_client_credentials", "rejected the client ID or client secret"),
            ("redirect_uri_mismatch", "callback URL does not match"),
            ("unsupported_grant_type", "unsupported_grant_type"),
        ],
    )
    def test_rejected(self, error, message):
        with pytest.raises(ProviderCheckError, match=message):
            self._check({"error": error})

    def test_code_accepted_is_a_failure(self):
        with pytest.raises(ProviderCheckError, match="accepted an invalid code"):
            self._check(load("token"))

    def test_http_error(self):
        with pytest.raises(ProviderCheckError, match="HTTP 500"):
            self._check(httpx.Response(500))

    def test_missing_credentials(self):
        with pytest.raises(ProviderCheckError, match="client ID and client secret"):
            github.GitHubAdapter().check(
                "tenant-1", _connection(client_id=None), redirect_uri=REDIRECT_URI
            )


# =============================================================================
# Connection service: create, update, test
# =============================================================================


class TestConnectionService:
    def test_create_with_defaults(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection

        config = create_connection(
            _super_admin(test_super_admin_user, test_tenant["id"]),
            OIDCConnectionCreate(
                name="GitHub",
                provider_type="github",
                client_id="Iv1.client",
                client_secret="secret",
                github_allowed_orgs=["Acme", "acme", "Globex"],
            ),
            BASE_URL,
        )
        assert config.issuer == "https://github.com"
        assert config.discovery_url is None
        assert config.scopes == "read:user user:email read:org"
        assert config.correlation_claim == "sub"
        assert config.uses_discovery is False
        assert config.provider_label == "GitHub"
        assert config.email_linking_trusted is True
        # Lower-cased and de-duplicated, order kept.
        assert config.github_allowed_orgs == ["acme", "globex"]

    def test_create_accepts_form_preset_values(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection

        config = create_connection(
            _super_admin(test_super_admin_user, test_tenant["id"]),
            OIDCConnectionCreate(
                name="GitHub",
                provider_type="github",
                issuer="https://github.com/",
                correlation_claim="sub",
            ),
            BASE_URL,
        )
        assert config.github_allowed_orgs == []

    @pytest.mark.parametrize(
        "field",
        [
            {"issuer": "https://github.example.com"},
            {"discovery_url": "https://github.com/.well-known/openid-configuration"},
            {"token_endpoint": "https://github.com/token"},
            {"correlation_claim": "login"},
            {"hosted_domain": "example.com"},
        ],
    )
    def test_create_rejects_discovery_settings(self, test_tenant, test_super_admin_user, field):
        from services.oidc_upstream.connections import create_connection

        with pytest.raises(ValidationError) as exc:
            create_connection(
                _super_admin(test_super_admin_user, test_tenant["id"]),
                OIDCConnectionCreate(name="GitHub", provider_type="github", **field),
                BASE_URL,
            )
        assert exc.value.code == "oidc_setting_not_supported"
        assert next(iter(field)) in exc.value.message

    def test_allowed_orgs_rejected_on_other_types(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection

        with pytest.raises(ValidationError) as exc:
            create_connection(
                _super_admin(test_super_admin_user, test_tenant["id"]),
                OIDCConnectionCreate(
                    name="Google", provider_type="google", github_allowed_orgs=["acme"]
                ),
                BASE_URL,
            )
        assert exc.value.code == "oidc_setting_not_supported"

    def test_empty_allowed_orgs_fine_on_other_types(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection

        config = create_connection(
            _super_admin(test_super_admin_user, test_tenant["id"]),
            OIDCConnectionCreate(name="Google", provider_type="google", github_allowed_orgs=[]),
            BASE_URL,
        )
        assert config.github_allowed_orgs == []
        assert config.uses_discovery is True

    def test_update_allowed_orgs(self, test_tenant, test_super_admin_user):
        import database
        from services.oidc_upstream.connections import create_connection, update_connection

        admin = _super_admin(test_super_admin_user, test_tenant["id"])
        config = create_connection(
            admin, OIDCConnectionCreate(name="GitHub", provider_type="github"), BASE_URL
        )

        updated = update_connection(
            admin, config.id, OIDCConnectionUpdate(github_allowed_orgs=["Initech"]), BASE_URL
        )
        assert updated.github_allowed_orgs == ["initech"]
        event = next(
            e
            for e in database.event_log.list_events(test_tenant["id"], limit=20)
            if e["event_type"] == "oidc_idp_connection_updated"
        )
        assert event["metadata"]["updated_fields"] == ["github_allowed_orgs"]

        cleared = update_connection(
            admin, config.id, OIDCConnectionUpdate(github_allowed_orgs=[]), BASE_URL
        )
        assert cleared.github_allowed_orgs == []
        row = database.oidc_upstream.get_connection(test_tenant["id"], config.id)
        assert row["github_allowed_orgs"] is None

        # None leaves it alone.
        unchanged = update_connection(
            admin, config.id, OIDCConnectionUpdate(scopes="read:user user:email"), BASE_URL
        )
        assert unchanged.github_allowed_orgs == []

    def test_update_rejects_discovery_settings(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection, update_connection

        admin = _super_admin(test_super_admin_user, test_tenant["id"])
        config = create_connection(
            admin, OIDCConnectionCreate(name="GitHub", provider_type="github"), BASE_URL
        )
        with pytest.raises(ValidationError) as exc:
            update_connection(
                admin,
                config.id,
                OIDCConnectionUpdate(jwks_uri="https://github.com/keys"),
                BASE_URL,
            )
        assert exc.value.code == "oidc_setting_not_supported"

    def test_list_item_uses_discovery(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection, list_connections

        admin = _super_admin(test_super_admin_user, test_tenant["id"])
        create_connection(
            admin, OIDCConnectionCreate(name="GitHub", provider_type="github"), BASE_URL
        )
        items = list_connections(admin).items
        assert [(i.provider_type, i.uses_discovery) for i in items] == [("github", False)]

    def _create(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream.connections import create_connection

        admin = _super_admin(test_super_admin_user, test_tenant["id"])
        return admin, create_connection(
            admin,
            OIDCConnectionCreate(
                name="GitHub-" + uuid4().hex[:6],
                provider_type="github",
                client_id="Iv1.client",
                client_secret="secret",
            ),
            BASE_URL,
        )

    def test_test_connection_success(self, test_tenant, test_super_admin_user):
        import database
        from services.oidc_upstream.connections import test_connection

        admin, config = self._create(test_tenant, test_super_admin_user)
        with github_api({"/login/oauth/access_token": {"error": "bad_verification_code"}}) as reqs:
            result = test_connection(admin, config.id, BASE_URL)

        assert result.id == config.id
        # The redirect URI sent is the connection's own callback URL.
        assert parse_qs(reqs[0].content.decode())["redirect_uri"] == [config.callback_url]
        # Discovery was not touched.
        row = database.oidc_upstream.get_connection(test_tenant["id"], config.id)
        assert row["discovery_fetched_at"] is None
        assert row["discovery_error"] is None
        event = next(
            e
            for e in database.event_log.list_events(test_tenant["id"], limit=20)
            if e["event_type"] == "oidc_idp_connection_tested"
        )
        assert event["metadata"]["result"] == "success"

    def test_test_connection_failure(self, test_tenant, test_super_admin_user):
        import database
        from services.oidc_upstream.connections import test_connection

        admin, config = self._create(test_tenant, test_super_admin_user)
        with (
            github_api({"/login/oauth/access_token": {"error": "incorrect_client_credentials"}}),
            pytest.raises(ValidationError) as exc,
        ):
            test_connection(admin, config.id, BASE_URL)

        assert exc.value.code == "oidc_connection_test_failed"
        assert "client ID or client secret" in exc.value.message
        event = next(
            e
            for e in database.event_log.list_events(test_tenant["id"], limit=20)
            if e["event_type"] == "oidc_idp_connection_tested"
        )
        assert event["metadata"]["result"] == "failed"
        assert "client ID or client secret" in event["metadata"]["detail"]


# =============================================================================
# Sign-in through the GitHub identity (provisioning reuse)
# =============================================================================


class TestSignIn:
    def _identity(self, connection_row, overrides=None):
        with github_api(overrides):
            return _complete(connection_row)

    def test_jit_and_group_sync(self, test_tenant, test_super_admin_user):
        import database
        from services.oidc_upstream.provisioning import authenticate_via_oidc

        row = database.oidc_upstream.create_connection(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="GitHub",
            provider_type="github",
            issuer="https://github.com",
            created_by=str(test_super_admin_user["id"]),
            client_id="Iv1.client",
            client_secret_enc=_encrypt_secret("gh-secret"),
            is_enabled=True,
            jit_provisioning=True,
            group_claim_source="groups",
            github_allowed_orgs=["acme"],
        )
        identity = self._identity(row)

        user = authenticate_via_oidc(
            tenant_id=str(test_tenant["id"]),
            connection=row,
            sub=identity.subject,
            claims=identity.claims,
        )

        assert (
            database.users.get_user_by_email_with_status(test_tenant["id"], "octocat@example.com")[
                "id"
            ]
            == user["id"]
        )
        assert user["first_name"] == "The"
        assert user["last_name"] == "Octocat"
        assert database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(row["id"]), "583231"
        ) == str(user["id"])
        group_names = {
            g["name"] for g in database.groups.get_user_groups(test_tenant["id"], str(user["id"]))
        }
        assert {"Acme", "Acme/platform"} <= group_names
        assert "octo-hobby" not in group_names

    def test_email_link_needs_verified_primary(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services.exceptions import NotFoundError
        from services.oidc_upstream.provisioning import authenticate_via_oidc

        row = database.oidc_upstream.create_connection(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="GitHub",
            provider_type="github",
            issuer="https://github.com",
            created_by=str(test_super_admin_user["id"]),
            client_id="Iv1.client",
            client_secret_enc=_encrypt_secret("gh-secret"),
            is_enabled=True,
            allow_email_linking=True,
        )
        emails = [{"email": test_user["email"], "primary": True, "verified": False}]
        identity = self._identity(row, {"/user/emails": emails})
        with pytest.raises(NotFoundError):
            authenticate_via_oidc(
                tenant_id=str(test_tenant["id"]),
                connection=row,
                sub=identity.subject,
                claims=identity.claims,
            )

        emails = [{"email": test_user["email"], "primary": True, "verified": True}]
        identity = self._identity(row, {"/user/emails": emails})
        user = authenticate_via_oidc(
            tenant_id=str(test_tenant["id"]),
            connection=row,
            sub=identity.subject,
            claims=identity.claims,
        )
        assert str(user["id"]) == str(test_user["id"])
