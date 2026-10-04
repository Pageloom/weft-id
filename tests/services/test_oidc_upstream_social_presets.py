"""Tests for the Microsoft personal, LinkedIn and GitLab presets.

Covers the registry entries, the server-side defaults applied on create
(including a self-managed GitLab issuer), and each preset against recorded
fixtures under ``tests/fixtures/oidc/<preset>/``: discovery parse and ID-token
validation. No live network calls.
"""

import json
from unittest.mock import patch
from uuid import uuid4

import pytest
from schemas.oidc_upstream import PROVIDER_TYPES, OIDCConnectionCreate
from services.oidc_upstream import discovery as discovery_service
from services.oidc_upstream import id_token as id_token_service
from services.oidc_upstream import jwks as jwks_service
from services.oidc_upstream import presets
from services.types import RequestingUser

from tests.fixtures.oidc import load_fixture, load_fixture_text

BASE_URL = "https://test.example.com"
MSA_ISSUER = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"


class _FakeResponse:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self._json_body = json_body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_bytes(self):
        yield json.dumps(self._json_body).encode()


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def stream(self, method, url, **kwargs):
        return self._response


def _super_admin(user, tenant_id):
    return RequestingUser(id=str(user["id"]), tenant_id=tenant_id, role="super_admin")


class TestRegistry:
    def test_microsoft(self):
        preset = presets.get_preset("microsoft")
        assert preset.display_name == "Microsoft (personal accounts)"
        # Microsoft publishes the consumer-tenant GUID as the issuer, not the
        # "consumers" authority, so discovery's issuer check needs the GUID.
        assert preset.issuer == MSA_ISSUER
        assert preset.discovery_url == (
            "https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration"
        )
        # Personal-account ID tokens carry no oid.
        assert preset.correlation_claim == "sub"
        assert preset.token_auth_method == presets.TOKEN_AUTH_BASIC
        assert preset.requires_entra_tenant_id is False

    def test_linkedin(self):
        preset = presets.get_preset("linkedin")
        assert preset.display_name == "LinkedIn"
        assert preset.issuer == "https://www.linkedin.com/oauth"
        assert preset.correlation_claim == "sub"
        assert preset.token_auth_method == presets.TOKEN_AUTH_POST

    def test_gitlab(self):
        preset = presets.get_preset("gitlab")
        assert preset.display_name == "GitLab"
        assert preset.issuer == "https://gitlab.com"
        assert preset.discovery_url == "https://gitlab.com/.well-known/openid-configuration"
        assert preset.issuer_overridable is True

    def test_only_gitlab_issuer_overridable(self):
        overridable = [t for t in PROVIDER_TYPES if presets.get_preset(t).issuer_overridable]
        assert overridable == ["gitlab"]

    def test_every_creatable_type_has_a_preset(self):
        for provider_type in PROVIDER_TYPES:
            assert presets.get_preset(provider_type) is not None

    def test_defaults_include_display_fields(self):
        defaults = presets.get_preset_defaults("gitlab")
        assert defaults["display_name"] == "GitLab"
        assert defaults["issuer_overridable"] is True

    @pytest.mark.parametrize(
        ("provider_type", "label"),
        [
            ("generic", "Generic OIDC"),
            ("google", "Google"),
            ("entra", "Entra ID"),
            ("linkedin", "LinkedIn"),
            ("github", "github"),
        ],
    )
    def test_provider_display_name(self, provider_type, label):
        assert presets.provider_display_name(provider_type) == label

    def test_token_auth_method_defaults_to_basic(self):
        assert presets.token_auth_method("google") == presets.TOKEN_AUTH_BASIC
        assert presets.token_auth_method("unknown") == presets.TOKEN_AUTH_BASIC
        assert presets.token_auth_method("linkedin") == presets.TOKEN_AUTH_POST


class TestCreateAppliesDefaults:
    def _create(self, tenant, user, **fields):
        from services import oidc_upstream as svc

        data = OIDCConnectionCreate(
            name=f"Social {uuid4().hex[:8]}", client_id="cid", client_secret="secret", **fields
        )
        return svc.create_connection(_super_admin(user, tenant["id"]), data, BASE_URL)

    def test_microsoft(self, test_tenant, test_super_admin_user):
        conn = self._create(test_tenant, test_super_admin_user, provider_type="microsoft")
        assert conn.issuer == MSA_ISSUER
        assert conn.discovery_url.endswith("/consumers/v2.0/.well-known/openid-configuration")
        assert conn.scopes == "openid profile email"
        assert conn.correlation_claim == "sub"
        assert conn.provider_label == "Microsoft (personal accounts)"

    def test_linkedin(self, test_tenant, test_super_admin_user):
        conn = self._create(test_tenant, test_super_admin_user, provider_type="linkedin")
        assert conn.issuer == "https://www.linkedin.com/oauth"
        assert conn.discovery_url == (
            "https://www.linkedin.com/oauth/.well-known/openid-configuration"
        )
        assert conn.provider_label == "LinkedIn"

    def test_gitlab_dot_com(self, test_tenant, test_super_admin_user):
        conn = self._create(test_tenant, test_super_admin_user, provider_type="gitlab")
        assert conn.issuer == "https://gitlab.com"
        assert conn.discovery_url == "https://gitlab.com/.well-known/openid-configuration"

    def test_gitlab_dot_com_issuer_given_explicitly(self, test_tenant, test_super_admin_user):
        conn = self._create(
            test_tenant, test_super_admin_user, provider_type="gitlab", issuer="https://gitlab.com/"
        )
        assert conn.discovery_url == "https://gitlab.com/.well-known/openid-configuration"

    def test_gitlab_self_managed_discovers_from_own_issuer(
        self, test_tenant, test_super_admin_user
    ):
        conn = self._create(
            test_tenant,
            test_super_admin_user,
            provider_type="gitlab",
            issuer="https://gitlab.acme.example",
        )
        assert conn.issuer == "https://gitlab.acme.example"
        # Not gitlab.com's document: discovery falls back to the issuer's
        # well-known path.
        assert conn.discovery_url is None

    def test_gitlab_self_managed_explicit_discovery_kept(self, test_tenant, test_super_admin_user):
        conn = self._create(
            test_tenant,
            test_super_admin_user,
            provider_type="gitlab",
            issuer="https://gitlab.acme.example",
            discovery_url="https://gitlab.acme.example/.well-known/openid-configuration",
        )
        assert conn.discovery_url == (
            "https://gitlab.acme.example/.well-known/openid-configuration"
        )

    def test_list_items_carry_label(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        conn = self._create(test_tenant, test_super_admin_user, provider_type="linkedin")
        listing = svc.list_connections(_super_admin(test_super_admin_user, test_tenant["id"]))
        item = next(i for i in listing.items if i.id == conn.id)
        assert item.provider_label == "LinkedIn"


# Fixture paths and expected values per preset.
_PRESET_FIXTURES = {
    "microsoft": {
        "discovery_url": (
            "https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration"
        ),
        "client_id": "msa-client-123",
        "nonce": "msa-nonce-1",
        "subject": "AAAAAAAAAAAAAAAAAAAAAMsaPairwiseSub123",
    },
    "linkedin": {
        "discovery_url": "https://www.linkedin.com/oauth/.well-known/openid-configuration",
        "client_id": "linkedin-client-123",
        "nonce": "linkedin-nonce-1",
        "subject": "li-subject-123",
    },
    "gitlab": {
        "discovery_url": "https://gitlab.com/.well-known/openid-configuration",
        "client_id": "gitlab-client-123",
        "nonce": "gitlab-nonce-1",
        "subject": "1234567",
    },
}


def _make_connection_row(tenant, provider_type):
    import database

    created_by = str(
        database.fetchone(
            tenant["id"],
            """
            INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
            VALUES (:tenant_id, :password_hash, 'T', 'U', 'member')
            RETURNING id
            """,
            {"tenant_id": tenant["id"], "password_hash": "x" * 60},
        )["id"]
    )
    preset = presets.get_preset(provider_type)
    return database.oidc_upstream.create_connection(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=f"Preset {uuid4().hex[:8]}",
        provider_type=provider_type,
        issuer=preset.issuer,
        discovery_url=preset.discovery_url,
        created_by=created_by,
    )


@pytest.mark.parametrize("provider_type", sorted(_PRESET_FIXTURES))
class TestRecordedFixtures:
    def test_discovery_parses(self, test_tenant, provider_type):
        conn = _make_connection_row(test_tenant, provider_type)
        doc = load_fixture(f"{provider_type}/discovery")
        with patch(
            "services.oidc_upstream.discovery.build_safe_client",
            return_value=_FakeClient(_FakeResponse(200, doc)),
        ):
            row = discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))
        assert row["discovery_error"] is None
        assert row["authorization_endpoint"] == doc["authorization_endpoint"]
        assert row["token_endpoint"] == doc["token_endpoint"]
        assert row["jwks_uri"] == doc["jwks_uri"]

    def test_id_token_validates_and_correlates(self, provider_type):
        expected = _PRESET_FIXTURES[provider_type]
        preset = presets.get_preset(provider_type)
        jwks_service.clear_jwks_cache("t1", provider_type)
        with patch(
            "services.oidc_upstream.jwks._fetch_jwks",
            return_value=load_fixture(f"{provider_type}/jwks"),
        ):
            claims = id_token_service.validate_id_token(
                token=load_fixture_text(f"{provider_type}/id_token.jwt"),
                tenant_id="t1",
                connection_id=provider_type,
                issuer=preset.issuer,
                client_id=expected["client_id"],
                jwks_uri=load_fixture(f"{provider_type}/discovery")["jwks_uri"],
                nonce=expected["nonce"],
            )
        assert claims[preset.correlation_claim] == expected["subject"]

    def test_userinfo_subject_matches_id_token(self, provider_type):
        # The callback rejects a userinfo response about another subject, so
        # the recorded pair must agree.
        userinfo = load_fixture(f"{provider_type}/userinfo")
        assert userinfo["sub"] == _PRESET_FIXTURES[provider_type]["subject"]


def test_microsoft_fixture_has_no_oid():
    """Personal-account tokens carry no oid, which is why the preset uses sub."""
    import jwt

    claims = jwt.decode(
        load_fixture_text("microsoft/id_token.jwt"), options={"verify_signature": False}
    )
    assert "oid" not in claims
    assert "oid" not in load_fixture("microsoft/discovery")["claims_supported"]
