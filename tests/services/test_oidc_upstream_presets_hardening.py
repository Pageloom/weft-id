"""Per-preset hardening tests (Iteration 8).

Verifies the Generic/Google/Entra presets against recorded fixtures under
``tests/fixtures/oidc/<preset>/``: discovery documents, signed ID-token JWTs,
and userinfo responses. Covers the authorize-URL shape (including the Google
``hd`` parameter), discovery parse + issuer-mismatch rejection, ID-token
validation, and correlation-subject selection (``sub`` for Google, ``oid`` for
Entra). No live network calls: the safe client / JWKS fetch are patched to
return the recorded fixture bytes.
"""

from unittest.mock import patch

import pytest
from services.oidc_upstream import auth as auth_helpers
from services.oidc_upstream import discovery as discovery_service
from services.oidc_upstream import id_token as id_token_service
from services.oidc_upstream import jwks as jwks_service
from services.oidc_upstream import presets
from services.oidc_upstream.errors import DiscoveryIssuerMismatchError

from tests.fixtures.oidc import load_fixture, load_fixture_text

GOOGLE_DISCOVERY = load_fixture("google/discovery")
GOOGLE_JWKS = load_fixture("google/jwks")
GOOGLE_ID_TOKEN = load_fixture_text("google/id_token.jwt")
GOOGLE_KEY_PEM = load_fixture_text("google/private_key.pem")

ENTRA_DISCOVERY = load_fixture("entra/discovery")
ENTRA_JWKS = load_fixture("entra/jwks")
ENTRA_ID_TOKEN = load_fixture_text("entra/id_token.jwt")
ENTRA_KEY_PEM = load_fixture_text("entra/private_key.pem")


class _FakeResponse:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self._json_body = json_body

    def json(self):
        if self._json_body is None:
            raise ValueError("no json")
        return self._json_body


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, url):
        return self._response


def _patch_discovery_client(response):
    return patch(
        "services.oidc_upstream.discovery.build_safe_client",
        return_value=_FakeClient(response),
    )


def _make_connection(tenant, **overrides):
    from uuid import uuid4

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
    return database.oidc_upstream.create_connection(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=f"Preset {uuid4().hex[:8]}",
        provider_type="generic",
        issuer=overrides.pop("issuer", "https://idp.example.com"),
        created_by=created_by,
        **overrides,
    )


class TestPresetRegistry:
    def test_google_preset_shape(self):
        preset = presets.get_preset("google")
        assert preset is not None
        assert preset.issuer == "https://accounts.google.com"
        assert preset.correlation_claim == "sub"
        assert preset.requires_entra_tenant_id is False

    def test_entra_preset_shape(self):
        preset = presets.get_preset("entra")
        assert preset is not None
        assert preset.correlation_claim == "oid"
        assert preset.requires_entra_tenant_id is True

    def test_entra_authority_composed_from_tenant_id(self):
        assert presets.compose_entra_authority("contoso.onmicrosoft.com") == (
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
        )
        assert presets.compose_entra_discovery_url("contoso.onmicrosoft.com") == (
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
            "/.well-known/openid-configuration"
        )


class TestAuthorizeUrlShape:
    def test_google_hosted_domain_present_when_configured(self):
        url = auth_helpers.build_authorize_url(
            authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
            client_id="google-client-123",
            redirect_uri="https://tenant.example.com/auth/oidc/c1/callback",
            state="s",
            nonce="n",
            code_challenge="c",
            scopes="openid profile email",
            hosted_domain="example.com",
        )
        assert "hd=example.com" in url
        assert "response_type=code" in url
        assert "code_challenge_method=S256" in url

    def test_google_hosted_domain_absent_when_not_configured(self):
        url = auth_helpers.build_authorize_url(
            authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
            client_id="google-client-123",
            redirect_uri="https://tenant.example.com/auth/oidc/c1/callback",
            state="s",
            nonce="n",
            code_challenge="c",
            scopes="openid profile email",
        )
        assert "hd=" not in url


class TestDiscoveryPerPreset:
    def test_google_discovery_parses(self, test_tenant):
        conn = _make_connection(
            test_tenant,
            issuer="https://accounts.google.com",
            discovery_url="https://accounts.google.com/.well-known/openid-configuration",
        )
        with _patch_discovery_client(_FakeResponse(200, GOOGLE_DISCOVERY)):
            row = discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))
        assert row["authorization_endpoint"] == "https://accounts.google.com/o/oauth2/v2/auth"
        assert row["token_endpoint"] == "https://oauth2.googleapis.com/token"
        assert row["jwks_uri"] == "https://www.googleapis.com/oauth2/v3/certs"

    def test_entra_discovery_parses(self, test_tenant):
        conn = _make_connection(
            test_tenant,
            issuer="https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0",
            discovery_url=(
                "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
                "/.well-known/openid-configuration"
            ),
        )
        with _patch_discovery_client(_FakeResponse(200, ENTRA_DISCOVERY)):
            row = discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))
        assert row["authorization_endpoint"] == (
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize"
        )
        assert row["token_endpoint"] == (
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"
        )

    def test_google_discovery_issuer_mismatch_rejected(self, test_tenant):
        conn = _make_connection(
            test_tenant,
            issuer="https://accounts.google.com",
            discovery_url="https://accounts.google.com/.well-known/openid-configuration",
        )
        bad = dict(GOOGLE_DISCOVERY, issuer="https://evil.example.com")
        with _patch_discovery_client(_FakeResponse(200, bad)):
            with pytest.raises(DiscoveryIssuerMismatchError):
                discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))


class TestIdTokenValidationPerPreset:
    def test_google_id_token_validates(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        with patch("services.oidc_upstream.jwks._fetch_jwks", return_value=GOOGLE_JWKS):
            claims = id_token_service.validate_id_token(
                token=GOOGLE_ID_TOKEN,
                tenant_id="t1",
                connection_id="c1",
                issuer="https://accounts.google.com",
                client_id="google-client-123",
                jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
                nonce="google-nonce-1",
            )
        assert claims["sub"] == "google-subject-123"
        assert claims["email"] == "google-user@example.com"

    def test_entra_id_token_validates(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        with patch("services.oidc_upstream.jwks._fetch_jwks", return_value=ENTRA_JWKS):
            claims = id_token_service.validate_id_token(
                token=ENTRA_ID_TOKEN,
                tenant_id="t1",
                connection_id="c1",
                issuer="https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0",
                client_id="entra-client-123",
                jwks_uri=(
                    "https://login.microsoftonline.com/contoso.onmicrosoft.com/discovery/v2.0/keys"
                ),
                nonce="entra-nonce-1",
            )
        assert claims["oid"] == "entra-oid-123"
        # Entra's sub is per-app-anonymous; the correlation subject is oid.
        assert claims["sub"] != "entra-oid-123"


class TestCorrelationSubjectSelection:
    def test_google_correlates_on_sub(self):
        """Google uses ``sub`` directly as the correlation subject."""
        assert presets.get_preset("google").correlation_claim == "sub"

    def test_entra_correlates_on_oid(self):
        """Entra uses ``oid`` (its ``sub`` is per-app-anonymous)."""
        assert presets.get_preset("entra").correlation_claim == "oid"
