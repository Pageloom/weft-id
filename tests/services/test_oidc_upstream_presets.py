"""Tests for the OIDC upstream preset registry."""

from services.oidc_upstream import presets


class TestGetPreset:
    def test_generic_is_spec_default(self):
        preset = presets.get_preset("generic")
        assert preset is not None
        assert preset.discovery_url is None
        assert preset.scopes == "openid profile email"
        assert preset.correlation_claim == "sub"
        assert preset.requires_entra_tenant_id is False

    def test_google(self):
        preset = presets.get_preset("google")
        assert preset is not None
        assert preset.discovery_url == (
            "https://accounts.google.com/.well-known/openid-configuration"
        )
        assert preset.scopes == "openid profile email"
        assert preset.correlation_claim == "sub"

    def test_entra(self):
        preset = presets.get_preset("entra")
        assert preset is not None
        assert preset.discovery_url is None
        assert preset.scopes == "openid profile email User.Read"
        assert preset.correlation_claim == "oid"
        assert preset.requires_entra_tenant_id is True

    def test_unknown_returns_none(self):
        assert presets.get_preset("okta") is None


class TestGetPresetDefaults:
    def test_returns_dict(self):
        defaults = presets.get_preset_defaults("google")
        assert defaults["provider_type"] == "google"
        assert defaults["correlation_claim"] == "sub"

    def test_unknown_returns_empty(self):
        assert presets.get_preset_defaults("nope") == {}


class TestEntraAuthority:
    def test_compose_authority(self):
        assert presets.compose_entra_authority("abc-123") == (
            "https://login.microsoftonline.com/abc-123/v2.0"
        )

    def test_compose_discovery_url(self):
        assert presets.compose_entra_discovery_url("abc-123") == (
            "https://login.microsoftonline.com/abc-123/v2.0/.well-known/openid-configuration"
        )
